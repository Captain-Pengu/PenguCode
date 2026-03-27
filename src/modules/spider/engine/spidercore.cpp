#include "spidercore.h"
#include "cdpclient.h"
#include "spiderworkflow.h"

#include <QEventLoop>
#include <QFileInfo>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkCookie>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QRegularExpression>
#include <QTcpSocket>
#include <QThread>
#include <QTemporaryDir>
#include <QTimer>
#include <QUrlQuery>
#include <QCryptographicHash>
#include <QProcess>
#include <QStandardPaths>

#include <algorithm>
#include <chrono>
#include <unordered_map>

#ifdef PENGUFOCE_WITH_LIBCURL
#include <curl/curl.h>
#endif

namespace {

QString buildLoginSignature(const SpiderFetchResult &result, const QString &body);
bool looksLikeSpaCandidate(const QString &body, const SpiderFetchResult &result);
bool looksLikeLoginWall(const QString &body);

QString bodyPreview(QString body, int limit = 420)
{
    body.replace(QRegularExpression(QStringLiteral("<script[^>]*>.*?</script>"),
                                    QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption),
                 QStringLiteral(" "));
    body.replace(QRegularExpression(QStringLiteral("<style[^>]*>.*?</style>"),
                                    QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption),
                 QStringLiteral(" "));
    body.replace(QRegularExpression(QStringLiteral("<[^>]+>")), QStringLiteral(" "));
    body = body.simplified();
    if (body.size() > limit) {
        body = body.left(limit) + QStringLiteral(" ...");
    }
    return body;
}

QVariantMap sanitizedFieldMap(const QVariantMap &fields, const QString &passwordField)
{
    QVariantMap copy = fields;
    for (auto it = copy.begin(); it != copy.end(); ++it) {
        const QString key = it.key().toLower();
        if (key == passwordField.toLower() || key.contains(QStringLiteral("password")) || key.contains(QStringLiteral("passwd"))) {
            it.value() = QStringLiteral("******");
        }
    }
    return copy;
}

QString resolveWorkflowPlaceholder(QString value, const SpiderAuthProfile &auth, const QString &csrfFieldName, const QString &csrfValue)
{
    value.replace(QStringLiteral("{{username}}"), auth.username, Qt::CaseInsensitive);
    value.replace(QStringLiteral("{{password}}"), auth.password, Qt::CaseInsensitive);
    value.replace(QStringLiteral("{{login_url}}"), auth.loginUrl.toString(), Qt::CaseInsensitive);
    if (!csrfFieldName.isEmpty()) {
        value.replace(QStringLiteral("{{%1}}").arg(csrfFieldName), csrfValue, Qt::CaseInsensitive);
    }
    value.replace(QStringLiteral("{{csrf}}"), csrfValue, Qt::CaseInsensitive);
    return value;
}

QUrl resolveWorkflowStepUrl(const SpiderAuthProfile::Step &step, const QUrl &currentUrl, const QUrl &fallbackBase)
{
    if (!step.url.isValid() || step.url.isRelative()) {
        const QUrl base = currentUrl.isValid() ? currentUrl : fallbackBase;
        return base.resolved(step.url);
    }
    return step.url;
}

QString hostPressureStateName(int score)
{
    if (score >= 8) {
        return QStringLiteral("STRESSED");
    }
    if (score >= 5) {
        return QStringLiteral("WAF-GUARDED");
    }
    if (score >= 2) {
        return QStringLiteral("GUARDED");
    }
    return QStringLiteral("STABLE");
}

bool isSafeReplayRole(const QString &role)
{
    return role == QLatin1String("arama")
        || role == QLatin1String("admin-filtresi")
        || role == QLatin1String("genel-girdi")
        || role == QLatin1String("iletisim-veya-sayisal");
}

QString safeReplayValueForRole(const QString &role, const QString &name)
{
    Q_UNUSED(name);
    if (role == QLatin1String("arama")) {
        return QStringLiteral("test");
    }
    if (role == QLatin1String("admin-filtresi")) {
        return QStringLiteral("1");
    }
    if (role == QLatin1String("iletisim-veya-sayisal")) {
        return QStringLiteral("1");
    }
    return QStringLiteral("test");
}

bool workflowStepMatches(const SpiderAuthProfile::Step &step, const SpiderFetchResult &result, const QStringList &cookieNames)
{
    if (step.expectedStatusCode > 0 && result.statusCode != step.expectedStatusCode) {
        return false;
    }
    if (!step.expectedUrlContains.trimmed().isEmpty()) {
        const QString finalUrl = result.finalUrl.isValid() ? result.finalUrl.toString() : result.url.toString();
        if (!finalUrl.contains(step.expectedUrlContains, Qt::CaseInsensitive)) {
            return false;
        }
    }
    if (!step.expectedRedirectContains.trimmed().isEmpty()) {
        const QString redirectUrl = result.redirectTarget.isValid()
            ? result.redirectTarget.toString()
            : (result.finalUrl.isValid() ? result.finalUrl.toString() : QString());
        if (!redirectUrl.contains(step.expectedRedirectContains, Qt::CaseInsensitive)) {
            return false;
        }
    }
    if (!step.expectedRedirectNotContains.trimmed().isEmpty()) {
        const QString redirectUrl = result.redirectTarget.isValid()
            ? result.redirectTarget.toString()
            : (result.finalUrl.isValid() ? result.finalUrl.toString() : QString());
        if (redirectUrl.contains(step.expectedRedirectNotContains, Qt::CaseInsensitive)) {
            return false;
        }
    }
    if (!step.expectedBodyContains.trimmed().isEmpty()) {
        const QString body = QString::fromUtf8(result.body);
        if (!body.contains(step.expectedBodyContains, Qt::CaseInsensitive)) {
            return false;
        }
    }
    if (!step.expectedHeaderContains.trimmed().isEmpty()) {
        const QString needle = step.expectedHeaderContains.trimmed();
        bool matched = false;
        for (auto it = result.responseHeaders.cbegin(); it != result.responseHeaders.cend(); ++it) {
            const QString candidate = QStringLiteral("%1: %2").arg(it.key(), it.value().toString());
            if (candidate.contains(needle, Qt::CaseInsensitive)) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            return false;
        }
    }
    if (!step.expectedCookieName.trimmed().isEmpty()) {
        const QString responseCookies = result.responseHeaders.value(QStringLiteral("set-cookie")).toString();
        const bool cookieMatched = responseCookies.contains(step.expectedCookieName, Qt::CaseInsensitive)
            || cookieNames.contains(step.expectedCookieName, Qt::CaseInsensitive);
        if (!cookieMatched) {
            return false;
        }
    }
    if (step.expectNotLogin && looksLikeLoginWall(QString::fromUtf8(result.body))) {
        return false;
    }
    return true;
}

class AsyncQtSpiderFetcher final : public QObject, public ISpiderFetcher, public ISpiderAsyncFetcher
{
public:
    AsyncQtSpiderFetcher()
    {
        m_workerRoot = new QObject();
        m_workerRoot->moveToThread(&m_thread);
        connect(&m_thread, &QThread::finished, m_workerRoot, &QObject::deleteLater);
        m_thread.start();
        QMetaObject::invokeMethod(m_workerRoot, [this]() {
            m_manager = new QNetworkAccessManager();
            m_manager->moveToThread(&m_thread);
        }, Qt::BlockingQueuedConnection);
    }

    ~AsyncQtSpiderFetcher() override
    {
        m_shuttingDown = true;
        QPointer<QObject> workerRoot(m_workerRoot);
        QMetaObject::invokeMethod(m_workerRoot, [this, workerRoot]() {
            if (!workerRoot) {
                return;
            }
            for (QNetworkReply *reply : std::as_const(m_liveReplies)) {
                if (reply) {
                    reply->abort();
                    reply->deleteLater();
                }
            }
            m_liveReplies.clear();
            if (m_manager) {
                m_manager->deleteLater();
                m_manager = nullptr;
            }
        }, Qt::BlockingQueuedConnection);
        {
            std::scoped_lock lock(m_callbackMutex);
            m_callbacks.clear();
        }
        m_thread.quit();
        m_thread.wait();
    }

    SpiderFetchResult fetch(const QUrl &url, int timeoutMs, const QVariantMap &headers = {}) override
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        SpiderFetchResult result;
        startRequest(url, timeoutMs, QByteArray(), false, headers, [&mutex, &cv, &done, &result](SpiderFetchResult response) mutable {
            {
                std::scoped_lock lock(mutex);
                result = std::move(response);
                done = true;
            }
            cv.notify_one();
        });
        std::unique_lock lock(mutex);
        cv.wait(lock, [&done]() { return done; });
        return result;
    }

    SpiderFetchResult submitForm(const QUrl &url, const QVariantMap &fields, int timeoutMs, const QVariantMap &headers = {}) override
    {
        QUrlQuery query;
        for (auto it = fields.cbegin(); it != fields.cend(); ++it) {
            query.addQueryItem(it.key(), it.value().toString());
        }
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        SpiderFetchResult result;
        startRequest(url, timeoutMs, query.query(QUrl::FullyEncoded).toUtf8(), true, headers, [&mutex, &cv, &done, &result](SpiderFetchResult response) mutable {
            {
                std::scoped_lock lock(mutex);
                result = std::move(response);
                done = true;
            }
            cv.notify_one();
        });
        std::unique_lock lock(mutex);
        cv.wait(lock, [&done]() { return done; });
        return result;
    }

    void fetchAsync(const QUrl &url, int timeoutMs, const QVariantMap &headers, FetchCallback callback) override
    {
        startRequest(url, timeoutMs, QByteArray(), false, headers, std::move(callback));
    }

    void cancelAll() override
    {
        QMetaObject::invokeMethod(m_workerRoot, [this]() {
            for (QNetworkReply *reply : std::as_const(m_liveReplies)) {
                if (reply) {
                    reply->setProperty("pengufoce_watchdog_abort", true);
                    reply->abort();
                }
            }
        }, Qt::QueuedConnection);
    }

    int cookieCount() const override
    {
        std::scoped_lock lock(m_cookieMutex);
        return m_cookies.size();
    }

    QStringList cookieNames() const override
    {
        std::scoped_lock lock(m_cookieMutex);
        QStringList names;
        for (const auto &cookie : m_cookies) {
            names << QString::fromUtf8(cookie.name());
        }
        names.removeDuplicates();
        return names;
    }

private:
    void prepareRequest(QNetworkRequest &request, const QUrl &url, int timeoutMs, bool isPost, const QVariantMap &headers)
    {
        request.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce-SpiderCore/1.0");
        request.setTransferTimeout(timeoutMs);
        {
            std::scoped_lock lock(m_cookieMutex);
            const QByteArray cookieHeader = cookieHeaderForUrl(url);
            if (!cookieHeader.isEmpty()) {
                request.setRawHeader("Cookie", cookieHeader);
            }
        }
        if (isPost) {
            request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
        }
        for (auto it = headers.cbegin(); it != headers.cend(); ++it) {
            const QByteArray name = it.key().toUtf8();
            if (name.isEmpty()) {
                continue;
            }
            request.setRawHeader(name, it.value().toString().toUtf8());
        }
    }

    void startRequest(const QUrl &url, int timeoutMs, const QByteArray &payload, bool isPost, const QVariantMap &headers, FetchCallback callback)
    {
        if (m_shuttingDown.load()) {
            SpiderFetchResult errorResult;
            errorResult.url = url;
            errorResult.finalUrl = url;
            errorResult.errorString = QStringLiteral("Async fetcher kapatiliyor");
            if (callback) {
                callback(std::move(errorResult));
            }
            return;
        }

        const quint64 requestId = ++m_requestId;
        {
            std::scoped_lock lock(m_callbackMutex);
            m_callbacks.emplace(requestId, std::move(callback));
        }

        QPointer<AsyncQtSpiderFetcher> self(this);
        QMetaObject::invokeMethod(m_workerRoot, [this, self, requestId, url, timeoutMs, payload, isPost, headers]() {
            if (!self || !m_manager || m_shuttingDown.load()) {
                SpiderFetchResult errorResult;
                errorResult.url = url;
                errorResult.finalUrl = url;
                errorResult.errorString = QStringLiteral("Async fetcher hazir degil");
                dispatchResult(requestId, std::move(errorResult));
                return;
            }

            QNetworkRequest request(url);
            prepareRequest(request, url, timeoutMs, isPost, headers);
            QNetworkReply *reply = isPost ? m_manager->post(request, payload) : m_manager->get(request);
            m_liveReplies.insert(reply);
            auto *timer = new QTimer(reply);
            timer->setSingleShot(true);
            QObject::connect(timer, &QTimer::timeout, reply, [reply]() {
                reply->abort();
            });
            timer->start(timeoutMs);

            QObject::connect(reply, &QNetworkReply::finished, reply, [this, requestId, reply, url, timer]() {
                Q_UNUSED(timer);
                SpiderFetchResult result;
                result.url = url;
                result.finalUrl = reply->url();
                if (reply->operation() == QNetworkAccessManager::UnknownOperation) {
                    result.finalUrl = url;
                }
                if (reply->error() == QNetworkReply::OperationCanceledError) {
                    result.errorString = reply->property("pengufoce_watchdog_abort").toBool()
                        ? QStringLiteral("Watchdog abort")
                        : QStringLiteral("Zaman asimi");
                } else {
                    result.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                    result.contentType = reply->header(QNetworkRequest::ContentTypeHeader).toString();
                    result.redirectTarget = reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
                    for (const auto &pair : reply->rawHeaderPairs()) {
                        const QString key = QString::fromUtf8(pair.first).toLower();
                        const QString value = QString::fromUtf8(pair.second);
                        if (result.responseHeaders.contains(key)) {
                            result.responseHeaders.insert(key, result.responseHeaders.value(key).toString() + QStringLiteral("; ") + value);
                        } else {
                            result.responseHeaders.insert(key, value);
                        }
                    }
                    result.body = reply->readAll();
                    const QString textBody = QString::fromUtf8(result.body);
                    result.pageTitle = m_htmlExtractor->extractPageTitle(textBody);
                    result.headingHints = m_htmlExtractor->extractHeadingHints(textBody);
                    updateCookies(url, reply->rawHeaderPairs());
                    if (reply->error() != QNetworkReply::NoError) {
                        result.errorString = reply->errorString();
                    }
                }
                m_liveReplies.remove(reply);
                reply->deleteLater();
                dispatchResult(requestId, std::move(result));
            });
        }, Qt::QueuedConnection);
    }

    void dispatchResult(quint64 requestId, SpiderFetchResult result)
    {
        FetchCallback callback;
        {
            std::scoped_lock lock(m_callbackMutex);
            auto it = m_callbacks.find(requestId);
            if (it != m_callbacks.end()) {
                callback = std::move(it->second);
                m_callbacks.erase(it);
            }
        }
        if (callback && !m_shuttingDown.load()) {
            callback(std::move(result));
        }
    }

    QByteArray cookieHeaderForUrl(const QUrl &url) const
    {
        QList<QByteArray> parts;
        for (const auto &cookie : m_cookies) {
            const QString domain = cookie.domain().startsWith('.') ? cookie.domain().mid(1) : cookie.domain();
            const bool domainOk = domain.isEmpty() || url.host().endsWith(domain, Qt::CaseInsensitive);
            const bool pathOk = cookie.path().isEmpty() || url.path().startsWith(cookie.path());
            const bool secureOk = !cookie.isSecure() || url.scheme().compare("https", Qt::CaseInsensitive) == 0;
            if (domainOk && pathOk && secureOk) {
                parts << cookie.name() + "=" + cookie.value();
            }
        }
        return parts.join("; ");
    }

    void updateCookies(const QUrl &url, const QList<QNetworkReply::RawHeaderPair> &headers)
    {
        std::scoped_lock lock(m_cookieMutex);
        for (const auto &header : headers) {
            if (header.first.compare("Set-Cookie", Qt::CaseInsensitive) != 0) {
                continue;
            }
            const auto parsedCookies = QNetworkCookie::parseCookies(header.second);
            for (auto cookie : parsedCookies) {
                if (cookie.domain().isEmpty()) {
                    cookie.setDomain(url.host());
                }
                if (cookie.path().isEmpty()) {
                    cookie.setPath("/");
                }
                bool replaced = false;
                for (auto &existing : m_cookies) {
                    if (existing.name() == cookie.name()
                        && existing.domain().compare(cookie.domain(), Qt::CaseInsensitive) == 0
                        && existing.path() == cookie.path()) {
                        existing = cookie;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced) {
                    m_cookies.push_back(cookie);
                }
            }
        }
    }

    mutable std::mutex m_cookieMutex;
    QList<QNetworkCookie> m_cookies;
    QThread m_thread;
    QObject *m_workerRoot = nullptr;
    QNetworkAccessManager *m_manager = nullptr;
    QSet<QNetworkReply *> m_liveReplies;
    std::atomic<bool> m_shuttingDown{false};
    std::unique_ptr<ISpiderHtmlExtractor> m_htmlExtractor = createBestSpiderHtmlExtractor();
    std::atomic<quint64> m_requestId{0};
    std::mutex m_callbackMutex;
    std::unordered_map<quint64, FetchCallback> m_callbacks;
};

class ProcessSpiderDomRenderer final : public ISpiderDomRenderer
{
public:
    ProcessSpiderDomRenderer()
    {
        const QStringList candidates = {
            QStringLiteral("msedge"),
            QStringLiteral("chrome"),
            QStringLiteral("chromium"),
            QStringLiteral("chromium-browser"),
            QStringLiteral("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
            QStringLiteral("C:/Program Files/Microsoft/Edge/Application/msedge.exe"),
            QStringLiteral("C:/Program Files/Google/Chrome/Application/chrome.exe"),
            QStringLiteral("C:/Program Files (x86)/Google/Chrome/Application/chrome.exe")
        };
        for (const QString &candidate : candidates) {
            const QString resolved = candidate.contains(":/", Qt::CaseInsensitive)
                ? candidate
                : QStandardPaths::findExecutable(candidate);
            if (!resolved.isEmpty() && QFileInfo::exists(resolved)) {
                m_binary = resolved;
                break;
            }
        }
    }

    bool available() const override
    {
        return !m_binary.isEmpty();
    }

    QString backendName() const override
    {
        return available() ? QFileInfo(m_binary).baseName() : QStringLiteral("headless-browser-yok");
    }

    SpiderRenderResult render(const QUrl &url, int timeoutMs) override
    {
        SpiderRenderResult result;
        result.available = available();
        result.backendName = backendName();
        if (!available()) {
            result.errorString = QStringLiteral("Headless tarayici bulunamadi");
            return result;
        }

        QProcess process;
        QTemporaryDir profileDir;
        profileDir.setAutoRemove(true);
        if (!profileDir.isValid()) {
            result.errorString = QStringLiteral("Gecici browser profili olusturulamadi");
            return result;
        }
        QStringList args = {
            QStringLiteral("--headless"),
            QStringLiteral("--disable-gpu"),
            QStringLiteral("--run-all-compositor-stages-before-draw"),
            QStringLiteral("--remote-debugging-port=0"),
            QStringLiteral("--user-data-dir=%1").arg(QDir::toNativeSeparators(profileDir.path())),
            QStringLiteral("--virtual-time-budget=%1").arg(qMax(2500, timeoutMs - 500)),
            QStringLiteral("--dump-dom"),
            url.toString()
        };
        process.start(m_binary, args);
        if (!process.waitForStarted(qMin(timeoutMs, 2000))) {
            result.errorString = QStringLiteral("Headless tarayici baslatilamadi");
            return result;
        }

        const auto fetchJson = [](const QUrl &targetUrl, int timeoutMs) -> QJsonDocument {
            QTcpSocket socket;
            socket.connectToHost(targetUrl.host(), quint16(targetUrl.port(80)));
            if (!socket.waitForConnected(qMin(timeoutMs, 1200))) {
                return {};
            }

            const QString path = targetUrl.path().isEmpty() ? QStringLiteral("/") : targetUrl.path();
            const QString requestPath = targetUrl.query().isEmpty() ? path : QStringLiteral("%1?%2").arg(path, targetUrl.query());
            QByteArray request;
            request += "GET " + requestPath.toUtf8() + " HTTP/1.1\r\n";
            request += "Host: " + targetUrl.host().toUtf8() + ":" + QByteArray::number(targetUrl.port(80)) + "\r\n";
            request += "Connection: close\r\n\r\n";
            socket.write(request);
            if (!socket.waitForBytesWritten(qMin(timeoutMs, 1200))) {
                socket.abort();
                return {};
            }

            QByteArray response;
            const qint64 deadline = QDateTime::currentMSecsSinceEpoch() + timeoutMs;
            while (QDateTime::currentMSecsSinceEpoch() < deadline) {
                if (!socket.waitForReadyRead(250)) {
                    if (socket.state() != QAbstractSocket::ConnectedState) {
                        break;
                    }
                    continue;
                }
                response += socket.readAll();
                if (socket.state() != QAbstractSocket::ConnectedState) {
                    break;
                }
            }
            socket.abort();
            const int headerEnd = response.indexOf("\r\n\r\n");
            const QByteArray body = headerEnd >= 0 ? response.mid(headerEnd + 4) : response;
            return QJsonDocument::fromJson(body);
        };

        const QString activePortFile = profileDir.filePath(QStringLiteral("DevToolsActivePort"));
        const qint64 discoveryDeadline = QDateTime::currentMSecsSinceEpoch() + qMin(timeoutMs / 2, 2500);
        while (QDateTime::currentMSecsSinceEpoch() < discoveryDeadline && !QFile::exists(activePortFile)) {
            QThread::msleep(50);
        }
        if (QFile::exists(activePortFile)) {
            QFile file(activePortFile);
            if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                const QStringList lines = QString::fromUtf8(file.readAll()).split('\n', Qt::SkipEmptyParts);
                const QString port = lines.value(0).trimmed();
                if (!port.isEmpty()) {
                    result.debuggerHttpUrl = QStringLiteral("http://127.0.0.1:%1").arg(port);
                    const QJsonDocument versionDoc = fetchJson(QUrl(result.debuggerHttpUrl + QStringLiteral("/json/version")), qMin(timeoutMs, 1500));
                    if (versionDoc.isObject()) {
                        const QJsonObject obj = versionDoc.object();
                        result.browserWsUrl = obj.value(QStringLiteral("webSocketDebuggerUrl")).toString();
                    }
                    const QJsonDocument listDoc = fetchJson(QUrl(result.debuggerHttpUrl + QStringLiteral("/json/list")), qMin(timeoutMs, 1500));
                    if (listDoc.isArray()) {
                        const QJsonArray pages = listDoc.array();
                        for (const auto &pageValue : pages) {
                            const QJsonObject page = pageValue.toObject();
                            const QString pageUrl = page.value(QStringLiteral("url")).toString();
                            if (pageUrl == url.toString()) {
                                result.pageWsUrl = page.value(QStringLiteral("webSocketDebuggerUrl")).toString();
                                break;
                            }
                            if (result.pageWsUrl.isEmpty()) {
                                result.pageWsUrl = page.value(QStringLiteral("webSocketDebuggerUrl")).toString();
                            }
                        }
                    }
                }
            }
        }

        if (!process.waitForFinished(timeoutMs)) {
            process.kill();
            process.waitForFinished(1000);
            result.errorString = QStringLiteral("Headless render zaman asimina ugradi");
            return result;
        }

        const QString stdOut = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        const QString stdErr = QString::fromUtf8(process.readAllStandardError()).trimmed();
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0 || stdOut.isEmpty()) {
            result.errorString = stdErr.isEmpty()
                ? QStringLiteral("Headless render ciktisi alinmadi")
                : stdErr.left(280);
            return result;
        }

        result.ok = true;
        result.renderedHtml = stdOut;
        return result;
    }

private:
    QString m_binary;
};

#ifdef PENGUFOCE_WITH_LIBCURL
size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    auto *buffer = static_cast<QByteArray *>(userdata);
    buffer->append(ptr, static_cast<qsizetype>(size * nmemb));
    return size * nmemb;
}

class CurlSpiderFetcher final : public ISpiderFetcher
{
public:
    CurlSpiderFetcher()
    {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~CurlSpiderFetcher() override
    {
        curl_global_cleanup();
    }

    SpiderFetchResult fetch(const QUrl &url, int timeoutMs, const QVariantMap &headers = {}) override
    {
        Q_UNUSED(headers);
        SpiderFetchResult result;
        result.url = url;
        result.finalUrl = url;

        CURLM *multi = curl_multi_init();
        CURL *easy = curl_easy_init();
        if (!multi || !easy) {
            if (easy) {
                curl_easy_cleanup(easy);
            }
            if (multi) {
                curl_multi_cleanup(multi);
            }
            result.errorString = QStringLiteral("libcurl baslatilamadi");
            return result;
        }

        QByteArray body;
        curl_easy_setopt(easy, CURLOPT_URL, url.toString().toUtf8().constData());
        curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(easy, CURLOPT_USERAGENT, "PenguFoce-SpiderCore/1.0");
        curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, curlWriteCallback);
        curl_easy_setopt(easy, CURLOPT_WRITEDATA, &body);
        curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, timeoutMs);
        curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, qMin(timeoutMs, 1500));
        curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);

        curl_multi_add_handle(multi, easy);

        int runningHandles = 0;
        curl_multi_perform(multi, &runningHandles);

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (runningHandles > 0 && std::chrono::steady_clock::now() < deadline) {
            int numfds = 0;
            curl_multi_wait(multi, nullptr, 0, 200, &numfds);
            curl_multi_perform(multi, &runningHandles);
        }

        long responseCode = 0;
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &responseCode);
        result.statusCode = static_cast<int>(responseCode);
        result.body = std::move(body);

        char *contentType = nullptr;
        curl_easy_getinfo(easy, CURLINFO_CONTENT_TYPE, &contentType);
        result.contentType = contentType ? QString::fromUtf8(contentType) : QString();
        char *effectiveUrl = nullptr;
        curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &effectiveUrl);
        if (effectiveUrl) {
            result.finalUrl = QUrl(QString::fromUtf8(effectiveUrl));
        }
        {
            const QString textBody = QString::fromUtf8(result.body);
            auto extractor = createBestSpiderHtmlExtractor();
            result.pageTitle = extractor->extractPageTitle(textBody);
            result.headingHints = extractor->extractHeadingHints(textBody);
        }

        if (runningHandles > 0) {
            result.errorString = QStringLiteral("Zaman asimi");
        } else {
            CURLcode code = CURLE_OK;
            curl_easy_getinfo(easy, CURLINFO_CONDITION_UNMET, &code);
            if (code != CURLE_OK && responseCode == 0) {
                result.errorString = QString::fromUtf8(curl_easy_strerror(code));
            }
        }

        curl_multi_remove_handle(multi, easy);
        curl_easy_cleanup(easy);
        curl_multi_cleanup(multi);
        return result;
    }

    SpiderFetchResult submitForm(const QUrl &url, const QVariantMap &fields, int timeoutMs, const QVariantMap &headers = {}) override
    {
        Q_UNUSED(headers);
        Q_UNUSED(fields);
        Q_UNUSED(timeoutMs);
        SpiderFetchResult result;
        result.url = url;
        result.finalUrl = url;
        result.errorString = QStringLiteral("libcurl form gonderimi bu profilde etkin degil");
        return result;
    }

    int cookieCount() const override
    {
        return 0;
    }

    QStringList cookieNames() const override
    {
        return {};
    }
};
#endif

bool isHtmlLike(const QString &contentType, const QUrl &url)
{
    return contentType.contains("text/html", Qt::CaseInsensitive)
        || contentType.contains("application/xhtml", Qt::CaseInsensitive)
        || url.path().endsWith(".html", Qt::CaseInsensitive)
        || url.path().endsWith(".php", Qt::CaseInsensitive)
        || url.path().endsWith(".asp", Qt::CaseInsensitive)
        || url.path().isEmpty()
        || url.path() == "/";
}

QString buildLoginSignature(const SpiderFetchResult &result, const QString &body)
{
    auto extractor = createBestSpiderHtmlExtractor();
    const QString title = extractor->extractPageTitle(body);
    const QStringList headings = extractor->extractHeadingHints(body);
    const QString lowered = body.left(4000).toLower();
    QStringList markers;
    if (lowered.contains("type=\"password\"") || lowered.contains("type='password'")) {
        markers << QStringLiteral("password");
    }
    if (lowered.contains("csrf") || lowered.contains("_token")) {
        markers << QStringLiteral("csrf");
    }
    if (lowered.contains("remember me") || lowered.contains("beni hatirla")) {
        markers << QStringLiteral("remember");
    }
    if (lowered.contains("otp") || lowered.contains("mfa") || lowered.contains("two-factor")) {
        markers << QStringLiteral("mfa");
    }

    return QStringLiteral("%1|%2|%3|%4|%5")
        .arg(result.statusCode)
        .arg(result.contentType.left(48))
        .arg(result.finalUrl.path())
        .arg(title)
        .arg((headings + markers).join('|'));
}

bool looksLikeSpaCandidate(const QString &body, const SpiderFetchResult &result)
{
    const QString lowered = body.left(20000).toLower();
    if (!result.contentType.contains("html", Qt::CaseInsensitive) && !result.contentType.isEmpty()) {
        return false;
    }

    return lowered.contains("__next_data__")
        || lowered.contains("window.__nuxt")
        || lowered.contains("data-reactroot")
        || lowered.contains("id=\"root\"")
        || lowered.contains("id='root'")
        || lowered.contains("id=\"app\"")
        || lowered.contains("id='app'")
        || lowered.contains("ng-version")
        || lowered.contains("vite/client")
        || lowered.contains("webpack")
        || lowered.contains("chunk.js")
        || lowered.contains("type=\"module\"")
        || lowered.contains("router-view")
        || lowered.contains("hydrateRoot");
}

bool looksLikeLoginWall(const QString &body)
{
    const QString lowered = body.left(12000).toLower();
    const bool hasPasswordField = lowered.contains("type=\"password\"")
        || lowered.contains("type='password'")
        || lowered.contains("name=\"password\"")
        || lowered.contains("name='password'");
    const bool hasLoginCopy = lowered.contains("login")
        || lowered.contains("sign in")
        || lowered.contains("oturum ac")
        || lowered.contains("giris yap")
        || lowered.contains("authenticate");
    return hasPasswordField && hasLoginCopy;
}

bool looksLikeLoginPath(const QUrl &url)
{
    const QString lowered = url.path().toLower();
    return lowered.contains("login")
        || lowered.contains("signin")
        || lowered.contains("auth")
        || lowered.contains("session")
        || lowered.contains("account");
}

bool looksLikeSoft404(const QString &body, const QUrl &url, int statusCode)
{
    if (statusCode != 200) {
        return false;
    }

    const QString lowered = body.left(8000).toLower();
    const bool bodySignalsMissing = lowered.contains("404")
        || lowered.contains("not found")
        || lowered.contains("page not found")
        || lowered.contains("sayfa bulunamadi")
        || lowered.contains("aradiginiz sayfa")
        || lowered.contains("bulunamadi");
    const bool suspiciousPath = url.path().contains("404", Qt::CaseInsensitive)
        || url.path().contains("not-found", Qt::CaseInsensitive)
        || url.path().contains("missing", Qt::CaseInsensitive);
    return bodySignalsMissing || suspiciousPath;
}

bool looksLikeAccessDenied(const QString &body, int statusCode)
{
    if (statusCode != 401 && statusCode != 403) {
        return false;
    }
    const QString lowered = body.left(8000).toLower();
    return lowered.contains("access denied")
        || lowered.contains("forbidden")
        || lowered.contains("yetkiniz yok")
        || lowered.contains("erişim engellendi")
        || lowered.contains("unauthorized")
        || lowered.contains("permission denied");
}

bool looksLikeWafChallenge(const QString &body, const SpiderFetchResult &result)
{
    const QString loweredBody = body.left(12000).toLower();
    const QString loweredTitle = result.pageTitle.toLower();
    const QString loweredType = result.contentType.toLower();
    const bool challengeStatus = result.statusCode == 403 || result.statusCode == 429 || result.statusCode == 503;
    const bool bodySignals = loweredBody.contains("attention required")
        || loweredBody.contains("cloudflare")
        || loweredBody.contains("captcha")
        || loweredBody.contains("verify you are human")
        || loweredBody.contains("bot challenge")
        || loweredBody.contains("request blocked")
        || loweredBody.contains("security check");
    const bool titleSignals = loweredTitle.contains("attention required")
        || loweredTitle.contains("just a moment")
        || loweredTitle.contains("captcha")
        || loweredTitle.contains("security check");
    const bool htmlLike = loweredType.contains("html") || loweredType.isEmpty();
    return htmlLike && (bodySignals || titleSignals) && challengeStatus;
}

qint64 retryAfterDelayMs(const SpiderFetchResult &result)
{
    const QString raw = result.responseHeaders.value(QStringLiteral("retry-after")).toString().trimmed();
    if (raw.isEmpty()) {
        return -1;
    }
    bool ok = false;
    const int seconds = raw.toInt(&ok);
    if (ok && seconds >= 0) {
        return static_cast<qint64>(seconds) * 1000;
    }
    const QDateTime retryAt = QDateTime::fromString(raw, Qt::RFC2822Date);
    if (retryAt.isValid()) {
        return qMax<qint64>(0, QDateTime::currentDateTimeUtc().msecsTo(retryAt.toUTC()));
    }
    return -1;
}

QString wafVendorHint(const QString &body, const SpiderFetchResult &result)
{
    const QString loweredBody = body.left(12000).toLower();
    const QString server = result.responseHeaders.value(QStringLiteral("server")).toString().toLower();
    const QString poweredBy = result.responseHeaders.value(QStringLiteral("x-powered-by")).toString().toLower();
    const QString cache = result.responseHeaders.value(QStringLiteral("cf-cache-status")).toString().toLower();

    if (loweredBody.contains(QStringLiteral("cloudflare")) || !cache.isEmpty() || server.contains(QStringLiteral("cloudflare"))) {
        return QStringLiteral("cloudflare");
    }
    if (loweredBody.contains(QStringLiteral("akamai")) || server.contains(QStringLiteral("akamai"))) {
        return QStringLiteral("akamai");
    }
    if (loweredBody.contains(QStringLiteral("imperva")) || server.contains(QStringLiteral("imperva")) || poweredBy.contains(QStringLiteral("imperva"))) {
        return QStringLiteral("imperva");
    }
    if (loweredBody.contains(QStringLiteral("perimeterx")) || loweredBody.contains(QStringLiteral("human security"))) {
        return QStringLiteral("perimeterx");
    }
    if (loweredBody.contains(QStringLiteral("sucuri")) || server.contains(QStringLiteral("sucuri"))) {
        return QStringLiteral("sucuri");
    }
    if (loweredBody.contains(QStringLiteral("aws waf")) || loweredBody.contains(QStringLiteral("request blocked"))) {
        return QStringLiteral("aws-waf");
    }
    return QStringLiteral("generic");
}

} // namespace

SpiderThreadPool::SpiderThreadPool()
{
    const unsigned int threadCount = qMax(2u, std::thread::hardware_concurrency());
    m_workers.reserve(threadCount);
    for (unsigned int i = 0; i < threadCount; ++i) {
        m_workers.emplace_back([this]() { workerLoop(); });
    }
}

SpiderThreadPool::~SpiderThreadPool()
{
    {
        std::scoped_lock lock(m_mutex);
        m_stopping = true;
    }
    m_cv.notify_all();
    for (auto &worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void SpiderThreadPool::enqueue(std::function<void()> task)
{
    {
        std::scoped_lock lock(m_mutex);
        m_tasks.push(std::move(task));
    }
    m_cv.notify_one();
}

void SpiderThreadPool::clearPendingTasks()
{
    {
        std::scoped_lock lock(m_mutex);
        std::queue<std::function<void()>> empty;
        std::swap(m_tasks, empty);
    }
    m_idleCv.notify_all();
}

void SpiderThreadPool::waitUntilIdle()
{
    std::unique_lock lock(m_mutex);
    m_idleCv.wait(lock, [this]() { return m_tasks.empty() && m_activeTasks.load() == 0; });
}

void SpiderThreadPool::workerLoop()
{
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock lock(m_mutex);
            m_cv.wait(lock, [this]() { return m_stopping || !m_tasks.empty(); });
            if (m_stopping && m_tasks.empty()) {
                return;
            }
            task = std::move(m_tasks.front());
            m_tasks.pop();
            ++m_activeTasks;
        }

        task();

        {
            std::scoped_lock lock(m_mutex);
            --m_activeTasks;
        }
        m_idleCv.notify_all();
    }
}

SpiderCore::SpiderCore(std::unique_ptr<ISpiderFetcher> fetcher,
                       std::unique_ptr<ISpiderDomRenderer> renderer,
                       std::unique_ptr<ISpiderHtmlExtractor> htmlExtractor)
    : m_fetcher(std::move(fetcher))
    , m_renderer(std::move(renderer))
    , m_htmlExtractor(htmlExtractor ? std::move(htmlExtractor) : createBestSpiderHtmlExtractor())
{
}

SpiderCore::~SpiderCore()
{
    stop();
    if (m_watchdogThread.joinable()) {
        m_watchdogThread.join();
    }
    {
        std::unique_lock lock(m_fetchDrainMutex);
        m_fetchDrainCv.wait(lock, [this]() { return m_activeFetches.load() == 0; });
    }
    m_pool.waitUntilIdle();
}

void SpiderCore::setEventCallback(EventCallback callback)
{
    m_eventCallback = std::move(callback);
}

void SpiderCore::setEndpointCallback(EndpointCallback callback)
{
    m_endpointCallback = std::move(callback);
}

void SpiderCore::setParameterCallback(ParameterCallback callback)
{
    m_parameterCallback = std::move(callback);
}

void SpiderCore::setAssetCallback(AssetCallback callback)
{
    m_assetCallback = std::move(callback);
}

void SpiderCore::setFinishedCallback(FinishedCallback callback)
{
    m_finishedCallback = std::move(callback);
}

void SpiderCore::start(const QUrl &seedUrl, const SpiderRunOptions &options)
{
    stop();
    reset();

    m_seedUrl = seedUrl;
    m_options = options;
    m_options.maxPages = qMax(5, m_options.maxPages);
    m_options.timeoutMs = qBound(800, m_options.timeoutMs, 10000);
    m_options.maxDepth = qBound(1, m_options.maxDepth, 10);
    m_options.maxWorkflowActions = qBound(0, m_options.maxWorkflowActions, 40);
    if (m_options.ignoredExtensions.isEmpty()) {
        m_options.ignoredExtensions = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "eot", "mp4", "mp3", "avi", "zip", "rar", "7z", "pdf", "css", "map"};
    }
    m_running = true;
    m_stopping = false;
    m_authenticated = false;
    m_workflowActionsUsed = 0;
    m_lastProgressMs = QDateTime::currentMSecsSinceEpoch();
    m_stallRecoveryCount = 0;

    emitEvent(QStringLiteral("SpiderCore basladi. Thread sayisi: %1").arg(std::thread::hardware_concurrency()));
    if (m_htmlExtractor) {
        emitEvent(QStringLiteral("[parser] HTML extractor: %1").arg(m_htmlExtractor->backendName()));
    }
    captureAnonymousSurfaceBaseline();
    authenticateIfNeeded();

    enqueue(seedUrl, QStringLiteral("seed"), QString(), 0);
    QUrl robotsUrl = seedUrl;
    robotsUrl.setPath("/robots.txt");
    enqueue(robotsUrl, QStringLiteral("robots"), QString(), 0);
    QUrl sitemapUrl = seedUrl;
    sitemapUrl.setPath("/sitemap.xml");
    enqueue(sitemapUrl, QStringLiteral("sitemap"), QString(), 0);
    QUrl manifestUrl = seedUrl;
    manifestUrl.setPath("/manifest.json");
    enqueue(manifestUrl, QStringLiteral("manifest"), QString(), 0);

    if (m_watchdogThread.joinable()) {
        m_watchdogThread.join();
    }
    m_watchdogThread = std::thread([this]() {
        while (m_running.load() && !m_stopping.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (!m_running.load() || m_stopping.load()) {
                break;
            }

            const int queued = queuedCount();
            const int active = m_activeFetches.load();
            const int processing = m_activeProcessing.load();
            const int visited = visitedCount();
            const qint64 stalledForMs = QDateTime::currentMSecsSinceEpoch() - m_lastProgressMs.load();
            if (queued == 0 && active == 0 && processing == 0) {
                emitEvent(QStringLiteral("[watchdog] Aktif is yok, bitis kontrolu zorlanıyor"));
                finishIfDone();
                continue;
            }
            if (stalledForMs < 12000) {
                continue;
            }

            emitEvent(QStringLiteral("[watchdog] queued=%1 active=%2 processing=%3 visited=%4 stall=%5ms")
                          .arg(queued)
                          .arg(active)
                          .arg(processing)
                          .arg(visited)
                          .arg(stalledForMs));

            if (active > 0) {
                if (auto *asyncFetcher = dynamic_cast<ISpiderAsyncFetcher *>(m_fetcher.get())) {
                    emitEvent(QStringLiteral("[watchdog] Asili aktif istekler iptal ediliyor"));
                    asyncFetcher->cancelAll();
                    m_lastProgressMs = QDateTime::currentMSecsSinceEpoch();
                    continue;
                }
            }

            if (queued > 0 && active == 0 && processing == 0) {
                emitEvent(QStringLiteral("[watchdog] Scheduler yeniden tetikleniyor"));
                scheduleMore();
                if (QDateTime::currentMSecsSinceEpoch() - m_lastProgressMs.load() > 12000) {
                    std::scoped_lock lock(m_queueMutex);
                    std::queue<QueueEntry> empty;
                    std::swap(m_queue, empty);
                    emitEvent(QStringLiteral("[watchdog] Bekleyen kuyruk temizlenerek tarama sonlandiriliyor"));
                }
            }
        }
    });
    scheduleMore();
}

void SpiderCore::stop()
{
    m_stopping = true;
    m_running = false;
    if (auto *asyncFetcher = dynamic_cast<ISpiderAsyncFetcher *>(m_fetcher.get())) {
        asyncFetcher->cancelAll();
    }
    {
        std::scoped_lock lock(m_queueMutex);
        std::queue<QueueEntry> empty;
        std::swap(m_queue, empty);
    }
    m_pool.clearPendingTasks();
    notifyFetchStateChanged();
    if (m_watchdogThread.joinable()) {
        m_watchdogThread.join();
    }
    m_pool.waitUntilIdle();
}

int SpiderCore::visitedCount() const
{
    return m_visitedCount.load();
}

int SpiderCore::queuedCount() const
{
    std::scoped_lock lock(m_queueMutex);
    return static_cast<int>(m_queue.size());
}

bool SpiderCore::running() const
{
    return m_running.load();
}

std::vector<QUrl> SpiderCore::extractLinks(const QString &html, const QUrl &baseUrl)
{
    return createBestSpiderHtmlExtractor()->extractLinks(html, baseUrl);
}

std::vector<QString> SpiderCore::extractParameters(const QUrl &url)
{
    std::vector<QString> result;
    const QUrlQuery query(url);
    const auto items = query.queryItems();
    result.reserve(items.size());
    for (const auto &item : items) {
        result.push_back(item.first);
    }
    return result;
}

void SpiderCore::reset()
{
    {
        std::scoped_lock queueLock(m_queueMutex);
        std::queue<QueueEntry> empty;
        std::swap(m_queue, empty);
    }
    {
        std::unique_lock seenLock(m_seenMutex);
        m_visited.clear();
        m_enqueued.clear();
        m_contentFingerprints.clear();
        m_loginFingerprints.clear();
        m_preAuthSurface.clear();
        m_hostNextAllowedAt.clear();
        m_hostPressureScore.clear();
    }
    m_activeFetches = 0;
    m_activeProcessing = 0;
    m_visitedCount = 0;
    m_authenticated = false;
    m_wakeScheduled = false;
    m_workflowActionsUsed = 0;
    m_lastProgressMs = QDateTime::currentMSecsSinceEpoch();
    m_lastSchedulerLogMs = 0;
    m_stallRecoveryCount = 0;
}

void SpiderCore::enqueue(const QUrl &url, const QString &kind, const QString &source, int depth)
{
    enqueueRequest(url, kind, source, depth, QStringLiteral("GET"));
}

void SpiderCore::enqueueRequest(const QUrl &url,
                                const QString &kind,
                                const QString &source,
                                int depth,
                                const QString &requestMethod,
                                const QVariantMap &requestFields,
                                const QVariantMap &requestHeaders)
{
    if (!url.isValid()) {
        return;
    }
    if (!isInScope(url)) {
        emitAsset({QStringLiteral("scope-outlier"),
                   QStringLiteral("%1 %2").arg(requestMethod.toUpper(), url.toString()),
                   source});
        return;
    }
    if (!matchesScopeRules(url)) {
        emitAsset({QStringLiteral("scope-excluded"),
                   QStringLiteral("%1 %2").arg(requestMethod.toUpper(), url.toString()),
                   source});
        return;
    }
    if (!shouldCrawlByExtension(url, kind)
        || alreadyQueuedOrVisited(url, requestMethod, requestFields) || depth > m_options.maxDepth) {
        return;
    }

    const std::string requestKey = keyForRequest(url, requestMethod, requestFields);
    {
        std::unique_lock lock(m_seenMutex);
        m_enqueued.insert(requestKey);
    }
    {
        std::scoped_lock lock(m_queueMutex);
        m_queue.push({url, kind, source, requestMethod, requestFields, requestHeaders, requestKey, depth, 0, 0});
    }
    m_lastProgressMs = QDateTime::currentMSecsSinceEpoch();
    m_stallRecoveryCount = 0;
    emitEvent(QStringLiteral("[%1][d%2] kuyruga alindi: %3 %4")
                  .arg(kind)
                  .arg(depth)
                  .arg(requestMethod.toUpper(), url.toString()));
}

void SpiderCore::scheduleMore()
{
    auto *asyncFetcher = dynamic_cast<ISpiderAsyncFetcher *>(m_fetcher.get());
    qint64 wakeDelayMs = -1;
    while (!m_stopping && m_running && queuedCount() > 0
           && m_activeFetches.load() < m_options.maxInFlight) {
        QueueEntry entry;
        bool foundReadyEntry = false;
        {
            std::scoped_lock lock(m_queueMutex);
            if (m_queue.empty()) {
                break;
            }
            const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
            const bool pageBudgetReached = (visitedCount() + m_activeFetches.load()) >= m_options.maxPages;
            const int queueSize = static_cast<int>(m_queue.size());
            for (int i = 0; i < queueSize; ++i) {
                QueueEntry candidate = std::move(m_queue.front());
                m_queue.pop();
                const std::string hostKey = candidate.url.host().toLower().toStdString();
                const qint64 hostReadyAt = m_hostNextAllowedAt.contains(hostKey) ? m_hostNextAllowedAt[hostKey] : 0;
                const qint64 nextReadyAt = qMax(candidate.earliestStartMs, hostReadyAt);
                const bool canDispatch = !pageBudgetReached || candidate.retryCount > 0;
                if (!foundReadyEntry && canDispatch && nextReadyAt <= nowMs) {
                    entry = std::move(candidate);
                    const int pressureScore = m_hostPressureScore.contains(hostKey) ? m_hostPressureScore[hostKey] : 0;
                    const qint64 adaptivePolitenessMs = m_options.politenessDelayMs + (pressureScore * 180);
                    m_hostNextAllowedAt[hostKey] = nowMs + adaptivePolitenessMs;
                    foundReadyEntry = true;
                    continue;
                }
                if (!foundReadyEntry) {
                    const qint64 candidateDelay = qMax<qint64>(10, nextReadyAt - nowMs);
                    wakeDelayMs = wakeDelayMs < 0 ? candidateDelay : qMin(wakeDelayMs, candidateDelay);
                }
                m_queue.push(std::move(candidate));
            }
            if (!foundReadyEntry) {
                break;
            }
        }
        m_lastProgressMs = QDateTime::currentMSecsSinceEpoch();
        m_stallRecoveryCount = 0;
        if (!markVisited(entry)) {
            continue;
        }
        ++m_activeFetches;
        notifyFetchStateChanged();
        if (asyncFetcher && entry.requestMethod.compare(QStringLiteral("GET"), Qt::CaseInsensitive) == 0 && entry.requestHeaders.isEmpty()) {
            const QUrl requestUrl = entry.url;
            asyncFetcher->fetchAsync(requestUrl, m_options.timeoutMs, {}, [this, entry = std::move(entry)](SpiderFetchResult result) mutable {
                if (m_stopping.load()) {
                    --m_activeFetches;
                    notifyFetchStateChanged();
                    finishIfDone();
                    return;
                }
                --m_activeFetches;
                ++m_activeProcessing;
                notifyFetchStateChanged();
                scheduleMore();
                m_pool.enqueue([this, entry = std::move(entry), result = std::move(result)]() mutable {
                    consumeFetchResult(std::move(entry), std::move(result));
                    m_lastProgressMs = QDateTime::currentMSecsSinceEpoch();
                    m_stallRecoveryCount = 0;
                    --m_activeProcessing;
                    notifyFetchStateChanged();
                    scheduleMore();
                });
            });
        } else {
            m_pool.enqueue([this, entry = std::move(entry)]() mutable {
                processOne(std::move(entry));
            });
        }
    }
    if (wakeDelayMs > 0 && m_activeFetches.load() == 0 && !m_stopping && m_running && !m_wakeScheduled.exchange(true)) {
        const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
        const qint64 lastSchedulerLogMs = m_lastSchedulerLogMs.load();
        if (wakeDelayMs >= 150 || lastSchedulerLogMs == 0 || (nowMs - lastSchedulerLogMs) >= 1000) {
            m_lastSchedulerLogMs = nowMs;
            emitEvent(QStringLiteral("[scheduler] Bekleyen URL'ler var, %1 ms sonra tekrar denenecek").arg(wakeDelayMs));
        }
        std::thread([this, wakeDelayMs]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(wakeDelayMs));
            m_wakeScheduled = false;
            if (!m_stopping && m_running) {
                scheduleMore();
            }
        }).detach();
    }
    if (!m_stopping && m_running && queuedCount() > 0 && m_activeFetches.load() == 0) {
        const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
        if (nowMs - m_lastProgressMs.load() > 12000) {
            const int attempt = ++m_stallRecoveryCount;
            if (attempt == 1) {
                m_lastProgressMs = nowMs;
                emitEvent(QStringLiteral("[watchdog] Ilerleme durdu, scheduler yeniden tetikleniyor"));
                m_pool.enqueue([this]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    if (!m_stopping && m_running) {
                        scheduleMore();
                    }
                });
            } else {
                {
                    std::scoped_lock lock(m_queueMutex);
                    std::queue<QueueEntry> empty;
                    std::swap(m_queue, empty);
                }
                emitEvent(QStringLiteral("[watchdog] Kuyruk ilerlemiyor, bekleyen URL'ler guvenli sekilde sonlandirildi"));
            }
        }
    }
    finishIfDone();
}

void SpiderCore::processOne(QueueEntry entry)
{
    if (m_stopping) {
        --m_activeFetches;
        notifyFetchStateChanged();
        finishIfDone();
        return;
    }

    SpiderFetchResult result;
    if (entry.requestMethod.compare(QStringLiteral("POST"), Qt::CaseInsensitive) == 0) {
        result = m_fetcher->submitForm(entry.url, entry.requestFields, m_options.timeoutMs, entry.requestHeaders);
    } else {
        result = m_fetcher->fetch(entry.url, m_options.timeoutMs, entry.requestHeaders);
    }
    consumeFetchResult(std::move(entry), result);
    m_lastProgressMs = QDateTime::currentMSecsSinceEpoch();
    m_stallRecoveryCount = 0;
    --m_activeFetches;
    notifyFetchStateChanged();
    scheduleMore();
}

void SpiderCore::consumeFetchResult(QueueEntry entry, SpiderFetchResult result)
{
    if (m_stopping.load()) {
        return;
    }
    const bool retryableHttp = result.statusCode == 429 || result.statusCode == 503 || result.statusCode == 504;
    const bool retryableNetwork = result.statusCode == 0 && !result.errorString.isEmpty()
        && !result.errorString.contains(QStringLiteral("Protocol"), Qt::CaseInsensitive)
        && !result.errorString.contains(QStringLiteral("Watchdog"), Qt::CaseInsensitive);
    if ((retryableHttp || retryableNetwork) && entry.retryCount < m_options.maxRetries && !m_stopping) {
        QueueEntry retryEntry = entry;
        retryEntry.retryCount += 1;
        const QString retryBody = QString::fromUtf8(result.body);
        const bool wafChallenge = looksLikeWafChallenge(retryBody, result);
        const QString vendorHint = wafChallenge ? wafVendorHint(retryBody, result) : QString();
        const qint64 retryAfterMs = retryAfterDelayMs(result);
        const qint64 quadraticDelayMs = 250 * retryEntry.retryCount * retryEntry.retryCount;
        const qint64 effectiveRetryDelayMs = qMax(quadraticDelayMs, retryAfterMs);
        retryEntry.earliestStartMs = QDateTime::currentMSecsSinceEpoch() + effectiveRetryDelayMs;
        {
            std::unique_lock seenLock(m_seenMutex);
            const std::string hostKey = entry.url.host().toLower().toStdString();
            qint64 adaptiveBackoffMs = retryableHttp ? (800 * retryEntry.retryCount * retryEntry.retryCount) : (350 * retryEntry.retryCount * retryEntry.retryCount);
            adaptiveBackoffMs = qMax(adaptiveBackoffMs, retryAfterMs);
            int pressureScore = m_hostPressureScore.contains(hostKey) ? m_hostPressureScore[hostKey] : 0;
            pressureScore += retryableHttp ? 2 : 1;
            if (wafChallenge) {
                pressureScore += 3;
                adaptiveBackoffMs = qMax<qint64>(adaptiveBackoffMs, 2500LL * retryEntry.retryCount);
            }
            m_hostPressureScore[hostKey] = qBound(0, pressureScore, 10);
            m_hostNextAllowedAt[hostKey] = qMax(m_hostNextAllowedAt[hostKey], QDateTime::currentMSecsSinceEpoch() + adaptiveBackoffMs);
            emitHostPressureAsset(QString::fromStdString(hostKey),
                                  m_hostPressureScore[hostKey],
                                  wafChallenge ? QStringLiteral("retry+waf") : QStringLiteral("retry"));
        }
        {
            std::scoped_lock lock(m_queueMutex);
            m_queue.push(std::move(retryEntry));
        }
        if (retryAfterMs > 0) {
            emitAsset({QStringLiteral("retry-after"),
                       QStringLiteral("host=%1 | delay=%2 ms | url=%3")
                           .arg(entry.url.host(),
                                QString::number(retryAfterMs),
                                entry.url.toString()),
                       entry.url.toString()});
        }
        emitAsset({QStringLiteral("retry-scheduled"),
                   QStringLiteral("host=%1 | retry=%2/%3 | delay=%4 ms")
                       .arg(entry.url.host())
                       .arg(entry.retryCount + 1)
                       .arg(m_options.maxRetries)
                       .arg(effectiveRetryDelayMs),
                   entry.url.toString()});
        if (wafChallenge) {
            emitAsset({QStringLiteral("waf-vendor"),
                       vendorHint,
                       entry.url.toString()});
        }
        emitEvent(QStringLiteral("[retry] %1 icin yeniden deneme planlandi (%2/%3 | gecikme=%4 ms%5)")
                      .arg(entry.url.toString())
                      .arg(entry.retryCount + 1)
                      .arg(m_options.maxRetries)
                      .arg(effectiveRetryDelayMs)
                      .arg(wafChallenge ? QStringLiteral(" | waf=%1").arg(vendorHint) : QString()));
        notifyFetchStateChanged();
        return;
    }

    if (result.statusCode > 0) {
        const QString sessionState = sessionStateForUrl(result.url);
        emitEndpoint({result.url,
                      entry.kind,
                      entry.source,
                      entry.depth,
                      result.statusCode,
                      result.contentType,
                      sessionState,
                      result.finalUrl.toString(),
                      result.pageTitle});
        if (!result.redirectTarget.isEmpty() || (result.finalUrl.isValid() && result.finalUrl != result.url)) {
            const QString redirectText = QStringLiteral("%1 -> %2")
                                             .arg(result.url.toString(),
                                                  (result.finalUrl.isValid() ? result.finalUrl : result.redirectTarget).toString());
            emitAsset({QStringLiteral("redirect-chain"), redirectText, entry.kind});
        }
        if (!result.pageTitle.isEmpty() || !result.headingHints.isEmpty()) {
            const QString signatureText = QStringLiteral("title=%1 | headings=%2")
                                              .arg(result.pageTitle,
                                                   result.headingHints.join(" | "));
            emitAsset({QStringLiteral("response-signature"), signatureText, result.url.toString()});
        }
        const QString body = QString::fromUtf8(result.body);
        if (entry.kind == QLatin1String("workflow-submit") || entry.kind == QLatin1String("workflow-action")) {
            emitAsset({entry.kind + QStringLiteral("-result"),
                       QStringLiteral("%1 %2 | final=%3 | status=%4")
                           .arg(entry.requestMethod.toUpper(),
                                result.url.toString(),
                                (result.finalUrl.isValid() ? result.finalUrl : result.url).toString())
                           .arg(result.statusCode),
                       entry.source});
        }
        if (!result.errorString.isEmpty()) {
            emitAsset({QStringLiteral("http-response"),
                       QStringLiteral("HTTP %1 | %2 | %3")
                           .arg(result.statusCode)
                           .arg(result.url.toString(), result.errorString),
                       entry.kind});
            if (result.statusCode == 403) {
                emitEvent(QStringLiteral("[http] HTTP 403 erisim reddi: %1").arg(result.url.toString()));
            } else if (result.statusCode == 404) {
                emitEvent(QStringLiteral("[http] HTTP 404 bulunamadi: %1").arg(result.url.toString()));
            } else if (result.statusCode >= 400) {
                emitEvent(QStringLiteral("[http] HTTP %1 yaniti: %2").arg(result.statusCode).arg(result.url.toString()));
            }
        }
        if (m_options.enableHeadlessRender && m_renderer && m_renderer->available() && looksLikeSpaCandidate(body, result)) {
            emitEndpoint({result.url,
                          QStringLiteral("render-candidate"),
                          entry.source,
                          entry.depth,
                          result.statusCode,
                          result.contentType,
                          sessionState,
                          result.finalUrl.toString(),
                          result.pageTitle});
            emitAsset({QStringLiteral("render-backend"),
                       QStringLiteral("%1 | %2").arg(m_renderer->backendName(), result.url.toString()),
                       result.url.toString()});
            const SpiderRenderResult renderResult = m_renderer->render(result.finalUrl.isValid() ? result.finalUrl : result.url,
                                                                       m_options.renderTimeoutMs);
            if (renderResult.ok && !renderResult.renderedHtml.trimmed().isEmpty()) {
                emitAsset({QStringLiteral("render-success"),
                           QStringLiteral("%1 | rendered=%2 karakter").arg(renderResult.backendName,
                                                                            QString::number(renderResult.renderedHtml.size())),
                           result.url.toString()});
                if (!renderResult.debuggerHttpUrl.isEmpty()) {
                    emitAsset({QStringLiteral("automation-browser-target"),
                               QStringLiteral("http=%1 | browser-ws=%2")
                                   .arg(renderResult.debuggerHttpUrl, renderResult.browserWsUrl),
                               result.url.toString()});
                }
                if (m_options.enableBrowserAutomation && !renderResult.pageWsUrl.isEmpty()) {
                    emitAsset({QStringLiteral("automation-page-target"),
                               renderResult.pageWsUrl,
                               result.url.toString()});
                    CdpClient cdp;
                    QString cdpError;
                    if (cdp.connectToPage(renderResult.pageWsUrl, qMin(m_options.renderTimeoutMs, 2500), &cdpError)) {
                        const QString liveTitle = cdp.evaluateExpression(QStringLiteral("document.title"), 1200, &cdpError);
                        if (!liveTitle.isEmpty()) {
                            emitAsset({QStringLiteral("automation-live-title"),
                                       liveTitle,
                                       result.url.toString()});
                        }
                        const QVariantList actions = cdp.collectInteractiveSnapshot(1800, &cdpError);
                        for (const QVariant &value : actions) {
                            const QVariantMap row = value.toMap();
                            const QString candidate = QStringLiteral("%1 | text=%2 | href=%3 | onclick=%4 | id=%5 | class=%6 | role=%7")
                                                          .arg(row.value("tag").toString(),
                                                               row.value("text").toString(),
                                                               row.value("href").toString(),
                                                               row.value("onclick").toString(),
                                                               row.value("id").toString(),
                                                               row.value("cls").toString(),
                                                               row.value("role").toString());
                            emitAsset({QStringLiteral("automation-live-action"),
                                       candidate,
                                       result.url.toString()});
                        }
                        const QList<CdpClient::StatefulResult> exploration = cdp.runSafeStatefulExploration(2200, &cdpError);
                        for (const CdpClient::StatefulResult &state : exploration) {
                            emitAsset({QStringLiteral("automation-state-step"),
                                       QStringLiteral("%1 | title=%2 | url=%3 | delta=%4")
                                           .arg(state.stepLabel, state.pageTitle, state.currentUrl)
                                           .arg(state.urls.size()),
                                       result.url.toString()});
                            if (!state.currentUrl.trimmed().isEmpty()) {
                                const QUrl currentUrl = QUrl(state.currentUrl.trimmed());
                                if (currentUrl.isValid()) {
                                    emitAsset({QStringLiteral("automation-state-url"),
                                               currentUrl.toString(),
                                               result.url.toString()});
                                    if (m_options.followRenderedRoutes && entry.depth + 1 <= m_options.maxDepth) {
                                        enqueue(currentUrl, QStringLiteral("automation-state-url"), result.url.toString(), entry.depth + 1);
                                    }
                                }
                            }
                            for (const QString &rawUrl : state.urls) {
                                const QUrl discovered = (result.finalUrl.isValid() ? result.finalUrl : result.url).resolved(QUrl(rawUrl));
                                if (!discovered.isValid()) {
                                    continue;
                                }
                                emitAsset({QStringLiteral("automation-state-delta"),
                                           discovered.toString(),
                                           result.url.toString()});
                                if (m_options.followRenderedRoutes && entry.depth + 1 <= m_options.maxDepth) {
                                    enqueue(discovered, QStringLiteral("automation-route"), result.url.toString(), entry.depth + 1);
                                }
                            }
                            for (const QString &rawAction : state.formActions) {
                                const QUrl actionUrl = (result.finalUrl.isValid() ? result.finalUrl : result.url).resolved(QUrl(rawAction));
                                if (!actionUrl.isValid()) {
                                    continue;
                                }
                                emitAsset({QStringLiteral("automation-form-delta"),
                                           actionUrl.toString(),
                                           result.url.toString()});
                                if (m_options.followRenderedRoutes && entry.depth + 1 <= m_options.maxDepth) {
                                    enqueue(actionUrl, QStringLiteral("automation-form"), result.url.toString(), entry.depth + 1);
                                }
                            }
                        }
                    } else {
                        emitAsset({QStringLiteral("automation-cdp-failed"),
                                   cdpError,
                                   result.url.toString()});
                    }
                }
                QSet<QString> rawLinkSet;
                QSet<QString> rawFormSet;
                QSet<QString> rawRouteSet;
                for (const QUrl &rawLink : m_htmlExtractor->extractLinks(body, result.finalUrl.isValid() ? result.finalUrl : result.url)) {
                    rawLinkSet.insert(rawLink.toString());
                }
                for (const auto &rawForm : m_htmlExtractor->extractForms(body, result.finalUrl.isValid() ? result.finalUrl : result.url)) {
                    rawFormSet.insert(rawForm.actionUrl.toString());
                }
                for (const QString &rawRoute : m_htmlExtractor->extractJsRoutes(body)) {
                    rawRouteSet.insert(rawRoute);
                }
                const auto renderedLinks = m_htmlExtractor->extractLinks(renderResult.renderedHtml,
                                                                         result.finalUrl.isValid() ? result.finalUrl : result.url);
                for (const QUrl &renderedLink : renderedLinks) {
                    emitAsset({QStringLiteral("render-dom-link"),
                               renderedLink.toString(),
                               result.url.toString()});
                    if (!rawLinkSet.contains(renderedLink.toString())) {
                        emitAsset({QStringLiteral("render-state-delta"),
                                   renderedLink.toString(),
                                   result.url.toString()});
                        if (m_options.followRenderedRoutes && entry.depth + 1 <= m_options.maxDepth) {
                            enqueue(renderedLink, QStringLiteral("render-route"), result.url.toString(), entry.depth + 1);
                        }
                    }
                }
                const auto renderedForms = m_htmlExtractor->extractForms(renderResult.renderedHtml,
                                                                         result.finalUrl.isValid() ? result.finalUrl : result.url);
                for (const auto &renderedForm : renderedForms) {
                    if (!renderedForm.actionUrl.isValid()) {
                        continue;
                    }
                    emitAsset({QStringLiteral("render-dom-form"),
                               QStringLiteral("%1 %2").arg(renderedForm.method, renderedForm.actionUrl.toString()),
                               result.url.toString()});
                    if (!rawFormSet.contains(renderedForm.actionUrl.toString())) {
                        emitAsset({QStringLiteral("render-form-delta"),
                                   QStringLiteral("%1 %2").arg(renderedForm.method, renderedForm.actionUrl.toString()),
                                   result.url.toString()});
                        if (m_options.followRenderedRoutes && entry.depth + 1 <= m_options.maxDepth) {
                            enqueue(renderedForm.actionUrl, QStringLiteral("render-form"), result.url.toString(), entry.depth + 1);
                        }
                    }
                }
                const auto interactionActions = m_htmlExtractor->extractInteractionActions(renderResult.renderedHtml,
                                                                                           result.finalUrl.isValid() ? result.finalUrl : result.url);
                for (const auto &action : interactionActions) {
                    if (!action.targetUrl.isValid()) {
                        continue;
                    }
                    emitAsset({QStringLiteral("render-action-candidate"),
                               QStringLiteral("%1 %2 %3 | selector=%4 | trigger=%5")
                                   .arg(action.kind,
                                        action.method,
                                        action.targetUrl.toString(),
                                        action.selectorHint,
                                        action.triggerKind),
                               result.url.toString()});
                    if (!rawLinkSet.contains(action.targetUrl.toString()) && entry.depth + 1 <= m_options.maxDepth) {
                        emitAsset({QStringLiteral("render-action-delta"),
                                   QStringLiteral("%1 -> %2 | selector=%3 | trigger=%4")
                                       .arg(action.label,
                                            action.targetUrl.toString(),
                                            action.selectorHint,
                                            action.triggerKind),
                                   result.url.toString()});
                        if (m_options.followRenderedRoutes) {
                            enqueue(action.targetUrl, QStringLiteral("interaction-route"), result.url.toString(), entry.depth + 1);
                        }
                    }
                }
                processRenderedWorkflowCandidates(result.finalUrl.isValid() ? result.finalUrl : result.url,
                                                  renderResult.renderedHtml,
                                                  entry.depth,
                                                  sessionState);
                processHtml(result.finalUrl.isValid() ? result.finalUrl : result.url,
                            renderResult.renderedHtml,
                            entry.depth);
                const auto renderedRoutes = m_htmlExtractor->extractJsRoutes(renderResult.renderedHtml);
                for (const QString &route : renderedRoutes) {
                    emitAsset({QStringLiteral("render-dom-delta"), route, result.url.toString()});
                    if (!rawRouteSet.contains(route)) {
                        emitAsset({QStringLiteral("render-route-delta"), route, result.url.toString()});
                        if (m_options.followRenderedRoutes && entry.depth + 1 <= m_options.maxDepth) {
                            const QUrl renderedRouteUrl = (result.finalUrl.isValid() ? result.finalUrl : result.url).resolved(QUrl(route));
                            enqueue(renderedRouteUrl, QStringLiteral("render-route"), result.url.toString(), entry.depth + 1);
                        }
                    }
                }
            } else {
                emitAsset({QStringLiteral("render-failed"),
                           QStringLiteral("%1 | %2").arg(renderResult.backendName,
                                                         renderResult.errorString),
                           result.url.toString()});
            }
        } else if (m_options.enableHeadlessRender && (!m_renderer || !m_renderer->available()) && looksLikeSpaCandidate(body, result)) {
            emitAsset({QStringLiteral("render-unavailable"),
                       QStringLiteral("SPA aday sayfa, ancak headless tarayici bulunamadi"),
                       result.url.toString()});
        }
        const std::string hash = QCryptographicHash::hash(result.body, QCryptographicHash::Sha1).toHex().toStdString();
        const std::string loginSignature = buildLoginSignature(result, body).toStdString();
        const bool explicitLoginWall = looksLikeLoginWall(body);
        bool fingerprintLoginWall = false;
        {
            std::shared_lock lock(m_seenMutex);
            fingerprintLoginWall = m_loginFingerprints.contains(loginSignature);
        }
        const bool redirectLoginWall = (!result.redirectTarget.isEmpty() && looksLikeLoginPath(result.redirectTarget))
            || (!result.finalUrl.isEmpty() && result.finalUrl != result.url && looksLikeLoginPath(result.finalUrl));
        if (explicitLoginWall || redirectLoginWall || fingerprintLoginWall) {
            emitEndpoint({result.url,
                          QStringLiteral("login-wall"),
                          entry.source,
                          entry.depth,
                          result.statusCode,
                          result.contentType,
                          sessionState,
                          result.finalUrl.toString(),
                          result.pageTitle});
            emitEvent(QStringLiteral("[heuristic] Giris duvari olasi tespit: %1").arg(result.url.toString()));
        }
        if (looksLikeSoft404(body, result.url, result.statusCode)) {
            emitEndpoint({result.url,
                          QStringLiteral("soft-404"),
                          entry.source,
                          entry.depth,
                          result.statusCode,
                          result.contentType,
                          sessionState,
                          result.finalUrl.toString(),
                          result.pageTitle});
            emitEvent(QStringLiteral("[heuristic] Soft-404 davranisi tespit: %1").arg(result.url.toString()));
        }
        if (looksLikeAccessDenied(body, result.statusCode)) {
            emitEndpoint({result.url,
                          QStringLiteral("access-denied"),
                          entry.source,
                          entry.depth,
                          result.statusCode,
                          result.contentType,
                          sessionState,
                          result.finalUrl.toString(),
                          result.pageTitle});
            emitEvent(QStringLiteral("[heuristic] Erisim reddi duvari tespit: %1").arg(result.url.toString()));
        }
        if (looksLikeWafChallenge(body, result)) {
            const QString vendor = wafVendorHint(body, result);
            {
                std::unique_lock seenLock(m_seenMutex);
                const std::string hostKey = result.url.host().toLower().toStdString();
                m_hostPressureScore[hostKey] = qBound(0, (m_hostPressureScore.contains(hostKey) ? m_hostPressureScore[hostKey] : 0) + 4, 10);
                m_hostNextAllowedAt[hostKey] = qMax(m_hostNextAllowedAt[hostKey], QDateTime::currentMSecsSinceEpoch() + 2500);
                emitHostPressureAsset(QString::fromStdString(hostKey),
                                      m_hostPressureScore[hostKey],
                                      QStringLiteral("waf-challenge"));
            }
            emitEndpoint({result.url,
                          QStringLiteral("waf-challenge"),
                          entry.source,
                          entry.depth,
                          result.statusCode,
                          result.contentType,
                          sessionState,
                          result.finalUrl.toString(),
                          result.pageTitle});
            emitAsset({QStringLiteral("waf-challenge"),
                       QStringLiteral("%1 | title=%2 | http=%3").arg(result.url.toString(),
                                                                     result.pageTitle,
                                                                     QString::number(result.statusCode)),
                       entry.kind});
            emitAsset({QStringLiteral("waf-vendor"),
                       vendor,
                       result.url.toString()});
            emitEvent(QStringLiteral("[heuristic] WAF veya challenge davranisi tespit: %1").arg(result.url.toString()));
        } else {
            std::unique_lock seenLock(m_seenMutex);
            const std::string hostKey = result.url.host().toLower().toStdString();
            if (m_hostPressureScore.contains(hostKey) && m_hostPressureScore[hostKey] > 0) {
                m_hostPressureScore[hostKey] = qMax(0, m_hostPressureScore[hostKey] - 1);
                emitHostPressureAsset(QString::fromStdString(hostKey),
                                      m_hostPressureScore[hostKey],
                                      QStringLiteral("success-cooldown"));
            }
        }
        {
            std::unique_lock lock(m_seenMutex);
            if (explicitLoginWall || redirectLoginWall) {
                m_loginFingerprints.insert(loginSignature);
            }
            if (m_contentFingerprints.contains(hash)) {
                emitEvent(QStringLiteral("[dedupe] Icerik tekrari atlandi: %1").arg(entry.url.toString()));
                return;
            }
            m_contentFingerprints.insert(hash);
        }
        if (entry.kind == "robots") {
            processRobots(result.url, body);
        } else if (entry.kind == "sitemap") {
            processSitemap(result.url, body);
        } else if (entry.kind == "manifest") {
            processManifest(result.url, body, entry.depth);
        } else if (result.url.path().endsWith(".js", Qt::CaseInsensitive)
                   || result.contentType.contains("javascript", Qt::CaseInsensitive)) {
            processJavaScript(result.url, body, entry.depth);
        } else if (isHtmlLike(result.contentType, result.url)) {
            processHtml(result.url, body, entry.depth);
        }
    } else {
        emitEvent(QStringLiteral("[%1] hata: %2").arg(entry.url.toString(), result.errorString));
    }
}

void SpiderCore::processHtml(const QUrl &url, const QString &html, int depth)
{
    if (m_stopping.load()) {
        return;
    }
    const QString pageSessionState = sessionStateForUrl(url);

    for (const QString &finding : m_htmlExtractor->extractInterestingLiterals(html)) {
        if (m_stopping.load()) {
            return;
        }
        emitAsset({QStringLiteral("literal"), finding, url.toString()});
    }

    static const QRegularExpression inlineScriptRegex(
        QStringLiteral(R"(<script\b[^>]*>(.*?)</script>)"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
    auto inlineScriptIt = inlineScriptRegex.globalMatch(html);
    while (inlineScriptIt.hasNext()) {
        if (m_stopping.load()) {
            return;
        }
        const QString scriptBody = inlineScriptIt.next().captured(1).trimmed();
        if (scriptBody.isEmpty()) {
            continue;
        }
        for (const QString &finding : m_htmlExtractor->extractInterestingLiterals(scriptBody.left(160000))) {
            emitAsset({QStringLiteral("inline-script-literal"), finding, url.toString()});
        }
        for (const QString &route : m_htmlExtractor->extractJsRoutes(scriptBody)) {
            const QUrl discovered = url.resolved(QUrl(route));
            if (!discovered.isValid()) {
                continue;
            }
            emitAsset({QStringLiteral("inline-script-route"), discovered.toString(), url.toString()});
            emitEndpoint({discovered,
                          QStringLiteral("inline-js-route"),
                          url.toString(),
                          depth + 1,
                          0,
                          QStringLiteral("text/html"),
                          sessionStateForUrl(discovered),
                          discovered.toString(),
                          QStringLiteral("Inline script route")});
            enqueue(discovered, QStringLiteral("inline-js-route"), url.toString(), depth + 1);
        }
    }

    const auto links = m_htmlExtractor->extractLinks(html, url);
    for (const QUrl &link : links) {
        if (m_stopping.load()) {
            return;
        }
        if (spiderLooksLikeSuppressedSafetyTarget(link)) {
            emitAsset({QStringLiteral("crawl-suppressed"),
                       QStringLiteral("link %1").arg(link.toString()),
                       url.toString()});
            continue;
        }
        const QString linkSessionState = sessionStateForUrl(link);
        if (linkSessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            emitAsset({QStringLiteral("auth-surface-delta"), link.toString(), url.toString()});
        }
        if (link.path().endsWith(".js", Qt::CaseInsensitive)) {
            emitAsset({QStringLiteral("script"), link.toString(), url.toString()});
        }
        enqueue(link, QStringLiteral("link"), url.toString(), depth + 1);
        for (const QString &name : extractParameters(link)) {
            emitParameter({name, link, url.toString()});
        }
    }

    static const QRegularExpression manifestRegex(
        QStringLiteral(R"(<link[^>]*rel\s*=\s*["'][^"']*manifest[^"']*["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*>)"),
        QRegularExpression::CaseInsensitiveOption);
    auto manifestIt = manifestRegex.globalMatch(html);
    while (manifestIt.hasNext()) {
        const QUrl manifestUrl = url.resolved(QUrl(manifestIt.next().captured(1).trimmed()));
        if (!manifestUrl.isValid()) {
            continue;
        }
        emitAsset({QStringLiteral("manifest-link"), manifestUrl.toString(), url.toString()});
        enqueue(manifestUrl, QStringLiteral("manifest"), url.toString(), depth + 1);
    }

    static const QRegularExpression serviceWorkerRegex(
        QStringLiteral(R"(serviceWorker\.register\s*\(\s*["']([^"']+)["'])"),
        QRegularExpression::CaseInsensitiveOption);
    auto serviceWorkerIt = serviceWorkerRegex.globalMatch(html);
    while (serviceWorkerIt.hasNext()) {
        const QUrl workerUrl = url.resolved(QUrl(serviceWorkerIt.next().captured(1).trimmed()));
        if (!workerUrl.isValid()) {
            continue;
        }
        emitAsset({QStringLiteral("service-worker"), workerUrl.toString(), url.toString()});
        enqueue(workerUrl, QStringLiteral("service-worker"), url.toString(), depth + 1);
    }

    const auto forms = m_htmlExtractor->extractForms(html, url);
    for (const auto &form : forms) {
        if (m_stopping.load()) {
            return;
        }
        if (spiderLooksLikeSuppressedSafetyTarget(form.actionUrl)) {
            emitAsset({QStringLiteral("crawl-suppressed"),
                       QStringLiteral("form %1 %2").arg(form.method, form.actionUrl.toString()),
                       url.toString()});
            continue;
        }
        const QString formSessionState = sessionStateForUrl(form.actionUrl);
        if (formSessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            emitAsset({QStringLiteral("auth-surface-delta"), form.actionUrl.toString(), url.toString()});
        }
        enqueue(form.actionUrl, QStringLiteral("form"), form.sourceSummary, depth + 1);
        emitEndpoint({form.actionUrl,
                      form.loginLike ? QStringLiteral("login-form") : QString("form:%1").arg(form.method.toLower()),
                      url.toString(),
                      depth + 1,
                      0,
                      QString(),
                      formSessionState,
                      form.actionUrl.toString(),
                      pageSessionState == QLatin1String("oturumlu-yeni-yuzey") ? QStringLiteral("Oturum sonrasi form") : QString()});

        for (const QString &name : extractParameters(form.actionUrl)) {
            emitParameter({name, form.actionUrl, QString("%1 action").arg(form.method)});
        }

        for (const auto &field : form.fields) {
            if (!field.name.isEmpty()) {
                emitParameter({field.name,
                               form.actionUrl,
                               QString("form-field:%1:%2:%3").arg(form.method.toLower(), field.type, field.role)});
            }
        }

        if (form.loginLike) {
            emitAsset({QStringLiteral("login-form"), form.actionUrl.toString(), url.toString()});
            emitEvent(QStringLiteral("[form] Kimlik dogrulama formu bulundu: %1").arg(form.actionUrl.toString()));
        }
    }

    const auto actions = m_htmlExtractor->extractInteractionActions(html, url);
    for (const auto &action : actions) {
        if (m_stopping.load()) {
            return;
        }
        if (!action.targetUrl.isValid()) {
            continue;
        }
        if (spiderLooksLikeSuppressedSafetyTarget(action.targetUrl)) {
            emitAsset({QStringLiteral("crawl-suppressed"),
                       QStringLiteral("action %1 -> %2").arg(action.label, action.targetUrl.toString()),
                       url.toString()});
            continue;
        }
        emitAsset({QStringLiteral("html-action-candidate"),
                   QStringLiteral("%1 %2 -> %3 | selector=%4 | trigger=%5")
                       .arg(action.kind, action.label, action.targetUrl.toString(), action.selectorHint, action.triggerKind),
                   url.toString()});
        emitEndpoint({action.targetUrl,
                      QStringLiteral("html-action"),
                      url.toString(),
                      depth + 1,
                      0,
                      QStringLiteral("text/html"),
                      sessionStateForUrl(action.targetUrl),
                      action.targetUrl.toString(),
                      action.label});
        enqueue(action.targetUrl, QStringLiteral("html-action"), url.toString(), depth + 1);
    }

    for (const QString &route : m_htmlExtractor->extractJsRoutes(html)) {
        if (m_stopping.load()) {
            return;
        }
        const QUrl discovered = url.resolved(QUrl(route));
        if (!discovered.isValid()) {
            continue;
        }
        if (spiderLooksLikeSuppressedSafetyTarget(discovered)) {
            emitAsset({QStringLiteral("crawl-suppressed"),
                       QStringLiteral("route %1").arg(discovered.toString()),
                       url.toString()});
            continue;
        }
        const QString routeSessionState = sessionStateForUrl(discovered);
        if (routeSessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            emitAsset({QStringLiteral("auth-surface-delta"), discovered.toString(), url.toString()});
        }
        emitEndpoint({discovered,
                      QStringLiteral("html-js-route"),
                      url.toString(),
                      depth + 1,
                      0,
                      QStringLiteral("text/html"),
                      routeSessionState,
                      discovered.toString(),
                      QStringLiteral("Inline route")});
        enqueue(discovered, QStringLiteral("html-js-route"), url.toString(), depth + 1);
    }
}

void SpiderCore::processRenderedWorkflowCandidates(const QUrl &pageUrl,
                                                   const QString &html,
                                                   int depth,
                                                   const QString &sessionState)
{
    if (m_stopping.load()) {
        return;
    }
    if (!m_options.enableSafeWorkflowReplay || m_workflowActionsUsed.load() >= m_options.maxWorkflowActions) {
        return;
    }

    const auto forms = m_htmlExtractor->extractForms(html, pageUrl);
    for (const auto &form : forms) {
        if (m_stopping.load()) {
            return;
        }
        if (m_workflowActionsUsed.load() >= m_options.maxWorkflowActions) {
            break;
        }
        const QString method = form.method.trimmed().toUpper();
        if (method != QLatin1String("GET") && method != QLatin1String("POST")) {
            continue;
        }

        QVariantMap fields;
        bool safe = true;
        bool hasReplayableInput = false;
        for (const auto &field : form.fields) {
            if (field.name.isEmpty()) {
                continue;
            }
            if (field.role == QLatin1String("parola")
                || field.role == QLatin1String("dosya-yukleme")
                || field.role == QLatin1String("yorum")
                || field.role == QLatin1String("kullanici-adi")) {
                safe = false;
                break;
            }
            if (field.role == QLatin1String("csrf") || field.type == QLatin1String("hidden")) {
                fields.insert(field.name, field.value);
                continue;
            }
            if (isSafeReplayRole(field.role)) {
                fields.insert(field.name, safeReplayValueForRole(field.role, field.name));
                hasReplayableInput = true;
            }
        }
        if (!safe || !hasReplayableInput || !form.actionUrl.isValid()) {
            continue;
        }
        if (spiderLooksLikeSuppressedSafetyTarget(form.actionUrl)) {
            emitAsset({QStringLiteral("crawl-suppressed"),
                       QStringLiteral("workflow-form %1 %2").arg(method, form.actionUrl.toString()),
                       pageUrl.toString()});
            continue;
        }

        ++m_workflowActionsUsed;
        if (method == QLatin1String("GET")) {
            QUrl replayUrl = form.actionUrl;
            QUrlQuery replayQuery(replayUrl);
            for (auto it = fields.cbegin(); it != fields.cend(); ++it) {
                replayQuery.addQueryItem(it.key(), it.value().toString());
            }
            replayUrl.setQuery(replayQuery);
            emitAsset({QStringLiteral("workflow-submit-candidate"),
                       QStringLiteral("GET %1 | session=%2").arg(replayUrl.toString(), sessionState),
                       pageUrl.toString()});
            enqueueRequest(replayUrl,
                           QStringLiteral("workflow-submit"),
                           pageUrl.toString(),
                           depth + 1,
                           QStringLiteral("GET"));
        } else {
            emitAsset({QStringLiteral("workflow-submit-candidate"),
                       QStringLiteral("POST %1 | fields=%2 | session=%3")
                           .arg(form.actionUrl.toString(),
                                fields.keys().join(','),
                                sessionState),
                       pageUrl.toString()});
            enqueueRequest(form.actionUrl,
                           QStringLiteral("workflow-submit"),
                           pageUrl.toString(),
                           depth + 1,
                           QStringLiteral("POST"),
                           fields);
        }
    }

    const auto actions = m_htmlExtractor->extractInteractionActions(html, pageUrl);
    for (const auto &action : actions) {
        if (m_stopping.load()) {
            return;
        }
        if (m_workflowActionsUsed.load() >= m_options.maxWorkflowActions) {
            break;
        }
        if (!action.targetUrl.isValid()) {
            continue;
        }
        if (spiderLooksLikeSuppressedSafetyTarget(action.targetUrl)) {
            emitAsset({QStringLiteral("crawl-suppressed"),
                       QStringLiteral("workflow-action %1 -> %2").arg(action.label, action.targetUrl.toString()),
                       pageUrl.toString()});
            continue;
        }
        ++m_workflowActionsUsed;
        emitAsset({QStringLiteral("workflow-action-candidate"),
                   QStringLiteral("%1 %2 -> %3 | session=%4")
                       .arg(action.kind, action.label, action.targetUrl.toString(), sessionState),
                   pageUrl.toString()});
        enqueue(action.targetUrl, QStringLiteral("workflow-action"), pageUrl.toString(), depth + 1);
    }
}

void SpiderCore::processJavaScript(const QUrl &url, const QString &body, int depth)
{
    if (m_stopping.load()) {
        return;
    }
    QString analysisBody = body;
    const QString fileName = url.fileName().toLower();
    const bool isKnownLibraryBundle = fileName.contains(QStringLiteral("pdf.min"))
        || fileName.contains(QStringLiteral("jquery"))
        || fileName.contains(QStringLiteral("bootstrap"))
        || fileName.contains(QStringLiteral("vendor"))
        || fileName.contains(QStringLiteral("bundle"))
        || fileName.contains(QStringLiteral("polyfill"));
    const bool isLargeBundle = analysisBody.size() > 180000
        || url.fileName().contains(QStringLiteral(".min."), Qt::CaseInsensitive)
        || isKnownLibraryBundle;
    const bool isVeryLargeBundle = analysisBody.size() > 500000 || (isKnownLibraryBundle && analysisBody.size() > 120000);

    QString routeAnalysisBody = body;
    if (isVeryLargeBundle) {
        routeAnalysisBody = body.left(220000) + QStringLiteral("\n") + body.right(120000);
        analysisBody = body.left(90000);
        emitAsset({QStringLiteral("js-large-bundle"),
                   QStringLiteral("%1 | %2 KB | rota avcisi aktif, derin literal analizi kisitlandi")
                       .arg(url.toString())
                       .arg(QString::number(body.size() / 1024)),
                   url.toString()});
        emitEvent(QStringLiteral("[js] Cok buyuk bundle rota odakli incelenecek: %1 (%2 KB)")
                      .arg(url.toString())
                      .arg(QString::number(body.size() / 1024)));
    } else if (isLargeBundle) {
        routeAnalysisBody = body.left(180000) + QStringLiteral("\n") + body.right(60000);
        analysisBody = analysisBody.left(80000);
        emitEvent(QStringLiteral("[js] Buyuk script sinirli incelenecek: %1 (%2 KB)")
                      .arg(url.toString())
                      .arg(QString::number(body.size() / 1024)));
    }

    if (!isLargeBundle) {
        for (const QString &finding : m_htmlExtractor->extractInterestingLiterals(analysisBody)) {
            if (m_stopping.load()) {
                return;
            }
            emitAsset({QStringLiteral("js-literal"), finding, url.toString()});
        }
    }
    for (const QString &route : m_htmlExtractor->extractJsRoutes(routeAnalysisBody)) {
        if (m_stopping.load()) {
            return;
        }
        const QUrl discovered = url.resolved(QUrl(route));
        const QString routeSessionState = sessionStateForUrl(discovered);
        if (routeSessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            emitAsset({QStringLiteral("auth-surface-delta"), discovered.toString(), url.toString()});
        }
        emitEndpoint({discovered,
                      QStringLiteral("js-route"),
                      url.toString(),
                      depth + 1,
                      0,
                      QStringLiteral("application/javascript"),
                      routeSessionState,
                      discovered.toString(),
                      QStringLiteral("JavaScript route")});
        if (depth + 1 <= m_options.maxDepth) {
            enqueue(discovered, QStringLiteral("js-route"), url.toString(), depth + 1);
        }
    }

    static const QRegularExpression manifestRegex(
        QStringLiteral(R"(["']((?:/[^"']*manifest[^"']*\.(?:json|webmanifest))|(?:https?://[^"']*manifest[^"']*\.(?:json|webmanifest)))["'])"),
        QRegularExpression::CaseInsensitiveOption);
    auto manifestIt = manifestRegex.globalMatch(routeAnalysisBody);
    while (manifestIt.hasNext()) {
        const QUrl manifestUrl = url.resolved(QUrl(manifestIt.next().captured(1).trimmed()));
        if (!manifestUrl.isValid()) {
            continue;
        }
        emitAsset({QStringLiteral("js-manifest"), manifestUrl.toString(), url.toString()});
        enqueue(manifestUrl, QStringLiteral("manifest"), url.toString(), depth + 1);
    }

    static const QRegularExpression importScriptsRegex(
        QStringLiteral(R"(importScripts\s*\(([^)]*)\))"),
        QRegularExpression::CaseInsensitiveOption);
    auto importScriptsIt = importScriptsRegex.globalMatch(routeAnalysisBody);
    while (importScriptsIt.hasNext()) {
        const QString args = importScriptsIt.next().captured(1);
        static const QRegularExpression scriptArgRegex(QStringLiteral(R"(["']([^"']+\.(?:js|mjs))["'])"),
                                                       QRegularExpression::CaseInsensitiveOption);
        auto scriptArgIt = scriptArgRegex.globalMatch(args);
        while (scriptArgIt.hasNext()) {
            const QUrl workerImport = url.resolved(QUrl(scriptArgIt.next().captured(1).trimmed()));
            if (!workerImport.isValid()) {
                continue;
            }
            emitAsset({QStringLiteral("service-worker-import"), workerImport.toString(), url.toString()});
            enqueue(workerImport, QStringLiteral("service-worker"), url.toString(), depth + 1);
        }
    }

    static const QRegularExpression precacheRegex(
        QStringLiteral(R"(["']((?:/[^"']+\.(?:json|js|css|html|png|svg|txt|xml))|(?:https?://[^"']+\.(?:json|js|css|html|png|svg|txt|xml)))["'])"),
        QRegularExpression::CaseInsensitiveOption);
    auto precacheIt = precacheRegex.globalMatch(routeAnalysisBody);
    while (precacheIt.hasNext()) {
        const QUrl precacheUrl = url.resolved(QUrl(precacheIt.next().captured(1).trimmed()));
        if (!precacheUrl.isValid()) {
            continue;
        }
        const QString path = precacheUrl.path().toLower();
        if (!(path.contains(QStringLiteral("precache"))
              || path.contains(QStringLiteral("manifest"))
              || path.contains(QStringLiteral("asset"))
              || path.contains(QStringLiteral("chunk"))
              || path.endsWith(QStringLiteral(".html"))
              || path.endsWith(QStringLiteral(".json")))) {
            continue;
        }
        emitAsset({QStringLiteral("service-worker-cache-candidate"), precacheUrl.toString(), url.toString()});
        enqueue(precacheUrl, QStringLiteral("js-route"), url.toString(), depth + 1);
    }
}

void SpiderCore::processRobots(const QUrl &url, const QString &text)
{
    const QStringList lines = text.split('\n');
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (trimmed.startsWith("Disallow:", Qt::CaseInsensitive) || trimmed.startsWith("Allow:", Qt::CaseInsensitive)) {
            const QString path = trimmed.section(':', 1).trimmed();
            if (!path.isEmpty()) {
                QUrl next = url;
                next.setPath(path);
                enqueue(next, QStringLiteral("robots"), QStringLiteral("robots.txt"), 1);
            }
        } else if (trimmed.startsWith("Sitemap:", Qt::CaseInsensitive)) {
            QUrl sitemapUrl = QUrl(trimmed.section(':', 1).trimmed());
            if (sitemapUrl.isRelative()) {
                sitemapUrl = url.resolved(sitemapUrl);
            }
            enqueue(sitemapUrl, QStringLiteral("sitemap"), QStringLiteral("robots.txt"), 1);
        }
    }
}

void SpiderCore::processSitemap(const QUrl &url, const QString &text)
{
    Q_UNUSED(url);
    static const QRegularExpression regex(QStringLiteral(R"(<loc>([^<]+)</loc>)"),
                                          QRegularExpression::CaseInsensitiveOption);
    auto it = regex.globalMatch(text);
    while (it.hasNext()) {
        enqueue(QUrl(it.next().captured(1).trimmed()), QStringLiteral("sitemap"), QStringLiteral("sitemap.xml"), 1);
    }
}

void SpiderCore::processManifest(const QUrl &url, const QString &text, int depth)
{
    if (m_stopping.load()) {
        return;
    }

    const QJsonDocument document = QJsonDocument::fromJson(text.toUtf8());
    if (!document.isObject()) {
        return;
    }

    const QJsonObject manifest = document.object();
    const auto enqueueManifestUrl = [this, &url, depth](const QString &raw, const QString &kind) {
        const QString normalized = raw.trimmed();
        if (normalized.isEmpty()) {
            return;
        }
        const QUrl discovered = url.resolved(QUrl(normalized));
        if (!discovered.isValid()) {
            return;
        }
        emitAsset({kind, discovered.toString(), url.toString()});
        emitEndpoint({discovered,
                      kind,
                      url.toString(),
                      depth + 1,
                      0,
                      QStringLiteral("application/manifest+json"),
                      sessionStateForUrl(discovered),
                      discovered.toString(),
                      QStringLiteral("Manifest discovery")});
        enqueue(discovered, kind, url.toString(), depth + 1);
    };

    enqueueManifestUrl(manifest.value(QStringLiteral("start_url")).toString(), QStringLiteral("manifest-start-url"));
    enqueueManifestUrl(manifest.value(QStringLiteral("scope")).toString(), QStringLiteral("manifest-scope"));

    const QJsonArray shortcuts = manifest.value(QStringLiteral("shortcuts")).toArray();
    for (const QJsonValue &shortcutValue : shortcuts) {
        if (shortcutValue.isObject()) {
            enqueueManifestUrl(shortcutValue.toObject().value(QStringLiteral("url")).toString(), QStringLiteral("manifest-shortcut"));
        }
    }

    const QJsonArray icons = manifest.value(QStringLiteral("icons")).toArray();
    for (const QJsonValue &iconValue : icons) {
        if (iconValue.isObject()) {
            enqueueManifestUrl(iconValue.toObject().value(QStringLiteral("src")).toString(), QStringLiteral("manifest-icon"));
        }
    }

    const QJsonArray protocolHandlers = manifest.value(QStringLiteral("protocol_handlers")).toArray();
    for (const QJsonValue &handlerValue : protocolHandlers) {
        if (handlerValue.isObject()) {
            enqueueManifestUrl(handlerValue.toObject().value(QStringLiteral("url")).toString(), QStringLiteral("manifest-protocol-handler"));
        }
    }

    const QJsonObject shareTarget = manifest.value(QStringLiteral("share_target")).toObject();
    if (!shareTarget.isEmpty()) {
        enqueueManifestUrl(shareTarget.value(QStringLiteral("action")).toString(), QStringLiteral("manifest-share-target"));
    }

    const QJsonArray fileHandlers = manifest.value(QStringLiteral("file_handlers")).toArray();
    for (const QJsonValue &handlerValue : fileHandlers) {
        if (handlerValue.isObject()) {
            enqueueManifestUrl(handlerValue.toObject().value(QStringLiteral("action")).toString(), QStringLiteral("manifest-file-handler"));
        }
    }
}

void SpiderCore::captureAnonymousSurfaceBaseline()
{
    if (!m_options.auth.enabled || !m_seedUrl.isValid() || !m_fetcher) {
        return;
    }

    const SpiderFetchResult baseline = m_fetcher->fetch(m_seedUrl, qMin(m_options.timeoutMs, 2500), {});
    if (!baseline.ok()) {
        emitEvent(QStringLiteral("[auth] Anonim yuzey baz cikarilamadi: %1").arg(baseline.errorString));
        return;
    }

    const QString body = QString::fromUtf8(baseline.body);
    std::unique_lock lock(m_seenMutex);
    m_preAuthSurface.insert(keyForUrl(m_seedUrl));
    for (const QUrl &link : m_htmlExtractor->extractLinks(body, m_seedUrl)) {
        if (isInScope(link) && matchesScopeRules(link) && shouldCrawlByExtension(link, QStringLiteral("baseline"))) {
            m_preAuthSurface.insert(keyForUrl(link));
        }
    }
    for (const auto &form : m_htmlExtractor->extractForms(body, m_seedUrl)) {
        if (isInScope(form.actionUrl) && matchesScopeRules(form.actionUrl) && shouldCrawlByExtension(form.actionUrl, QStringLiteral("baseline"))) {
            m_preAuthSurface.insert(keyForUrl(form.actionUrl));
        }
    }
    emitEvent(QStringLiteral("[auth] Anonim yuzey baz cikarildi: %1 nokta").arg(m_preAuthSurface.size()));
}

bool SpiderCore::markVisited(const QueueEntry &entry)
{
    std::unique_lock lock(m_seenMutex);
    const std::string key = entry.requestKey.empty()
        ? keyForRequest(entry.url, entry.requestMethod, entry.requestFields)
        : entry.requestKey;
    if (m_visited.contains(key)) {
        if (entry.retryCount > 0) {
            m_enqueued.erase(key);
            return true;
        }
        return false;
    }
    m_visited.insert(key);
    m_enqueued.erase(key);
    ++m_visitedCount;
    return true;
}

QString SpiderCore::sessionStateForUrl(const QUrl &url) const
{
    if (!m_authenticated.load()) {
        return QStringLiteral("anonim");
    }

    std::shared_lock lock(m_seenMutex);
    return m_preAuthSurface.contains(keyForUrl(url))
        ? QStringLiteral("oturumlu-ortak")
        : QStringLiteral("oturumlu-yeni-yuzey");
}

bool SpiderCore::alreadyQueuedOrVisited(const QUrl &url,
                                        const QString &requestMethod,
                                        const QVariantMap &requestFields) const
{
    std::shared_lock lock(m_seenMutex);
    const std::string key = keyForRequest(url, requestMethod, requestFields);
    return m_enqueued.contains(key) || m_visited.contains(key);
}

bool SpiderCore::isInScope(const QUrl &url) const
{
    if (!url.isValid()) {
        return false;
    }

    if (m_options.allowSubdomains) {
        return url.host().compare(m_seedUrl.host(), Qt::CaseInsensitive) == 0
            || url.host().endsWith(QStringLiteral(".") + m_seedUrl.host(), Qt::CaseInsensitive);
    }

    return url.host().compare(m_seedUrl.host(), Qt::CaseInsensitive) == 0;
}

bool SpiderCore::matchesScopeRules(const QUrl &url) const
{
    const QString candidate = url.toString();
    for (const QString &pattern : m_options.excludePatterns) {
        if (!pattern.trimmed().isEmpty()
            && QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption).match(candidate).hasMatch()) {
            return false;
        }
    }

    if (m_options.includePatterns.isEmpty()) {
        return true;
    }

    for (const QString &pattern : m_options.includePatterns) {
        if (!pattern.trimmed().isEmpty()
            && QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption).match(candidate).hasMatch()) {
            return true;
        }
    }
    return false;
}

bool SpiderCore::shouldCrawlByExtension(const QUrl &url, const QString &kind) const
{
    if (kind == "robots" || kind == "sitemap" || kind == "manifest" || kind == "js-route") {
        return true;
    }

    const QString suffix = QFileInfo(url.path()).suffix().toLower();
    return suffix.isEmpty() || !m_options.ignoredExtensions.contains(suffix, Qt::CaseInsensitive);
}

std::string SpiderCore::keyForUrl(const QUrl &url) const
{
    QUrl normalized = url.adjusted(QUrl::RemoveFragment | QUrl::NormalizePathSegments);
    normalized.setScheme(normalized.scheme().toLower());
    normalized.setHost(normalized.host().toLower());
    if ((normalized.scheme() == "http" && normalized.port() == 80)
        || (normalized.scheme() == "https" && normalized.port() == 443)) {
        normalized.setPort(-1);
    }

    QUrlQuery oldQuery(normalized);
    QList<QPair<QString, QString>> items = oldQuery.queryItems(QUrl::FullyDecoded);
    QList<QPair<QString, QString>> filtered;
    for (const auto &item : items) {
        const QString key = item.first.toLower();
        if (key.startsWith("utm_") || key == "fbclid" || key == "gclid" || key == "ref" || key == "source") {
            continue;
        }
        filtered.append(item);
    }
    std::sort(filtered.begin(), filtered.end(), [](const auto &left, const auto &right) {
        return left.first == right.first ? left.second < right.second : left.first < right.first;
    });
    QUrlQuery newQuery;
    for (const auto &item : filtered) {
        newQuery.addQueryItem(item.first, item.second);
    }
    normalized.setQuery(newQuery);

    QString path = normalized.path();
    if (path.endsWith('/') && path != "/") {
        path.chop(1);
        normalized.setPath(path);
    }

    return normalized.toString().toStdString();
}

std::string SpiderCore::keyForRequest(const QUrl &url,
                                      const QString &requestMethod,
                                      const QVariantMap &requestFields) const
{
    const std::string baseKey = keyForUrl(url);
    if (requestMethod.compare(QStringLiteral("POST"), Qt::CaseInsensitive) != 0 || requestFields.isEmpty()) {
        return baseKey;
    }

    QStringList pairs;
    for (auto it = requestFields.cbegin(); it != requestFields.cend(); ++it) {
        pairs << QStringLiteral("%1=%2").arg(it.key().toLower(), it.value().toString());
    }
    std::sort(pairs.begin(), pairs.end());
    const QByteArray digest = QCryptographicHash::hash(pairs.join('&').toUtf8(), QCryptographicHash::Sha1).toHex();
    return baseKey + "|post|" + digest.toStdString();
}

void SpiderCore::finishIfDone()
{
    if (!m_running || m_stopping) {
        notifyFetchStateChanged();
        return;
    }

    bool hasPendingRetry = false;
    {
        std::scoped_lock lock(m_queueMutex);
        std::queue<QueueEntry> copy = m_queue;
        while (!copy.empty()) {
            if (copy.front().retryCount > 0) {
                hasPendingRetry = true;
                break;
            }
            copy.pop();
        }
    }

    if (((queuedCount() == 0 && !hasPendingRetry) || (visitedCount() >= m_options.maxPages && !hasPendingRetry))
        && m_activeFetches.load() == 0
        && m_activeProcessing.load() == 0) {
        m_running = false;
        emitEvent(QStringLiteral("SpiderCore tamamlandi. Gezilen sayfa: %1").arg(visitedCount()));
        if (m_finishedCallback) {
            m_finishedCallback();
        }
    }
    notifyFetchStateChanged();
}

void SpiderCore::notifyFetchStateChanged()
{
    m_fetchDrainCv.notify_all();
}

void SpiderCore::emitEvent(const QString &message) const
{
    if (m_stopping.load()) {
        return;
    }
    if (m_eventCallback) {
        m_eventCallback(message);
    }
}

void SpiderCore::emitEndpoint(SpiderDiscoveredEndpoint endpoint) const
{
    if (m_stopping.load()) {
        return;
    }
    if (m_endpointCallback) {
        m_endpointCallback(std::move(endpoint));
    }
}

void SpiderCore::emitParameter(SpiderDiscoveredParameter parameter) const
{
    if (m_stopping.load()) {
        return;
    }
    if (m_parameterCallback) {
        m_parameterCallback(std::move(parameter));
    }
}

void SpiderCore::emitAsset(SpiderDiscoveredAsset asset) const
{
    if (m_stopping.load()) {
        return;
    }
    if (m_assetCallback) {
        m_assetCallback(std::move(asset));
    }
}

void SpiderCore::emitHostPressureAsset(const QString &host, int score, const QString &reason) const
{
    emitAsset({QStringLiteral("host-pressure"),
               QStringLiteral("host=%1 | score=%2 | state=%3 | reason=%4")
                   .arg(host,
                        QString::number(score),
                        hostPressureStateName(score),
                        reason),
               host});
}

bool SpiderCore::authenticateIfNeeded()
{
    if (!m_options.auth.enabled || !m_options.auth.loginUrl.isValid()) {
        return false;
    }

    if (!m_options.auth.workflowSteps.empty()) {
        emitEvent(QStringLiteral("[auth] Workflow profili aktif: %1 adim").arg(m_options.auth.workflowSteps.size()));
        SpiderFetchResult lastResult;
        QUrl currentUrl = m_options.auth.loginUrl;
        QString csrfField = m_options.auth.csrfField;
        QString csrfValue;
        const int cookiesBefore = m_fetcher ? m_fetcher->cookieCount() : 0;
        QStringList cookieNamesBefore = m_fetcher ? m_fetcher->cookieNames() : QStringList{};

        for (std::size_t index = 0; index < m_options.auth.workflowSteps.size(); ++index) {
            const auto &step = m_options.auth.workflowSteps[index];
            const QUrl stepUrl = resolveWorkflowStepUrl(step, currentUrl, m_options.auth.loginUrl);
            const QString stepLabel = step.label.trimmed().isEmpty()
                ? QStringLiteral("step-%1").arg(index + 1)
                : step.label.trimmed();
            emitEvent(QStringLiteral("[auth] Workflow adimi %1 (%2): %3 %4")
                          .arg(index + 1)
                          .arg(stepLabel, step.method, stepUrl.toString()));
            emitAsset({QStringLiteral("auth-step-label"),
                       QStringLiteral("%1 | %2 %3").arg(stepLabel, step.method.toUpper(), stepUrl.toString()),
                       stepUrl.toString()});

            SpiderFetchResult formPage;
            QVariantMap fields = m_options.auth.extraFields;
            if (step.fetchFormFirst) {
                formPage = m_fetcher->fetch(stepUrl, m_options.timeoutMs, step.headers);
                const QString formHtml = QString::fromUtf8(formPage.body);
                const auto forms = m_htmlExtractor->extractForms(formHtml, stepUrl);
                const SpiderHtmlForm *selectedForm = nullptr;
                for (const auto &form : forms) {
                    if (form.loginLike) {
                        selectedForm = &form;
                        break;
                    }
                }
                if (!selectedForm && !forms.empty()) {
                    selectedForm = &forms.front();
                }
                if (selectedForm) {
                    currentUrl = selectedForm->actionUrl.isValid() ? selectedForm->actionUrl : stepUrl;
                    for (const auto &field : selectedForm->fields) {
                        if ((field.role == QLatin1String("csrf") || field.type == QLatin1String("hidden")) && !field.name.isEmpty()) {
                            fields.insert(field.name, field.value);
                        }
                        if (field.role == QLatin1String("csrf") && !field.name.isEmpty()) {
                            csrfField = field.name;
                            csrfValue = field.value;
                        }
                    }
                } else {
                    currentUrl = stepUrl;
                }
            } else {
                currentUrl = stepUrl;
            }

            for (auto it = step.fields.cbegin(); it != step.fields.cend(); ++it) {
                fields.insert(it.key(), resolveWorkflowPlaceholder(it.value().toString(), m_options.auth, csrfField, csrfValue));
            }
            if (!fields.contains(m_options.auth.usernameField)) {
                fields.insert(m_options.auth.usernameField, m_options.auth.username);
            }
            if (!fields.contains(m_options.auth.passwordField)) {
                fields.insert(m_options.auth.passwordField, m_options.auth.password);
            }
            if (!csrfField.isEmpty() && !csrfValue.isEmpty() && !fields.contains(csrfField)) {
                fields.insert(csrfField, csrfValue);
            }

            if (step.method.compare(QStringLiteral("GET"), Qt::CaseInsensitive) == 0) {
                QUrlQuery query(currentUrl);
                for (auto it = fields.cbegin(); it != fields.cend(); ++it) {
                    query.addQueryItem(it.key(), it.value().toString());
                }
                currentUrl.setQuery(query);
                lastResult = m_fetcher->fetch(currentUrl, m_options.timeoutMs, step.headers);
            } else {
                lastResult = m_fetcher->submitForm(currentUrl, fields, m_options.timeoutMs, step.headers);
            }

            const QVariantMap safeFields = sanitizedFieldMap(fields, m_options.auth.passwordField);
            QUrlQuery safeQuery;
            for (auto it = safeFields.cbegin(); it != safeFields.cend(); ++it) {
                safeQuery.addQueryItem(it.key(), it.value().toString());
            }
            emitAsset({QStringLiteral("auth-request"),
                       QStringLiteral("workflow-step=%1 %2 %3 | fields=%4")
                           .arg(index + 1)
                           .arg(step.method.toUpper(), currentUrl.toString(), safeFields.keys().join(',')),
                       stepUrl.toString()});
            if (!step.headers.isEmpty()) {
                QStringList headerPairs;
                for (auto it = step.headers.cbegin(); it != step.headers.cend(); ++it) {
                    headerPairs << QStringLiteral("%1=%2").arg(it.key(), it.value().toString());
                }
                emitAsset({QStringLiteral("auth-request-headers"),
                           QStringLiteral("workflow-step=%1 | headers=%2")
                               .arg(static_cast<int>(index + 1))
                               .arg(headerPairs.join(QStringLiteral(", "))),
                           stepUrl.toString()});
            }
            emitAsset({QStringLiteral("auth-request-body"),
                       QStringLiteral("payload=%1").arg(safeQuery.query(QUrl::FullyDecoded)),
                       stepUrl.toString()});
            emitAsset({QStringLiteral("auth-response"),
                       QStringLiteral("workflow-step=%1 HTTP %2 | final=%3 | title=%4")
                           .arg(index + 1)
                           .arg(lastResult.statusCode)
                           .arg(lastResult.finalUrl.toString(), lastResult.pageTitle),
                       currentUrl.toString()});
            if (!lastResult.responseHeaders.isEmpty()) {
                QStringList headerPairs;
                for (auto it = lastResult.responseHeaders.cbegin(); it != lastResult.responseHeaders.cend(); ++it) {
                    headerPairs << QStringLiteral("%1=%2").arg(it.key(), it.value().toString());
                }
                emitAsset({QStringLiteral("auth-response-headers"),
                           QStringLiteral("workflow-step=%1 | headers=%2")
                               .arg(static_cast<int>(index + 1))
                               .arg(headerPairs.join(QStringLiteral(" | "))),
                           currentUrl.toString()});
            }
            emitAsset({QStringLiteral("auth-response-body"),
                       bodyPreview(QString::fromUtf8(lastResult.body)),
                       lastResult.finalUrl.isValid() ? lastResult.finalUrl.toString() : currentUrl.toString()});

            currentUrl = lastResult.finalUrl.isValid() ? lastResult.finalUrl : currentUrl;
            if (!lastResult.ok()) {
                emitEvent(QStringLiteral("[auth] Workflow adimi basarisiz: %1").arg(lastResult.errorString));
                if (step.optional) {
                    emitAsset({QStringLiteral("auth-step-optional-skip"),
                               QStringLiteral("%1 | error=%2").arg(stepLabel, lastResult.errorString),
                               currentUrl.toString()});
                    continue;
                }
                m_authenticated = false;
                return false;
            }
            if (!workflowStepMatches(step, lastResult, m_fetcher ? m_fetcher->cookieNames() : QStringList{})) {
                emitEvent(QStringLiteral("[auth] Workflow beklentisi saglanmadi: adim %1").arg(index + 1));
                emitAsset({QStringLiteral("auth-expectation-failed"),
                           QStringLiteral("step=%1 | status=%2 | final=%3")
                               .arg(index + 1)
                               .arg(lastResult.statusCode)
                               .arg(currentUrl.toString()),
                           currentUrl.toString()});
                if (step.optional) {
                    emitAsset({QStringLiteral("auth-step-optional-skip"),
                               QStringLiteral("%1 | expectation-miss").arg(stepLabel),
                               currentUrl.toString()});
                    continue;
                }
                m_authenticated = false;
                return false;
            }
            if (step.pauseAfterMs > 0) {
                emitEvent(QStringLiteral("[auth] Workflow adimi sonrasi bekleniyor: %1 ms").arg(step.pauseAfterMs));
                std::this_thread::sleep_for(std::chrono::milliseconds(step.pauseAfterMs));
            }
        }

        const bool ok = lastResult.ok()
            && !looksLikeLoginWall(QString::fromUtf8(lastResult.body))
            && (!looksLikeLoginPath(lastResult.finalUrl) || m_fetcher->cookieCount() > 0);
        if (m_fetcher) {
            const QStringList cookieNamesAfter = m_fetcher->cookieNames();
            QStringList newCookies;
            for (const QString &cookieName : cookieNamesAfter) {
                if (!cookieNamesBefore.contains(cookieName, Qt::CaseInsensitive)) {
                    newCookies << cookieName;
                }
            }
            emitAsset({QStringLiteral("auth-cookie-jar"),
                       QStringLiteral("%1 cookie | %2")
                           .arg(m_fetcher->cookieCount())
                           .arg(cookieNamesAfter.join(',')),
                       currentUrl.toString()});
            emitAsset({QStringLiteral("auth-boundary"),
                       QStringLiteral("cookies %1->%2 | final=%3 | login-path=%4 | yeni-cookie=%5")
                           .arg(cookiesBefore)
                           .arg(m_fetcher->cookieCount())
                           .arg(currentUrl.toString())
                           .arg(looksLikeLoginPath(currentUrl) ? QStringLiteral("evet") : QStringLiteral("hayir"))
                           .arg(newCookies.join(',')),
                       currentUrl.toString()});
            for (const QString &cookieName : newCookies) {
                emitAsset({QStringLiteral("auth-new-cookie"),
                           cookieName,
                           currentUrl.toString()});
            }
        }
        m_authenticated = ok;
        emitEvent(ok
                      ? QStringLiteral("[auth] Workflow giris akisi tamamlandi: %1").arg(currentUrl.toString())
                      : QStringLiteral("[auth] Workflow giris akisi dogrulanamadi"));
        return ok;
    }

    emitEvent(QStringLiteral("[auth] Giris profili deneniyor: %1").arg(m_options.auth.loginUrl.toString()));
    const int cookiesBefore = m_fetcher ? m_fetcher->cookieCount() : 0;
    const QStringList cookieNamesBefore = m_fetcher ? m_fetcher->cookieNames() : QStringList{};
    SpiderFetchResult loginPage = m_fetcher->fetch(m_options.auth.loginUrl, m_options.timeoutMs, {});
    const QString loginHtml = QString::fromUtf8(loginPage.body);
    const auto forms = m_htmlExtractor->extractForms(loginHtml, m_options.auth.loginUrl);
    QVariantMap fields = m_options.auth.extraFields;
    QUrl submitUrl = m_options.auth.loginUrl;
    QString usernameField = m_options.auth.usernameField;
    QString passwordField = m_options.auth.passwordField;
    QString csrfField = m_options.auth.csrfField;

    const SpiderHtmlForm *selectedForm = nullptr;
    for (const auto &form : forms) {
        if (form.loginLike) {
            selectedForm = &form;
            break;
        }
    }
    if (!selectedForm && !forms.empty()) {
        selectedForm = &forms.front();
    }

    if (selectedForm) {
        submitUrl = selectedForm->actionUrl.isValid() ? selectedForm->actionUrl : submitUrl;
        for (const auto &field : selectedForm->fields) {
            if (field.role == "csrf" && !field.name.isEmpty()) {
                csrfField = field.name;
            }
            if (field.role == "kullanici-adi" && usernameField == "username") {
                usernameField = field.name;
            }
            if (field.role == "parola" && passwordField == "password") {
                passwordField = field.name;
            }
            if ((field.role == "csrf" || field.type == "hidden") && !field.name.isEmpty()) {
                fields.insert(field.name, field.value);
            }
        }
        emitEvent(QStringLiteral("[auth] Login formu secildi: %1").arg(submitUrl.toString()));
    }

    fields.insert(usernameField, m_options.auth.username);
    fields.insert(passwordField, m_options.auth.password);
    if (!csrfField.isEmpty() && !fields.contains(csrfField)) {
        static const QString patternTemplate = QStringLiteral(R"(<input[^>]*name\s*=\s*["']%1["'][^>]*value\s*=\s*["']([^"']+)["'])");
        const QRegularExpression csrfRegex(patternTemplate.arg(QRegularExpression::escape(csrfField)),
                                           QRegularExpression::CaseInsensitiveOption);
        const auto match = csrfRegex.match(loginHtml);
        if (match.hasMatch()) {
            fields.insert(csrfField, match.captured(1));
        }
    }

    const SpiderFetchResult loginResult = m_fetcher->submitForm(submitUrl, fields, m_options.timeoutMs, {});
    const bool ok = loginResult.ok();
    const QVariantMap safeFields = sanitizedFieldMap(fields, passwordField);
    QUrlQuery safeQuery;
    for (auto it = safeFields.cbegin(); it != safeFields.cend(); ++it) {
        safeQuery.addQueryItem(it.key(), it.value().toString());
    }
    emitAsset({QStringLiteral("auth-request"),
               QStringLiteral("POST %1 | fields=%2").arg(submitUrl.toString(), fields.keys().join(',')),
               m_options.auth.loginUrl.toString()});
    emitAsset({QStringLiteral("auth-request-body"),
               QStringLiteral("payload=%1")
                   .arg(safeQuery.query(QUrl::FullyDecoded)),
               m_options.auth.loginUrl.toString()});
    emitAsset({QStringLiteral("auth-response"),
               QStringLiteral("HTTP %1 | final=%2 | title=%3")
                   .arg(loginResult.statusCode)
                   .arg(loginResult.finalUrl.toString(), loginResult.pageTitle),
               submitUrl.toString()});
    emitAsset({QStringLiteral("auth-response-body"),
               bodyPreview(QString::fromUtf8(loginResult.body)),
               loginResult.finalUrl.isValid() ? loginResult.finalUrl.toString() : submitUrl.toString()});
    if (m_fetcher) {
        const QStringList cookieNamesAfter = m_fetcher->cookieNames();
        QStringList newCookies;
        for (const QString &cookieName : cookieNamesAfter) {
            if (!cookieNamesBefore.contains(cookieName, Qt::CaseInsensitive)) {
                newCookies << cookieName;
            }
        }
        emitAsset({QStringLiteral("auth-cookie-jar"),
                   QStringLiteral("%1 cookie | %2")
                       .arg(m_fetcher->cookieCount())
                       .arg(cookieNamesAfter.join(',')),
                   submitUrl.toString()});
        emitAsset({QStringLiteral("auth-boundary"),
                   QStringLiteral("cookies %1->%2 | final=%3 | login-path=%4")
                       .arg(cookiesBefore)
                       .arg(m_fetcher->cookieCount())
                       .arg(loginResult.finalUrl.toString())
                       .arg(looksLikeLoginPath(loginResult.finalUrl) ? QStringLiteral("evet") : QStringLiteral("hayir")),
                   submitUrl.toString()});
        for (const QString &cookieName : newCookies) {
            emitAsset({QStringLiteral("auth-new-cookie"),
                       cookieName,
                       submitUrl.toString()});
        }
    }
    m_authenticated = ok;
    emitEvent(ok
                  ? QStringLiteral("[auth] Giris akisi tamamlandi: %1").arg(loginResult.finalUrl.toString())
                  : QStringLiteral("[auth] Giris akisi basarisiz: %1").arg(loginResult.errorString));
    return ok;
}

std::unique_ptr<ISpiderFetcher> createBestSpiderFetcher()
{
#ifdef PENGUFOCE_WITH_LIBCURL
    return std::make_unique<CurlSpiderFetcher>();
#else
    return std::make_unique<AsyncQtSpiderFetcher>();
#endif
}

std::unique_ptr<ISpiderDomRenderer> createBestSpiderRenderer()
{
    auto renderer = std::make_unique<ProcessSpiderDomRenderer>();
    if (!renderer->available()) {
        return nullptr;
    }
    return renderer;
}
