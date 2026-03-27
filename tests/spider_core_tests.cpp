#include "modules/spider/engine/spidercore.h"
#include "modules/spider/engine/spiderworkflow.h"
#include "modules/spider/engine/spiderscope.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QTimer>

#include <iostream>
#include <memory>
namespace {

bool require(bool condition, const QString &message)
{
    if (!condition) {
        std::cerr << message.toStdString() << std::endl;
    }
    return condition;
}

SpiderFetchResult makeHtmlResult(const QString &url, const QString &html, int statusCode = 200)
{
    SpiderFetchResult result;
    result.url = QUrl(url);
    result.finalUrl = result.url;
    result.statusCode = statusCode;
    result.contentType = QStringLiteral("text/html");
    result.body = html.toUtf8();
    result.pageTitle = QStringLiteral("Portal");
    return result;
}

class FakeSpiderFetcher final : public ISpiderFetcher
{
public:
    void addGet(const QString &url, const SpiderFetchResult &result)
    {
        m_getResults[url].push_back(result);
    }

    void addPost(const QString &url, const SpiderFetchResult &result)
    {
        m_postResults[url].push_back(result);
    }

    int fetchCount(const QString &url) const
    {
        return m_fetchCounts.value(url);
    }

    SpiderFetchResult fetch(const QUrl &url, int timeoutMs, const QVariantMap &headers = {}) override
    {
        Q_UNUSED(timeoutMs);
        Q_UNUSED(headers);
        const QString key = url.toString();
        m_fetchCounts[key] += 1;
        auto it = m_getResults.find(key);
        if (it != m_getResults.end() && !it.value().isEmpty()) {
            if (it.value().size() > 1) {
                SpiderFetchResult result = it.value().front();
                it.value().pop_front();
                return result;
            }
            return it.value().front();
        }

        SpiderFetchResult result;
        result.url = url;
        result.finalUrl = url;
        result.statusCode = 404;
        result.contentType = QStringLiteral("text/plain");
        result.body = QByteArrayLiteral("missing");
        return result;
    }

    SpiderFetchResult submitForm(const QUrl &url, const QVariantMap &fields, int timeoutMs, const QVariantMap &headers = {}) override
    {
        Q_UNUSED(fields);
        Q_UNUSED(timeoutMs);
        Q_UNUSED(headers);
        const QString key = url.toString();
        m_postCounts[key] += 1;
        auto it = m_postResults.find(key);
        if (it != m_postResults.end() && !it.value().isEmpty()) {
            if (it.value().size() > 1) {
                SpiderFetchResult result = it.value().front();
                it.value().pop_front();
                return result;
            }
            return it.value().front();
        }
        return fetch(url, timeoutMs, headers);
    }

    int cookieCount() const override
    {
        return 0;
    }

    QStringList cookieNames() const override
    {
        return {};
    }

private:
    QHash<QString, QList<SpiderFetchResult>> m_getResults;
    QHash<QString, QList<SpiderFetchResult>> m_postResults;
    QHash<QString, int> m_fetchCounts;
    QHash<QString, int> m_postCounts;
};

class FakeSpiderRenderer final : public ISpiderDomRenderer
{
public:
    explicit FakeSpiderRenderer(QString renderedHtml)
        : m_renderedHtml(std::move(renderedHtml))
    {
    }

    bool available() const override
    {
        return true;
    }

    QString backendName() const override
    {
        return QStringLiteral("fake-renderer");
    }

    SpiderRenderResult render(const QUrl &url, int timeoutMs) override
    {
        Q_UNUSED(url);
        Q_UNUSED(timeoutMs);
        SpiderRenderResult result;
        result.available = true;
        result.ok = true;
        result.backendName = backendName();
        result.renderedHtml = m_renderedHtml;
        return result;
    }

private:
    QString m_renderedHtml;
};

bool hasAssetKind(const QList<SpiderDiscoveredAsset> &assets, const QString &kind, const QString &contains = {})
{
    for (const SpiderDiscoveredAsset &asset : assets) {
        if (asset.kind != kind) {
            continue;
        }
        if (contains.isEmpty() || asset.value.contains(contains, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

int testPortalReplayAndSuppression()
{
    const QString seedUrl = QStringLiteral("https://portal.example.com/app");
    const QString html = QStringLiteral(R"(
        <html>
        <head>
            <title>Tenant Portal</title>
            <script type="module">
                history.pushState({}, "", "/tenant/acme/dashboard");
                router.push("/tenant/acme/reports");
            </script>
        </head>
        <body>
            <div id="app"></div>
            <a href="/tenant/acme/reports">Reports</a>
            <a href="https://cdn.example.net/lib.js">CDN</a>
            <button data-url="/tenant/acme/export" id="export-btn">Export</button>
            <button data-url="/logout" id="logout-btn">Logout</button>
            <form action="/tenant/acme/search" method="get">
                <input type="search" name="q">
                <input type="hidden" name="workspace" value="acme">
            </form>
        </body>
        </html>
    )");

    auto fetcher = std::make_unique<FakeSpiderFetcher>();
    FakeSpiderFetcher *fetcherPtr = fetcher.get();
    fetcher->addGet(seedUrl, makeHtmlResult(seedUrl, html));
    fetcher->addGet(QStringLiteral("https://portal.example.com/robots.txt"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/robots.txt"), QStringLiteral("User-agent: *")));
    fetcher->addGet(QStringLiteral("https://portal.example.com/sitemap.xml"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/sitemap.xml"), QStringLiteral("<xml/>"), 404));
    fetcher->addGet(QStringLiteral("https://portal.example.com/manifest.json"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/manifest.json"), QStringLiteral("{}"), 404));
    fetcher->addGet(QStringLiteral("https://portal.example.com/tenant/acme/search?q=test&workspace=acme"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/tenant/acme/search?q=test&workspace=acme"),
                                   QStringLiteral("<html><body>search ok</body></html>")));
    fetcher->addGet(QStringLiteral("https://portal.example.com/tenant/acme/export"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/tenant/acme/export"),
                                   QStringLiteral("<html><body>export ok</body></html>")));

    SpiderCore core(std::move(fetcher),
                    std::make_unique<FakeSpiderRenderer>(html),
                    createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::FastTokenizer));

    QList<SpiderDiscoveredAsset> assets;
    QMutex assetsMutex;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);

    core.setAssetCallback([&](SpiderDiscoveredAsset asset) {
        QMutexLocker locker(&assetsMutex);
        assets.push_back(std::move(asset));
    });
    core.setFinishedCallback([&]() {
        QMetaObject::invokeMethod(&loop, [&]() { loop.quit(); }, Qt::QueuedConnection);
    });

    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(6000);

    SpiderRunOptions options;
    options.maxPages = 10;
    options.maxDepth = 2;
    options.maxInFlight = 2;
    options.timeoutMs = 600;
    options.politenessDelayMs = 0;
    options.maxRetries = 0;
    options.enableHeadlessRender = true;
    options.followRenderedRoutes = true;
    options.enableSafeWorkflowReplay = true;

    core.start(QUrl(seedUrl), options);
    loop.exec();
    core.stop();

    {
        QMutexLocker locker(&assetsMutex);
        if (!require(hasAssetKind(assets, QStringLiteral("render-success")),
                     QStringLiteral("render-success asset gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("workflow-submit-candidate"), QStringLiteral("/tenant/acme/search")),
                     QStringLiteral("workflow submit candidate gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("workflow-action-candidate"), QStringLiteral("/tenant/acme/export")),
                     QStringLiteral("workflow action candidate gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("crawl-suppressed"), QStringLiteral("/logout")),
                     QStringLiteral("logout suppression asset gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("scope-outlier"), QStringLiteral("cdn.example.net")),
                     QStringLiteral("scope-outlier asset gelmedi"))) {
            return 1;
        }
    }

    return 0;
}

int testAuthWorkflowOptionalSkip()
{
    const QString seedUrl = QStringLiteral("https://portal.example.com/app");
    const QString seedHtml = QStringLiteral("<html><body><a href=\"/tenant/acme/reports\">Reports</a></body></html>");

    auto fetcher = std::make_unique<FakeSpiderFetcher>();
    FakeSpiderFetcher *fetcherPtr = fetcher.get();
    fetcher->addGet(seedUrl, makeHtmlResult(seedUrl, seedHtml));
    fetcher->addGet(QStringLiteral("https://portal.example.com/robots.txt"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/robots.txt"), QStringLiteral("User-agent: *")));
    fetcher->addGet(QStringLiteral("https://portal.example.com/sitemap.xml"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/sitemap.xml"), QStringLiteral("<xml/>"), 404));
    fetcher->addGet(QStringLiteral("https://portal.example.com/manifest.json"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/manifest.json"), QStringLiteral("{}"), 404));
    fetcher->addPost(QStringLiteral("https://portal.example.com/tenant/acme/login"),
                     makeHtmlResult(QStringLiteral("https://portal.example.com/tenant/acme/home"),
                                    QStringLiteral("<html><body>Workspace Home</body></html>")));
    fetcher->addGet(QStringLiteral("https://portal.example.com/tenant/acme/profile"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/tenant/acme/profile"),
                                   QStringLiteral("<html><body>Profile</body></html>")));

    SpiderCore core(std::move(fetcher),
                    nullptr,
                    createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::FastTokenizer));

    QList<SpiderDiscoveredAsset> assets;
    QMutex assetsMutex;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);

    core.setAssetCallback([&](SpiderDiscoveredAsset asset) {
        QMutexLocker locker(&assetsMutex);
        assets.push_back(std::move(asset));
    });
    core.setFinishedCallback([&]() {
        QMetaObject::invokeMethod(&loop, [&]() { loop.quit(); }, Qt::QueuedConnection);
    });

    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(5000);

    SpiderRunOptions options;
    options.maxPages = 6;
    options.maxDepth = 1;
    options.maxInFlight = 2;
    options.timeoutMs = 500;
    options.maxRetries = 0;
    options.auth.enabled = true;
    options.auth.loginUrl = QUrl(QStringLiteral("https://portal.example.com/tenant/acme/login"));
    options.auth.username = QStringLiteral("analyst");
    options.auth.password = QStringLiteral("secret");
    options.auth.workflowSteps = parseSpiderWorkflowSteps(QStringLiteral(
        "https://portal.example.com/tenant/acme/login|POST|direct|label=Tenant Login|expect=status:200|expect=body:Workspace\n"
        "https://portal.example.com/tenant/acme/profile|GET|direct|label=Profile|optional|expect=url:/missing\n"));

    core.start(QUrl(seedUrl), options);
    loop.exec();
    core.stop();

    {
        QMutexLocker locker(&assetsMutex);
        if (!require(hasAssetKind(assets, QStringLiteral("auth-step-label"), QStringLiteral("Tenant Login")),
                     QStringLiteral("auth-step-label gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("auth-request"), QStringLiteral("workflow-step=1")),
                     QStringLiteral("auth-request gelmedi"))) {
            return 1;
        }
        if (!hasAssetKind(assets, QStringLiteral("auth-step-optional-skip"), QStringLiteral("Profile"))) {
            std::cerr << "auth assets:" << std::endl;
            for (const SpiderDiscoveredAsset &asset : assets) {
                if (asset.kind.startsWith(QStringLiteral("auth-"))) {
                    std::cerr << "  " << asset.kind.toStdString() << " => " << asset.value.toStdString() << std::endl;
                }
            }
        }
        if (!require(hasAssetKind(assets, QStringLiteral("auth-step-optional-skip"), QStringLiteral("Profile")),
                     QStringLiteral("optional skip asset gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("auth-boundary")),
                     QStringLiteral("auth-boundary asset gelmedi"))) {
            return 1;
        }
    }

    return 0;
}

int testWafVendorDetection()
{
    const QString seedUrl = QStringLiteral("https://portal.example.com/app");
    SpiderFetchResult wafResult = makeHtmlResult(seedUrl,
                                                 QStringLiteral("<html><title>Just a moment</title><body>Attention Required! Cloudflare security check</body></html>"),
                                                 429);
    wafResult.responseHeaders.insert(QStringLiteral("cf-cache-status"), QStringLiteral("DYNAMIC"));
    wafResult.pageTitle = QStringLiteral("Just a moment");

    auto fetcher = std::make_unique<FakeSpiderFetcher>();
    fetcher->addGet(seedUrl, wafResult);
    fetcher->addGet(QStringLiteral("https://portal.example.com/robots.txt"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/robots.txt"), QStringLiteral("User-agent: *")));
    fetcher->addGet(QStringLiteral("https://portal.example.com/sitemap.xml"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/sitemap.xml"), QStringLiteral("<xml/>"), 404));
    fetcher->addGet(QStringLiteral("https://portal.example.com/manifest.json"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/manifest.json"), QStringLiteral("{}"), 404));

    SpiderCore core(std::move(fetcher),
                    nullptr,
                    createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::FastTokenizer));

    QList<SpiderDiscoveredAsset> assets;
    QMutex assetsMutex;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);

    core.setAssetCallback([&](SpiderDiscoveredAsset asset) {
        QMutexLocker locker(&assetsMutex);
        assets.push_back(std::move(asset));
    });
    core.setFinishedCallback([&]() {
        QMetaObject::invokeMethod(&loop, [&]() { loop.quit(); }, Qt::QueuedConnection);
    });

    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(5000);

    SpiderRunOptions options;
    options.maxPages = 4;
    options.maxDepth = 0;
    options.maxInFlight = 1;
    options.timeoutMs = 500;
    options.maxRetries = 0;

    core.start(QUrl(seedUrl), options);
    loop.exec();
    core.stop();

    {
        QMutexLocker locker(&assetsMutex);
        if (!require(hasAssetKind(assets, QStringLiteral("waf-vendor"), QStringLiteral("cloudflare")),
                     QStringLiteral("waf-vendor asset gelmedi"))) {
            return 1;
        }
    }

    return 0;
}

int testRetryAfterAndWafBackoff()
{
    const QString seedUrl = QStringLiteral("https://portal.example.com/app");
    SpiderFetchResult retryResult = makeHtmlResult(seedUrl,
                                                   QStringLiteral("<html><title>Attention Required</title><body>Cloudflare security check</body></html>"),
                                                   429);
    retryResult.responseHeaders.insert(QStringLiteral("retry-after"), QStringLiteral("1"));
    retryResult.responseHeaders.insert(QStringLiteral("cf-cache-status"), QStringLiteral("DYNAMIC"));
    retryResult.pageTitle = QStringLiteral("Attention Required");

    auto fetcher = std::make_unique<FakeSpiderFetcher>();
    FakeSpiderFetcher *fetcherPtr = fetcher.get();
    fetcher->addGet(seedUrl, retryResult);
    fetcher->addGet(QStringLiteral("https://portal.example.com/robots.txt"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/robots.txt"), QStringLiteral("User-agent: *")));
    fetcher->addGet(QStringLiteral("https://portal.example.com/sitemap.xml"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/sitemap.xml"), QStringLiteral("<xml/>"), 404));
    fetcher->addGet(QStringLiteral("https://portal.example.com/manifest.json"),
                    makeHtmlResult(QStringLiteral("https://portal.example.com/manifest.json"), QStringLiteral("{}"), 404));
    fetcher->addGet(seedUrl,
                    makeHtmlResult(seedUrl,
                                   QStringLiteral("<html><body>portal ok</body></html>"),
                                   200));

    SpiderCore core(std::move(fetcher),
                    nullptr,
                    createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::FastTokenizer));

    QList<QString> events;
    QList<SpiderDiscoveredAsset> assets;
    QMutex mutex;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);

    core.setEventCallback([&](QString message) {
        QMutexLocker locker(&mutex);
        events.push_back(std::move(message));
    });
    core.setAssetCallback([&](SpiderDiscoveredAsset asset) {
        QMutexLocker locker(&mutex);
        assets.push_back(std::move(asset));
    });
    core.setFinishedCallback([&]() {
        QMetaObject::invokeMethod(&loop, [&]() { loop.quit(); }, Qt::QueuedConnection);
    });

    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(5000);

    SpiderRunOptions options;
    options.maxPages = 4;
    options.maxDepth = 0;
    options.maxInFlight = 1;
    options.timeoutMs = 500;
    options.maxRetries = 1;
    options.politenessDelayMs = 0;

    core.start(QUrl(seedUrl), options);
    loop.exec();
    core.stop();

    {
        QMutexLocker locker(&mutex);
        bool sawRetryEvent = false;
        for (const QString &message : events) {
            if (message.contains(QStringLiteral("[retry]")) && message.contains(QStringLiteral("cloudflare"), Qt::CaseInsensitive)) {
                sawRetryEvent = true;
                break;
            }
        }
        if (!require(sawRetryEvent, QStringLiteral("retry/waf event gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("waf-vendor"), QStringLiteral("cloudflare")),
                     QStringLiteral("retry senaryosunda waf-vendor gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("retry-after"), QStringLiteral("delay=1000 ms")),
                     QStringLiteral("retry-after asset gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("retry-scheduled"), QStringLiteral("retry=1/1")),
                     QStringLiteral("retry-scheduled asset gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("host-pressure"), QStringLiteral("reason=retry+waf")),
                     QStringLiteral("host-pressure retry asset gelmedi"))) {
            return 1;
        }
        if (!require(hasAssetKind(assets, QStringLiteral("host-pressure"), QStringLiteral("reason=success-cooldown")),
                     QStringLiteral("host-pressure cooldown asset gelmedi"))) {
            return 1;
        }
        if (!require(fetcherPtr->fetchCount(seedUrl) >= 2,
                     QStringLiteral("retry sonrasi ikinci fetch gerceklesmedi"))) {
            return 1;
        }
    }

    return 0;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const int failures =
        testPortalReplayAndSuppression() +
        testAuthWorkflowOptionalSkip() +
        testWafVendorDetection() +
        testRetryAfterAndWafBackoff();

    if (failures == 0) {
        std::cout << "spider core tests passed" << std::endl;
        return 0;
    }

    std::cerr << "spider core tests failed: " << failures << std::endl;
    return 1;
}
