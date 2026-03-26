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
        m_getResults[url] = result;
    }

    SpiderFetchResult fetch(const QUrl &url, int timeoutMs, const QVariantMap &headers = {}) override
    {
        Q_UNUSED(timeoutMs);
        Q_UNUSED(headers);
        const QString key = url.toString();
        auto it = m_getResults.find(key);
        if (it != m_getResults.end()) {
            return it.value();
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
    QHash<QString, SpiderFetchResult> m_getResults;
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

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const int failures = testPortalReplayAndSuppression();

    if (failures == 0) {
        std::cout << "spider core tests passed" << std::endl;
        return 0;
    }

    std::cerr << "spider core tests failed: " << failures << std::endl;
    return 1;
}
