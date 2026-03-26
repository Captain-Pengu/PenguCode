#include "modules/spider/engine/htmlextractor.h"

#include <QCoreApplication>

#include <iostream>

namespace {

bool require(bool condition, const QString &message)
{
    if (!condition) {
        std::cerr << message.toStdString() << std::endl;
    }
    return condition;
}

QString sampleHtml()
{
    return QStringLiteral(R"(
        <html>
        <head>
            <title>Admin Console</title>
            <meta property="og:url" content="/panel">
            <link rel="manifest" href="/manifest.json">
            <script>
                const api = "/api/v1/users";
                const admin = "/admin/settings";
                history.pushState({}, "", "/portal/audit");
                history.replaceState({}, "", "/portal/review");
                const graphqlEndpoint = "/graphql/query";
                router.push("/dashboard/insights");
                navigateTo("/workspace/overview");
                redirectTo("/gateway/health");
                navigator.serviceWorker.register("/sw.js");
            </script>
        </head>
        <body>
            <h1>Dashboard</h1>
            <a href="/reports">Reports</a>
            <button data-url="/admin/export" id="export-btn">Export</button>
            <form action="/login" method="post">
                <input type="text" name="username" autocomplete="username">
                <input type="password" name="password" autocomplete="current-password">
                <input type="hidden" name="csrf_token" value="abc123">
            </form>
            <form action="/search" method="get">
                <input type="search" name="q" autocomplete="off">
                <input type="hidden" name="scope" value="internal">
            </form>
        </body>
        </html>
    )");
}

QString samplePortalHtml()
{
    return QStringLiteral(R"(
        <html>
        <head>
            <title>Workspace Portal</title>
            <meta property="og:url" content="/tenant/acme/home">
            <link rel="manifest" href="/tenant/acme/manifest.json">
            <script>
                const apiBase = "/tenant/acme/api";
                history.pushState({}, "", "/tenant/acme/billing");
                router.replace("/tenant/acme/audit");
                navigateTo("/tenant/acme/reports");
                window.location.assign("/tenant/acme/profile");
                navigator.serviceWorker.register("/tenant/acme/sw.js");
            </script>
        </head>
        <body>
            <h1>Workspace</h1>
            <a href="/tenant/acme/settings">Settings</a>
            <button data-url="/tenant/acme/export" id="tenant-export">Export</button>
            <form action="/tenant/acme/login" method="post">
                <input type="email" name="email" autocomplete="username">
                <input type="password" name="password" autocomplete="current-password">
                <input type="hidden" name="_token" value="csrf-portal">
            </form>
            <form action="/tenant/acme/search" method="get">
                <input type="search" name="q">
                <input type="hidden" name="workspace" value="acme">
            </form>
        </body>
        </html>
    )");
}

int testExtractor(std::unique_ptr<ISpiderHtmlExtractor> extractor, const QString &label)
{
    if (!require(static_cast<bool>(extractor), QStringLiteral("%1 extractor olusmadi").arg(label))) {
        return 1;
    }

    const QString html = sampleHtml();
    const QUrl baseUrl(QStringLiteral("https://example.com/base"));

    if (!require(extractor->extractPageTitle(html) == QStringLiteral("Admin Console"),
                 QStringLiteral("%1 title parse edemedi").arg(label))) {
        return 1;
    }

    const QStringList headings = extractor->extractHeadingHints(html);
    if (!require(headings.contains(QStringLiteral("Dashboard")),
                 QStringLiteral("%1 heading parse edemedi").arg(label))) {
        return 1;
    }

    const auto links = extractor->extractLinks(html, baseUrl);
    bool sawReports = false;
    bool sawPanel = false;
    bool sawManifest = false;
    for (const QUrl &url : links) {
        sawReports = sawReports || url.toString().contains(QStringLiteral("/reports"));
        sawPanel = sawPanel || url.toString().contains(QStringLiteral("/panel"));
        sawManifest = sawManifest || url.toString().contains(QStringLiteral("/manifest.json"));
    }
    if (!require(sawReports && sawPanel && sawManifest,
                 QStringLiteral("%1 links parse edemedi").arg(label))) {
        return 1;
    }

    const auto forms = extractor->extractForms(html, baseUrl);
    if (!require(forms.size() == 2, QStringLiteral("%1 form parse edemedi").arg(label))) {
        return 1;
    }
    if (!require(forms.front().loginLike, QStringLiteral("%1 login form tespiti yapamadi").arg(label))) {
        return 1;
    }
    bool sawReplayableSearchField = false;
    for (const auto &form : forms) {
        for (const auto &field : form.fields) {
            if (field.name == QStringLiteral("q") && field.role == QStringLiteral("arama")) {
                sawReplayableSearchField = true;
            }
        }
    }
    if (!require(sawReplayableSearchField, QStringLiteral("%1 replayable form alani parse edemedi").arg(label))) {
        return 1;
    }

    const auto actions = extractor->extractInteractionActions(html, baseUrl);
    bool sawExport = false;
    for (const auto &action : actions) {
        sawExport = sawExport || action.targetUrl.toString().contains(QStringLiteral("/admin/export"));
    }
    if (!require(sawExport, QStringLiteral("%1 action parse edemedi").arg(label))) {
        return 1;
    }

    const QStringList routes = extractor->extractJsRoutes(html);
    if (!require(routes.contains(QStringLiteral("/api/v1/users"))
                 && routes.contains(QStringLiteral("/admin/settings"))
                 && routes.contains(QStringLiteral("/portal/audit"))
                 && routes.contains(QStringLiteral("/portal/review"))
                 && routes.contains(QStringLiteral("/graphql/query"))
                 && routes.contains(QStringLiteral("/dashboard/insights"))
                 && routes.contains(QStringLiteral("/workspace/overview"))
                 && routes.contains(QStringLiteral("/gateway/health"))
                 && routes.contains(QStringLiteral("/sw.js")),
                 QStringLiteral("%1 js route parse edemedi").arg(label))) {
        return 1;
    }

    return 0;
}

int testPortalScenario(std::unique_ptr<ISpiderHtmlExtractor> extractor, const QString &label)
{
    if (!require(static_cast<bool>(extractor), QStringLiteral("%1 portal extractor olusmadi").arg(label))) {
        return 1;
    }

    const QString html = samplePortalHtml();
    const QUrl baseUrl(QStringLiteral("https://portal.example.com/app"));
    const auto links = extractor->extractLinks(html, baseUrl);
    bool sawTenantSettings = false;
    bool sawTenantManifest = false;
    for (const QUrl &url : links) {
        sawTenantSettings = sawTenantSettings || url.toString().contains(QStringLiteral("/tenant/acme/settings"));
        sawTenantManifest = sawTenantManifest || url.toString().contains(QStringLiteral("/tenant/acme/manifest.json"));
    }
    if (!require(sawTenantSettings && sawTenantManifest,
                 QStringLiteral("%1 portal linklerini parse edemedi").arg(label))) {
        return 1;
    }

    const auto routes = extractor->extractJsRoutes(html);
    if (!require(routes.contains(QStringLiteral("/tenant/acme/api"))
                 && routes.contains(QStringLiteral("/tenant/acme/billing"))
                 && routes.contains(QStringLiteral("/tenant/acme/audit"))
                 && routes.contains(QStringLiteral("/tenant/acme/reports"))
                 && routes.contains(QStringLiteral("/tenant/acme/profile"))
                 && routes.contains(QStringLiteral("/tenant/acme/sw.js")),
                 QStringLiteral("%1 portal route'larini parse edemedi").arg(label))) {
        return 1;
    }

    const auto actions = extractor->extractInteractionActions(html, baseUrl);
    bool sawExport = false;
    for (const auto &action : actions) {
        sawExport = sawExport || action.targetUrl.toString().contains(QStringLiteral("/tenant/acme/export"));
    }
    if (!require(sawExport, QStringLiteral("%1 portal export action'ini parse edemedi").arg(label))) {
        return 1;
    }

    return 0;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const int failures =
        testExtractor(createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::Regex), QStringLiteral("regex")) +
        testExtractor(createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::FastTokenizer), QStringLiteral("fast")) +
        testExtractor(createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::DomLite), QStringLiteral("dom")) +
        testPortalScenario(createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::Regex), QStringLiteral("regex")) +
        testPortalScenario(createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::FastTokenizer), QStringLiteral("fast")) +
        testPortalScenario(createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::DomLite), QStringLiteral("dom"));

    if (failures == 0) {
        std::cout << "spider extractor tests passed" << std::endl;
        return 0;
    }

    std::cerr << "spider extractor tests failed: " << failures << std::endl;
    return 1;
}
