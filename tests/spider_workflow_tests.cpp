#include "modules/spider/engine/spiderworkflow.h"
#include "modules/spider/engine/htmlextractor.h"
#include "modules/spider/engine/spiderscope.h"

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

int testWorkflowParseAndValidate()
{
    const QString workflow = QStringLiteral(
        "# login workflow\n"
        "/login|POST|form|label=Login|optional|delay=150|email={{username}}|password={{password}}|expect=status:200|header:X-Test=1\n"
        "@current|GET|direct|label=Dashboard|expect=!login\n");

    const SpiderWorkflowValidationResult validation = validateSpiderWorkflowText(workflow);
    if (!require(validation.valid(), QStringLiteral("workflow validation gecmedi"))) {
        return 1;
    }
    if (!require(validation.validSteps == 2, QStringLiteral("workflow valid adim sayisi yanlis"))) {
        return 1;
    }

    const auto steps = parseSpiderWorkflowSteps(workflow);
    if (!require(steps.size() == 2, QStringLiteral("workflow step parse sayisi yanlis"))) {
        return 1;
    }
    if (!require(steps.front().optional, QStringLiteral("optional flag parse edilmedi"))) {
        return 1;
    }
    if (!require(steps.front().pauseAfterMs == 150, QStringLiteral("delay parse edilmedi"))) {
        return 1;
    }
    if (!require(steps.front().label == QStringLiteral("Login"), QStringLiteral("label parse edilmedi"))) {
        return 1;
    }
    if (!require(steps.front().headers.value(QStringLiteral("X-Test")).toString() == QStringLiteral("1"),
                 QStringLiteral("header parse edilmedi"))) {
        return 1;
    }
    if (!require(steps.front().fields.value(QStringLiteral("email")).toString() == QStringLiteral("{{username}}"),
                 QStringLiteral("field parse edilmedi"))) {
        return 1;
    }
    if (!require(steps.back().url.isEmpty(), QStringLiteral("@current adimi beklenmedik URL uretti"))) {
        return 1;
    }
    if (!require(steps.back().expectNotLogin, QStringLiteral("expect=!login parse edilmedi"))) {
        return 1;
    }

    return 0;
}

int testWorkflowValidationWarnings()
{
    const QString workflow = QStringLiteral("bad-url|PUT|strange|delay=abc|header:broken|expect=unknown:rule\n");

    const SpiderWorkflowValidationResult validation = validateSpiderWorkflowText(workflow);
    if (!require(!validation.valid(), QStringLiteral("invalid workflow warning vermedi"))) {
        return 1;
    }
    if (!require(!validation.issues.isEmpty(), QStringLiteral("issues listesi bos"))) {
        return 1;
    }
    return 0;
}

int testPortalWorkflowScenario()
{
    const QString workflow = QStringLiteral(
        "/tenant/acme/login|POST|form|label=Tenant Login|email={{username}}|password={{password}}|expect=status:200|expect=body:Workspace\n"
        "@current|GET|direct|label=Billing|expect=url:/tenant/acme/billing|header:X-Tenant=acme\n"
        "/tenant/acme/reports|GET|direct|label=Reports|optional|delay=250|expect=!redirect:/logout\n");

    const SpiderWorkflowValidationResult validation = validateSpiderWorkflowText(workflow);
    if (!require(validation.valid(), QStringLiteral("portal workflow validation gecmedi"))) {
        return 1;
    }
    if (!require(validation.validSteps == 3, QStringLiteral("portal workflow adim sayisi yanlis"))) {
        return 1;
    }

    const auto steps = parseSpiderWorkflowSteps(workflow);
    if (!require(steps.size() == 3, QStringLiteral("portal workflow parse sayisi yanlis"))) {
        return 1;
    }
    if (!require(steps.at(1).url.isEmpty(), QStringLiteral("portal @current parse edilmedi"))) {
        return 1;
    }
    if (!require(steps.at(2).optional && steps.at(2).pauseAfterMs == 250,
                 QStringLiteral("portal optional/delay parse edilmedi"))) {
        return 1;
    }
    if (!require(steps.at(1).headers.value(QStringLiteral("X-Tenant")).toString() == QStringLiteral("acme"),
                 QStringLiteral("portal tenant header parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testSuppressedTargets()
{
    if (!require(spiderLooksLikeSuppressedSafetyTarget(QUrl(QStringLiteral("https://target.test/logout"))),
                 QStringLiteral("logout suppress edilmedi"))) {
        return 1;
    }
    if (!require(spiderLooksLikeSuppressedSafetyTarget(QUrl(QStringLiteral("https://target.test/account/delete-account?id=7"))),
                 QStringLiteral("delete-account suppress edilmedi"))) {
        return 1;
    }
    if (!require(!spiderLooksLikeSuppressedSafetyTarget(QUrl(QStringLiteral("https://target.test/admin/export"))),
                 QStringLiteral("export yanlis suppress edildi"))) {
        return 1;
    }
    return 0;
}

int testPortalSafetySurface()
{
    const QString html = QStringLiteral(R"(
        <html>
        <body>
            <a href="/tenant/acme/reports">Reports</a>
            <a href="/logout">Logout</a>
            <button data-url="/tenant/acme/export" id="export-btn">Export</button>
            <button data-url="/session/revoke" id="revoke-btn">Revoke</button>
            <form action="/tenant/acme/search" method="get">
                <input type="search" name="q">
            </form>
            <form action="/signout" method="post">
                <input type="hidden" name="_token" value="1">
            </form>
        </body>
        </html>
    )");

    const QUrl baseUrl(QStringLiteral("https://portal.example.com/app"));
    const auto extractor = createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::FastTokenizer);
    if (!require(static_cast<bool>(extractor), QStringLiteral("portal safety extractor olusmadi"))) {
        return 1;
    }

    const auto links = extractor->extractLinks(html, baseUrl);
    bool sawReports = false;
    bool sawLogout = false;
    for (const QUrl &url : links) {
        sawReports = sawReports || url.toString().contains(QStringLiteral("/tenant/acme/reports"));
        sawLogout = sawLogout || url.toString().contains(QStringLiteral("/logout"));
    }
    if (!require(sawReports && sawLogout, QStringLiteral("portal safety links parse edemedi"))) {
        return 1;
    }

    const auto forms = extractor->extractForms(html, baseUrl);
    bool sawSearch = false;
    bool sawSignout = false;
    for (const auto &form : forms) {
        sawSearch = sawSearch || form.actionUrl.toString().contains(QStringLiteral("/tenant/acme/search"));
        sawSignout = sawSignout || form.actionUrl.toString().contains(QStringLiteral("/signout"));
    }
    if (!require(sawSearch && sawSignout, QStringLiteral("portal safety forms parse edemedi"))) {
        return 1;
    }

    const auto actions = extractor->extractInteractionActions(html, baseUrl);
    bool sawExport = false;
    bool sawRevoke = false;
    for (const auto &action : actions) {
        sawExport = sawExport || action.targetUrl.toString().contains(QStringLiteral("/tenant/acme/export"));
        sawRevoke = sawRevoke || action.targetUrl.toString().contains(QStringLiteral("/session/revoke"));
    }
    if (!require(sawExport && sawRevoke, QStringLiteral("portal safety actions parse edemedi"))) {
        return 1;
    }

    if (!require(!spiderLooksLikeSuppressedSafetyTarget(QUrl(QStringLiteral("https://portal.example.com/tenant/acme/export"))),
                 QStringLiteral("export action yanlis suppress edildi"))) {
        return 1;
    }
    if (!require(spiderLooksLikeSuppressedSafetyTarget(QUrl(QStringLiteral("https://portal.example.com/logout"))),
                 QStringLiteral("logout link suppress edilmedi"))) {
        return 1;
    }
    if (!require(spiderLooksLikeSuppressedSafetyTarget(QUrl(QStringLiteral("https://portal.example.com/signout"))),
                 QStringLiteral("signout form suppress edilmedi"))) {
        return 1;
    }
    if (!require(spiderLooksLikeSuppressedSafetyTarget(QUrl(QStringLiteral("https://portal.example.com/session/revoke"))),
                 QStringLiteral("revoke action suppress edilmedi"))) {
        return 1;
    }

    return 0;
}

int testScopePresetUtilities()
{
    const QStringList safePatterns = spiderScopePresetPatterns(QStringLiteral("guvenli"));
    if (!require(!safePatterns.isEmpty(), QStringLiteral("guvenli preset bos dondu"))) {
        return 1;
    }

    const QString merged = mergeSpiderExcludePatterns(QStringLiteral("(^|\\.)custom\\.cdn\\.test"), QStringLiteral("guvenli"));
    if (!require(merged.contains(QStringLiteral("custom\\.cdn\\.test")),
                 QStringLiteral("manual exclude merge edilmedi"))) {
        return 1;
    }
    if (!require(merged.contains(QStringLiteral("fonts\\.googleapis\\.com")),
                 QStringLiteral("preset exclude merge edilmedi"))) {
        return 1;
    }

    if (!require(spiderAssetShouldBeSuppressed(QStringLiteral("script"),
                                               QStringLiteral("https://fonts.googleapis.com/css2?family=Inter"),
                                               QStringLiteral("guvenli")),
                 QStringLiteral("guvenli preset google fonts suppress etmedi"))) {
        return 1;
    }
    if (!require(!spiderAssetShouldBeSuppressed(QStringLiteral("auth-request"),
                                                QStringLiteral("https://fonts.googleapis.com/css2?family=Inter"),
                                                QStringLiteral("guvenli")),
                 QStringLiteral("auth asset yanlis suppress edildi"))) {
        return 1;
    }
    if (!require(!spiderAssetShouldBeSuppressed(QStringLiteral("script"),
                                                QStringLiteral("https://portal.example.com/tenant/acme/app.js"),
                                                QStringLiteral("guvenli")),
                 QStringLiteral("in-scope portal asset yanlis suppress edildi"))) {
        return 1;
    }

    return 0;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const int failures =
        testWorkflowParseAndValidate() +
        testWorkflowValidationWarnings() +
        testPortalWorkflowScenario() +
        testSuppressedTargets() +
        testPortalSafetySurface() +
        testScopePresetUtilities();

    if (failures == 0) {
        std::cout << "spider workflow tests passed" << std::endl;
        return 0;
    }

    std::cerr << "spider workflow tests failed: " << failures << std::endl;
    return 1;
}
