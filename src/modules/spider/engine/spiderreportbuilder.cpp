#include "modules/spider/engine/spiderreportbuilder.h"

#include "modules/spider/spidermodule.h"

#include <QDate>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QPageLayout>
#include <QPageSize>
#include <QPdfWriter>
#include <QRegularExpression>
#include <QSet>
#include <QStandardPaths>
#include <QTextDocument>

namespace {

QString sanitizedFileStem(QString text)
{
    text = text.trimmed();
    if (text.isEmpty()) {
        return QStringLiteral("pengufoce-spider-raporu");
    }

    text.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9]+")), QStringLiteral("-"));
    while (text.contains(QStringLiteral("--"))) {
        text.replace(QStringLiteral("--"), QStringLiteral("-"));
    }
    text.remove(QRegularExpression(QStringLiteral("^-+|-+$")));
    return text.isEmpty() ? QStringLiteral("pengufoce-spider-raporu") : text.toLower();
}

bool shouldSuppressReportAsset(const QVariantMap &row)
{
    const QString kind = row.value("kind").toString();
    const QString value = row.value("value").toString();
    return (kind == QLatin1String("literal") || kind == QLatin1String("js-literal"))
        && value.startsWith(QStringLiteral("jwt:"), Qt::CaseInsensitive)
        && (value.contains(QStringLiteral("beacon.min.js"), Qt::CaseInsensitive)
            || value.contains(QStringLiteral("static.cloudflare"), Qt::CaseInsensitive)
            || value.contains(QStringLiteral("document.body"), Qt::CaseInsensitive)
            || value.contains(QStringLiteral("window.location"), Qt::CaseInsensitive));
}

} // namespace

QString spiderReportFileName(const QString &target, const QString &extension)
{
    return QStringLiteral("pengufoce-spider-kesif-raporu-%1-v1.0-%2.%3")
        .arg(sanitizedFileStem(target),
             QDate::currentDate().toString(QStringLiteral("yyyyMMdd")),
             extension);
}

QString spiderReportDefaultPath(const QString &target, const QString &extension)
{
    QString baseDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (baseDir.trimmed().isEmpty()) {
        baseDir = QDir::currentPath();
    }
    return QDir(baseDir).filePath(spiderReportFileName(target, extension));
}

bool saveSpiderPdfReport(const QString &path, const QString &html, QString *errorMessage)
{
    QString resolvedPath = path.trimmed();
    if (resolvedPath.isEmpty()) {
        if (errorMessage) {
            *errorMessage = QObject::tr("Gecerli bir dosya yolu secilmedi.");
        }
        return false;
    }
    if (!resolvedPath.endsWith(QStringLiteral(".pdf"), Qt::CaseInsensitive)) {
        resolvedPath += QStringLiteral(".pdf");
    }

    {
        QPdfWriter writer(resolvedPath);
        writer.setResolution(144);
        writer.setPageSize(QPageSize(QPageSize::A4));
        writer.setPageMargins(QMarginsF(18, 18, 18, 18), QPageLayout::Millimeter);
        writer.setTitle(QObject::tr("PenguFoce Spider Kesif Raporu"));
        QTextDocument document;
        document.setDocumentMargin(18.0);
        document.setHtml(html);
        document.setPageSize(writer.pageLayout().paintRectPixels(writer.resolution()).size());
        document.print(&writer);
    }

    const QFileInfo info(resolvedPath);
    if (!info.exists() || info.size() <= 0) {
        if (errorMessage) {
            *errorMessage = QObject::tr("PDF dosyasi olusturulamadi.");
        }
        return false;
    }
    return true;
}

QString buildSpiderReportHtml(const SpiderModule &module, const QStringList &featureItems)
{
    QString endpointHtml;
    QSet<QString> seenEndpoints;
    int protectedCount = 0;
    int authDeltaCount = 0;
    int missingCount = 0;
    for (const QVariant &value : module.endpoints()) {
        const QVariantMap row = value.toMap();
        const QString key = QStringLiteral("%1|%2").arg(row.value("kind").toString(), row.value("url").toString());
        if (seenEndpoints.contains(key)) {
            continue;
        }
        seenEndpoints.insert(key);
        const QString kind = row.value("kind").toString();
        const int statusCode = row.value("statusCode").toInt();
        const QString sessionState = row.value("sessionState").toString();
        if (kind == QLatin1String("login-wall") || kind == QLatin1String("access-denied") || kind == QLatin1String("waf-challenge") || statusCode == 401 || statusCode == 403) {
            ++protectedCount;
        }
        if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            ++authDeltaCount;
        }
        if (kind == QLatin1String("soft-404") || statusCode == 404) {
            ++missingCount;
        }
        endpointHtml += QString("<li><b>%1</b> - %2 (d%3, HTTP %4, %5)</li>")
            .arg(row.value("kind").toString().toHtmlEscaped(),
                 row.value("url").toString().toHtmlEscaped(),
                 row.value("depth").toString().toHtmlEscaped(),
                 row.value("statusCode").toString().toHtmlEscaped(),
                 row.value("sessionState").toString().toHtmlEscaped());
    }
    if (endpointHtml.isEmpty()) {
        endpointHtml = "<li>Endpoint kaydi bulunmadi.</li>";
    }

    QString parameterHtml;
    for (const QVariant &value : module.parameters()) {
        const QVariantMap row = value.toMap();
        parameterHtml += QString("<li><b>%1</b> - %2 (%3)</li>")
            .arg(row.value("name").toString().toHtmlEscaped(),
                 row.value("url").toString().toHtmlEscaped(),
                 row.value("origin").toString().toHtmlEscaped());
    }
    if (parameterHtml.isEmpty()) {
        parameterHtml = "<li>Parametre veya form girdisi kaydi bulunmadi.</li>";
    }

    QString assetHtml;
    QSet<QString> seenAssets;
    int workflowCandidates = 0;
    int workflowResults = 0;
    int wafHits = 0;
    int suppressedHits = 0;
    int pressureHits = 0;
    for (const QVariant &value : module.assets()) {
        const QVariantMap row = value.toMap();
        if (shouldSuppressReportAsset(row)) {
            continue;
        }
        const QString kind = row.value("kind").toString();
        if (kind == QLatin1String("workflow-submit-candidate") || kind == QLatin1String("workflow-action-candidate")) ++workflowCandidates;
        else if (kind == QLatin1String("workflow-submit-result") || kind == QLatin1String("workflow-action-result")) ++workflowResults;
        else if (kind == QLatin1String("waf-vendor") || kind == QLatin1String("waf-challenge")) ++wafHits;
        else if (kind == QLatin1String("host-pressure") || kind == QLatin1String("retry-after") || kind == QLatin1String("retry-scheduled")) ++pressureHits;
        else if (kind == QLatin1String("crawl-suppressed") || kind == QLatin1String("scope-outlier") || kind == QLatin1String("scope-excluded")) ++suppressedHits;
        const QString key = QStringLiteral("%1|%2").arg(kind, row.value("value").toString());
        if (seenAssets.contains(key)) continue;
        seenAssets.insert(key);
        assetHtml += QString("<li><b>%1</b> - %2 <span style='color:#5b6677'>(%3)</span></li>")
            .arg(kind.toHtmlEscaped(),
                 row.value("value").toString().toHtmlEscaped(),
                 row.value("source").toString().toHtmlEscaped());
    }
    if (assetHtml.isEmpty()) {
        assetHtml = "<li>Asset veya literal kaydi bulunmadi.</li>";
    }

    QString featureHtml;
    for (const QString &item : featureItems) {
        featureHtml += QString("<li>%1</li>").arg(item.toHtmlEscaped());
    }
    if (featureHtml.isEmpty()) {
        featureHtml = "<li>Ozellik listesi hazir degil.</li>";
    }

    QString timelineHtml;
    for (const QVariant &value : module.coverageTimeline()) {
        const QVariantMap row = value.toMap();
        timelineHtml += QString("<li>[%1] <b>%2</b> - %3 <span style='color:#5b6677'>(%4)</span></li>")
            .arg(row.value("time").toString().toHtmlEscaped(),
                 row.value("title").toString().toHtmlEscaped(),
                 row.value("detail").toString().toHtmlEscaped(),
                 row.value("stage").toString().toHtmlEscaped());
    }
    if (timelineHtml.isEmpty()) {
        timelineHtml = "<li>Timeline kaydi bulunmadi.</li>";
    }

    const QVariantMap breakdown = module.coverageBreakdown();
    const QString operationalSummary = QStringLiteral("Korunan yuzey %1 | oturum sonrasi yeni yuzey %2 | 404/soft-404 %3")
        .arg(protectedCount).arg(authDeltaCount).arg(missingCount);
    const QString workflowSummary = QStringLiteral("Workflow aday %1 | replay sonuc %2 | WAF %3 | pressure %4 | baskilanan/scope %5")
        .arg(workflowCandidates).arg(workflowResults).arg(wafHits).arg(pressureHits).arg(suppressedHits);

    return QString(
        "<html><body style='font-family:Bahnschrift;font-size:12pt;line-height:1.45;padding:0;color:#171a20;'>"
        "<div style='border-bottom:2px solid #8f1732;padding-bottom:12px;margin-bottom:18px;'>"
        "<h1 style='margin:0;font-size:24pt;'>PenguFoce Spider Kesif Raporu</h1>"
        "<p style='margin:8px 0 0 0;font-size:11pt;'><b>Hedef:</b> %1<br><b>Rapor Tarihi:</b> %2<br><b>Scope Profili:</b> %3</p>"
        "</div>"
        "<h2>1. Yonetici Ozeti</h2><p>Coverage puani <b>%4/100</b>. %5</p><p><b>Workflow/WAF Ozeti:</b> %6</p>"
        "<h2>2. Aktif Spider Yetenekleri</h2><ul>%7</ul>"
        "<h2>3. Coverage Kirilimi</h2><p>auth %8 | form %9 | js %10 | secret %11 | admin %12 | upload %13 | delta %14 | korunan %15 | 404 %16 | render %17 | automation %18</p>"
        "<h2>4. Endpoint Ozetleri</h2><ul>%19</ul>"
        "<h2>5. Parametre ve Form Girdileri</h2><ul>%20</ul>"
        "<h2>6. Asset, Render ve Automation Bulgulari</h2><ul>%21</ul>"
        "<h2>7. Coverage Timeline</h2><ul>%22</ul>"
        "</body></html>")
        .arg(module.targetUrl().toHtmlEscaped(),
             QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm"),
             module.scopePreset().toHtmlEscaped(),
             QString::number(module.coverageScore()),
             operationalSummary.toHtmlEscaped(),
             workflowSummary.toHtmlEscaped(),
             featureHtml,
             QString::number(breakdown.value("auth").toInt()),
             QString::number(breakdown.value("form").toInt()),
             QString::number(breakdown.value("js").toInt()),
             QString::number(breakdown.value("secret").toInt()),
             QString::number(breakdown.value("admin").toInt()),
             QString::number(breakdown.value("upload").toInt()),
             QString::number(breakdown.value("delta").toInt()),
             QString::number(breakdown.value("protected").toInt()),
             QString::number(breakdown.value("missing").toInt()),
             QString::number(breakdown.value("render").toInt()),
             QString::number(breakdown.value("automation").toInt()),
             endpointHtml,
             parameterHtml,
             assetHtml,
             timelineHtml);
}
