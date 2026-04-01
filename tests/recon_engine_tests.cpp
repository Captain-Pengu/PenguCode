#include "modules/recon/engine/reconcoreutils.h"
#include "modules/recon/engine/reconreportbuilder.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QTextStream>

namespace {

void fail(const QString &message)
{
    QTextStream(stderr) << "[FAIL] " << message << Qt::endl;
}

bool expect(bool condition, const QString &message)
{
    if (!condition) {
        fail(message);
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    bool ok = true;

    {
        const ReconParsedTarget parsed = reconParseTarget(QStringLiteral("scanme.nmap.org"));
        ok &= expect(parsed.host == QStringLiteral("scanme.nmap.org"), QStringLiteral("target parser host failed"));
        ok &= expect(parsed.scheme == QStringLiteral("http") || parsed.scheme == QStringLiteral("https"),
                     QStringLiteral("target parser scheme inference failed"));
        ok &= expect(parsed.sanitized.contains(QStringLiteral("scanme.nmap.org")),
                     QStringLiteral("target parser sanitized url failed"));
    }

    {
        const ReconParsedTarget parsed = reconParseTarget(QStringLiteral("http://example.com/admin"));
        ok &= expect(parsed.host == QStringLiteral("example.com"), QStringLiteral("url parser host failed"));
        ok &= expect(parsed.scheme == QStringLiteral("http"), QStringLiteral("url parser scheme failed"));
        ok &= expect(parsed.sanitized.contains(QStringLiteral("/admin")), QStringLiteral("url parser path failed"));
    }

    ok &= expect(reconClampedSecurityScore(140) == 100, QStringLiteral("score clamp upper bound failed"));
    ok &= expect(reconClampedSecurityScore(-5) == 0, QStringLiteral("score clamp lower bound failed"));
    ok &= expect(reconClampedSecurityScore(77) == 77, QStringLiteral("score clamp passthrough failed"));

    ok &= expect(reconSeverityForPenalty(30) == QStringLiteral("high"), QStringLiteral("severity high mapping failed"));
    ok &= expect(reconSeverityForPenalty(12) == QStringLiteral("medium"), QStringLiteral("severity medium mapping failed"));
    ok &= expect(reconSeverityForPenalty(2) == QStringLiteral("low"), QStringLiteral("severity low mapping failed"));

    ok &= expect(reconProgressPercent(0, 0) == 0, QStringLiteral("progress zero stage failed"));
    ok &= expect(reconProgressPercent(10, 3) == 70, QStringLiteral("progress percentage failed"));

    {
        ScanReport report;
        report.sanitizedTarget = QStringLiteral("example.com");
        report.resolvedIp = QStringLiteral("93.184.216.34");
        report.findings << QVariantMap{{"severity", "high"}, {"title", "CSP eksik"}, {"description", "Baslik yok"}, {"category", "web"}};
        report.openPorts << QVariantMap{{"port", 443}, {"service", "https"}};
        report.dnsRecords << QVariantMap{{"type", "A"}, {"value", "93.184.216.34"}};

        ReconReportContext context;
        context.companyName = QStringLiteral("PenguFoce");
        context.clientName = QStringLiteral("Acme");
        context.testerName = QStringLiteral("Tester");
        context.classification = QStringLiteral("Internal");
        context.scopeSummary = QStringLiteral("Web ve DNS");
        context.spiderSnapshot = QVariantMap{
            {"coverageScore", 78},
            {"coverageSummary", QStringLiteral("Coverage iyi")},
            {"endpoints", QVariantList{QVariantMap{{"kind", "link"}, {"url", "https://example.com/login"}}}}
        };

        const QString html = buildReconReportHtml(context, report, 64);
        ok &= expect(html.contains(QStringLiteral("PenguFoce Sizma Testi ve Kesif Raporu")),
                     QStringLiteral("report html title missing"));
        ok &= expect(html.contains(QStringLiteral("CSP eksik")), QStringLiteral("report html finding missing"));
        ok &= expect(html.contains(QStringLiteral("Coverage iyi")), QStringLiteral("report html spider summary missing"));
    }

    {
        const QVariantMap guidance = reconDeveloperGuidanceForFinding(QStringLiteral("TLS sorunu"), QStringLiteral("HSTS eksik"));
        ok &= expect(!guidance.value(QStringLiteral("action")).toString().isEmpty(), QStringLiteral("guidance action missing"));
        const QString detail = buildReconFindingDetailHtml(QStringLiteral("high"),
                                                           QStringLiteral("TLS sorunu"),
                                                           QStringLiteral("HSTS eksik"),
                                                           QStringLiteral("Not"));
        ok &= expect(detail.contains(QStringLiteral("Analist Notu")), QStringLiteral("finding detail html note missing"));
    }

    if (!ok) {
        return 1;
    }

    QTextStream(stdout) << "[PASS] recon_engine_tests" << Qt::endl;
    return 0;
}
