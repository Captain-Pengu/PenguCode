#include "modules/recon/engine/reconwebinsights.h"

#include <QCoreApplication>
#include <QNetworkCookie>
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

bool containsFinding(const QList<ReconFindingCandidate> &findings, const QString &title)
{
    for (const ReconFindingCandidate &finding : findings) {
        if (finding.title == title) {
            return true;
        }
    }
    return false;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    bool ok = true;

    {
        QNetworkCookie insecureCookie("session", "abc");
        insecureCookie.setHttpOnly(false);
        insecureCookie.setSecure(false);

        const ReconWebAnalysis analysis = reconAnalyzeWebResponse({
            QUrl(QStringLiteral("https://example.com")),
            {
                {QByteArrayLiteral("Server"), QByteArrayLiteral("Apache/2.2.34")},
                {QByteArrayLiteral("X-Powered-By"), QByteArrayLiteral("PHP/5.6.40")},
                {QByteArrayLiteral("cf-ray"), QByteArrayLiteral("edge")}
            },
            {insecureCookie},
            QByteArrayLiteral("<html><title>Index of /</title> phpinfo() server api </html>"),
            200
        });

        ok &= expect(containsFinding(analysis.findings, QStringLiteral("CSP eksik")), QStringLiteral("missing CSP finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("HSTS eksik")), QStringLiteral("missing HSTS finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("WAF tespit edildi")), QStringLiteral("missing WAF finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("Sunucu surumu ifsa oluyor")), QStringLiteral("missing server disclosure finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("Guvensiz cookie")), QStringLiteral("missing insecure cookie finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("HttpOnly eksik")), QStringLiteral("missing httponly finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("Dizin listeleme izi")), QStringLiteral("missing directory listing finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("Bilgi ifsasi")), QStringLiteral("missing info disclosure finding"));
        ok &= expect(analysis.cveCandidates.size() >= 2, QStringLiteral("missing CVE candidates"));
        ok &= expect(analysis.observation.value(QStringLiteral("waf")).toString() == QStringLiteral("Cloudflare"),
                     QStringLiteral("missing waf observation"));
    }

    {
        const ReconTlsAnalysis analysis = reconAnalyzeTlsState({
            true,
            QDateTime::currentDateTimeUtc().addDays(-1),
            QSsl::TlsV1_0,
            {QStringLiteral("TLS_RSA_WITH_3DES_EDE_CBC_SHA")},
            QString(),
            QStringLiteral("Let's Encrypt")
        });

        ok &= expect(containsFinding(analysis.findings, QStringLiteral("TLS sertifikasi suresi dolmus")),
                     QStringLiteral("missing expired cert finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("Eski TLS protokolu")),
                     QStringLiteral("missing old tls finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("Zayif TLS sifre paketi")),
                     QStringLiteral("missing weak cipher finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("Sertifika subject eksik")),
                     QStringLiteral("missing subject finding"));
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("TLS gozlemi")),
                     QStringLiteral("missing issuer observation finding"));
    }

    {
        const ReconTlsAnalysis analysis = reconAnalyzeTlsState({
            false,
            {},
            QSsl::UnknownProtocol,
            {},
            QString(),
            QString()
        });
        ok &= expect(containsFinding(analysis.findings, QStringLiteral("TLS sertifikasi eksik")),
                     QStringLiteral("missing no-cert finding"));
    }

    if (!ok) {
        return 1;
    }

    QTextStream(stdout) << "[PASS] recon_web_tls_tests" << Qt::endl;
    return 0;
}
