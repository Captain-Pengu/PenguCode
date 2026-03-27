#include "modules/recon/engine/reconreportbuilder.h"

#include <QDate>
#include <QDateTime>
#include <QRegularExpression>
#include <QSet>

namespace {

QString sanitizedFileStem(QString text)
{
    text = text.trimmed();
    if (text.isEmpty()) {
        return QStringLiteral("pengufoce-resmi-pentest-raporu");
    }

    text.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9]+")), QStringLiteral("-"));
    while (text.contains(QStringLiteral("--"))) {
        text.replace(QStringLiteral("--"), QStringLiteral("-"));
    }
    text.remove(QRegularExpression(QStringLiteral("^-+|-+$")));
    return text.isEmpty() ? QStringLiteral("pengufoce-resmi-pentest-raporu") : text.toLower();
}

QString renderList(const QVariantList &rows,
                   const std::function<QString(const QVariantMap &)> &formatter,
                   const QString &emptyText)
{
    QString html;
    for (const QVariant &value : rows) {
        html += formatter(value.toMap());
    }
    return html.isEmpty() ? QStringLiteral("<li>%1</li>").arg(emptyText.toHtmlEscaped()) : html;
}

QString renderScalarList(const QVariantList &rows, const QString &emptyText)
{
    QString html;
    for (const QVariant &value : rows) {
        html += QStringLiteral("<li>%1</li>").arg(value.toString().toHtmlEscaped());
    }
    return html.isEmpty() ? QStringLiteral("<li>%1</li>").arg(emptyText.toHtmlEscaped()) : html;
}

} // namespace

ScanReport reconScanReportFromVariantMap(const QVariantMap &map)
{
    ScanReport report;
    report.originalTarget = map.value("originalTarget").toString();
    report.sanitizedTarget = map.value("sanitizedTarget").toString();
    report.host = map.value("host").toString();
    report.scheme = map.value("scheme").toString();
    report.resolvedIp = map.value("resolvedIp").toString();
    report.openPorts = map.value("openPorts").toList();
    report.dnsRecords = map.value("dnsRecords").toList();
    report.findings = map.value("findings").toList();
    report.webObservations = map.value("webObservations").toList();
    report.osintObservations = map.value("osintObservations").toList();
    report.subdomains = map.value("subdomains").toList();
    report.archivedUrls = map.value("archivedUrls").toList();
    report.jsFindings = map.value("jsFindings").toList();
    report.cveMatches = map.value("cveMatches").toList();
    report.whoisInfo = map.value("whoisInfo").toMap();
    report.spiderEndpoints = map.value("spiderEndpoints").toList();
    report.spiderParameters = map.value("spiderParameters").toList();
    report.spiderAssets = map.value("spiderAssets").toList();
    return report;
}

QString reconCorporateReportFileName(const QString &company, const QString &target, const QString &extension)
{
    return QString("%1-sizma-testi-raporu-%2-v1.0-%3.%4")
        .arg(sanitizedFileStem(company),
             sanitizedFileStem(target),
             QDate::currentDate().toString("yyyyMMdd"),
             extension);
}

QVariantMap reconDeveloperGuidanceForFinding(const QString &title, const QString &description)
{
    QVariantMap map{
        {"riskNames", QObject::tr("Bilgi toplama, temel maruziyet analizi")},
        {"impact", QObject::tr("Bu bulgu saldiri yuzeyini genisletebilir veya guvenlik durusunu zayiflatabilir.")},
        {"attackerPlay", QObject::tr("Bilgi toplama, maruziyet haritalama ve sonraki asama erisim denemeleri icin kullanilabilir.")},
        {"action", QObject::tr("Servis ihtiyaci, maruziyet ve koruma kontrolleri birlikte degerlendirilerek duzeltici aksiyon alinmalidir.")},
        {"developerNotes", QObject::tr("Ilgili servis veya uygulama konfigurasyonu kod, reverse proxy, deployment ve altyapi katmanlarinda birlikte incelenmelidir.")}
    };

    if (title.contains("TLS", Qt::CaseInsensitive) || title.contains("HSTS", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("Ortadaki adam saldirisi, TLS dusurme, oturum gozetleme");
        map["impact"] = QObject::tr("Iletisim gizliligi ve butunlugu zayiflayabilir.");
        map["attackerPlay"] = QObject::tr("Aradaki adam saldirilari, sifreleme dusurme ve oturum/cookie gozetleme denenebilir.");
        map["action"] = QObject::tr("TLS konfigrasyonu guncellenmeli ve koruyucu basliklar etkinlestirilmelidir.");
        map["developerNotes"] = QObject::tr("Load balancer, reverse proxy ve web sunucusu birlikte sertlestirilmelidir.");
    } else if (title.contains("SPF", Qt::CaseInsensitive) || title.contains("DMARC", Qt::CaseInsensitive) || title.contains("MX", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("E-posta sahteciligi, phishing, alan adi itibari istismari");
        map["action"] = QObject::tr("DNS politika kayitlari kurumsal posta mimarisine gore duzenlenmelidir.");
    } else if (title.contains("cookie", Qt::CaseInsensitive) || title.contains("HttpOnly", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("Oturum cerezinin calinmasi, istemci tarafli script istismari");
        map["action"] = QObject::tr("Kimlik dogrulama cerezlerinde HttpOnly, Secure ve uygun SameSite bayraklari zorunlu hale getirilmelidir.");
    } else if (title.contains("OSINT", Qt::CaseInsensitive) || title.contains("sizinti", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("Kimlik bilgisi doldurma, hedefli phishing, parola tekrar kullanim istismari");
        map["action"] = QObject::tr("Harici gorunurluk ve sizinti kayitlari olay mudahalesi ile ele alinmalidir.");
    }

    if (description.contains("WAF", Qt::CaseInsensitive) || title.contains("WAF", Qt::CaseInsensitive)) {
        map["developerNotes"] = QObject::tr("WAF tespiti tek basina acik degildir; ters vekil ve rate-limit katmanlariyla birlikte okunmalidir.");
    }

    return map;
}

QString buildReconFindingDetailHtml(const QString &severity,
                                    const QString &title,
                                    const QString &description,
                                    const QString &analystNote)
{
    const QString normalized = severity.trimmed().toLower();
    const QVariantMap guidance = reconDeveloperGuidanceForFinding(title, description);
    const QString severityColor = normalized.contains("yuksek") ? "#d14343"
                                : normalized.contains("orta") ? "#d08b2e"
                                : normalized.contains("dusuk") ? "#5c7cfa"
                                : "#7b8794";

    return QString(
               "<html><body style='font-family:Bahnschrift;padding:10px;font-size:11pt;'>"
               "<h2 style='margin:0 0 8px 0;'>%1</h2>"
               "<p><b>Risk Seviyesi:</b> <span style='color:%2;font-weight:700;'>%3</span></p>"
               "<p><b>Olasi Risk Adlari:</b> %4</p>"
               "<h3>Neden Var?</h3><p>%5</p>"
               "<h3>Muhtemel Etki</h3><p>%6</p>"
               "<h3>Bu Acik Uzerinden Neler Yapilabilir?</h3><p>%7</p>"
               "<h3>Yazilim Ekibi Icin Cozum Rehberi</h3><p>%8</p>"
               "<h3>Onerilen Aksiyon</h3><p>%9</p>"
               "<h3>Analist Notu</h3><p>%10</p>"
               "</body></html>")
        .arg(title.toHtmlEscaped(),
             severityColor,
             severity.toUpper().toHtmlEscaped(),
             guidance.value("riskNames").toString().toHtmlEscaped(),
             description.toHtmlEscaped(),
             guidance.value("impact").toString().toHtmlEscaped(),
             guidance.value("attackerPlay").toString().toHtmlEscaped(),
             guidance.value("developerNotes").toString().toHtmlEscaped(),
             guidance.value("action").toString().toHtmlEscaped(),
             analystNote.isEmpty() ? QObject::tr("Bu bulgu icin manuel analist notu eklenmedi.").toHtmlEscaped()
                                   : analystNote.toHtmlEscaped());
}

int reconSeverityRank(const QString &severity)
{
    const QString normalized = severity.trimmed().toLower();
    if (normalized == "high" || normalized == QObject::tr("yuksek")) return 4;
    if (normalized == "medium" || normalized == QObject::tr("orta")) return 3;
    if (normalized == "low" || normalized == QObject::tr("dusuk")) return 2;
    return 1;
}

QString buildReconDiffSummary(const QVariantMap &currentReport, const QVariantMap &baselineReport)
{
    if (currentReport.isEmpty() || baselineReport.isEmpty()) {
        return QObject::tr("Karsilastirma icin iki recon oturumu da hazir olmali.");
    }

    const QVariantList currentPorts = currentReport.value("openPorts").toList();
    const QVariantList baselinePorts = baselineReport.value("openPorts").toList();
    const QVariantList currentSubs = currentReport.value("subdomains").toList();
    const QVariantList baselineSubs = baselineReport.value("subdomains").toList();
    const QVariantList currentFindings = currentReport.value("findings").toList();
    const QVariantList baselineFindings = baselineReport.value("findings").toList();

    auto portsToSet = [](const QVariantList &ports) {
        QSet<QString> set;
        for (const QVariant &value : ports) {
            const QVariantMap row = value.toMap();
            set.insert(QString("%1/%2").arg(row.value("port").toString(), row.value("service").toString()));
        }
        return set;
    };

    const QSet<QString> currentPortSet = portsToSet(currentPorts);
    const QSet<QString> baselinePortSet = portsToSet(baselinePorts);
    QSet<QString> currentSubSet;
    QSet<QString> baselineSubSet;
    for (const QVariant &value : currentSubs) currentSubSet.insert(value.toString());
    for (const QVariant &value : baselineSubs) baselineSubSet.insert(value.toString());
    QSet<QString> currentFindingSet;
    QSet<QString> baselineFindingSet;
    for (const QVariant &value : currentFindings) {
        const QVariantMap row = value.toMap();
        currentFindingSet.insert(QString("%1|%2").arg(row.value("severity").toString(), row.value("title").toString()));
    }
    for (const QVariant &value : baselineFindings) {
        const QVariantMap row = value.toMap();
        baselineFindingSet.insert(QString("%1|%2").arg(row.value("severity").toString(), row.value("title").toString()));
    }

    const QString newPorts = QStringList((currentPortSet - baselinePortSet).values()).join(" | ");
    const QString lostPorts = QStringList((baselinePortSet - currentPortSet).values()).join(" | ");
    const QString newSubs = QStringList((currentSubSet - baselineSubSet).values()).join(" | ");
    const QString newFindings = QStringList((currentFindingSet - baselineFindingSet).values()).join(" | ");

    return QObject::tr("Karsilastirma: %1 -> yeni portlar: %2 | kaybolan portlar: %3 | yeni subdomain: %4 | yeni bulgular: %5")
        .arg(baselineReport.value("sanitizedTarget").toString(),
             newPorts.isEmpty() ? QObject::tr("-") : newPorts,
             lostPorts.isEmpty() ? QObject::tr("-") : lostPorts,
             newSubs.isEmpty() ? QObject::tr("-") : newSubs,
             newFindings.isEmpty() ? QObject::tr("-") : newFindings);
}

QString buildReconReportHtml(const ReconReportContext &context, const ScanReport &report, int securityScore)
{
    const QString companyName = context.companyName.isEmpty() ? QStringLiteral("PenguFoce Security Lab") : context.companyName;
    const QString clientName = context.clientName.isEmpty() ? QObject::tr("Belirtilmedi") : context.clientName;
    const QString testerName = context.testerName.isEmpty() ? QObject::tr("Operator") : context.testerName;
    const QString classification = context.classification.isEmpty() ? QObject::tr("Kurum Ici") : context.classification;
    const QString scopeSummary = context.scopeSummary.isEmpty()
        ? QObject::tr("DNS, web guvenligi, TLS, OSINT ve acik servis degerlendirmesi")
        : context.scopeSummary;
    const QVariantMap &spiderSnapshot = context.spiderSnapshot;
    const int spiderCoverageScore = spiderSnapshot.value("coverageScore", 0).toInt();
    const QString spiderCoverageSummary = spiderSnapshot.value("coverageSummary").toString();

    auto riskLevel = [securityScore]() {
        if (securityScore >= 85) return QStringLiteral("Dusuk");
        if (securityScore >= 65) return QStringLiteral("Orta");
        return QStringLiteral("Yuksek");
    };

    QString findingsHtml;
    QString detailedFindingsHtml;
    for (const QVariant &value : report.findings) {
        const QVariantMap finding = value.toMap();
        const QString title = finding.value("title").toString();
        const QString description = finding.value("description").toString();
        const QVariantMap guidance = reconDeveloperGuidanceForFinding(title, description);
        findingsHtml += QString("<tr><td>%1</td><td>%2</td><td>%3</td><td>%4</td></tr>")
            .arg(finding.value("severity").toString().toUpper(),
                 title.toHtmlEscaped(),
                 description.toHtmlEscaped(),
                 finding.value("category").toString().toHtmlEscaped());
        detailedFindingsHtml += QString("<div style='margin:0 0 18px 0; padding:12px 14px; border:1px solid #cfd6df; border-radius:8px;'><h3 style='margin:0 0 8px 0;'>%1</h3><p><b>Acigin Teknik Nedeni:</b> %2</p><p><b>Olasi Riskler:</b> %3</p><p><b>Saldirgan Ne Yapabilir?</b> %4</p><p><b>Yazilim Ekibi Icin Uygulama Notu:</b> %5</p><p><b>Kapatma ve Iyilestirme Adimi:</b> %6</p></div>")
            .arg(title.toHtmlEscaped(),
                 description.toHtmlEscaped(),
                 guidance.value("riskNames").toString().toHtmlEscaped(),
                 guidance.value("attackerPlay").toString().toHtmlEscaped(),
                 guidance.value("developerNotes").toString().toHtmlEscaped(),
                 guidance.value("action").toString().toHtmlEscaped());
    }
    if (findingsHtml.isEmpty()) {
        findingsHtml = "<tr><td colspan='4'>Kritik bulgu kaydi olusmadi.</td></tr>";
        detailedFindingsHtml = "<p>Detaylandirilacak teknik bulgu kaydi olusmadi.</p>";
    }

    const QString portHtml = renderList(report.openPorts, [](const QVariantMap &row) {
        return QString("<li>%1 / %2</li>").arg(row.value("port").toString().toHtmlEscaped(), row.value("service").toString().toHtmlEscaped());
    }, QObject::tr("Acik servis tespit edilmedi."));
    const QString dnsHtml = renderList(report.dnsRecords, [](const QVariantMap &row) {
        return QString("<li><b>%1</b>: %2</li>").arg(row.value("type").toString().toHtmlEscaped(), row.value("value").toString().toHtmlEscaped());
    }, QObject::tr("DNS kaydi toplanamadi."));
    const QString webHtml = renderList(report.webObservations, [](const QVariantMap &row) {
        return QString("<li>%1 - HTTP %2 - Sunucu: %3 - Surum izi: %4</li>")
            .arg(row.value("url").toString().toHtmlEscaped(),
                 row.value("status").toString().toHtmlEscaped(),
                 row.value("server").toString().toHtmlEscaped(),
                 row.value("version").toString().toHtmlEscaped());
    }, QObject::tr("Web guvenligi verisi toplanamadi."));
    const QString osintHtml = renderList(report.osintObservations, [](const QVariantMap &row) {
        return QString("<li>%1 - %2</li>")
            .arg(row.value("source").toString().toHtmlEscaped(),
                 row.value("details").toString().toHtmlEscaped());
    }, QObject::tr("OSINT veya sizinti kaydi bulunmadi."));
    const QString subdomainHtml = renderScalarList(report.subdomains, QObject::tr("Dogrulanmis alt alan adi kaydi bulunmadi."));
    const QString archiveHtml = renderScalarList(report.archivedUrls, QObject::tr("Wayback veya gizli endpoint kaydi bulunmadi."));
    const QString jsHtml = renderList(report.jsFindings, [](const QVariantMap &row) {
        return QString("<li>%1 - %2 (%3)</li>")
            .arg(row.value("type").toString().toHtmlEscaped(),
                 row.value("value").toString().toHtmlEscaped(),
                 row.value("source").toString().toHtmlEscaped());
    }, QObject::tr("JavaScript analizi bulgusu uretilmedi."));
    const QString cveHtml = renderList(report.cveMatches, [](const QVariantMap &row) {
        return QString("<li>%1 %2 - %3 - %4</li>")
            .arg(row.value("product").toString().toHtmlEscaped(),
                 row.value("version").toString().toHtmlEscaped(),
                 row.value("cve").toString().toHtmlEscaped(),
                 row.value("summary").toString().toHtmlEscaped());
    }, QObject::tr("Yerel CVE eslesmesi bulunmadi."));
    const QString spiderEndpointHtml = renderList(spiderSnapshot.value("endpoints").toList(), [](const QVariantMap &row) {
        return QString("<li><b>%1</b> - %2</li>")
            .arg(row.value("kind").toString().toHtmlEscaped(),
                 row.value("url").toString().toHtmlEscaped());
    }, QObject::tr("Spider endpoint kaydi bulunmadi."));

    return QString(
               "<html><body style='font-family:Bahnschrift;font-size:12pt;line-height:1.45;padding:0;color:#171a20;'>"
               "<div style='border-bottom:2px solid #8f1732;padding-bottom:12px;margin-bottom:18px;'>"
               "<h1 style='margin:0;font-size:24pt;'>PenguFoce Sizma Testi ve Kesif Raporu</h1>"
               "<p style='margin:8px 0 0 0;font-size:11pt;'><b>Hazirlayan Kurum:</b> %1<br><b>Musteri:</b> %2<br><b>Test Uzmani:</b> %3<br><b>Siniflandirma:</b> %4<br><b>Rapor Tarihi:</b> %5</p>"
               "</div>"
               "<h2>1. Yonetici Ozeti</h2><p>Guvenlik puani <b>%6/100</b>, genel risk seviyesi <b>%7</b>.</p>"
               "<h2>2. Kapsam</h2><p><b>Hedef:</b> %8<br><b>Cozumlenen IP:</b> %9<br><b>Kapsam:</b> %10</p>"
               "<h2>3. Acik Servisler</h2><ul>%11</ul>"
               "<h2>4. DNS ve Politika Gozlemleri</h2><ul>%12</ul>"
               "<h2>5. Web ve TLS Gozlemleri</h2><ul>%13</ul>"
               "<h2>6. OSINT ve Sizinti Gozlemleri</h2><ul>%14</ul>"
               "<h2>7. Alt Alan Adi Sonuclari</h2><ul>%15</ul>"
               "<h2>8. Wayback ve Gizli Endpoint Gozlemleri</h2><ul>%16</ul>"
               "<h2>9. JavaScript Analizi</h2><ul>%17</ul>"
               "<h2>10. CVE ve Surum Eslestirmeleri</h2><ul>%18</ul>"
               "<h2>11. Spider Ozet</h2><p>Coverage: <b>%19/100</b> - %20</p><ul>%21</ul>"
               "<h2>12. Detayli Bulgu Tablosu</h2><table border='1' cellspacing='0' cellpadding='8' width='100%%' style='font-size:10.5pt;border-collapse:collapse;'><tr><th>Oncelik</th><th>Baslik</th><th>Aciklama</th><th>Kategori</th></tr>%22</table>"
               "<h2>13. Teknik Bulgular</h2>%23"
               "</body></html>")
        .arg(companyName.toHtmlEscaped(),
             clientName.toHtmlEscaped(),
             testerName.toHtmlEscaped(),
             classification.toHtmlEscaped(),
             QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm"),
             QString::number(securityScore),
             riskLevel(),
             report.sanitizedTarget.toHtmlEscaped(),
             report.resolvedIp.toHtmlEscaped(),
             scopeSummary.toHtmlEscaped(),
             portHtml,
             dnsHtml,
             webHtml,
             osintHtml,
             subdomainHtml,
             archiveHtml,
             jsHtml,
             cveHtml,
             QString::number(spiderCoverageScore),
             spiderCoverageSummary.toHtmlEscaped(),
             spiderEndpointHtml,
             findingsHtml,
             detailedFindingsHtml);
}
