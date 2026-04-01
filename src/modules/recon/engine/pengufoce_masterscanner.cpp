#include "pengufoce_masterscanner.h"

#include "core/logging/logger.h"
#include "modules/recon/engine/reconcoreutils.h"
#include "modules/recon/engine/reconwebinsights.h"

#include <QDateTime>
#include <QDnsLookup>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkCookie>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSharedPointer>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QTcpSocket>
#include <QUrlQuery>

namespace {

const QList<int> kCommonPorts = {
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3128, 3306, 3389, 5000,
    5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017
};

const QMap<int, QString> kKnownServices = {
    {21, "ftp"}, {22, "ssh"}, {25, "smtp"}, {53, "dns"}, {80, "http"},
    {110, "pop3"}, {143, "imap"}, {443, "https"}, {465, "smtps"},
    {587, "submission"}, {993, "imaps"}, {995, "pop3s"}, {1433, "mssql"},
    {1521, "oracle"}, {2049, "nfs"}, {2375, "docker"}, {3000, "node"},
    {3128, "proxy"}, {3306, "mysql"}, {3389, "rdp"}, {5000, "http-alt"},
    {5432, "postgresql"}, {5900, "vnc"}, {5985, "winrm"}, {5986, "winrm-tls"},
    {6379, "redis"}, {8080, "http-alt"}, {8443, "https-alt"}, {9200, "elasticsearch"},
    {27017, "mongodb"}
};

const QStringList kCommonPaths = {
    "/", "/admin", "/admin/login", "/backup.zip", "/config.php.bak", "/.env", "/.git/config",
    "/old", "/test", "/debug", "/phpinfo.php", "/wp-login.php", "/server-status"
};

QString extractVersion(const QByteArray &payload)
{
    static const QRegularExpression regex(QStringLiteral("((?:\\d+\\.){1,3}\\d+[a-z0-9\\-]*)"),
                                          QRegularExpression::CaseInsensitiveOption);
    const auto match = regex.match(QString::fromUtf8(payload));
    return match.hasMatch() ? match.captured(1) : QString();
}

QString trimBanner(const QByteArray &payload)
{
    QString text = QString::fromUtf8(payload).simplified();
    if (text.size() > 120) {
        text = text.left(120);
    }
    return text;
}

QString guessService(int port, const QString &banner)
{
    const QString lower = banner.toLower();
    if (lower.contains("ssh")) return "ssh";
    if (lower.contains("smtp")) return "smtp";
    if (lower.contains("imap")) return "imap";
    if (lower.contains("pop3")) return "pop3";
    if (lower.contains("mysql")) return "mysql";
    if (lower.contains("postgres")) return "postgresql";
    if (lower.contains("redis")) return "redis";
    if (lower.contains("mongodb")) return "mongodb";
    if (lower.contains("elasticsearch")) return "elasticsearch";
    if (lower.contains("http")) return port == 443 || port == 8443 ? "https" : "http";
    return kKnownServices.value(port, "open");
}

bool looksLikeDomain(const QString &host)
{
    QHostAddress address;
    return !host.isEmpty() && !address.setAddress(host) && host.contains('.');
}

QString normalizedSubdomain(const QString &host)
{
    QString value = host.trimmed().toLower();
    if (value.startsWith("*.")) {
        value.remove(0, 2);
    }
    return value;
}

QStringList extractInterestingUrls(const QString &text)
{
    QStringList urls;
    static const QRegularExpression regex(QStringLiteral("(https?://[A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+)"));
    auto it = regex.globalMatch(text);
    while (it.hasNext()) {
        const QString url = it.next().captured(1).trimmed();
        if (!url.isEmpty()) {
            urls << url;
        }
    }
    urls.removeDuplicates();
    return urls;
}

QVariantMap cveHintForService(const QString &product, const QString &version)
{
    const QString key = QString("%1 %2").arg(product.toLower(), version.toLower()).trimmed();
    if (key.contains("apache 2.4.49")) {
        return {{"cve", "CVE-2021-41773"}, {"summary", "Apache path traversal / code execution riski"}, {"severity", "high"}};
    }
    if (key.contains("apache 2.4.50")) {
        return {{"cve", "CVE-2021-42013"}, {"summary", "Apache path traversal / RCE riski"}, {"severity", "high"}};
    }
    if (key.contains("openssl 1.0.1")) {
        return {{"cve", "CVE-2014-0160"}, {"summary", "Heartbleed riski"}, {"severity", "high"}};
    }
    if (key.contains("nginx 1.14")) {
        return {{"cve", "CVE-2019-20372"}, {"summary", "Eski nginx surumu bilinen zafiyetlerle iliskili olabilir"}, {"severity", "medium"}};
    }
    if (key.contains("php 5.")) {
        return {{"cve", "LEGACY-PHP-5"}, {"summary", "Destek disi PHP 5 serisi, birden fazla bilinen RCE ve bilgi ifsasi riski tasir"}, {"severity", "high"}};
    }
    return {};
}

QByteArray portProbe(int port)
{
    if (port == 80 || port == 443 || port == 3000 || port == 5000 || port == 8080 || port == 8443) {
        return QByteArrayLiteral("HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: PenguFoce\r\n\r\n");
    }
    if (port == 25 || port == 465 || port == 587) {
        return QByteArrayLiteral("EHLO pengufoce.local\r\n");
    }
    if (port == 21) {
        return QByteArrayLiteral("FEAT\r\n");
    }
    if (port == 110 || port == 995) {
        return QByteArrayLiteral("CAPA\r\n");
    }
    if (port == 143 || port == 993) {
        return QByteArrayLiteral("a1 CAPABILITY\r\n");
    }
    if (port == 6379) {
        return QByteArrayLiteral("PING\r\n");
    }
    return {};
}

class PortScanTask final : public QObject, public QRunnable
{
    Q_OBJECT

public:
    PortScanTask(QString host, QList<int> ports)
        : m_host(std::move(host))
        , m_ports(std::move(ports))
    {
        setAutoDelete(true);
    }

signals:
    void taskFinished(const QVariantList &openPorts);

protected:
    void run() override
    {
        QVariantList openPorts;
        for (const int port : m_ports) {
            QTcpSocket socket;
            socket.connectToHost(m_host, static_cast<quint16>(port));
            if (!socket.waitForConnected(450)) {
                socket.abort();
                continue;
            }

            QString banner = trimBanner(socket.readAll());
            if (banner.isEmpty()) {
                const QByteArray probe = portProbe(port);
                if (!probe.isEmpty()) {
                    socket.write(probe);
                    socket.flush();
                    if (socket.waitForReadyRead(220)) {
                        banner = trimBanner(socket.readAll());
                    }
                }
            }

            openPorts << QVariantMap{
                {"port", port},
                {"service", guessService(port, banner)},
                {"banner", banner}
            };
            socket.disconnectFromHost();
        }
        emit taskFinished(openPorts);
    }

private:
    QString m_host;
    QList<int> m_ports;
};

class WhoisTask final : public QObject, public QRunnable
{
    Q_OBJECT

public:
    explicit WhoisTask(QString host)
        : m_host(std::move(host))
    {
        setAutoDelete(true);
    }

signals:
    void taskFinished(const QVariantMap &data);

protected:
    void run() override
    {
        QVariantMap data{{"domain", m_host}};
        auto queryWhoisServer = [](const QString &server, const QString &query) -> QString {
            QTcpSocket socket;
            socket.connectToHost(server, 43);
            if (!socket.waitForConnected(3000)) {
                return {};
            }
            socket.write((query + "\r\n").toUtf8());
            socket.flush();
            QByteArray payload;
            while (socket.waitForReadyRead(1500)) {
                payload += socket.readAll();
            }
            payload += socket.readAll();
            return QString::fromUtf8(payload);
        };

        const QString ianaResponse = queryWhoisServer(QStringLiteral("whois.iana.org"), m_host);
        QString referServer = QStringLiteral("whois.iana.org");
        if (!ianaResponse.isEmpty()) {
            const QRegularExpression referRegex(QStringLiteral("refer:\\s*(\\S+)"), QRegularExpression::CaseInsensitiveOption);
            const auto referMatch = referRegex.match(ianaResponse);
            if (referMatch.hasMatch()) {
                referServer = referMatch.captured(1).trimmed();
            }
        }

        data.insert("registry", referServer);
        QString detailedResponse = referServer == QStringLiteral("whois.iana.org")
                                       ? ianaResponse
                                       : queryWhoisServer(referServer, m_host);
        if (detailedResponse.isEmpty()) {
            detailedResponse = ianaResponse;
        }

        auto captureField = [&detailedResponse](const QStringList &patterns) {
            for (const QString &pattern : patterns) {
                const QRegularExpression regex(pattern, QRegularExpression::CaseInsensitiveOption);
                const auto match = regex.match(detailedResponse);
                if (match.hasMatch()) {
                    return match.captured(1).trimmed();
                }
            }
            return QString();
        };

        QStringList nameServers;
        const QRegularExpression nsRegex(QStringLiteral("^\\s*Name Server:\\s*(.+)$"),
                                         QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);
        auto nsIt = nsRegex.globalMatch(detailedResponse);
        while (nsIt.hasNext()) {
            const QString ns = nsIt.next().captured(1).trimmed();
            if (!ns.isEmpty() && !nameServers.contains(ns, Qt::CaseInsensitive)) {
                nameServers << ns;
            }
        }

        data.insert("registrar", captureField({
            QStringLiteral("^\\s*Registrar:\\s*(.+)$"),
            QStringLiteral("^\\s*Sponsoring Registrar:\\s*(.+)$"),
            QStringLiteral("^\\s*registrar-name:\\s*(.+)$")
        }));
        data.insert("created", captureField({
            QStringLiteral("^\\s*Creation Date:\\s*(.+)$"),
            QStringLiteral("^\\s*Created On:\\s*(.+)$"),
            QStringLiteral("^\\s*Created:\\s*(.+)$"),
            QStringLiteral("^\\s*Registered On:\\s*(.+)$")
        }));
        data.insert("updated", captureField({
            QStringLiteral("^\\s*Updated Date:\\s*(.+)$"),
            QStringLiteral("^\\s*Last Updated On:\\s*(.+)$"),
            QStringLiteral("^\\s*Changed:\\s*(.+)$")
        }));
        data.insert("expiry", captureField({
            QStringLiteral("^\\s*Registry Expiry Date:\\s*(.+)$"),
            QStringLiteral("^\\s*Registrar Registration Expiration Date:\\s*(.+)$"),
            QStringLiteral("^\\s*Expiry Date:\\s*(.+)$"),
            QStringLiteral("^\\s*Expiration Date:\\s*(.+)$"),
            QStringLiteral("^\\s*Expires On:\\s*(.+)$")
        }));
        data.insert("status", captureField({
            QStringLiteral("^\\s*Domain Status:\\s*(.+)$"),
            QStringLiteral("^\\s*Status:\\s*(.+)$")
        }));
        data.insert("nameServers", nameServers);
        data.insert("raw", detailedResponse.left(2500));
        emit taskFinished(data);
    }

private:
    QString m_host;
};

} // namespace

PenguFoceMasterScanner::PenguFoceMasterScanner(QObject *parent)
    : QObject(parent)
    , m_networkAccessManager(new QNetworkAccessManager(this))
{
    qRegisterMetaType<ScanReport>("ScanReport");
    qRegisterMetaType<ScanFinding>("ScanFinding");
    m_threadPool.setMaxThreadCount(12);
}

PenguFoceMasterScanner::~PenguFoceMasterScanner()
{
    stop();
    m_threadPool.waitForDone();
}

void PenguFoceMasterScanner::setLogger(Logger *logger)
{
    m_logger = logger;
}

void PenguFoceMasterScanner::startScan(const QString &target, const QUrl &osintEndpoint)
{
    stop();
    resetScanState();
    m_currentTarget = parseTarget(target);
    m_report.originalTarget = target;
    m_report.sanitizedTarget = m_currentTarget.sanitized;
    m_report.host = m_currentTarget.host;
    m_report.scheme = m_currentTarget.scheme;
    m_osintEndpoint = osintEndpoint;

    if (m_currentTarget.host.isEmpty()) {
        addFinding("high", "Gecersiz hedef", "Hedef gecerli bir alan adi, IP veya URL olarak ayrisamadi", "input", 40);
        emit scanFinished(m_report, calculateSecurityScore());
        return;
    }

    emit statusMessage(QString("Ana tarama baslatildi: %1").arg(m_currentTarget.sanitized));
    if (m_logger) {
        m_logger->info("master_scanner", QString("Tek tus taramasi baslatildi: %1").arg(m_currentTarget.sanitized));
    }

    registerStageStarted();
    emit statusMessage(QString("DNS cozumleme ve port tarama plani olusturuluyor: %1").arg(m_currentTarget.host));
    QHostInfo::lookupHost(m_currentTarget.host, this, &PenguFoceMasterScanner::handleResolvedHost);

    if (shouldScanWeb()) {
        registerStageStarted();
        emit statusMessage(QString("Web guvenligi analizi gonderiliyor: %1").arg(m_currentTarget.url.toString()));
        QNetworkRequest request(m_currentTarget.url);
        request.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce/0.1");
        request.setTransferTimeout(6000);
        QNetworkReply *webReply = m_networkAccessManager->get(request);
        connect(webReply, &QNetworkReply::finished, this, &PenguFoceMasterScanner::handleWebReply);
    }

    registerStageStarted();
    emit statusMessage(QString("DNS kayitlari toplanmaya baslandi: %1").arg(m_currentTarget.host));
    startDnsRecon(m_currentTarget.host);

    if (isDomainTarget()) {
        registerStageStarted();
        emit statusMessage(QString("Alt alan adi kesfi baslatildi: %1").arg(m_currentTarget.host));
        startSubdomainRecon(m_currentTarget.host);

        registerStageStarted();
        emit statusMessage(QString("Wayback URL arsivi sorgulaniyor: %1").arg(m_currentTarget.host));
        startWaybackRecon(m_currentTarget.host);

        registerStageStarted();
        emit statusMessage(QString("Whois bilgileri toplanmaya baslandi: %1").arg(m_currentTarget.host));
        startWhoisTask(m_currentTarget.host);
    }

    if (m_osintEndpoint.isValid() && !m_osintEndpoint.isEmpty()) {
        registerStageStarted();
        emit statusMessage(QString("OSINT ucnokta sorgusu gonderiliyor: %1").arg(m_currentTarget.host));
        startOsintTask(m_currentTarget.host);
    }

    if (shouldScanWeb()) {
        registerStageStarted();
        emit statusMessage(QString("Dizin ve dosya fuzzing baslatildi: %1").arg(m_currentTarget.url.toString()));
        startDirectoryFuzzing(m_currentTarget.url);

        registerStageStarted();
        emit statusMessage(QString("CMS ve JavaScript analizi baslatildi: %1").arg(m_currentTarget.url.toString()));
        startTechnologyRecon(m_currentTarget.url);
    }
}

void PenguFoceMasterScanner::stop()
{
    m_cancelled = true;
}

void PenguFoceMasterScanner::handleResolvedHost(const QHostInfo &info)
{
    if (m_cancelled) {
        registerStageFinished();
        return;
    }

    QString resolvedIp;
    for (const QHostAddress &address : info.addresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) {
            resolvedIp = address.toString();
            break;
        }
    }

    if (resolvedIp.isEmpty()) {
        addFinding("high", "DNS cozumleme basarisiz", info.errorString().isEmpty() ? "IPv4 adresi cozumlenemedi" : info.errorString(), "network", 35);
        registerStageFinished();
        return;
    }

    m_report.resolvedIp = resolvedIp;
    emit statusMessage(QString("IPv4 adresi cozumlendi: %1").arg(resolvedIp));

    const int chunkSize = 6;
    for (int start = 0; start < kCommonPorts.size(); start += chunkSize) {
        QList<int> chunk;
        for (int i = start; i < qMin(start + chunkSize, kCommonPorts.size()); ++i) {
            chunk << kCommonPorts.at(i);
        }
        registerStageStarted();
        auto *task = new PortScanTask(resolvedIp, chunk);
        connect(task, &PortScanTask::taskFinished, this, &PenguFoceMasterScanner::handlePortTaskResult, Qt::QueuedConnection);
        m_threadPool.start(task);
    }

    registerStageFinished();
}

void PenguFoceMasterScanner::handlePortTaskResult(const QVariantList &openPorts)
{
    if (!m_cancelled) {
        for (const QVariant &value : openPorts) {
            const QVariantMap row = value.toMap();
            addOpenPort(row);

            const int port = row.value("port").toInt();
            const QString service = row.value("service").toString();
            const QString banner = row.value("banner").toString();

            if (port == 3306 || port == 5432 || port == 27017 || port == 6379 || port == 9200) {
                addFinding("high",
                           tr("Veri servisi acik"),
                           tr("%1 portu (%2) dis erisime acik gorunuyor").arg(QString::number(port), service),
                           "ports",
                           30);
            } else if (port == 21 || port == 22 || port == 3389 || port == 5985 || port == 5986) {
                addFinding("medium",
                           tr("Yonetim servisi acik"),
                           tr("Hassas yonetim portu %1 (%2) erisilebilir durumda").arg(QString::number(port), service),
                           "ports",
                           12);
            } else if (port == 2375) {
                addFinding("high",
                           tr("Docker API acik"),
                           tr("Kimlik dogrulamasiz Docker uzaktan yonetim portu acik olabilir"),
                           "ports",
                           35);
            } else {
                emit findingDiscovered("info",
                                       QString("Acik port %1").arg(port),
                                       banner.isEmpty()
                                           ? QString("%1 servisi erisilebilir durumda").arg(service)
                                           : QString("%1 servisi erisilebilir: %2").arg(service, banner));
            }

            const QString version = extractVersion(banner.toUtf8());
            if (!version.isEmpty()) {
                startCveLookup(service, version);
            }
        }
    }

    registerStageFinished();
}

void PenguFoceMasterScanner::handleWebReply()
{
    auto *reply = qobject_cast<QNetworkReply *>(sender());
    if (!reply) {
        registerStageFinished();
        return;
    }

    analyzeWebReply(reply);
    analyzeTls(reply);
    reply->deleteLater();
    registerStageFinished();
}

void PenguFoceMasterScanner::handleOsintReply()
{
    auto *reply = qobject_cast<QNetworkReply *>(sender());
    if (!reply) {
        registerStageFinished();
        return;
    }

    if (!m_cancelled && reply->error() == QNetworkReply::NoError) {
        const QByteArray payload = reply->readAll();
        const QJsonDocument document = QJsonDocument::fromJson(payload);
        if (document.isArray() && !document.array().isEmpty()) {
            addFinding("medium",
                       "OSINT eslesmesi",
                       QString("Tehdit istihbarati ucnoktasi %1 kayit dondurdu").arg(document.array().size()),
                       "osint",
                       12);
            m_report.osintObservations << QVariantMap{
                {"source", reply->url().toString()},
                {"resultCount", document.array().size()},
                {"details", tr("Harici veri kaynagi hedefle ilgili kayit dondurdu")}
            };
        } else if (document.isObject()) {
            const QJsonObject object = document.object();
            const int count = object.value("count").toInt(object.value("hits").toArray().size());
            if (count > 0 || object.value("found").toBool()) {
                addFinding("medium",
                           "Tehdit istihbarati bulgusu",
                           object.value("details").toString(QString("%1 gosterge donduruldu").arg(qMax(1, count))),
                           "osint",
                           12);
                m_report.osintObservations << object.toVariantMap();
            } else {
                m_report.osintObservations << QVariantMap{
                    {"source", reply->url().toString()},
                    {"details", tr("Harici veri kaynagi acik kayit bulmadi")}
                };
            }
        }
    } else if (!m_cancelled) {
        emit statusMessage(QString("OSINT ucnokta hatasi: %1").arg(reply->errorString()));
    }

    reply->deleteLater();
    registerStageFinished();
}

void PenguFoceMasterScanner::handleDnsLookupFinished()
{
    auto *lookup = qobject_cast<QDnsLookup *>(sender());
    if (!lookup) {
        return;
    }

    if (!m_cancelled && lookup->error() == QDnsLookup::NoError) {
        switch (lookup->type()) {
        case QDnsLookup::A:
            for (const auto &record : lookup->hostAddressRecords()) {
                m_report.dnsRecords << makeDnsRecord("A", record.value().toString());
            }
            if (lookup->hostAddressRecords().isEmpty()) {
                addFinding("medium", "A kaydi eksik", "Alan adi icin IPv4 A kaydi bulunamadi", "dns", 10);
            }
            break;
        case QDnsLookup::AAAA:
            for (const auto &record : lookup->hostAddressRecords()) {
                m_report.dnsRecords << makeDnsRecord("AAAA", record.value().toString());
            }
            break;
        case QDnsLookup::NS:
            for (const auto &record : lookup->nameServerRecords()) {
                m_report.dnsRecords << makeDnsRecord("NS", record.value());
            }
            if (lookup->nameServerRecords().size() < 2) {
                addFinding("low", "NS cesitliligi dusuk", "Alan adi icin yedekli ad sunucusu gorunmuyor", "dns", 4);
            }
            break;
        case QDnsLookup::MX:
            for (const auto &record : lookup->mailExchangeRecords()) {
                m_report.dnsRecords << makeDnsRecord("MX", QString("%1 (pref=%2)").arg(record.exchange()).arg(record.preference()));
            }
            if (lookup->mailExchangeRecords().isEmpty()) {
                addFinding("medium", "MX kaydi eksik", "Hedef alan adi icin MX kaydi bulunamadi", "dns", 8);
            }
            break;
        case QDnsLookup::TXT: {
            bool spfFound = false;
            bool dmarcFound = false;
            for (const auto &record : lookup->textRecords()) {
                const QString value = record.values().join(' ');
                m_report.dnsRecords << makeDnsRecord("TXT", value);
                const QString lower = value.toLower();
                if (lower.startsWith("v=spf1")) {
                    spfFound = true;
                    if (lower.contains("+all")) {
                        addFinding("high", "SPF asiri izinli", "SPF kaydi +all iceriyor, sahte gonderime izin verebilir", "dns", 22);
                    }
                }
                if (lower.contains("v=dmarc1")) {
                    dmarcFound = true;
                    if (lower.contains("p=none")) {
                        addFinding("medium", "DMARC yalnizca izleme modunda", "DMARC politikasi yaptirim uygulamiyor", "dns", 8);
                    }
                }
            }
            if (!spfFound) {
                addFinding("medium", "SPF eksik", "SPF TXT kaydi bulunamadi", "dns", 10);
            }
            if (!dmarcFound) {
                addFinding("medium", "DMARC eksik", "DMARC politikasi bulunamadi", "dns", 10);
            }
            break;
        }
        default:
            break;
        }
    } else if (!m_cancelled) {
        emit statusMessage(QString("DNS sorgusu basarisiz: %1").arg(lookup->errorString()));
    }

    m_dnsLookups.removeAll(lookup);
    lookup->deleteLater();
    if (m_dnsLookups.isEmpty()) {
        registerStageFinished();
    }
}

PenguFoceMasterScanner::ParsedTarget PenguFoceMasterScanner::parseTarget(const QString &target) const
{
    const ReconParsedTarget parsedTarget = reconParseTarget(target);
    ParsedTarget parsed;
    parsed.original = parsedTarget.original;
    parsed.sanitized = parsedTarget.sanitized;
    parsed.host = parsedTarget.host;
    parsed.scheme = parsedTarget.scheme;
    parsed.url = parsedTarget.url;
    return parsed;
}

void PenguFoceMasterScanner::resetScanState()
{
    m_cancelled = false;
    m_pendingStages = 0;
    m_totalStages = 0;
    m_securityScore = 100;
    m_report = {};
    m_findingKeys.clear();
    m_openPortKeys.clear();
    m_seenArtifacts.clear();

    for (QDnsLookup *lookup : std::as_const(m_dnsLookups)) {
        if (lookup) {
            lookup->deleteLater();
        }
    }
    m_dnsLookups.clear();
}

void PenguFoceMasterScanner::registerStageStarted()
{
    ++m_pendingStages;
    ++m_totalStages;
    updateProgress();
}

void PenguFoceMasterScanner::registerStageFinished()
{
    m_pendingStages = qMax(0, m_pendingStages - 1);
    updateProgress();
    if (m_pendingStages == 0 && !m_cancelled) {
        const int score = calculateSecurityScore();
        emit scanFinished(m_report, score);
        if (m_logger) {
            m_logger->info("master_scanner", QString("Tek tus taramasi %1 puan ile tamamlandi").arg(score));
        }
    }
}

void PenguFoceMasterScanner::updateProgress()
{
    emit scanProgress(reconProgressPercent(m_totalStages, m_pendingStages));
}

void PenguFoceMasterScanner::addFinding(const QString &severity,
                                        const QString &title,
                                        const QString &description,
                                        const QString &category,
                                        int penalty)
{
    const QString key = QString("%1|%2|%3").arg(category, title, description);
    if (m_findingKeys.contains(key)) {
        return;
    }

    m_findingKeys.insert(key);
    ScanFinding finding{severity, title, description, category};
    m_report.findings << finding.toVariantMap();
    m_securityScore = qMax(0, m_securityScore - penalty);
    emit findingDiscovered(severity, title, description);
    if (m_logger) {
        m_logger->warning("master_scanner", QString("[%1] %2 - %3").arg(severity, title, description));
    }
}

int PenguFoceMasterScanner::calculateSecurityScore() const
{
    return reconClampedSecurityScore(m_securityScore);
}

QString PenguFoceMasterScanner::severityForPenalty(int penalty) const
{
    return reconSeverityForPenalty(penalty);
}

void PenguFoceMasterScanner::analyzeWebReply(QNetworkReply *reply)
{
    if (m_cancelled || !reply) {
        return;
    }

    if (reply->error() != QNetworkReply::NoError) {
        addFinding("medium", "Web istegi basarisiz", reply->errorString(), "web", 15);
        return;
    }

    const ReconWebAnalysis analysis = reconAnalyzeWebResponse({
        reply->url(),
        reply->rawHeaderPairs(),
        reply->header(QNetworkRequest::SetCookieHeader).value<QList<QNetworkCookie>>(),
        reply->readAll().left(4096),
        reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()
    });

    for (const ReconFindingCandidate &finding : analysis.findings) {
        addFinding(finding.severity, finding.title, finding.description, finding.category, finding.penalty);
    }
    for (const ReconCveCandidate &cveCandidate : analysis.cveCandidates) {
        if (!cveCandidate.product.isEmpty() && !cveCandidate.version.isEmpty()) {
            startCveLookup(cveCandidate.product, cveCandidate.version);
        }
    }
    if (!analysis.observation.isEmpty()) {
        m_report.webObservations << analysis.observation;
    }
}

void PenguFoceMasterScanner::analyzeTls(QNetworkReply *reply)
{
    if (!reply || reply->url().scheme().toLower() != "https") {
        return;
    }

    const QSslConfiguration ssl = reply->sslConfiguration();
    const QSslCertificate cert = ssl.peerCertificate();
    QStringList cipherNames;
    const QList<QSslCipher> ciphers = ssl.sessionCipher().isNull() ? ssl.ciphers() : QList<QSslCipher>{ssl.sessionCipher()};
    for (const QSslCipher &cipher : ciphers) {
        if (!cipher.name().isEmpty() && !cipherNames.contains(cipher.name())) {
            cipherNames << cipher.name();
        }
    }

    const ReconTlsAnalysis analysis = reconAnalyzeTlsState({
        !cert.isNull(),
        cert.expiryDate(),
        ssl.sessionProtocol(),
        cipherNames,
        cert.subjectInfo(QSslCertificate::CommonName).join(' ').trimmed(),
        cert.issuerInfo(QSslCertificate::Organization).join(' ')
    });

    for (const ReconFindingCandidate &finding : analysis.findings) {
        if (finding.severity == QStringLiteral("info")) {
            emit findingDiscovered(finding.severity, finding.title, finding.description);
            continue;
        }
        addFinding(finding.severity, finding.title, finding.description, finding.category, finding.penalty);
    }
}

void PenguFoceMasterScanner::startDnsRecon(const QString &host)
{
    for (const QDnsLookup::Type type : {QDnsLookup::A, QDnsLookup::AAAA, QDnsLookup::NS, QDnsLookup::MX, QDnsLookup::TXT}) {
        auto *lookup = new QDnsLookup(type, host, this);
        m_dnsLookups << lookup;
        connect(lookup, &QDnsLookup::finished, this, &PenguFoceMasterScanner::handleDnsLookupFinished);
        lookup->lookup();
    }
}

void PenguFoceMasterScanner::startOsintTask(const QString &host)
{
    QUrl endpoint = m_osintEndpoint;
    QUrlQuery query(endpoint);
    query.addQueryItem("domain", host);
    endpoint.setQuery(query);

    QNetworkRequest request(endpoint);
    request.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce/0.1");
    request.setTransferTimeout(5000);
    QNetworkReply *reply = m_networkAccessManager->get(request);
    connect(reply, &QNetworkReply::finished, this, &PenguFoceMasterScanner::handleOsintReply);
}

void PenguFoceMasterScanner::startSubdomainRecon(const QString &host)
{
    QUrl endpoint(QStringLiteral("https://crt.sh/"));
    QUrlQuery query(endpoint);
    query.addQueryItem(QStringLiteral("q"), QStringLiteral("%%.%1").arg(host));
    query.addQueryItem(QStringLiteral("output"), QStringLiteral("json"));
    endpoint.setQuery(query);

    QNetworkRequest request(endpoint);
    request.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce/0.1");
    request.setTransferTimeout(7000);
    QNetworkReply *reply = m_networkAccessManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, host]() {
        if (!m_cancelled && reply->error() == QNetworkReply::NoError) {
            const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QSet<QString> discovered;
            if (doc.isArray()) {
                for (const QJsonValue &value : doc.array()) {
                    const QString commonName = normalizedSubdomain(value.toObject().value("name_value").toString());
                    for (const QString &line : commonName.split('\n', Qt::SkipEmptyParts)) {
                        const QString sub = normalizedSubdomain(line);
                        if (sub.endsWith(host) && !discovered.contains(sub)) {
                            discovered.insert(sub);
                            m_report.subdomains << sub;
                        }
                    }
                }
            }
            if (!discovered.isEmpty()) {
                addFinding("info",
                           tr("Alt alan adlari bulundu"),
                           tr("%1 adet alt alan adi kaydi toplandi").arg(discovered.size()),
                           "osint",
                           0);
            }
        }
        reply->deleteLater();
        registerStageFinished();
    });
}

void PenguFoceMasterScanner::startWaybackRecon(const QString &host)
{
    QUrl endpoint(QStringLiteral("https://web.archive.org/cdx/search/cdx"));
    QUrlQuery query(endpoint);
    query.addQueryItem(QStringLiteral("url"), QStringLiteral("%1/*").arg(host));
    query.addQueryItem(QStringLiteral("output"), QStringLiteral("json"));
    query.addQueryItem(QStringLiteral("fl"), QStringLiteral("original,statuscode,mimetype,timestamp"));
    query.addQueryItem(QStringLiteral("filter"), QStringLiteral("statuscode:200"));
    query.addQueryItem(QStringLiteral("limit"), QStringLiteral("20"));
    endpoint.setQuery(query);

    QNetworkRequest request(endpoint);
    request.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce/0.1");
    request.setTransferTimeout(7000);
    QNetworkReply *reply = m_networkAccessManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (!m_cancelled && reply->error() == QNetworkReply::NoError) {
            const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (doc.isArray()) {
                bool first = true;
                for (const QJsonValue &value : doc.array()) {
                    if (first) {
                        first = false;
                        continue;
                    }
                    const QJsonArray row = value.toArray();
                    if (!row.isEmpty()) {
                        const QString archivedUrl = row.at(0).toString();
                        if (!archivedUrl.isEmpty() && !m_seenArtifacts.contains(QStringLiteral("wb|%1").arg(archivedUrl))) {
                            m_seenArtifacts.insert(QStringLiteral("wb|%1").arg(archivedUrl));
                            m_report.archivedUrls << archivedUrl;
                        }
                    }
                }
            }
            if (!m_report.archivedUrls.isEmpty()) {
                addFinding("info",
                           tr("Wayback URL arsivi bulundu"),
                           tr("%1 adet gecmis URL kaydi toplandi").arg(m_report.archivedUrls.size()),
                           "osint",
                           0);
            }
        }
        reply->deleteLater();
        registerStageFinished();
    });
}

void PenguFoceMasterScanner::startDirectoryFuzzing(const QUrl &baseUrl)
{
    const auto pendingReplies = QSharedPointer<int>::create(kCommonPaths.size());
    for (const QString &path : kCommonPaths) {
        QUrl url = baseUrl;
        url.setPath(path);
        QNetworkRequest request(url);
        request.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce/0.1");
        request.setTransferTimeout(3500);
        QNetworkReply *reply = m_networkAccessManager->get(request);
        connect(reply, &QNetworkReply::finished, this, [this, reply, pendingReplies, path]() {
            const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (!m_cancelled && reply->error() == QNetworkReply::NoError && status >= 200 && status < 300) {
                const QString url = reply->url().toString();
                if (!m_seenArtifacts.contains(QStringLiteral("dir|%1").arg(url))) {
                    m_seenArtifacts.insert(QStringLiteral("dir|%1").arg(url));
                    m_report.archivedUrls << url;
                    addFinding("medium",
                               tr("Gorunur endpoint bulundu"),
                               tr("%1 yolu HTTP %2 dondu").arg(path).arg(status),
                               "web",
                               path.contains("admin", Qt::CaseInsensitive) || path.contains(".env") || path.contains(".git") ? 12 : 6);
                }
            }

            reply->deleteLater();
            --(*pendingReplies);
            if (*pendingReplies == 0) {
                registerStageFinished();
            }
        });
    }
}

void PenguFoceMasterScanner::startTechnologyRecon(const QUrl &baseUrl)
{
    QNetworkRequest mainRequest(baseUrl);
    mainRequest.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce/0.1");
    mainRequest.setTransferTimeout(6000);
    QNetworkReply *reply = m_networkAccessManager->get(mainRequest);
    connect(reply, &QNetworkReply::finished, this, [this, reply, baseUrl]() {
        QStringList jsUrls;
        if (!m_cancelled && reply->error() == QNetworkReply::NoError) {
            const QString html = QString::fromUtf8(reply->readAll());
            if (html.contains("wp-content", Qt::CaseInsensitive) || html.contains("wordpress", Qt::CaseInsensitive)) {
                addFinding("medium", tr("CMS tespiti"), tr("Hedefte WordPress izi bulundu"), "web", 6);
                m_report.webObservations << QVariantMap{{"url", baseUrl.toString()}, {"cms", "WordPress"}};
            } else if (html.contains("joomla", Qt::CaseInsensitive)) {
                addFinding("info", tr("CMS tespiti"), tr("Hedefte Joomla izi bulundu"), "web", 0);
                m_report.webObservations << QVariantMap{{"url", baseUrl.toString()}, {"cms", "Joomla"}};
            } else if (html.contains("drupal", Qt::CaseInsensitive)) {
                addFinding("info", tr("CMS tespiti"), tr("Hedefte Drupal izi bulundu"), "web", 0);
                m_report.webObservations << QVariantMap{{"url", baseUrl.toString()}, {"cms", "Drupal"}};
            }

            static const QRegularExpression scriptRegex(QStringLiteral("<script[^>]+src=[\"']([^\"']+\\.js[^\"']*)[\"']"),
                                                        QRegularExpression::CaseInsensitiveOption);
            auto it = scriptRegex.globalMatch(html);
            while (it.hasNext()) {
                QString jsPath = it.next().captured(1);
                QUrl jsUrl = baseUrl.resolved(QUrl(jsPath));
                jsUrls << jsUrl.toString();
            }
            jsUrls.removeDuplicates();
        }
        reply->deleteLater();

        if (jsUrls.isEmpty()) {
            registerStageFinished();
            return;
        }

        const auto pendingJs = QSharedPointer<int>::create(jsUrls.size());
        for (const QString &jsUrlString : std::as_const(jsUrls)) {
            QNetworkRequest jsRequest{QUrl(jsUrlString)};
            jsRequest.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce/0.1");
            jsRequest.setTransferTimeout(5000);
            QNetworkReply *jsReply = m_networkAccessManager->get(jsRequest);
            connect(jsReply, &QNetworkReply::finished, this, [this, jsReply, pendingJs]() {
                if (!m_cancelled && jsReply->error() == QNetworkReply::NoError) {
                    const QString body = QString::fromUtf8(jsReply->readAll());
                    const QStringList urls = extractInterestingUrls(body);
                    for (const QString &url : urls) {
                        if (!m_seenArtifacts.contains(QStringLiteral("jsurl|%1").arg(url))) {
                            m_seenArtifacts.insert(QStringLiteral("jsurl|%1").arg(url));
                            m_report.jsFindings << QVariantMap{{"type", "url"}, {"value", url}, {"source", jsReply->url().toString()}};
                        }
                    }

                    static const QRegularExpression secretRegex(QStringLiteral("(api[_-]?key|token|secret)[\"'\\s:=]+([A-Za-z0-9_\\-]{8,})"),
                                                                QRegularExpression::CaseInsensitiveOption);
                    auto matchIt = secretRegex.globalMatch(body);
                    while (matchIt.hasNext()) {
                        const auto match = matchIt.next();
                        const QString secretName = match.captured(1);
                        const QString redacted = QString("%1...").arg(match.captured(2).left(6));
                        const QString key = QStringLiteral("jssecret|%1|%2").arg(jsReply->url().toString(), redacted);
                        if (!m_seenArtifacts.contains(key)) {
                            m_seenArtifacts.insert(key);
                            m_report.jsFindings << QVariantMap{{"type", "secret"}, {"value", QString("%1 => %2").arg(secretName, redacted)}, {"source", jsReply->url().toString()}};
                            addFinding("high",
                                       tr("JavaScript icinde gizli veri izi"),
                                       tr("%1 dosyasinda olasi %2 ifsasi goruldu").arg(jsReply->url().toString(), secretName),
                                       "web",
                                       16);
                        }
                    }
                }
                jsReply->deleteLater();
                --(*pendingJs);
                if (*pendingJs == 0) {
                    registerStageFinished();
                }
            });
        }
    });
}

void PenguFoceMasterScanner::startWhoisTask(const QString &host)
{
    auto *task = new WhoisTask(host);
    connect(task, &WhoisTask::taskFinished, this, [this](const QVariantMap &data) {
        m_report.whoisInfo = data;
        if (!data.isEmpty()) {
            addFinding("info", tr("Whois bilgisi toplandi"), tr("%1 icin kayit otoritesi bilgisi cekildi").arg(data.value("domain").toString()), "osint", 0);
        }
        registerStageFinished();
    }, Qt::QueuedConnection);
    m_threadPool.start(task);
}

void PenguFoceMasterScanner::startCveLookup(const QString &product, const QString &version)
{
    const QVariantMap cve = cveHintForService(product, version);
    if (cve.isEmpty()) {
        return;
    }

    const QString key = QStringLiteral("cve|%1|%2").arg(product, version);
    if (m_seenArtifacts.contains(key)) {
        return;
    }
    m_seenArtifacts.insert(key);
    m_report.cveMatches << QVariantMap{
        {"product", product},
        {"version", version},
        {"cve", cve.value("cve").toString()},
        {"summary", cve.value("summary").toString()},
        {"severity", cve.value("severity").toString()}
    };
    addFinding(cve.value("severity").toString(),
               tr("Bilinen zafiyet eslesmesi"),
               tr("%1 %2 icin %3 - %4").arg(product, version, cve.value("cve").toString(), cve.value("summary").toString()),
               "web",
               cve.value("severity").toString() == "high" ? 18 : 10);
}

QVariantMap PenguFoceMasterScanner::makeDnsRecord(const QString &type, const QString &value) const
{
    return {
        {"type", type},
        {"value", value}
    };
}

void PenguFoceMasterScanner::addOpenPort(const QVariantMap &row)
{
    const QString key = QString("%1|%2").arg(row.value("port").toString(), row.value("service").toString());
    if (m_openPortKeys.contains(key)) {
        return;
    }
    m_openPortKeys.insert(key);
    m_report.openPorts << row;
}

bool PenguFoceMasterScanner::shouldScanWeb() const
{
    return m_currentTarget.scheme == "http" || m_currentTarget.scheme == "https";
}

bool PenguFoceMasterScanner::isDomainTarget() const
{
    return looksLikeDomain(m_currentTarget.host);
}

#include "pengufoce_masterscanner.moc"
