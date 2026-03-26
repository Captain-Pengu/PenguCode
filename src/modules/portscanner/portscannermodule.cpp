#include "portscannermodule.h"

#include "core/logging/logger.h"
#include "core/framework/moduleregistry.h"
#include "core/settings/settingsmanager.h"

#include <QClipboard>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QGuiApplication>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkDatagram>
#include <QRegularExpression>
#include <QTcpSocket>
#include <QTextStream>
#include <QUdpSocket>

namespace {

QStringList splitAndTrim(const QString &value, const QChar separator)
{
    QStringList parts;
    for (const QString &part : value.split(separator, Qt::SkipEmptyParts)) {
        parts << part.trimmed();
    }
    return parts;
}

quint32 ipv4ToInt(const QHostAddress &address)
{
    return address.toIPv4Address();
}

QHostAddress intToIpv4(quint32 value)
{
    return QHostAddress(value);
}

PortScanWorker::ScanMode toWorkerMode(const QString &scanType)
{
    const QString normalized = scanType.trimmed().toLower();
    if (normalized == "udp") {
        return PortScanWorker::ScanMode::Udp;
    }
    if (normalized == "service/version" || normalized == "service detect") {
        return PortScanWorker::ScanMode::ServiceDetect;
    }
    if (normalized == "os fingerprint") {
        return PortScanWorker::ScanMode::OsFingerprint;
    }
    return PortScanWorker::ScanMode::TcpConnect;
}

QString normalizeFileFormat(const QString &format)
{
    return format.trimmed().toLower();
}

QString csvEscape(QString value)
{
    value.replace('"', "\"\"");
    if (value.contains(',') || value.contains('"') || value.contains('\n')) {
        return '"' + value + '"';
    }
    return value;
}

} // namespace

QVariantMap ScanResult::toVariantMap() const
{
    return {
        {"ip", ip},
        {"port", port},
        {"protocol", protocol},
        {"state", state},
        {"service", serviceName},
        {"banner", banner},
        {"responseTime", responseTimeMs >= 0 ? QString::number(responseTimeMs) + " ms" : "--"},
        {"responseTimeMs", responseTimeMs},
        {"osFingerprint", osFingerprint}
    };
}

PortScanWorker::PortScanWorker(QString host,
                               int port,
                               ScanMode mode,
                               int timeoutMs,
                               int retryCount,
                               bool serviceDetection,
                               bool osFingerprinting,
                               const std::atomic_bool *cancelled)
    : m_host(std::move(host))
    , m_port(port)
    , m_mode(mode)
    , m_timeoutMs(timeoutMs)
    , m_retryCount(retryCount)
    , m_serviceDetection(serviceDetection)
    , m_osFingerprinting(osFingerprinting)
    , m_cancelled(cancelled)
{
    setAutoDelete(true);
}

void PortScanWorker::run()
{
    if (m_cancelled && m_cancelled->load()) {
        return;
    }

    ScanResult result;
    switch (m_mode) {
    case ScanMode::Udp:
        result = performUdpScan();
        break;
    case ScanMode::ServiceDetect:
    case ScanMode::OsFingerprint:
    case ScanMode::TcpConnect:
    default:
        result = performTcpConnect();
        break;
    }

    if (!result.serviceName.isEmpty() || !result.banner.isEmpty()) {
        emit serviceBannerDetected(result.ip, result.port, result.serviceName, result.banner);
    }
    emit scanCompleted(result);
}

ScanResult PortScanWorker::performTcpConnect() const
{
    ScanResult bestResult;
    bestResult.ip = m_host;
    bestResult.port = m_port;
    bestResult.protocol = "TCP";
    bestResult.state = "closed";
    bestResult.serviceName = detectServiceName(m_port, {});

    for (int attempt = 0; attempt <= m_retryCount; ++attempt) {
        if (m_cancelled && m_cancelled->load()) {
            bestResult.state = "filtered";
            return bestResult;
        }

        QTcpSocket socket;
        QElapsedTimer timer;
        timer.start();
        socket.connectToHost(m_host, static_cast<quint16>(m_port));
        const bool connected = socket.waitForConnected(m_timeoutMs);
        bestResult.responseTimeMs = timer.elapsed();

        if (!connected) {
            bestResult.state = socket.error() == QAbstractSocket::SocketTimeoutError ? "filtered" : "closed";
            continue;
        }

        bestResult.state = "open";
        bestResult.responseTimeMs = timer.elapsed();
        if (m_serviceDetection || m_mode != ScanMode::TcpConnect) {
            bestResult.banner = detectBanner(socket, m_port, m_timeoutMs);
            bestResult.serviceName = detectServiceName(m_port, bestResult.banner);
        }
        if (m_osFingerprinting || m_mode == ScanMode::OsFingerprint) {
            bestResult.osFingerprint = guessOsFingerprint(bestResult.banner, bestResult.serviceName);
        }
        socket.disconnectFromHost();
        return bestResult;
    }

    return bestResult;
}

ScanResult PortScanWorker::performUdpScan() const
{
    ScanResult result;
    result.ip = m_host;
    result.port = m_port;
    result.protocol = "UDP";
    result.state = "filtered";
    result.serviceName = detectServiceName(m_port, {});

    QUdpSocket socket;
    QElapsedTimer timer;
    timer.start();

    QByteArray probe = "PF-UDP-PROBE";
    socket.writeDatagram(probe, QHostAddress(m_host), static_cast<quint16>(m_port));
    const bool received = socket.waitForReadyRead(m_timeoutMs);
    result.responseTimeMs = timer.elapsed();

    if (received) {
        const QNetworkDatagram datagram = socket.receiveDatagram();
        result.state = "open";
        result.banner = QString::fromUtf8(datagram.data()).trimmed();
    } else if (socket.error() != QAbstractSocket::UnknownSocketError) {
        result.state = "closed";
    }

    if (m_osFingerprinting) {
        result.osFingerprint = guessOsFingerprint(result.banner, result.serviceName);
    }

    return result;
}

QString PortScanWorker::detectServiceName(int port, const QString &banner) const
{
    const QString lowerBanner = banner.toLower();
    if (lowerBanner.contains("ssh")) return "ssh";
    if (lowerBanner.contains("smtp")) return "smtp";
    if (lowerBanner.contains("mysql")) return "mysql";
    if (lowerBanner.contains("redis")) return "redis";
    if (lowerBanner.contains("postgres")) return "postgresql";
    if (lowerBanner.contains("http")) return port == 443 ? "https" : "http";

    return PortScannerModule::serviceNameLookup().value(port, "unknown");
}

QString PortScanWorker::detectBanner(QTcpSocket &socket, int port, int timeoutMs) const
{
    if (socket.waitForReadyRead(80)) {
        return QString::fromUtf8(socket.readAll()).simplified();
    }

    if (port == 80 || port == 8080 || port == 8000 || port == 3000 || port == 5000 || port == 8443) {
        socket.write("HEAD / HTTP/1.0\r\nHost: target\r\n\r\n");
    } else if (port == 25 || port == 587) {
        socket.write("EHLO pengufoce.local\r\n");
    } else if (port == 21) {
        socket.write("FEAT\r\n");
    } else if (port == 6379) {
        socket.write("PING\r\n");
    }

    socket.flush();
    if (socket.waitForReadyRead(timeoutMs)) {
        return QString::fromUtf8(socket.readAll()).simplified();
    }

    return {};
}

QString PortScanWorker::guessOsFingerprint(const QString &banner, const QString &serviceName) const
{
    const QString haystack = (banner + " " + serviceName).toLower();
    if (haystack.contains("microsoft") || haystack.contains("iis") || haystack.contains("windows")) {
        return "Windows family";
    }
    if (haystack.contains("ubuntu") || haystack.contains("debian") || haystack.contains("linux")
        || haystack.contains("openssh") || haystack.contains("nginx")) {
        return "Linux/Unix family";
    }
    if (haystack.contains("freebsd")) {
        return "BSD family";
    }

    // Qt socket APIs do not expose packet TTL directly, so banner/service clues are used here.
    return "Unknown";
}

PortScannerModule::PortScannerModule(QObject *parent)
    : ModuleInterface(parent)
{
    qRegisterMetaType<ScanResult>("ScanResult");
}

PortScannerModule::~PortScannerModule()
{
    stop();
    m_threadPool.waitForDone();
}

QString PortScannerModule::id() const
{
    return "port_scanner";
}

QString PortScannerModule::name() const
{
    return "Port Scanner";
}

QString PortScannerModule::description() const
{
    return "TCP/UDP tarama, banner grabbing ve temel OS fingerprinting iceren cok is parcacikli tarayici.";
}

QString PortScannerModule::icon() const
{
    return "radar";
}

QUrl PortScannerModule::pageSource() const
{
    return QUrl("qrc:/qt/qml/PenguFoce/qml/pages/PortScannerView.qml");
}

void PortScannerModule::initialize(SettingsManager *settings, Logger *logger)
{
    m_settings = settings;
    m_logger = logger;
    reloadSettings();

    m_logger->info(id(), "Port Scanner module initialized");
}

QVariantMap PortScannerModule::defaultSettings() const
{
    return {
        {"defaultHost", "127.0.0.1"},
        {"defaultPorts", "common"},
        {"timeoutMs", 600},
        {"threadCount", 64},
        {"retryCount", 1},
        {"scanType", "TCP Connect"},
        {"serviceDetection", true},
        {"osFingerprinting", false}
    };
}

QString PortScannerModule::targetSpec() const { return m_targetSpec; }
QString PortScannerModule::portSpec() const { return m_portSpec; }
QString PortScannerModule::scanType() const { return m_scanType; }
int PortScannerModule::threadCount() const { return m_threadCount; }
int PortScannerModule::timeoutMs() const { return m_timeoutMs; }
int PortScannerModule::retryCount() const { return m_retryCount; }
bool PortScannerModule::serviceDetectionEnabled() const { return m_serviceDetectionEnabled; }
bool PortScannerModule::osFingerprintingEnabled() const { return m_osFingerprintingEnabled; }
bool PortScannerModule::scanning() const { return m_scanning; }
QVariantList PortScannerModule::results() const { return m_results; }
int PortScannerModule::openPorts() const { return m_openPorts; }
int PortScannerModule::scannedCount() const { return m_scannedCount; }
int PortScannerModule::totalTasks() const { return m_totalTasks; }
double PortScannerModule::progress() const { return m_progress; }
double PortScannerModule::portsPerSecond() const { return m_portsPerSecond; }
QString PortScannerModule::etaText() const { return m_etaText; }
QString PortScannerModule::elapsedText() const { return m_elapsedText; }
QString PortScannerModule::statusText() const { return m_statusText; }

const QMap<int, QString> &PortScannerModule::serviceNameLookup()
{
    static const QMap<int, QString> map = {
        {20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"},
        {53, "dns"}, {67, "dhcp"}, {68, "dhcp"}, {69, "tftp"}, {80, "http"},
        {110, "pop3"}, {111, "rpcbind"}, {123, "ntp"}, {135, "msrpc"}, {137, "netbios-ns"},
        {138, "netbios-dgm"}, {139, "netbios-ssn"}, {143, "imap"}, {161, "snmp"},
        {389, "ldap"}, {443, "https"}, {445, "smb"}, {465, "smtps"}, {514, "syslog"},
        {515, "printer"}, {587, "submission"}, {631, "ipp"}, {993, "imaps"}, {995, "pop3s"},
        {1080, "socks"}, {1433, "mssql"}, {1521, "oracle"}, {1723, "pptp"}, {1883, "mqtt"},
        {2049, "nfs"}, {2375, "docker"}, {3000, "node"}, {3128, "squid"}, {3306, "mysql"},
        {3389, "rdp"}, {5000, "upnp"}, {5432, "postgresql"}, {5900, "vnc"}, {6379, "redis"},
        {8080, "http-proxy"}, {8081, "http-alt"}, {8443, "https-alt"}, {9200, "elasticsearch"},
        {9300, "elasticsearch"}, {11211, "memcached"}, {27017, "mongodb"}
    };
    return map;
}

void PortScannerModule::configureScan(const QString &targetSpec,
                                      const QString &portSpec,
                                      const QString &scanType,
                                      int threadCount,
                                      int timeoutMs,
                                      int retryCount,
                                      bool serviceDetection,
                                      bool osFingerprinting)
{
    setTargetSpec(targetSpec);
    setPortSpec(portSpec);
    setScanType(scanType);
    setThreadCount(threadCount);
    setTimeoutMs(timeoutMs);
    setRetryCount(retryCount);
    setServiceDetectionEnabled(serviceDetection);
    setOsFingerprintingEnabled(osFingerprinting);
}

QVariantList PortScannerModule::scanTypeOptions() const
{
    return {"TCP Connect", "UDP", "Service/Version", "OS Fingerprint"};
}

QVariantList PortScannerModule::presetPortGroups() const
{
    return {"Common", "Web", "Database", "Full"};
}

void PortScannerModule::applyPreset(const QString &presetName)
{
    setPortSpec(presetName.toLower());
}

bool PortScannerModule::exportResults(const QString &filePath, const QString &format) const
{
    return writeResults(m_results, filePath.isEmpty() ? defaultExportPath(format) : filePath, format);
}

bool PortScannerModule::exportRow(const QVariantMap &row, const QString &filePath, const QString &format) const
{
    QVariantList single;
    single << row;
    return writeResults(single, filePath.isEmpty() ? defaultExportPath(format) : filePath, format);
}

void PortScannerModule::copyRow(const QVariantMap &row) const
{
    QStringList lines;
    for (auto it = row.cbegin(); it != row.cend(); ++it) {
        lines << QString("%1: %2").arg(it.key(), it.value().toString());
    }
    if (QGuiApplication::clipboard()) {
        QGuiApplication::clipboard()->setText(lines.join('\n'));
    }
}

void PortScannerModule::investigatePort(const QVariantMap &row)
{
    if (!m_logger) {
        return;
    }
    m_logger->info(id(), QString("Investigate queued for %1:%2 (%3)")
                             .arg(row.value("ip").toString(),
                                  row.value("port").toString(),
                                  row.value("service").toString()));
}

void PortScannerModule::reloadSettings()
{
    if (!m_settings) {
        return;
    }

    m_targetSpec = m_settings->value("modules/port_scanner", "defaultHost", "127.0.0.1").toString();
    m_portSpec = m_settings->value("modules/port_scanner", "defaultPorts", "common").toString();
    m_timeoutMs = m_settings->value("modules/port_scanner", "timeoutMs", 500).toInt();
    m_threadCount = m_settings->value("modules/port_scanner", "threadCount", 64).toInt();
    m_retryCount = m_settings->value("modules/port_scanner", "retryCount", 1).toInt();
    m_scanType = normalizedScanType(m_settings->value("modules/port_scanner", "scanType", "TCP Connect").toString());
    m_serviceDetectionEnabled = m_settings->value("modules/port_scanner", "serviceDetection", true).toBool();
    m_osFingerprintingEnabled = m_settings->value("modules/port_scanner", "osFingerprinting", false).toBool();
    emit configurationChanged();
}

void PortScannerModule::start()
{
    if (m_scanning) {
        return;
    }

    const QList<QString> targets = expandTargets(m_targetSpec);
    const QList<int> ports = expandPorts(m_portSpec);
    if (targets.isEmpty() || ports.isEmpty()) {
        m_statusText = "Invalid target or port input";
        emit statusTextChanged();
        if (m_logger) {
            m_logger->error(id(), m_statusText);
        }
        return;
    }

    resetForScan();
    m_scanning = true;
    m_cancelled.store(false);
    m_startedAtUtc = QDateTime::currentDateTimeUtc();
    m_threadPool.setMaxThreadCount(m_threadCount);
    m_totalTasks = targets.size() * ports.size();
    m_statusText = "Scanning";

    emit scanningChanged();
    emit statusTextChanged();
    emit statsChanged();
    emit progressChanged();

    if (m_logger) {
        m_logger->info(id(), QString("Starting %1 scan: %2 hosts, %3 ports, %4 tasks")
                                 .arg(m_scanType)
                                 .arg(targets.size())
                                 .arg(ports.size())
                                 .arg(m_totalTasks));
    }

    const auto mode = toWorkerMode(m_scanType);
    for (const QString &target : targets) {
        for (const int port : ports) {
            auto *worker = new PortScanWorker(target,
                                              port,
                                              mode,
                                              m_timeoutMs,
                                              m_retryCount,
                                              m_serviceDetectionEnabled,
                                              m_osFingerprintingEnabled,
                                              &m_cancelled);
            connect(worker, &PortScanWorker::scanCompleted, this, &PortScannerModule::handleWorkerResult, Qt::QueuedConnection);
            connect(worker, &PortScanWorker::serviceBannerDetected, this, &PortScannerModule::handleServiceDetected, Qt::QueuedConnection);
            m_threadPool.start(worker);
        }
    }
}

void PortScannerModule::stop()
{
    if (!m_scanning) {
        return;
    }

    m_cancelled.store(true);
    m_statusText = "Stopping";
    emit statusTextChanged();
    if (m_logger) {
        m_logger->warning(id(), "Scan stop requested");
    }
}

void PortScannerModule::setTargetSpec(const QString &value)
{
    const QString trimmed = value.trimmed();
    if (trimmed == m_targetSpec) return;
    m_targetSpec = trimmed;
    if (m_settings) m_settings->setValue("modules/port_scanner", "defaultHost", trimmed);
    emit configurationChanged();
}

void PortScannerModule::setPortSpec(const QString &value)
{
    const QString trimmed = value.trimmed();
    if (trimmed == m_portSpec) return;
    m_portSpec = trimmed;
    if (m_settings) m_settings->setValue("modules/port_scanner", "defaultPorts", trimmed);
    emit configurationChanged();
}

void PortScannerModule::setScanType(const QString &value)
{
    const QString normalized = normalizedScanType(value);
    if (normalized == m_scanType) return;
    m_scanType = normalized;
    if (m_settings) m_settings->setValue("modules/port_scanner", "scanType", normalized);
    emit configurationChanged();
}

void PortScannerModule::setThreadCount(int value)
{
    const int bounded = qBound(1, value, 2048);
    if (bounded == m_threadCount) return;
    m_threadCount = bounded;
    if (m_settings) m_settings->setValue("modules/port_scanner", "threadCount", bounded);
    emit configurationChanged();
}

void PortScannerModule::setTimeoutMs(int value)
{
    const int bounded = qBound(50, value, 10000);
    if (bounded == m_timeoutMs) return;
    m_timeoutMs = bounded;
    if (m_settings) m_settings->setValue("modules/port_scanner", "timeoutMs", bounded);
    emit configurationChanged();
}

void PortScannerModule::setRetryCount(int value)
{
    const int bounded = qBound(0, value, 10);
    if (bounded == m_retryCount) return;
    m_retryCount = bounded;
    if (m_settings) m_settings->setValue("modules/port_scanner", "retryCount", bounded);
    emit configurationChanged();
}

void PortScannerModule::setServiceDetectionEnabled(bool value)
{
    if (value == m_serviceDetectionEnabled) return;
    m_serviceDetectionEnabled = value;
    if (m_settings) m_settings->setValue("modules/port_scanner", "serviceDetection", value);
    emit configurationChanged();
}

void PortScannerModule::setOsFingerprintingEnabled(bool value)
{
    if (value == m_osFingerprintingEnabled) return;
    m_osFingerprintingEnabled = value;
    if (m_settings) m_settings->setValue("modules/port_scanner", "osFingerprinting", value);
    emit configurationChanged();
}

void PortScannerModule::handleWorkerResult(const ScanResult &result)
{
    if (m_cancelled.load() && !m_scanning) {
        return;
    }

    ++m_scannedCount;
    if (result.state == "open") {
        ++m_openPorts;
    }

    m_results << result.toVariantMap();
    emit resultsChanged();

    if (result.state == "open") {
        emit portFound(result.toVariantMap());
    }

    updateStats();
    emit scanProgress(m_scannedCount, m_totalTasks, m_progress, m_portsPerSecond, m_etaText);

    if (m_scannedCount >= m_totalTasks) {
        finalizeScan(m_cancelled.load() ? "Stopped" : "Complete");
    }
}

void PortScannerModule::handleServiceDetected(const QString &ip, int port, const QString &serviceName, const QString &banner)
{
    emit serviceDetected(ip, port, serviceName, banner);
}

QString PortScannerModule::normalizedScanType(const QString &value) const
{
    const QString lowered = value.trimmed().toLower();
    if (lowered == "udp") return "UDP";
    if (lowered == "service/version" || lowered == "service detect") return "Service/Version";
    if (lowered == "os fingerprint") return "OS Fingerprint";
    return "TCP Connect";
}

QList<QString> PortScannerModule::expandTargets(const QString &spec) const
{
    const QString trimmed = spec.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }
    if (trimmed.contains('/')) {
        return expandCidr(trimmed);
    }
    if (trimmed.contains('-')) {
        return expandIpRange(trimmed);
    }

    QHostAddress address(trimmed);
    if (!address.isNull()) {
        return {address.toString()};
    }

    const QHostInfo info = QHostInfo::fromName(trimmed);
    QList<QString> results;
    for (const auto &resolved : info.addresses()) {
        if (resolved.protocol() == QAbstractSocket::IPv4Protocol) {
            results << resolved.toString();
        }
    }
    return results;
}

QList<int> PortScannerModule::expandPorts(const QString &spec) const
{
    const QString trimmed = spec.trimmed().toLower();
    if (trimmed.isEmpty()) {
        return {};
    }

    QList<int> ports;
    for (const QString &segment : splitAndTrim(trimmed, ',')) {
        if (segment == "common" || segment == "web" || segment == "db" || segment == "database" || segment == "full") {
            ports.append(presetPorts(segment));
            continue;
        }

        if (segment.contains('-')) {
            const QStringList bounds = splitAndTrim(segment, '-');
            if (bounds.size() == 2) {
                const int start = bounds.at(0).toInt();
                const int end = bounds.at(1).toInt();
                for (int port = qMax(1, start); port <= qMin(65535, end); ++port) {
                    ports << port;
                }
            }
            continue;
        }

        const int single = segment.toInt();
        if (single >= 1 && single <= 65535) {
            ports << single;
        }
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

QList<int> PortScannerModule::presetPorts(const QString &presetName) const
{
    const QString preset = presetName.trimmed().toLower();
    if (preset == "web") {
        return {80, 443, 8080, 8443, 3000, 5000};
    }
    if (preset == "db" || preset == "database") {
        return {3306, 5432, 1433, 27017, 6379};
    }
    if (preset == "full") {
        QList<int> full;
        full.reserve(65535);
        for (int port = 1; port <= 65535; ++port) {
            full << port;
        }
        return full;
    }
    return commonPorts();
}

QList<int> PortScannerModule::commonPorts() const
{
    return {
        7, 9, 13, 21, 22, 23, 25, 37, 53, 79, 80, 81, 88, 110, 111, 113, 119, 123, 135, 137,
        138, 139, 143, 161, 179, 199, 389, 427, 443, 445, 465, 500, 512, 513, 514, 515, 543, 544,
        548, 554, 587, 631, 636, 873, 902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080,
        1194, 1214, 1433, 1434, 1521, 1720, 1723, 1883, 1900, 2049, 2082, 2083, 2086, 2087, 2483,
        2484, 3128, 3306, 3389, 3690, 4333, 4444, 4664, 4899, 5000, 5001, 5060, 5432, 5631, 5666,
        5800, 5900, 5985, 5986, 6000, 6379, 6667, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
        9090, 9200, 9300, 9418, 9999, 10000, 11211, 27017
    };
}

QList<QString> PortScannerModule::expandIpRange(const QString &spec) const
{
    const QStringList bounds = splitAndTrim(spec, '-');
    if (bounds.size() != 2) {
        return {};
    }

    QHostAddress startAddress(bounds.at(0));
    if (startAddress.protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }

    QHostAddress endAddress(bounds.at(1));
    if (endAddress.protocol() != QAbstractSocket::IPv4Protocol) {
        const QStringList octets = bounds.at(0).split('.');
        if (octets.size() == 4) {
            endAddress = QHostAddress(QString("%1.%2.%3.%4").arg(octets.at(0), octets.at(1), octets.at(2), bounds.at(1)));
        }
    }

    if (endAddress.protocol() != QAbstractSocket::IPv4Protocol) {
        return {};
    }

    const quint32 start = ipv4ToInt(startAddress);
    const quint32 end = ipv4ToInt(endAddress);
    if (end < start || (end - start) > 4096) {
        return {};
    }

    QList<QString> hosts;
    for (quint32 value = start; value <= end; ++value) {
        hosts << intToIpv4(value).toString();
    }
    return hosts;
}

QList<QString> PortScannerModule::expandCidr(const QString &spec) const
{
    const QStringList parts = spec.split('/');
    if (parts.size() != 2) {
        return {};
    }

    const QHostAddress base(parts.at(0));
    const int prefix = parts.at(1).toInt();
    if (base.protocol() != QAbstractSocket::IPv4Protocol || prefix < 0 || prefix > 32) {
        return {};
    }

    const quint32 ip = ipv4ToInt(base);
    const quint32 mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    const quint32 network = ip & mask;
    const quint32 broadcast = network | ~mask;
    if ((broadcast - network) > 4096) {
        return {};
    }

    QList<QString> hosts;
    const quint32 start = prefix <= 30 ? network + 1 : network;
    const quint32 end = prefix <= 30 ? broadcast - 1 : broadcast;
    for (quint32 value = start; value <= end; ++value) {
        hosts << intToIpv4(value).toString();
    }
    return hosts;
}

QString PortScannerModule::defaultExportPath(const QString &format) const
{
    const QString suffix = normalizeFileFormat(format).isEmpty() ? "json" : normalizeFileFormat(format);
    return QCoreApplication::applicationDirPath()
        + QString("/port-scan-%1.%2").arg(QDateTime::currentDateTime().toString("yyyyMMdd-hhmmss"), suffix);
}

void PortScannerModule::resetForScan()
{
    m_results.clear();
    m_openPorts = 0;
    m_scannedCount = 0;
    m_totalTasks = 0;
    m_progress = 0.0;
    m_portsPerSecond = 0.0;
    m_etaText = "--";
    m_elapsedText = "00:00";
    emit resultsChanged();
}

void PortScannerModule::finalizeScan(const QString &finalStatus)
{
    if (!m_scanning) {
        return;
    }

    m_scanning = false;
    m_statusText = finalStatus;
    m_progress = 1.0;
    updateStats();

    emit scanningChanged();
    emit statusTextChanged();
    emit progressChanged();
    emit scanFinished();

    if (m_logger) {
        m_logger->info(id(), QString("Scan finished: %1 open ports across %2 results")
                                 .arg(m_openPorts)
                                 .arg(m_results.size()));
    }
}

void PortScannerModule::updateStats()
{
    const qint64 elapsedMs = qMax<qint64>(1, m_startedAtUtc.msecsTo(QDateTime::currentDateTimeUtc()));
    m_progress = m_totalTasks > 0 ? static_cast<double>(m_scannedCount) / static_cast<double>(m_totalTasks) : 0.0;
    m_portsPerSecond = (static_cast<double>(m_scannedCount) * 1000.0) / static_cast<double>(elapsedMs);
    const qint64 remainingTasks = qMax(0, m_totalTasks - m_scannedCount);
    const qint64 etaMs = m_portsPerSecond > 0.01 ? static_cast<qint64>((remainingTasks / m_portsPerSecond) * 1000.0) : 0;
    const int elapsedSeconds = static_cast<int>(elapsedMs / 1000);
    m_elapsedText = QString("%1:%2")
                        .arg(elapsedSeconds / 60, 2, 10, QLatin1Char('0'))
                        .arg(elapsedSeconds % 60, 2, 10, QLatin1Char('0'));
    m_etaText = etaMs <= 0 ? "00:00"
                           : QString("%1:%2")
                                 .arg(static_cast<int>(etaMs / 1000) / 60, 2, 10, QLatin1Char('0'))
                                 .arg(static_cast<int>(etaMs / 1000) % 60, 2, 10, QLatin1Char('0'));
    emit statsChanged();
    emit progressChanged();
}

bool PortScannerModule::writeResults(const QVariantList &rows, const QString &filePath, const QString &format) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    const QString normalized = normalizeFileFormat(format);
    if (normalized == "csv") {
        QTextStream stream(&file);
        stream << "IP,Port,Protocol,State,Service,Banner,ResponseTimeMs,OSFingerprint\n";
        for (const QVariant &rowValue : rows) {
            const QVariantMap row = rowValue.toMap();
            stream << csvEscape(row.value("ip").toString()) << ','
                   << csvEscape(row.value("port").toString()) << ','
                   << csvEscape(row.value("protocol").toString()) << ','
                   << csvEscape(row.value("state").toString()) << ','
                   << csvEscape(row.value("service").toString()) << ','
                   << csvEscape(row.value("banner").toString()) << ','
                   << csvEscape(row.value("responseTimeMs").toString()) << ','
                   << csvEscape(row.value("osFingerprint").toString()) << '\n';
        }
        return true;
    }

    if (normalized == "txt") {
        QTextStream stream(&file);
        for (const QVariant &rowValue : rows) {
            const QVariantMap row = rowValue.toMap();
            stream << row.value("ip").toString() << ':'
                   << row.value("port").toString() << ' '
                   << row.value("protocol").toString() << ' '
                   << row.value("state").toString() << ' '
                   << row.value("service").toString() << ' '
                   << row.value("banner").toString() << ' '
                   << row.value("responseTime").toString() << '\n';
        }
        return true;
    }

    QJsonArray array;
    for (const QVariant &rowValue : rows) {
        array.append(QJsonObject::fromVariantMap(rowValue.toMap()));
    }
    file.write(QJsonDocument(array).toJson(QJsonDocument::Indented));
    return true;
}

REGISTER_MODULE(PortScannerModule, "port_scanner");
