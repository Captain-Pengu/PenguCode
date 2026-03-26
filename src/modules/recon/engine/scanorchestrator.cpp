#include "scanorchestrator.h"

#include "core/logging/logger.h"
#include "modules/recon/engine/dnsreconmodule.h"
#include "modules/recon/engine/fastportscannermodule.h"
#include "modules/recon/engine/osintandleakmodule.h"
#include "modules/recon/engine/vulnmatchermodule.h"

ScanOrchestrator::ScanOrchestrator(QObject *parent)
    : QObject(parent)
    , m_fastPortScanner(new FastPortScannerModule(this))
    , m_dnsRecon(new DnsReconModule())
    , m_osint(new OsintAndLeakModule())
    , m_vulnMatcher(new VulnMatcherModule())
{
    registerMetaTypes();

    m_dnsRecon->moveToThread(&m_dnsThread);
    m_osint->moveToThread(&m_osintThread);
    m_vulnMatcher->moveToThread(&m_vulnThread);

    connect(&m_dnsThread, &QThread::finished, m_dnsRecon, &QObject::deleteLater);
    connect(&m_osintThread, &QThread::finished, m_osint, &QObject::deleteLater);
    connect(&m_vulnThread, &QThread::finished, m_vulnMatcher, &QObject::deleteLater);

    connect(this, &ScanOrchestrator::requestDnsLookup, m_dnsRecon, &DnsReconModule::startLookup, Qt::QueuedConnection);
    connect(this, &ScanOrchestrator::requestLeakCheck, m_osint, &OsintAndLeakModule::queryPublicLeaks, Qt::QueuedConnection);
    connect(this, &ScanOrchestrator::requestVulnerabilityMatch, m_vulnMatcher, &VulnMatcherModule::matchServiceAsync, Qt::QueuedConnection);

    connect(m_fastPortScanner, &FastPortScannerModule::portFound, this, &ScanOrchestrator::handlePortFound);
    connect(m_fastPortScanner, &FastPortScannerModule::bannerGrabbed, this, &ScanOrchestrator::handleBannerGrabbed);
    connect(m_fastPortScanner, &FastPortScannerModule::statusMessage, this, &ScanOrchestrator::handleModuleStatus);
    connect(m_fastPortScanner, &FastPortScannerModule::scanFinished, this, &ScanOrchestrator::handlePortScanFinished);

    connect(m_dnsRecon, &DnsReconModule::dnsRecordFound, this, &ScanOrchestrator::handleDnsRecordFound);
    connect(m_dnsRecon, &DnsReconModule::misconfigurationFound, this, &ScanOrchestrator::handleLeakDetected);
    connect(m_dnsRecon, &DnsReconModule::statusMessage, this, &ScanOrchestrator::handleModuleStatus);
    connect(m_dnsRecon, &DnsReconModule::lookupFinished, this, &ScanOrchestrator::handleDnsFinished);

    connect(m_osint, &OsintAndLeakModule::leakDetected, this, &ScanOrchestrator::handleLeakDetected);
    connect(m_osint, &OsintAndLeakModule::statusMessage, this, &ScanOrchestrator::handleModuleStatus);
    connect(m_osint, &OsintAndLeakModule::queryFinished, this, &ScanOrchestrator::handleOsintFinished);

    connect(m_vulnMatcher, &VulnMatcherModule::vulnerabilityMatched, this, &ScanOrchestrator::handleVulnerabilityMatched);
    connect(m_vulnMatcher, &VulnMatcherModule::statusMessage, this, &ScanOrchestrator::handleModuleStatus);

    m_dnsThread.start();
    m_osintThread.start();
    m_vulnThread.start();
}

ScanOrchestrator::~ScanOrchestrator()
{
    stopAll();
    stopThreads();
}

void ScanOrchestrator::setLogger(Logger *logger)
{
    m_logger = logger;
}

void ScanOrchestrator::startRecon(const QString &target,
                                  const QString &domain,
                                  const QList<int> &ports,
                                  const QUrl &osintEndpoint,
                                  int timeoutMs)
{
    resetJobState();
    emit scanStarted(target);

    if (!ports.isEmpty()) {
        markJobStarted(JobKind::PortScan);
        m_fastPortScanner->startScan(target, ports, timeoutMs);
    }

    if (!domain.trimmed().isEmpty()) {
        markJobStarted(JobKind::Dns);
        emit requestDnsLookup(domain);
    }

    if (osintEndpoint.isValid() && !osintEndpoint.isEmpty()) {
        markJobStarted(JobKind::Osint);
        emit requestLeakCheck(domain.isEmpty() ? target : domain, osintEndpoint, QString());
    }

    if (m_logger) {
        m_logger->info("scan_orchestrator",
                       QString("Recon started for target=%1 domain=%2 ports=%3")
                           .arg(target, domain)
                           .arg(ports.size()));
    }

    if (m_activeJobs == 0) {
        emit reconFinished();
    }
}

void ScanOrchestrator::stopAll()
{
    if (m_fastPortScanner) {
        m_fastPortScanner->stop();
    }
    resetJobState();
}

void ScanOrchestrator::handlePortFound(int port, const QString &service)
{
    emit portFound(port, service);
    if (m_logger) {
        m_logger->info("fast_port_scanner", QString("Open port %1 (%2)").arg(port).arg(service));
    }
}

void ScanOrchestrator::handleBannerGrabbed(const ServiceFingerprint &fingerprint)
{
    emit bannerGrabbed(fingerprint);
    emit requestVulnerabilityMatch(fingerprint);
}

void ScanOrchestrator::handleDnsRecordFound(const QString &type, const QString &value)
{
    emit dnsRecordFound(type, value);
}

void ScanOrchestrator::handleLeakDetected(const QString &severity, const QString &details)
{
    emit leakDetected(severity, details);
    if (m_logger) {
        m_logger->warning("recon", QString("[%1] %2").arg(severity, details));
    }
}

void ScanOrchestrator::handleVulnerabilityMatched(const VulnerabilityMatch &match)
{
    emit vulnerabilityMatched(match);
    if (m_logger) {
        m_logger->warning("vuln_matcher",
                          QString("%1 matched for %2:%3 (%4)")
                              .arg(match.cveId, match.host)
                              .arg(match.port)
                              .arg(match.service));
    }
}

void ScanOrchestrator::handleModuleStatus(const QString &message)
{
    const QString moduleName = sender() ? sender()->metaObject()->className() : QString("scan");
    emit statusMessage(moduleName, message);
    if (m_logger) {
        m_logger->info(moduleName.toLower(), message);
    }
}

void ScanOrchestrator::handlePortScanFinished()
{
    markJobFinished(JobKind::PortScan);
}

void ScanOrchestrator::handleDnsFinished()
{
    markJobFinished(JobKind::Dns);
}

void ScanOrchestrator::handleOsintFinished()
{
    markJobFinished(JobKind::Osint);
}

void ScanOrchestrator::registerMetaTypes()
{
    qRegisterMetaType<ServiceFingerprint>("ServiceFingerprint");
    qRegisterMetaType<DnsRecordResult>("DnsRecordResult");
    qRegisterMetaType<LeakFinding>("LeakFinding");
    qRegisterMetaType<VulnerabilityMatch>("VulnerabilityMatch");
}

void ScanOrchestrator::resetJobState()
{
    m_activeJobs = 0;
    m_portScanPending = false;
    m_dnsPending = false;
    m_osintPending = false;
    m_finishEmitted = false;
}

void ScanOrchestrator::markJobStarted(JobKind kind)
{
    bool *flag = nullptr;
    switch (kind) {
    case JobKind::PortScan:
        flag = &m_portScanPending;
        break;
    case JobKind::Dns:
        flag = &m_dnsPending;
        break;
    case JobKind::Osint:
        flag = &m_osintPending;
        break;
    }

    if (flag && !*flag) {
        *flag = true;
        ++m_activeJobs;
        m_finishEmitted = false;
    }
}

void ScanOrchestrator::markJobFinished(JobKind kind)
{
    bool *flag = nullptr;
    switch (kind) {
    case JobKind::PortScan:
        flag = &m_portScanPending;
        break;
    case JobKind::Dns:
        flag = &m_dnsPending;
        break;
    case JobKind::Osint:
        flag = &m_osintPending;
        break;
    }

    if (!flag || !*flag) {
        return;
    }

    *flag = false;
    if (m_activeJobs > 0) {
        --m_activeJobs;
    }

    if (m_activeJobs == 0 && !m_finishEmitted) {
        m_finishEmitted = true;
        emit reconFinished();
    }
}

void ScanOrchestrator::stopThreads()
{
    for (QThread *thread : {&m_dnsThread, &m_osintThread, &m_vulnThread}) {
        thread->quit();
        thread->wait();
    }
}
