#pragma once

#include "scantypes.h"
#include "reconorchestratorstate.h"

#include <QObject>
#include <QPointer>
#include <QThread>
#include <QUrl>

class Logger;
class FastPortScannerModule;
class DnsReconModule;
class OsintAndLeakModule;
class VulnMatcherModule;

class ScanOrchestrator : public QObject
{
    Q_OBJECT

public:
    explicit ScanOrchestrator(QObject *parent = nullptr);
    ~ScanOrchestrator() override;

    void setLogger(Logger *logger);

public slots:
    void startRecon(const QString &target,
                    const QString &domain,
                    const QList<int> &ports,
                    const QUrl &osintEndpoint = QUrl(),
                    int timeoutMs = 500);
    void stopAll();

signals:
    void requestDnsLookup(const QString &domain);
    void requestLeakCheck(const QString &target, const QUrl &endpoint, const QString &apiKey);
    void requestVulnerabilityMatch(const ServiceFingerprint &fingerprint);

    void scanStarted(const QString &target);
    void statusMessage(const QString &module, const QString &message);
    void portFound(int port, const QString &service);
    void bannerGrabbed(const ServiceFingerprint &fingerprint);
    void dnsRecordFound(const QString &type, const QString &value);
    void leakDetected(const QString &severity, const QString &details);
    void vulnerabilityMatched(const VulnerabilityMatch &match);
    void reconFinished();

private slots:
    void handlePortFound(int port, const QString &service);
    void handleBannerGrabbed(const ServiceFingerprint &fingerprint);
    void handleDnsRecordFound(const QString &type, const QString &value);
    void handleLeakDetected(const QString &severity, const QString &details);
    void handleVulnerabilityMatched(const VulnerabilityMatch &match);
    void handleModuleStatus(const QString &message);
    void handlePortScanFinished();
    void handleDnsFinished();
    void handleOsintFinished();

private:
    void registerMetaTypes();
    void stopThreads();
    void resetJobState();
    void markJobStarted(ReconOrchestratorState::JobKind kind);
    void markJobFinished(ReconOrchestratorState::JobKind kind);

    Logger *m_logger = nullptr;
    FastPortScannerModule *m_fastPortScanner = nullptr;
    DnsReconModule *m_dnsRecon = nullptr;
    OsintAndLeakModule *m_osint = nullptr;
    VulnMatcherModule *m_vulnMatcher = nullptr;
    QThread m_dnsThread;
    QThread m_osintThread;
    QThread m_vulnThread;
    ReconOrchestratorState m_jobState;
};
