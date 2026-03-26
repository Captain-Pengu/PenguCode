#pragma once

#include <QHostInfo>
#include <QObject>
#include <QSet>
#include <QThreadPool>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

class QDnsLookup;
class QNetworkAccessManager;
class QNetworkReply;
class Logger;

struct ScanFinding
{
    QString severity;
    QString title;
    QString description;
    QString category;

    QVariantMap toVariantMap() const
    {
        return {
            {"severity", severity},
            {"title", title},
            {"description", description},
            {"category", category}
        };
    }
};

struct ScanReport
{
    QString originalTarget;
    QString sanitizedTarget;
    QString host;
    QString scheme;
    QString resolvedIp;
    QVariantList openPorts;
    QVariantList dnsRecords;
    QVariantList findings;
    QVariantList webObservations;
    QVariantList osintObservations;
    QVariantList subdomains;
    QVariantList archivedUrls;
    QVariantList jsFindings;
    QVariantList cveMatches;
    QVariantMap whoisInfo;
    QVariantList spiderEndpoints;
    QVariantList spiderParameters;
    QVariantList spiderAssets;

    QVariantMap toVariantMap() const
    {
        return {
            {"originalTarget", originalTarget},
            {"sanitizedTarget", sanitizedTarget},
            {"host", host},
            {"scheme", scheme},
            {"resolvedIp", resolvedIp},
            {"openPorts", openPorts},
            {"dnsRecords", dnsRecords},
            {"findings", findings},
            {"webObservations", webObservations},
            {"osintObservations", osintObservations},
            {"subdomains", subdomains},
            {"archivedUrls", archivedUrls},
            {"jsFindings", jsFindings},
            {"cveMatches", cveMatches},
            {"whoisInfo", whoisInfo},
            {"spiderEndpoints", spiderEndpoints},
            {"spiderParameters", spiderParameters},
            {"spiderAssets", spiderAssets}
        };
    }
};

Q_DECLARE_METATYPE(ScanFinding)
Q_DECLARE_METATYPE(ScanReport)

class PenguFoceMasterScanner : public QObject
{
    Q_OBJECT

public:
    explicit PenguFoceMasterScanner(QObject *parent = nullptr);
    ~PenguFoceMasterScanner() override;

    void setLogger(Logger *logger);

public slots:
    void startScan(const QString &target, const QUrl &osintEndpoint = QUrl());
    void stop();

signals:
    void scanProgress(int percent);
    void findingDiscovered(const QString &severity, const QString &title, const QString &description);
    void scanFinished(const ScanReport &finalReport, int securityScore);
    void statusMessage(const QString &message);

private slots:
    void handleResolvedHost(const QHostInfo &info);
    void handlePortTaskResult(const QVariantList &openPorts);
    void handleWebReply();
    void handleOsintReply();
    void handleDnsLookupFinished();

private:
    struct ParsedTarget {
        QString original;
        QString sanitized;
        QString host;
        QString scheme;
        QUrl url;
    };

    ParsedTarget parseTarget(const QString &target) const;
    void resetScanState();
    void registerStageStarted();
    void registerStageFinished();
    void updateProgress();
    void addFinding(const QString &severity,
                    const QString &title,
                    const QString &description,
                    const QString &category,
                    int penalty);
    int calculateSecurityScore() const;
    QString severityForPenalty(int penalty) const;
    void analyzeWebReply(QNetworkReply *reply);
    void analyzeTls(QNetworkReply *reply);
    void startDnsRecon(const QString &host);
    void startOsintTask(const QString &host);
    void startSubdomainRecon(const QString &host);
    void startWaybackRecon(const QString &host);
    void startDirectoryFuzzing(const QUrl &baseUrl);
    void startTechnologyRecon(const QUrl &baseUrl);
    void startWhoisTask(const QString &host);
    void startCveLookup(const QString &product, const QString &version);
    QVariantMap makeDnsRecord(const QString &type, const QString &value) const;
    void addOpenPort(const QVariantMap &row);
    bool shouldScanWeb() const;
    bool isDomainTarget() const;

    Logger *m_logger = nullptr;
    QThreadPool m_threadPool;
    QNetworkAccessManager *m_networkAccessManager = nullptr;
    ParsedTarget m_currentTarget;
    ScanReport m_report;
    QUrl m_osintEndpoint;
    QList<QDnsLookup *> m_dnsLookups;
    int m_pendingStages = 0;
    int m_totalStages = 0;
    int m_securityScore = 100;
    bool m_cancelled = false;
    QSet<QString> m_findingKeys;
    QSet<QString> m_openPortKeys;
    QSet<QString> m_seenArtifacts;
};
