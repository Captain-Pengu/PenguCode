#pragma once

#include "core/framework/moduleinterface.h"

#include <QDateTime>
#include <QMap>
#include <QObject>
#include <QTcpSocket>
#include <QThreadPool>
#include <QRunnable>
#include <QVariantList>
#include <atomic>

class SettingsManager;
class Logger;

struct ScanResult
{
    QString ip;
    int port = 0;
    QString protocol;
    QString state;
    QString serviceName;
    QString banner;
    qint64 responseTimeMs = -1;
    QString osFingerprint;

    QVariantMap toVariantMap() const;
};

Q_DECLARE_METATYPE(ScanResult)

class PortScanWorker : public QObject, public QRunnable
{
    Q_OBJECT

public:
    enum class ScanMode {
        TcpConnect,
        Udp,
        ServiceDetect,
        OsFingerprint
    };

    PortScanWorker(QString host,
                   int port,
                   ScanMode mode,
                   int timeoutMs,
                   int retryCount,
                   bool serviceDetection,
                   bool osFingerprinting,
                   const std::atomic_bool *cancelled);

    void run() override;

signals:
    void scanCompleted(const ScanResult &result);
    void serviceBannerDetected(const QString &ip, int port, const QString &serviceName, const QString &banner);

private:
    ScanResult performTcpConnect() const;
    ScanResult performUdpScan() const;
    QString detectServiceName(int port, const QString &banner) const;
    QString detectBanner(QTcpSocket &socket, int port, int timeoutMs) const;
    QString guessOsFingerprint(const QString &banner, const QString &serviceName) const;

    QString m_host;
    int m_port = 0;
    ScanMode m_mode = ScanMode::TcpConnect;
    int m_timeoutMs = 500;
    int m_retryCount = 0;
    bool m_serviceDetection = false;
    bool m_osFingerprinting = false;
    const std::atomic_bool *m_cancelled = nullptr;
};

class PortScannerModule : public ModuleInterface
{
    Q_OBJECT
    Q_PROPERTY(QString targetSpec READ targetSpec WRITE setTargetSpec NOTIFY configurationChanged)
    Q_PROPERTY(QString portSpec READ portSpec WRITE setPortSpec NOTIFY configurationChanged)
    Q_PROPERTY(QString scanType READ scanType WRITE setScanType NOTIFY configurationChanged)
    Q_PROPERTY(int threadCount READ threadCount WRITE setThreadCount NOTIFY configurationChanged)
    Q_PROPERTY(int timeoutMs READ timeoutMs WRITE setTimeoutMs NOTIFY configurationChanged)
    Q_PROPERTY(int retryCount READ retryCount WRITE setRetryCount NOTIFY configurationChanged)
    Q_PROPERTY(bool serviceDetectionEnabled READ serviceDetectionEnabled WRITE setServiceDetectionEnabled NOTIFY configurationChanged)
    Q_PROPERTY(bool osFingerprintingEnabled READ osFingerprintingEnabled WRITE setOsFingerprintingEnabled NOTIFY configurationChanged)
    Q_PROPERTY(bool scanning READ scanning NOTIFY scanningChanged)
    Q_PROPERTY(QVariantList results READ results NOTIFY resultsChanged)
    Q_PROPERTY(int openPorts READ openPorts NOTIFY statsChanged)
    Q_PROPERTY(int scannedCount READ scannedCount NOTIFY statsChanged)
    Q_PROPERTY(int totalTasks READ totalTasks NOTIFY statsChanged)
    Q_PROPERTY(double progress READ progress NOTIFY progressChanged)
    Q_PROPERTY(double portsPerSecond READ portsPerSecond NOTIFY statsChanged)
    Q_PROPERTY(QString etaText READ etaText NOTIFY statsChanged)
    Q_PROPERTY(QString elapsedText READ elapsedText NOTIFY statsChanged)
    Q_PROPERTY(QString statusText READ statusText NOTIFY statusTextChanged)

public:
    explicit PortScannerModule(QObject *parent = nullptr);
    ~PortScannerModule() override;

    QString id() const override;
    QString name() const override;
    QString description() const override;
    QString icon() const override;
    QUrl pageSource() const override;

    void initialize(SettingsManager *settings, Logger *logger) override;
    QVariantMap defaultSettings() const override;

    QString targetSpec() const;
    QString portSpec() const;
    QString scanType() const;
    int threadCount() const;
    int timeoutMs() const;
    int retryCount() const;
    bool serviceDetectionEnabled() const;
    bool osFingerprintingEnabled() const;
    bool scanning() const;
    QVariantList results() const;
    int openPorts() const;
    int scannedCount() const;
    int totalTasks() const;
    double progress() const;
    double portsPerSecond() const;
    QString etaText() const;
    QString elapsedText() const;
    QString statusText() const;

    static const QMap<int, QString> &serviceNameLookup();

    Q_INVOKABLE void configureScan(const QString &targetSpec,
                                   const QString &portSpec,
                                   const QString &scanType,
                                   int threadCount,
                                   int timeoutMs,
                                   int retryCount,
                                   bool serviceDetection,
                                   bool osFingerprinting);
    Q_INVOKABLE QVariantList scanTypeOptions() const;
    Q_INVOKABLE QVariantList presetPortGroups() const;
    Q_INVOKABLE void applyPreset(const QString &presetName);
    Q_INVOKABLE bool exportResults(const QString &filePath, const QString &format) const;
    Q_INVOKABLE bool exportRow(const QVariantMap &row, const QString &filePath, const QString &format) const;
    Q_INVOKABLE void copyRow(const QVariantMap &row) const;
    Q_INVOKABLE void investigatePort(const QVariantMap &row);
    Q_INVOKABLE void reloadSettings();

public slots:
    void start() override;
    void stop() override;

    void setTargetSpec(const QString &value);
    void setPortSpec(const QString &value);
    void setScanType(const QString &value);
    void setThreadCount(int value);
    void setTimeoutMs(int value);
    void setRetryCount(int value);
    void setServiceDetectionEnabled(bool value);
    void setOsFingerprintingEnabled(bool value);

signals:
    void portFound(const QVariantMap &result);
    void serviceDetected(const QString &ip, int port, const QString &serviceName, const QString &banner);
    void scanProgress(int scanned, int total, double percent, double portsPerSecond, const QString &etaText);
    void scanFinished();
    void configurationChanged();
    void scanningChanged();
    void resultsChanged();
    void statsChanged();
    void progressChanged();
    void statusTextChanged();

private slots:
    void handleWorkerResult(const ScanResult &result);
    void handleServiceDetected(const QString &ip, int port, const QString &serviceName, const QString &banner);

private:
    enum class ScanMode {
        TcpConnect,
        Udp,
        ServiceDetect,
        OsFingerprint
    };

    QString normalizedScanType(const QString &value) const;
    QList<QString> expandTargets(const QString &spec) const;
    QList<int> expandPorts(const QString &spec) const;
    QList<int> presetPorts(const QString &presetName) const;
    QList<int> commonPorts() const;
    QList<QString> expandIpRange(const QString &spec) const;
    QList<QString> expandCidr(const QString &spec) const;
    QString defaultExportPath(const QString &format) const;
    void resetForScan();
    void finalizeScan(const QString &finalStatus);
    void updateStats();
    bool writeResults(const QVariantList &rows, const QString &filePath, const QString &format) const;

    SettingsManager *m_settings = nullptr;
    Logger *m_logger = nullptr;
    QThreadPool m_threadPool;
    std::atomic_bool m_cancelled{false};

    QString m_targetSpec;
    QString m_portSpec;
    QString m_scanType;
    int m_threadCount = 64;
    int m_timeoutMs = 500;
    int m_retryCount = 1;
    bool m_serviceDetectionEnabled = true;
    bool m_osFingerprintingEnabled = false;
    bool m_scanning = false;
    QVariantList m_results;
    int m_openPorts = 0;
    int m_scannedCount = 0;
    int m_totalTasks = 0;
    double m_progress = 0.0;
    double m_portsPerSecond = 0.0;
    QString m_etaText = "--";
    QString m_elapsedText = "00:00";
    QString m_statusText = "Idle";
    QDateTime m_startedAtUtc;
};
