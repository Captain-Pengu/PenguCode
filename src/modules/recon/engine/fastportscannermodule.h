#pragma once

#include "scantypes.h"

#include <QObject>
#include <QThreadPool>
#include <QStringList>
#include <atomic>

class FastPortScannerModule : public QObject
{
    Q_OBJECT

public:
    explicit FastPortScannerModule(QObject *parent = nullptr);
    ~FastPortScannerModule() override;

public slots:
    void startScan(const QString &target, const QList<int> &ports, int timeoutMs = 500, int concurrency = 128);
    void stop();

signals:
    void portFound(int port, const QString &service);
    void bannerGrabbed(const ServiceFingerprint &fingerprint);
    void progressChanged(int completed, int total);
    void scanFinished();
    void statusMessage(const QString &message);

private slots:
    void handleProbeFinished(const ServiceFingerprint &fingerprint);

private:
    QString normalizedServiceName(int port, const QString &banner) const;
    QString extractedVersion(const QString &banner) const;

    QThreadPool m_threadPool;
    std::atomic_bool m_cancelled{false};
    int m_totalTasks = 0;
    int m_completedTasks = 0;
};
