#pragma once

#include "pengucore/model/packettypes.h"

#include <QObject>
#include <QVector>

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

struct pcap;

namespace pengufoce::pengucore {

class LiveCaptureEngine : public QObject
{
    Q_OBJECT

public:
    explicit LiveCaptureEngine(QObject *parent = nullptr);
    ~LiveCaptureEngine() override;

    QVector<CaptureAdapterInfo> adapters() const;
    bool refreshAdapters();
    bool startCapture(const QString &adapterName, const QString &captureFilter = QString());
    void stopCapture();
    bool isRunning() const;
    QString lastError() const;

signals:
    void adaptersChanged();
    void packetCaptured(const pengufoce::pengucore::RawFrame &frame);
    void captureStateChanged(bool running, const QString &message);

private:
    void captureLoop(QString adapterName, QString captureFilter);
    void setError(const QString &message);

    QVector<CaptureAdapterInfo> m_adapters;
    std::atomic_bool m_running = false;
    std::atomic_bool m_stopRequested = false;
    std::thread m_captureThread;
    pcap *m_activeHandle = nullptr;
    std::mutex m_handleMutex;
    QString m_lastError;
    int m_nextFrameNumber = 1;
};

} // namespace pengufoce::pengucore
