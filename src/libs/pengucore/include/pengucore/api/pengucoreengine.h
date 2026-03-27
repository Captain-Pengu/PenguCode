#pragma once

#include "pengucore/model/packettypes.h"

#include <QDateTime>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QVector>

namespace pengufoce::pengucore {

class LiveCaptureEngine;
class PcapFileWriter;

class PenguCoreEngine : public QObject
{
    Q_OBJECT

public:
    explicit PenguCoreEngine(QObject *parent = nullptr);

    const QVector<PacketRecord> &packets() const;
    const QVector<FlowStats> &flows() const;
    QString statusText() const;
    QString lastOpenedFile() const;
    QString lastOpenedFormat() const;
    QDateTime lastSessionOpenedUtc() const;
    QVector<CaptureAdapterInfo> liveAdapters() const;
    QString liveCaptureFilter() const;
    void setLiveCaptureFilter(const QString &captureFilter);
    QString liveSaveFormat() const;
    void setLiveSaveFormat(const QString &saveFormat);
    bool refreshLiveAdapters();
    bool startLiveCapture(const QString &adapterName);
    void stopLiveCapture();
    bool isLiveCaptureRunning() const;
    QString lastLiveCaptureSavePath() const;
    bool openLastLiveCaptureFile();
    qint64 liveDroppedFrameCount() const;
    qint64 liveTrimmedFrameCount() const;
    qint64 liveCapturedFrameCount() const;
    qint64 liveAnalyzedFrameCount() const;
    double livePacketsPerSecond() const;
    double liveBytesPerSecond() const;
    QDateTime liveCaptureStartedUtc() const;
    QDateTime liveCaptureStoppedUtc() const;
    qint64 liveCaptureDurationMs() const;
    QString liveHealthStatus() const;

    bool openCaptureFile(const QString &filePath);
    void clearSession();

signals:
    void sessionReset();
    void sessionUpdated();
    void statusChanged(const QString &message);
    void liveAdaptersChanged();
    void liveCaptureStateChanged(bool running, const QString &message);

private:
    bool loadCaptureSession(const QString &filePath);
    QVector<RawFrame> ingestFrames(const QVector<RawFrame> &frames) const;
    QVector<PacketRecord> parseFrames(const QVector<RawFrame> &frames) const;
    void classifyPackets(QVector<PacketRecord> &packets) const;
    void appendLiveFrame(const RawFrame &frame);
    void flushPendingLiveFrames();
    void rebuildFlows();
    void updateFlowState();
    void emitSessionState(const QString &message, bool reset = false);
    void stressSafeShutdownLiveCapture();

    QVector<PacketRecord> m_packets;
    QVector<FlowStats> m_flows;
    QVector<RawFrame> m_pendingLiveFrames;
    qint64 m_liveDroppedFrameCount = 0;
    qint64 m_liveTrimmedFrameCount = 0;
    qint64 m_liveCapturedFrameCount = 0;
    qint64 m_liveAnalyzedFrameCount = 0;
    int m_liveFlushCount = 0;
    double m_livePacketsPerSecond = 0.0;
    double m_liveBytesPerSecond = 0.0;
    QString m_statusText;
    QString m_lastOpenedFile;
    QString m_lastOpenedFormat;
    QString m_lastLiveCaptureSavePath;
    QString m_liveCaptureFilter;
    QString m_liveSaveFormat = QStringLiteral("pcap");
    QDateTime m_lastSessionOpenedUtc;
    QDateTime m_lastLiveMetricSampleUtc;
    QDateTime m_liveCaptureStartedUtc;
    QDateTime m_liveCaptureStoppedUtc;
    LiveCaptureEngine *m_liveCapture = nullptr;
    PcapFileWriter *m_liveCaptureWriter = nullptr;
    QTimer *m_liveFlushTimer = nullptr;
    bool m_liveStopRequested = false;
};

} // namespace pengufoce::pengucore
