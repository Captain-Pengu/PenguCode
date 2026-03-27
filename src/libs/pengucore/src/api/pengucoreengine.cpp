#include "pengucore/api/pengucoreengine.h"

#include "pengucore/capture/livecaptureengine.h"
#include "pengucore/capture/pcapfilereader.h"
#include "pengucore/capture/pcapfilewriter.h"
#include "pengucore/flow/flowtracker.h"
#include "pengucore/parser/basicframeparser.h"

#include <QDir>
#include <QMetaType>
#include <QStandardPaths>

namespace pengufoce::pengucore {

namespace {

constexpr int kLiveFlushIntervalMs = 180;
constexpr int kLiveImmediateFlushThreshold = 64;
constexpr int kLivePendingFrameLimit = 256;
constexpr int kLiveStoredPacketLimit = 600;
constexpr int kLiveFlowRebuildEveryNFlushes = 4;

QString buildLiveCaptureSavePath(const QString &format)
{
    QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (baseDir.isEmpty()) {
        baseDir = QDir::tempPath() + QStringLiteral("/PenguFoce");
    }

    QDir dir(baseDir);
    dir.mkpath(QStringLiteral("pengucore/live"));
    const QString normalizedFormat = format.trimmed().toLower();
    const QString extension = normalizedFormat == QStringLiteral("pcapng") ? QStringLiteral("pcapng") : QStringLiteral("pcap");
    return dir.filePath(QStringLiteral("pengucore/live/live_capture_%1.%2")
                            .arg(QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd_hhmmss_zzz")),
                                 extension));
}

QString classifyLiveHealth(qint64 capturedFrames, qint64 droppedFrames, qint64 trimmedFrames)
{
    if (capturedFrames <= 0) {
        return QStringLiteral("IDLE");
    }

    const qint64 impactedFrames = droppedFrames + trimmedFrames;
    if (impactedFrames <= 0) {
        return QStringLiteral("STABLE");
    }

    const double impactedRatio = static_cast<double>(impactedFrames) / static_cast<double>(std::max<qint64>(1, capturedFrames));
    if (impactedRatio < 0.02) {
        return QStringLiteral("STABLE");
    }
    if (impactedRatio < 0.10) {
        return QStringLiteral("DEGRADED");
    }
    return QStringLiteral("STRESSED");
}

}

PenguCoreEngine::PenguCoreEngine(QObject *parent)
    : QObject(parent)
    , m_liveCapture(new LiveCaptureEngine(this))
    , m_liveCaptureWriter(new PcapFileWriter())
    , m_liveFlushTimer(new QTimer(this))
{
    m_statusText = QStringLiteral("PenguCore hazir. Gercek pcap reader baglandi, parser pipeline sonraki adimda eklenecek.");
    m_liveFlushTimer->setInterval(kLiveFlushIntervalMs);
    m_liveFlushTimer->setSingleShot(true);
    connect(m_liveFlushTimer, &QTimer::timeout, this, &PenguCoreEngine::flushPendingLiveFrames);

    qRegisterMetaType<RawFrame>("pengufoce::pengucore::RawFrame");

    connect(m_liveCapture, &LiveCaptureEngine::packetCaptured, this, &PenguCoreEngine::appendLiveFrame, Qt::QueuedConnection);
    connect(m_liveCapture, &LiveCaptureEngine::adaptersChanged, this, &PenguCoreEngine::liveAdaptersChanged, Qt::QueuedConnection);
    connect(m_liveCapture, &LiveCaptureEngine::captureStateChanged, this, [this](bool running, const QString &message) {
        if (!message.isEmpty()) {
            m_statusText = message;
            emit statusChanged(m_statusText);
        }
        emit liveCaptureStateChanged(running, message);
    }, Qt::QueuedConnection);

    m_liveCapture->refreshAdapters();
}

const QVector<PacketRecord> &PenguCoreEngine::packets() const
{
    return m_packets;
}

const QVector<FlowStats> &PenguCoreEngine::flows() const
{
    return m_flows;
}

QString PenguCoreEngine::statusText() const
{
    return m_statusText;
}

QString PenguCoreEngine::lastOpenedFile() const
{
    return m_lastOpenedFile;
}

QString PenguCoreEngine::lastOpenedFormat() const
{
    return m_lastOpenedFormat;
}

QDateTime PenguCoreEngine::lastSessionOpenedUtc() const
{
    return m_lastSessionOpenedUtc;
}

QString PenguCoreEngine::liveCaptureFilter() const
{
    return m_liveCaptureFilter;
}

void PenguCoreEngine::setLiveCaptureFilter(const QString &captureFilter)
{
    m_liveCaptureFilter = captureFilter.trimmed();
}

QString PenguCoreEngine::liveSaveFormat() const
{
    return m_liveSaveFormat;
}

void PenguCoreEngine::setLiveSaveFormat(const QString &saveFormat)
{
    const QString normalized = saveFormat.trimmed().toLower();
    m_liveSaveFormat = (normalized == QStringLiteral("pcapng")) ? QStringLiteral("pcapng") : QStringLiteral("pcap");
}

QVector<CaptureAdapterInfo> PenguCoreEngine::liveAdapters() const
{
    return m_liveCapture ? m_liveCapture->adapters() : QVector<CaptureAdapterInfo>{};
}

bool PenguCoreEngine::refreshLiveAdapters()
{
    return m_liveCapture ? m_liveCapture->refreshAdapters() : false;
}

bool PenguCoreEngine::startLiveCapture(const QString &adapterName)
{
    if (!m_liveCapture) {
        return false;
    }

    clearSession();
    m_lastOpenedFile = adapterName;
    m_lastOpenedFormat = QStringLiteral("live");
    m_lastSessionOpenedUtc = QDateTime::currentDateTimeUtc();
    m_lastLiveCaptureSavePath = buildLiveCaptureSavePath(m_liveSaveFormat);
    QString saveError;
    if (!m_liveCaptureWriter->open(m_lastLiveCaptureSavePath, m_liveSaveFormat, &saveError)) {
        m_statusText = saveError;
        emit statusChanged(m_statusText);
        return false;
    }
    m_liveCapturedFrameCount = 0;
    m_liveAnalyzedFrameCount = 0;
    m_livePacketsPerSecond = 0.0;
    m_liveBytesPerSecond = 0.0;
    m_lastLiveMetricSampleUtc = QDateTime::currentDateTimeUtc();
    m_liveCaptureStartedUtc = m_lastLiveMetricSampleUtc;
    m_liveCaptureStoppedUtc = {};
    m_liveStopRequested = false;
    if (!m_liveCapture->startCapture(adapterName, m_liveCaptureFilter)) {
        if (m_liveCaptureWriter) {
            m_liveCaptureWriter->close();
        }
        m_lastLiveCaptureSavePath.clear();
        m_liveCaptureStartedUtc = {};
        m_statusText = QStringLiteral("Canli capture baslatilamadi.");
        emit statusChanged(m_statusText);
        return false;
    }
    return true;
}

void PenguCoreEngine::stopLiveCapture()
{
    stressSafeShutdownLiveCapture();
    m_liveCaptureStoppedUtc = QDateTime::currentDateTimeUtc();
    flushPendingLiveFrames();
    updateFlowState();
    if (m_liveCaptureWriter) {
        m_liveCaptureWriter->close();
    }
    m_statusText = QStringLiteral("Canli oturum durduruldu: yakalanan %1, analiz edilen %2, pencerede tutulan %3, flow %4, sure %5 ms, health %6")
                       .arg(m_liveCapturedFrameCount)
                       .arg(m_liveAnalyzedFrameCount)
                       .arg(m_packets.size())
                       .arg(m_flows.size())
                       .arg(liveCaptureDurationMs())
                       .arg(liveHealthStatus());
    emit sessionUpdated();
    emit statusChanged(m_statusText);
}

bool PenguCoreEngine::isLiveCaptureRunning() const
{
    return m_liveCapture && m_liveCapture->isRunning();
}

QString PenguCoreEngine::lastLiveCaptureSavePath() const
{
    return m_lastLiveCaptureSavePath;
}

bool PenguCoreEngine::openLastLiveCaptureFile()
{
    if (m_lastLiveCaptureSavePath.isEmpty()) {
        return false;
    }
    return openCaptureFile(m_lastLiveCaptureSavePath);
}

qint64 PenguCoreEngine::liveDroppedFrameCount() const
{
    return m_liveDroppedFrameCount;
}

qint64 PenguCoreEngine::liveTrimmedFrameCount() const
{
    return m_liveTrimmedFrameCount;
}

qint64 PenguCoreEngine::liveCapturedFrameCount() const
{
    return m_liveCapturedFrameCount;
}

qint64 PenguCoreEngine::liveAnalyzedFrameCount() const
{
    return m_liveAnalyzedFrameCount;
}

double PenguCoreEngine::livePacketsPerSecond() const
{
    return m_livePacketsPerSecond;
}

double PenguCoreEngine::liveBytesPerSecond() const
{
    return m_liveBytesPerSecond;
}

QDateTime PenguCoreEngine::liveCaptureStartedUtc() const
{
    return m_liveCaptureStartedUtc;
}

QDateTime PenguCoreEngine::liveCaptureStoppedUtc() const
{
    return m_liveCaptureStoppedUtc;
}

qint64 PenguCoreEngine::liveCaptureDurationMs() const
{
    if (!m_liveCaptureStartedUtc.isValid()) {
        return 0;
    }
    const QDateTime endUtc = (m_liveCaptureStoppedUtc.isValid() && !isLiveCaptureRunning())
        ? m_liveCaptureStoppedUtc
        : QDateTime::currentDateTimeUtc();
    return std::max<qint64>(0, m_liveCaptureStartedUtc.msecsTo(endUtc));
}

QString PenguCoreEngine::liveHealthStatus() const
{
    return classifyLiveHealth(m_liveCapturedFrameCount, m_liveDroppedFrameCount, m_liveTrimmedFrameCount);
}

bool PenguCoreEngine::openCaptureFile(const QString &filePath)
{
    return loadCaptureSession(filePath);
}

void PenguCoreEngine::clearSession()
{
    stressSafeShutdownLiveCapture();
    if (m_liveFlushTimer) {
        m_liveFlushTimer->stop();
    }
    m_packets.clear();
    m_flows.clear();
    m_pendingLiveFrames.clear();
    m_liveDroppedFrameCount = 0;
    m_liveTrimmedFrameCount = 0;
    m_liveCapturedFrameCount = 0;
    m_liveAnalyzedFrameCount = 0;
    m_liveFlushCount = 0;
    m_livePacketsPerSecond = 0.0;
    m_liveBytesPerSecond = 0.0;
    m_lastOpenedFile.clear();
    m_lastOpenedFormat.clear();
    m_lastSessionOpenedUtc = {};
    m_lastLiveMetricSampleUtc = {};
    m_liveCaptureStartedUtc = {};
    m_liveCaptureStoppedUtc = {};
    if (m_liveCaptureWriter) {
        m_liveCaptureWriter->close();
    }
    emitSessionState(QStringLiteral("PenguCore oturumu temizlendi."), true);
}

bool PenguCoreEngine::loadCaptureSession(const QString &filePath)
{
    clearSession();

    const QString normalizedPath = filePath.trimmed();
    m_lastOpenedFile = normalizedPath;
    m_lastSessionOpenedUtc = QDateTime::currentDateTimeUtc();

    PcapFileReader reader;
    const PcapFileReader::Result result = reader.readFile(normalizedPath);
    if (!result.success) {
        m_statusText = result.errorMessage;
        emit statusChanged(m_statusText);
        return false;
    }

    m_lastOpenedFormat = result.pcapngDetected ? QStringLiteral("pcapng") : QStringLiteral("pcap");

    const QVector<RawFrame> ingested = ingestFrames(result.frames);
    m_packets = parseFrames(ingested);
    classifyPackets(m_packets);
    updateFlowState();
    emitSessionState(QStringLiteral("PenguCore %1 frame ve %2 flow yukledi.")
                         .arg(m_packets.size())
                         .arg(m_flows.size()));
    return true;
}

QVector<RawFrame> PenguCoreEngine::ingestFrames(const QVector<RawFrame> &frames) const
{
    return frames;
}

QVector<PacketRecord> PenguCoreEngine::parseFrames(const QVector<RawFrame> &frames) const
{
    BasicFrameParser parser;
    QVector<PacketRecord> records;
    records.reserve(frames.size());
    for (const RawFrame &frame : frames) {
        records.push_back(parser.parse(frame));
    }
    return records;
}

void PenguCoreEngine::classifyPackets(QVector<PacketRecord> &packets) const
{
    for (PacketRecord &packet : packets) {
        if (packet.summary.trimmed().isEmpty()) {
            packet.summary = QStringLiteral("Unknown frame");
        }
        if (packet.sourceEndpoint.trimmed().isEmpty()) {
            packet.sourceEndpoint = QStringLiteral("unknown");
        }
        if (packet.destinationEndpoint.trimmed().isEmpty()) {
            packet.destinationEndpoint = QStringLiteral("unknown");
        }
    }
}

void PenguCoreEngine::appendLiveFrame(const RawFrame &frame)
{
    if (m_liveStopRequested) {
        ++m_liveDroppedFrameCount;
        return;
    }
    ++m_liveCapturedFrameCount;
    if (m_liveCaptureWriter && m_liveCaptureWriter->isOpen()) {
        QString writeError;
        if (!m_liveCaptureWriter->writeFrame(frame, &writeError)) {
            m_statusText = writeError;
            emit statusChanged(m_statusText);
        }
    }

    if (m_pendingLiveFrames.size() >= kLivePendingFrameLimit) {
        ++m_liveDroppedFrameCount;
        if (m_liveDroppedFrameCount % 100 == 0) {
            m_statusText = QStringLiteral("Canli oturum baskilandi: %1 frame drop edildi.")
                               .arg(m_liveDroppedFrameCount);
            emit statusChanged(m_statusText);
        }
        return;
    }

    m_pendingLiveFrames.push_back(frame);
    if (m_pendingLiveFrames.size() >= kLiveImmediateFlushThreshold) {
        flushPendingLiveFrames();
        return;
    }

    if (m_liveFlushTimer && !m_liveFlushTimer->isActive()) {
        m_liveFlushTimer->start();
    }
}

void PenguCoreEngine::flushPendingLiveFrames()
{
    if (m_pendingLiveFrames.isEmpty()) {
        return;
    }

    const int batchFrameCount = m_pendingLiveFrames.size();
    qint64 batchBytes = 0;
    const QVector<RawFrame> batch = ingestFrames(m_pendingLiveFrames);
    QVector<PacketRecord> parsed = parseFrames(batch);
    classifyPackets(parsed);
    for (const PacketRecord &record : std::as_const(parsed)) {
        m_packets.push_back(record);
    }
    for (const RawFrame &frame : std::as_const(batch)) {
        batchBytes += frame.capturedLength;
    }
    m_liveAnalyzedFrameCount += batchFrameCount;
    m_pendingLiveFrames.clear();
    ++m_liveFlushCount;

    const QDateTime nowUtc = QDateTime::currentDateTimeUtc();
    if (m_lastLiveMetricSampleUtc.isValid()) {
        const qint64 elapsedMs = std::max<qint64>(1, m_lastLiveMetricSampleUtc.msecsTo(nowUtc));
        const double elapsedSeconds = static_cast<double>(elapsedMs) / 1000.0;
        m_livePacketsPerSecond = static_cast<double>(batchFrameCount) / elapsedSeconds;
        m_liveBytesPerSecond = static_cast<double>(batchBytes) / elapsedSeconds;
    }
    m_lastLiveMetricSampleUtc = nowUtc;

    if (m_packets.size() > kLiveStoredPacketLimit) {
        const int trimCount = m_packets.size() - kLiveStoredPacketLimit;
        m_packets.erase(m_packets.begin(), m_packets.begin() + trimCount);
        m_liveTrimmedFrameCount += trimCount;
    }

    if (m_liveFlushCount % kLiveFlowRebuildEveryNFlushes == 0 || m_flows.isEmpty()) {
        updateFlowState();
    }

    emitSessionState(QStringLiteral("Canli oturum: pencere %1, analiz %2, flow %3, drop %4, trim %5, health %6")
                         .arg(m_packets.size())
                         .arg(m_liveAnalyzedFrameCount)
                         .arg(m_flows.size())
                         .arg(m_liveDroppedFrameCount)
                         .arg(m_liveTrimmedFrameCount)
                         .arg(liveHealthStatus()));
}

void PenguCoreEngine::rebuildFlows()
{
    FlowTracker tracker;
    m_flows = tracker.build(m_packets);
}

void PenguCoreEngine::updateFlowState()
{
    rebuildFlows();
}

void PenguCoreEngine::emitSessionState(const QString &message, bool reset)
{
    if (reset) {
        emit sessionReset();
    } else {
        emit sessionUpdated();
    }
    m_statusText = message;
    emit statusChanged(m_statusText);
}

void PenguCoreEngine::stressSafeShutdownLiveCapture()
{
    m_liveStopRequested = true;
    if (m_liveFlushTimer) {
        m_liveFlushTimer->stop();
    }
    if (m_liveCapture && m_liveCapture->isRunning()) {
        m_liveCapture->stopCapture();
    }
}

} // namespace pengufoce::pengucore
