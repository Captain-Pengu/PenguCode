#include "pengucore/api/pengucoresessionreportservice.h"

#include "pengucore/api/pengucoreengine.h"

#include <QJsonArray>
#include <QMap>

namespace pengufoce::pengucore {

namespace {

struct SessionPacketStats
{
    QDateTime firstPacketUtc;
    QDateTime lastPacketUtc;
    qint64 totalBytes = 0;
    qint64 totalCapturedBytes = 0;
    QMap<QString, int> protocolCounts;
};

SessionPacketStats collectSessionPacketStats(const QVector<PacketRecord> &packets,
                                             const std::function<QString(const PacketRecord &)> &protocolLabelForPacket)
{
    SessionPacketStats stats;
    for (const PacketRecord &packet : packets) {
        const QDateTime timestamp = packet.rawFrame.timestampUtc;
        if (timestamp.isValid()) {
            if (!stats.firstPacketUtc.isValid() || timestamp < stats.firstPacketUtc) {
                stats.firstPacketUtc = timestamp;
            }
            if (!stats.lastPacketUtc.isValid() || timestamp > stats.lastPacketUtc) {
                stats.lastPacketUtc = timestamp;
            }
        }
        stats.totalBytes += packet.rawFrame.originalLength;
        stats.totalCapturedBytes += packet.rawFrame.capturedLength;
        const QString protocol = protocolLabelForPacket ? protocolLabelForPacket(packet) : QStringLiteral("Unknown");
        stats.protocolCounts[protocol] += 1;
    }
    return stats;
}

} // namespace

QJsonObject buildPacketJsonObject(const PacketRecord &packet)
{
    QJsonObject root;
    root.insert(QStringLiteral("frame_number"), packet.rawFrame.frameNumber);
    root.insert(QStringLiteral("timestamp_utc"), packet.rawFrame.timestampUtc.toString(Qt::ISODateWithMs));
    root.insert(QStringLiteral("captured_length"), packet.rawFrame.capturedLength);
    root.insert(QStringLiteral("original_length"), packet.rawFrame.originalLength);
    root.insert(QStringLiteral("source_endpoint"), packet.sourceEndpoint);
    root.insert(QStringLiteral("destination_endpoint"), packet.destinationEndpoint);
    root.insert(QStringLiteral("summary"), packet.summary);
    root.insert(QStringLiteral("raw_hex"), QString::fromLatin1(packet.rawFrame.bytes.toHex()));

    QJsonArray warningsArray;
    for (const QString &warning : packet.warnings) {
        warningsArray.append(warning);
    }
    root.insert(QStringLiteral("warnings"), warningsArray);

    QJsonArray layersArray;
    for (const ProtocolLayer &layer : packet.layers) {
        QJsonObject layerObject;
        layerObject.insert(QStringLiteral("name"), layer.name);
        QJsonArray fieldsArray;
        for (const auto &field : layer.fields) {
            QJsonObject fieldObject;
            fieldObject.insert(QStringLiteral("name"), field.name);
            fieldObject.insert(QStringLiteral("value"), field.value);
            fieldObject.insert(QStringLiteral("offset"), field.offset);
            fieldObject.insert(QStringLiteral("length"), field.length);
            fieldsArray.append(fieldObject);
        }
        layerObject.insert(QStringLiteral("fields"), fieldsArray);
        layersArray.append(layerObject);
    }
    root.insert(QStringLiteral("layers"), layersArray);
    return root;
}

QJsonObject buildSessionReportObject(const PenguCoreEngine &engine,
                                     const QVector<int> &visiblePacketIndices,
                                     const QVector<int> &visibleFlowIndices,
                                     bool visibleOnly,
                                     const std::function<QString(const PacketRecord &)> &protocolLabelForPacket,
                                     const std::function<QString(const FlowStats &)> &flowDetailBuilder)
{
    QJsonObject rootObject;
    const auto &packets = engine.packets();
    const auto &flows = engine.flows();
    const SessionPacketStats stats = collectSessionPacketStats(packets, protocolLabelForPacket);
    const qint64 durationMs = (stats.firstPacketUtc.isValid() && stats.lastPacketUtc.isValid())
        ? std::max<qint64>(0, stats.firstPacketUtc.msecsTo(stats.lastPacketUtc))
        : 0;

    rootObject.insert(QStringLiteral("file"), engine.lastOpenedFile());
    rootObject.insert(QStringLiteral("format"), engine.lastOpenedFormat());
    rootObject.insert(QStringLiteral("status"), engine.statusText());
    rootObject.insert(QStringLiteral("session_opened_utc"), engine.lastSessionOpenedUtc().toString(Qt::ISODateWithMs));
    rootObject.insert(QStringLiteral("first_packet_utc"), stats.firstPacketUtc.toString(Qt::ISODateWithMs));
    rootObject.insert(QStringLiteral("last_packet_utc"), stats.lastPacketUtc.toString(Qt::ISODateWithMs));
    rootObject.insert(QStringLiteral("duration_ms"), QString::number(durationMs));
    rootObject.insert(QStringLiteral("total_original_bytes"), QString::number(stats.totalBytes));
    rootObject.insert(QStringLiteral("total_captured_bytes"), QString::number(stats.totalCapturedBytes));
    rootObject.insert(QStringLiteral("captured_frames"), QString::number(engine.liveCapturedFrameCount()));
    rootObject.insert(QStringLiteral("analyzed_frames"), QString::number(engine.liveAnalyzedFrameCount()));
    rootObject.insert(QStringLiteral("window_frames"), QString::number(engine.packets().size()));
    rootObject.insert(QStringLiteral("flow_count"), flows.size());
    rootObject.insert(QStringLiteral("live_running"), engine.isLiveCaptureRunning());
    rootObject.insert(QStringLiteral("live_health"), engine.liveHealthStatus());
    rootObject.insert(QStringLiteral("live_filter"), engine.liveCaptureFilter());
    rootObject.insert(QStringLiteral("live_save_format"), engine.liveSaveFormat());
    rootObject.insert(QStringLiteral("live_save_path"), engine.lastLiveCaptureSavePath());
    rootObject.insert(QStringLiteral("live_started_utc"), engine.liveCaptureStartedUtc().toString(Qt::ISODateWithMs));
    rootObject.insert(QStringLiteral("live_stopped_utc"), engine.liveCaptureStoppedUtc().toString(Qt::ISODateWithMs));
    rootObject.insert(QStringLiteral("live_duration_ms"), QString::number(engine.liveCaptureDurationMs()));
    rootObject.insert(QStringLiteral("drop_count"), QString::number(engine.liveDroppedFrameCount()));
    rootObject.insert(QStringLiteral("trim_count"), QString::number(engine.liveTrimmedFrameCount()));
    rootObject.insert(QStringLiteral("packets_per_second"), QString::number(engine.livePacketsPerSecond(), 'f', 3));
    rootObject.insert(QStringLiteral("bytes_per_second"), QString::number(engine.liveBytesPerSecond(), 'f', 3));
    rootObject.insert(QStringLiteral("visible_only"), visibleOnly);
    rootObject.insert(QStringLiteral("visible_packet_count"), visiblePacketIndices.size());
    rootObject.insert(QStringLiteral("visible_flow_count"), visibleFlowIndices.size());

    QJsonArray protocolArray;
    for (auto it = stats.protocolCounts.cbegin(); it != stats.protocolCounts.cend(); ++it) {
        QJsonObject protocolObject;
        protocolObject.insert(QStringLiteral("name"), it.key());
        protocolObject.insert(QStringLiteral("count"), it.value());
        protocolArray.append(protocolObject);
    }
    rootObject.insert(QStringLiteral("protocol_breakdown"), protocolArray);

    QJsonArray packetsArray;
    const QVector<int> packetIndices = visibleOnly
        ? visiblePacketIndices
        : [&packets]() {
              QVector<int> indices;
              indices.reserve(packets.size());
              for (int i = 0; i < packets.size(); ++i) {
                  indices.push_back(i);
              }
              return indices;
          }();
    for (int index : packetIndices) {
        if (index < 0 || index >= packets.size()) {
            continue;
        }
        packetsArray.append(buildPacketJsonObject(packets[index]));
    }
    rootObject.insert(QStringLiteral("packets"), packetsArray);

    QJsonArray flowsArray;
    const QVector<int> flowIndices = visibleOnly
        ? visibleFlowIndices
        : [&flows]() {
              QVector<int> indices;
              indices.reserve(flows.size());
              for (int i = 0; i < flows.size(); ++i) {
                  indices.push_back(i);
              }
              return indices;
          }();
    for (int index : flowIndices) {
        if (index < 0 || index >= flows.size()) {
            continue;
        }
        const FlowStats &flow = flows[index];
        QJsonObject flowObject;
        flowObject.insert(QStringLiteral("source"), QStringLiteral("%1:%2").arg(flow.key.sourceAddress).arg(flow.key.sourcePort));
        flowObject.insert(QStringLiteral("destination"), QStringLiteral("%1:%2").arg(flow.key.destinationAddress).arg(flow.key.destinationPort));
        flowObject.insert(QStringLiteral("transport"), flow.key.transport);
        flowObject.insert(QStringLiteral("packet_count"), flow.packetCount);
        flowObject.insert(QStringLiteral("byte_count"), QString::number(flow.byteCount));
        flowObject.insert(QStringLiteral("first_seen_utc"), flow.firstSeenUtc.toString(Qt::ISODateWithMs));
        flowObject.insert(QStringLiteral("last_seen_utc"), flow.lastSeenUtc.toString(Qt::ISODateWithMs));
        flowObject.insert(QStringLiteral("detail"), flowDetailBuilder ? flowDetailBuilder(flow) : QString());
        flowsArray.append(flowObject);
    }
    rootObject.insert(QStringLiteral("flows"), flowsArray);

    return rootObject;
}

} // namespace pengufoce::pengucore
