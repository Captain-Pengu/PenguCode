#include "pengucore/flow/flowtracker.h"

#include <QHash>

namespace pengufoce::pengucore {

namespace {

struct FlowAccumulator
{
    FlowStats stats;
};

QString flowMapKey(const FlowKey &key)
{
    return QStringLiteral("%1|%2|%3|%4|%5")
        .arg(key.sourceAddress,
             key.destinationAddress,
             QString::number(key.sourcePort),
             QString::number(key.destinationPort),
             key.transport);
}

FlowKey buildFlowKey(const PacketRecord &packet)
{
    FlowKey key;
    key.transport = packet.transportLayer == TransportLayerType::Tcp
                        ? QStringLiteral("TCP")
                        : (packet.transportLayer == TransportLayerType::Udp ? QStringLiteral("UDP") : QStringLiteral("OTHER"));

    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name == QStringLiteral("IPv4")) {
            for (const ProtocolField &field : layer.fields) {
                if (field.name == QStringLiteral("Source")) {
                    key.sourceAddress = field.value;
                } else if (field.name == QStringLiteral("Destination")) {
                    key.destinationAddress = field.value;
                }
            }
        } else if (layer.name == QStringLiteral("TCP") || layer.name == QStringLiteral("UDP")) {
            for (const ProtocolField &field : layer.fields) {
                if (field.name == QStringLiteral("Source Port")) {
                    key.sourcePort = static_cast<std::uint16_t>(field.value.toUShort());
                } else if (field.name == QStringLiteral("Destination Port")) {
                    key.destinationPort = static_cast<std::uint16_t>(field.value.toUShort());
                }
            }
        }
    }

    return key;
}

bool packetCanParticipateInFlow(const PacketRecord &packet)
{
    return packet.networkLayer == NetworkLayerType::IPv4
           && (packet.transportLayer == TransportLayerType::Tcp
               || packet.transportLayer == TransportLayerType::Udp);
}

} // namespace

QVector<FlowStats> FlowTracker::build(const QVector<PacketRecord> &packets) const
{
    QHash<QString, FlowAccumulator> buckets;

    for (const PacketRecord &packet : packets) {
        if (!packetCanParticipateInFlow(packet)) {
            continue;
        }

        const FlowKey key = buildFlowKey(packet);
        if (key.sourceAddress.isEmpty() || key.destinationAddress.isEmpty()) {
            continue;
        }

        const QString bucketKey = flowMapKey(key);
        auto it = buckets.find(bucketKey);
        if (it == buckets.end()) {
            FlowAccumulator accumulator;
            accumulator.stats.key = key;
            accumulator.stats.packetCount = 1;
            accumulator.stats.byteCount = static_cast<std::uint64_t>(packet.rawFrame.originalLength);
            accumulator.stats.firstSeenUtc = packet.rawFrame.timestampUtc;
            accumulator.stats.lastSeenUtc = packet.rawFrame.timestampUtc;
            buckets.insert(bucketKey, accumulator);
            continue;
        }

        it->stats.packetCount += 1;
        it->stats.byteCount += static_cast<std::uint64_t>(packet.rawFrame.originalLength);
        if (!it->stats.firstSeenUtc.isValid() || packet.rawFrame.timestampUtc < it->stats.firstSeenUtc) {
            it->stats.firstSeenUtc = packet.rawFrame.timestampUtc;
        }
        if (!it->stats.lastSeenUtc.isValid() || packet.rawFrame.timestampUtc > it->stats.lastSeenUtc) {
            it->stats.lastSeenUtc = packet.rawFrame.timestampUtc;
        }
    }

    QVector<FlowStats> flows;
    flows.reserve(buckets.size());
    for (auto it = buckets.cbegin(); it != buckets.cend(); ++it) {
        flows.push_back(it->stats);
    }
    return flows;
}

} // namespace pengufoce::pengucore
