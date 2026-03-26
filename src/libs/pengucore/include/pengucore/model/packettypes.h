#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QMetaType>
#include <QString>
#include <QStringList>
#include <QVector>

#include <cstdint>

namespace pengufoce::pengucore {

enum class LinkLayerType
{
    Unknown,
    Ethernet
};

enum class NetworkLayerType
{
    Unknown,
    Arp,
    IPv4
};

enum class TransportLayerType
{
    Unknown,
    Tcp,
    Udp,
    Icmp
};

struct RawFrame
{
    int frameNumber = 0;
    QDateTime timestampUtc;
    int capturedLength = 0;
    int originalLength = 0;
    QByteArray bytes;
};

struct CaptureAdapterInfo
{
    QString name;
    QString description;
    QStringList addresses;
    bool loopback = false;
};

struct ProtocolField
{
    QString name;
    QString value;
    int offset = -1;
    int length = 0;
};

struct ProtocolLayer
{
    QString name;
    QVector<ProtocolField> fields;
};

struct PacketRecord
{
    RawFrame rawFrame;
    LinkLayerType linkLayer = LinkLayerType::Unknown;
    NetworkLayerType networkLayer = NetworkLayerType::Unknown;
    TransportLayerType transportLayer = TransportLayerType::Unknown;
    QString sourceEndpoint;
    QString destinationEndpoint;
    QString summary;
    QStringList warnings;
    QVector<ProtocolLayer> layers;
};

struct FlowKey
{
    QString sourceAddress;
    QString destinationAddress;
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    QString transport;
};

struct FlowStats
{
    FlowKey key;
    int packetCount = 0;
    std::uint64_t byteCount = 0;
    QDateTime firstSeenUtc;
    QDateTime lastSeenUtc;
};

} // namespace pengufoce::pengucore

Q_DECLARE_METATYPE(pengufoce::pengucore::RawFrame)
Q_DECLARE_METATYPE(pengufoce::pengucore::CaptureAdapterInfo)
