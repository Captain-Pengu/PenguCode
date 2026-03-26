#include "pengucore/capture/pcapfilereader.h"

#include <QDataStream>
#include <QDateTime>
#include <QFile>
#include <QTimeZone>
#include <QtEndian>

namespace pengufoce::pengucore {

namespace {

constexpr quint32 kPcapMagicMicroBig = 0xa1b2c3d4u;
constexpr quint32 kPcapMagicMicroLittle = 0xd4c3b2a1u;
constexpr quint32 kPcapMagicNanoBig = 0xa1b23c4du;
constexpr quint32 kPcapMagicNanoLittle = 0x4d3cb2a1u;
constexpr quint32 kPcapNgMagic = 0x0a0d0d0au;
constexpr quint32 kPcapNgByteOrderMagic = 0x1a2b3c4du;
constexpr quint32 kPcapNgSectionHeaderBlock = 0x0a0d0d0au;
constexpr quint32 kPcapNgInterfaceDescriptionBlock = 0x00000001u;
constexpr quint32 kPcapNgEnhancedPacketBlock = 0x00000006u;

quint16 read16(const char *data, bool littleEndian)
{
    return littleEndian ? qFromLittleEndian<quint16>(reinterpret_cast<const uchar *>(data))
                        : qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(data));
}

quint32 read32(const char *data, bool littleEndian)
{
    return littleEndian ? qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(data))
                        : qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(data));
}

quint32 read32(const QByteArray &bytes, int offset, bool littleEndian)
{
    return read32(bytes.constData() + offset, littleEndian);
}

QDateTime timestampFromSeconds(quint32 seconds, quint32 fraction, bool nanoResolution)
{
    QDateTime timestamp = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(seconds), QTimeZone::UTC);
    const int msec = nanoResolution
                         ? static_cast<int>(fraction / 1000000u)
                         : static_cast<int>(fraction / 1000u);
    return timestamp.addMSecs(msec);
}

QDateTime timestampFromPcapNg(quint32 high, quint32 low)
{
    const quint64 combined = (static_cast<quint64>(high) << 32) | static_cast<quint64>(low);
    const qint64 microseconds = static_cast<qint64>(combined);
    const qint64 seconds = microseconds / 1000000ll;
    const qint64 millis = (microseconds % 1000000ll) / 1000ll;
    return QDateTime::fromSecsSinceEpoch(seconds, QTimeZone::UTC).addMSecs(millis);
}

bool readPcapNgFile(QFile &file, PcapFileReader::Result &result)
{
    file.seek(0);
    const QByteArray sectionHeader = file.read(12);
    if (sectionHeader.size() < 12) {
        result.errorMessage = QStringLiteral("Pcapng section header eksik.");
        return false;
    }

    const quint32 blockType = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(sectionHeader.constData()));
    if (blockType != kPcapNgSectionHeaderBlock) {
        result.errorMessage = QStringLiteral("Gecersiz pcapng section header.");
        return false;
    }

    const quint32 byteOrderMagicBig = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(sectionHeader.constData() + 8));
    const quint32 byteOrderMagicLittle = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(sectionHeader.constData() + 8));
    const bool littleEndian = (byteOrderMagicLittle == kPcapNgByteOrderMagic);
    if (!littleEndian || byteOrderMagicBig != 0x4d3c2b1au) {
        result.errorMessage = QStringLiteral("Bu ilk surum yalnizca little-endian pcapng destekliyor.");
        return false;
    }

    file.seek(0);
    int frameNumber = 1;
    while (!file.atEnd()) {
        const QByteArray blockHeader = file.read(8);
        if (blockHeader.isEmpty()) {
            break;
        }
        if (blockHeader.size() < 8) {
            result.errorMessage = QStringLiteral("Eksik pcapng block header bulundu.");
            result.frames.clear();
            return false;
        }

        const quint32 currentBlockType = read32(blockHeader, 0, true);
        const quint32 blockTotalLength = read32(blockHeader, 4, true);
        if (blockTotalLength < 12) {
            result.errorMessage = QStringLiteral("Gecersiz pcapng block uzunlugu.");
            result.frames.clear();
            return false;
        }

        const QByteArray body = file.read(static_cast<qint64>(blockTotalLength) - 12);
        const QByteArray trailingLength = file.read(4);
        if (body.size() != static_cast<int>(blockTotalLength - 12) || trailingLength.size() != 4) {
            result.errorMessage = QStringLiteral("Pcapng block beklenenden kisa okundu.");
            result.frames.clear();
            return false;
        }

        const quint32 trailingBlockLength = read32(trailingLength.constData(), true);
        if (trailingBlockLength != blockTotalLength) {
            result.errorMessage = QStringLiteral("Pcapng block uzunlugu tutarsiz.");
            result.frames.clear();
            return false;
        }

        if (currentBlockType == kPcapNgEnhancedPacketBlock) {
            if (body.size() < 20) {
                result.errorMessage = QStringLiteral("Eksik Enhanced Packet Block bulundu.");
                result.frames.clear();
                return false;
            }

            const quint32 timestampHigh = read32(body, 4, true);
            const quint32 timestampLow = read32(body, 8, true);
            const quint32 capturedLength = read32(body, 12, true);
            const quint32 originalLength = read32(body, 16, true);
            if (body.size() < 20 + static_cast<int>(capturedLength)) {
                result.errorMessage = QStringLiteral("Pcapng packet payload eksik.");
                result.frames.clear();
                return false;
            }

            RawFrame frame;
            frame.frameNumber = frameNumber++;
            frame.timestampUtc = timestampFromPcapNg(timestampHigh, timestampLow);
            frame.capturedLength = static_cast<int>(capturedLength);
            frame.originalLength = static_cast<int>(originalLength);
            frame.bytes = body.mid(20, static_cast<int>(capturedLength));
            result.frames.push_back(frame);
        } else if (currentBlockType == kPcapNgSectionHeaderBlock || currentBlockType == kPcapNgInterfaceDescriptionBlock) {
            continue;
        }
    }

    result.success = true;
    return true;
}

} // namespace

PcapFileReader::Result PcapFileReader::readFile(const QString &filePath) const
{
    Result result;

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        result.errorMessage = QStringLiteral("Capture dosyasi acilamadi: %1").arg(file.errorString());
        return result;
    }

    const QByteArray header = file.read(24);
    if (header.size() < 24) {
        result.errorMessage = QStringLiteral("Dosya pcap global header icin cok kisa.");
        return result;
    }

    const quint32 rawMagic = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(header.constData()));
    if (rawMagic == kPcapNgMagic) {
        result.pcapngDetected = true;
        readPcapNgFile(file, result);
        return result;
    }

    bool littleEndian = false;
    bool nanoResolution = false;

    switch (rawMagic) {
    case kPcapMagicMicroBig:
        littleEndian = false;
        nanoResolution = false;
        break;
    case kPcapMagicMicroLittle:
        littleEndian = true;
        nanoResolution = false;
        break;
    case kPcapMagicNanoBig:
        littleEndian = false;
        nanoResolution = true;
        break;
    case kPcapMagicNanoLittle:
        littleEndian = true;
        nanoResolution = true;
        break;
    default:
        result.errorMessage = QStringLiteral("Desteklenmeyen capture formati veya gecersiz pcap magic.");
        return result;
    }

    int frameNumber = 1;
    while (!file.atEnd()) {
        const QByteArray recordHeader = file.read(16);
        if (recordHeader.isEmpty()) {
            break;
        }
        if (recordHeader.size() < 16) {
            result.errorMessage = QStringLiteral("Eksik packet header bulundu.");
            result.frames.clear();
            return result;
        }

        const quint32 tsSec = read32(recordHeader.constData(), littleEndian);
        const quint32 tsFraction = read32(recordHeader.constData() + 4, littleEndian);
        const quint32 inclLen = read32(recordHeader.constData() + 8, littleEndian);
        const quint32 origLen = read32(recordHeader.constData() + 12, littleEndian);

        const QByteArray frameBytes = file.read(static_cast<qint64>(inclLen));
        if (frameBytes.size() != static_cast<int>(inclLen)) {
            result.errorMessage = QStringLiteral("Packet payload beklenenden kisa okundu.");
            result.frames.clear();
            return result;
        }

        RawFrame frame;
        frame.frameNumber = frameNumber++;
        frame.timestampUtc = timestampFromSeconds(tsSec, tsFraction, nanoResolution);
        frame.capturedLength = static_cast<int>(inclLen);
        frame.originalLength = static_cast<int>(origLen);
        frame.bytes = frameBytes;
        result.frames.push_back(frame);
    }

    result.success = true;
    return result;
}

} // namespace pengufoce::pengucore
