#include "pengucore/capture/pcapfilewriter.h"

#include <QtEndian>

namespace pengufoce::pengucore {

namespace {

constexpr quint32 kPcapNgSectionHeaderBlock = 0x0a0d0d0au;
constexpr quint32 kPcapNgInterfaceDescriptionBlock = 0x00000001u;
constexpr quint32 kPcapNgEnhancedPacketBlock = 0x00000006u;
constexpr quint32 kPcapNgByteOrderMagic = 0x1a2b3c4du;

template <typename T>
void appendLittleEndian(QByteArray &buffer, T value)
{
    const T encoded = qToLittleEndian(value);
    buffer.append(reinterpret_cast<const char *>(&encoded), static_cast<int>(sizeof(T)));
}

void appendBlockWithLength(QByteArray &buffer, quint32 blockType, const QByteArray &body)
{
    const quint32 totalLength = static_cast<quint32>(body.size() + 12);
    appendLittleEndian<quint32>(buffer, blockType);
    appendLittleEndian<quint32>(buffer, totalLength);
    buffer.append(body);
    appendLittleEndian<quint32>(buffer, totalLength);
}

int paddedLength(int length)
{
    return (length + 3) & ~3;
}

}

bool PcapFileWriter::open(const QString &filePath, const QString &format, QString *errorMessage)
{
    close();
    m_file.setFileName(filePath);
    if (!m_file.open(QIODevice::WriteOnly)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Kayit dosyasi acilamadi: %1").arg(m_file.errorString());
        }
        return false;
    }

    const QString normalizedFormat = format.trimmed().toLower();
    m_writePcapNg = (normalizedFormat == QStringLiteral("pcapng"))
                    || (normalizedFormat.isEmpty() && filePath.endsWith(QStringLiteral(".pcapng"), Qt::CaseInsensitive));
    return m_writePcapNg ? writePcapNgHeaders(errorMessage) : writeGlobalHeader(errorMessage);
}

void PcapFileWriter::close()
{
    if (m_file.isOpen()) {
        m_file.flush();
        m_file.close();
    }
}

bool PcapFileWriter::isOpen() const
{
    return m_file.isOpen();
}

QString PcapFileWriter::filePath() const
{
    return m_file.fileName();
}

bool PcapFileWriter::writeFrame(const RawFrame &frame, QString *errorMessage)
{
    if (!m_file.isOpen()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Kayit dosyasi acik degil.");
        }
        return false;
    }

    return m_writePcapNg ? writePcapNgRecord(frame, errorMessage) : writePcapRecord(frame, errorMessage);
}

bool PcapFileWriter::writePcapRecord(const RawFrame &frame, QString *errorMessage)
{
    const qint64 epochMs = frame.timestampUtc.toMSecsSinceEpoch();
    const quint32 seconds = epochMs > 0 ? static_cast<quint32>(epochMs / 1000) : 0u;
    const quint32 microseconds = epochMs > 0 ? static_cast<quint32>((epochMs % 1000) * 1000) : 0u;

    QByteArray record;
    appendLittleEndian<quint32>(record, seconds);
    appendLittleEndian<quint32>(record, microseconds);
    appendLittleEndian<quint32>(record, static_cast<quint32>(frame.capturedLength));
    appendLittleEndian<quint32>(record, static_cast<quint32>(frame.originalLength));
    record.append(frame.bytes);

    if (m_file.write(record) != record.size()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Frame kaydi yazilamadi: %1").arg(m_file.errorString());
        }
        return false;
    }

    return true;
}

bool PcapFileWriter::writeGlobalHeader(QString *errorMessage)
{
    QByteArray header;
    appendLittleEndian<quint32>(header, 0xa1b2c3d4u);
    appendLittleEndian<quint16>(header, 2u);
    appendLittleEndian<quint16>(header, 4u);
    appendLittleEndian<quint32>(header, 0u);
    appendLittleEndian<quint32>(header, 0u);
    appendLittleEndian<quint32>(header, 65535u);
    appendLittleEndian<quint32>(header, 1u);

    if (m_file.write(header) != header.size()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Pcap global header yazilamadi: %1").arg(m_file.errorString());
        }
        close();
        return false;
    }

    return true;
}

bool PcapFileWriter::writePcapNgHeaders(QString *errorMessage)
{
    QByteArray buffer;

    QByteArray sectionBody;
    appendLittleEndian<quint32>(sectionBody, kPcapNgByteOrderMagic);
    appendLittleEndian<quint16>(sectionBody, 1u);
    appendLittleEndian<quint16>(sectionBody, 0u);
    appendLittleEndian<quint32>(sectionBody, 0xFFFFFFFFu);
    appendLittleEndian<quint32>(sectionBody, 0xFFFFFFFFu);
    appendBlockWithLength(buffer, kPcapNgSectionHeaderBlock, sectionBody);

    QByteArray interfaceBody;
    appendLittleEndian<quint16>(interfaceBody, 1u);
    appendLittleEndian<quint16>(interfaceBody, 0u);
    appendLittleEndian<quint32>(interfaceBody, 65535u);
    appendBlockWithLength(buffer, kPcapNgInterfaceDescriptionBlock, interfaceBody);

    if (m_file.write(buffer) != buffer.size()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Pcapng header yazilamadi: %1").arg(m_file.errorString());
        }
        close();
        return false;
    }

    return true;
}

bool PcapFileWriter::writePcapNgRecord(const RawFrame &frame, QString *errorMessage)
{
    const qint64 epochMs = frame.timestampUtc.toMSecsSinceEpoch();
    const quint64 microseconds = epochMs > 0 ? static_cast<quint64>(epochMs) * 1000ull : 0ull;
    const quint32 timestampHigh = static_cast<quint32>(microseconds >> 32);
    const quint32 timestampLow = static_cast<quint32>(microseconds & 0xFFFFFFFFull);

    QByteArray body;
    appendLittleEndian<quint32>(body, 0u);
    appendLittleEndian<quint32>(body, timestampHigh);
    appendLittleEndian<quint32>(body, timestampLow);
    appendLittleEndian<quint32>(body, static_cast<quint32>(frame.capturedLength));
    appendLittleEndian<quint32>(body, static_cast<quint32>(frame.originalLength));
    body.append(frame.bytes);

    const int targetLength = paddedLength(body.size());
    if (body.size() < targetLength) {
        body.append(QByteArray(targetLength - body.size(), '\0'));
    }

    QByteArray block;
    appendBlockWithLength(block, kPcapNgEnhancedPacketBlock, body);
    if (m_file.write(block) != block.size()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Pcapng frame yazilamadi: %1").arg(m_file.errorString());
        }
        return false;
    }

    return true;
}

} // namespace pengufoce::pengucore
