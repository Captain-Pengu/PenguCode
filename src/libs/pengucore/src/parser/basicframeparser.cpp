#include "pengucore/parser/basicframeparser.h"

#include <QCryptographicHash>
#include <QtEndian>

namespace pengufoce::pengucore {

namespace {

constexpr quint16 kEtherTypeIpv4 = 0x0800;
constexpr quint16 kEtherTypeArp = 0x0806;

QString formatMac(const QByteArray &bytes, int offset)
{
    if (bytes.size() < offset + 6) {
        return QStringLiteral("invalid");
    }

    QStringList parts;
    parts.reserve(6);
    for (int i = 0; i < 6; ++i) {
        const quint8 value = static_cast<quint8>(bytes[offset + i]);
        parts << QStringLiteral("%1").arg(value, 2, 16, QLatin1Char('0')).toUpper();
    }
    return parts.join(':');
}

quint16 readBig16(const QByteArray &bytes, int offset)
{
    return qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(bytes.constData() + offset));
}

quint32 readBig32(const QByteArray &bytes, int offset)
{
    return qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(bytes.constData() + offset));
}

QString formatIpv4(const QByteArray &bytes, int offset)
{
    if (bytes.size() < offset + 4) {
        return QStringLiteral("invalid");
    }

    return QStringLiteral("%1.%2.%3.%4")
        .arg(static_cast<quint8>(bytes[offset + 0]))
        .arg(static_cast<quint8>(bytes[offset + 1]))
        .arg(static_cast<quint8>(bytes[offset + 2]))
        .arg(static_cast<quint8>(bytes[offset + 3]));
}

QString ipv4ProtocolName(quint8 protocol)
{
    switch (protocol) {
    case 1:
        return QStringLiteral("ICMP");
    case 6:
        return QStringLiteral("TCP");
    case 17:
        return QStringLiteral("UDP");
    default:
        return QStringLiteral("IPv4-%1").arg(protocol);
    }
}

QString arpOperationName(quint16 operation)
{
    switch (operation) {
    case 1:
        return QStringLiteral("Request");
    case 2:
        return QStringLiteral("Reply");
    default:
        return QStringLiteral("Op-%1").arg(operation);
    }
}

QString dnsMessageType(quint16 flags)
{
    const bool response = (flags & 0x8000u) != 0;
    return response ? QStringLiteral("Response") : QStringLiteral("Query");
}

QString parseDnsName(const QByteArray &bytes,
                     int offset,
                     int limit,
                     int *consumedBytes = nullptr,
                     int recursionDepth = 0)
{
    if (recursionDepth > 8 || offset < 0 || offset >= limit) {
        if (consumedBytes) {
            *consumedBytes = 0;
        }
        return {};
    }

    QStringList labels;
    int cursor = offset;
    int visibleConsumed = 0;
    while (cursor < limit) {
        const quint8 labelLength = static_cast<quint8>(bytes[cursor]);
        ++cursor;
        ++visibleConsumed;
        if (labelLength == 0) {
            if (consumedBytes) {
                *consumedBytes = visibleConsumed;
            }
            return labels.isEmpty() ? QStringLiteral("<root>") : labels.join('.');
        }
        if ((labelLength & 0xC0u) == 0xC0u) {
            if (cursor >= limit) {
                break;
            }
            const quint16 pointerOffset =
                static_cast<quint16>(((labelLength & 0x3Fu) << 8) | static_cast<quint8>(bytes[cursor]));
            ++visibleConsumed;
            int nestedConsumed = 0;
            const QString pointedName = parseDnsName(bytes, pointerOffset, limit, &nestedConsumed, recursionDepth + 1);
            if (!pointedName.isEmpty()) {
                if (pointedName != QStringLiteral("<root>")) {
                    labels << pointedName;
                }
                if (consumedBytes) {
                    *consumedBytes = visibleConsumed;
                }
                return labels.isEmpty() ? QStringLiteral("<root>") : labels.join('.');
            }
            break;
        }
        if (cursor + labelLength > limit) {
            break;
        }
        labels << QString::fromLatin1(bytes.mid(cursor, labelLength));
        cursor += labelLength;
        visibleConsumed += labelLength;
    }
    if (consumedBytes) {
        *consumedBytes = qMax(0, visibleConsumed);
    }
    return {};
}

QString dnsTypeName(quint16 type)
{
    switch (type) {
    case 1: return QStringLiteral("A");
    case 2: return QStringLiteral("NS");
    case 5: return QStringLiteral("CNAME");
    case 6: return QStringLiteral("SOA");
    case 12: return QStringLiteral("PTR");
    case 15: return QStringLiteral("MX");
    case 16: return QStringLiteral("TXT");
    case 28: return QStringLiteral("AAAA");
    default: return QStringLiteral("TYPE-%1").arg(type);
    }
}

QString dnsClassName(quint16 dnsClass)
{
    switch (dnsClass) {
    case 1: return QStringLiteral("IN");
    case 3: return QStringLiteral("CH");
    case 4: return QStringLiteral("HS");
    default: return QStringLiteral("CLASS-%1").arg(dnsClass);
    }
}

QString previewHttpBody(const QByteArray &payload)
{
    const int bodyOffset = payload.indexOf("\r\n\r\n");
    if (bodyOffset < 0) {
        return {};
    }

    QByteArray body = payload.mid(bodyOffset + 4, 160);
    if (body.isEmpty()) {
        return {};
    }

    QString text = QString::fromLatin1(body);
    for (QChar &ch : text) {
        if (!ch.isPrint() && !ch.isSpace()) {
            ch = QLatin1Char('.');
        }
    }
    text.replace(QStringLiteral("\r"), QString());
    text.replace(QLatin1Char('\n'), QStringLiteral(" "));
    return text.trimmed();
}

QString extractHttpHeaderValue(const QStringList &lines, const QString &headerName)
{
    for (const QString &line : lines) {
        if (line.startsWith(headerName, Qt::CaseInsensitive)) {
            const int colonIndex = line.indexOf(QLatin1Char(':'));
            if (colonIndex > 0) {
                return line.mid(colonIndex + 1).trimmed();
            }
        }
    }
    return {};
}

QString extractAuthorizationScheme(const QString &authorizationValue)
{
    if (authorizationValue.isEmpty()) {
        return {};
    }
    return authorizationValue.section(QLatin1Char(' '), 0, 0).trimmed();
}

int countCookiePairs(const QString &cookieValue)
{
    if (cookieValue.trimmed().isEmpty()) {
        return 0;
    }
    return cookieValue.split(QLatin1Char(';'), Qt::SkipEmptyParts).size();
}

QStringList extractCookieNames(const QString &cookieValue)
{
    QStringList names;
    for (const QString &part : cookieValue.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
        const QString trimmed = part.trimmed();
        const int equalIndex = trimmed.indexOf(QLatin1Char('='));
        if (equalIndex > 0) {
            names << trimmed.left(equalIndex).trimmed();
        }
    }
    names.removeDuplicates();
    return names;
}

QString extractCookieValue(const QString &cookieValue, const QString &cookieName)
{
    for (const QString &part : cookieValue.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
        const QString trimmed = part.trimmed();
        const int equalIndex = trimmed.indexOf(QLatin1Char('='));
        if (equalIndex > 0 && trimmed.left(equalIndex).trimmed().compare(cookieName, Qt::CaseInsensitive) == 0) {
            return trimmed.mid(equalIndex + 1).trimmed();
        }
    }
    return {};
}

QString extractAuthRealm(const QString &challengeValue)
{
    const QString lower = challengeValue.toLower();
    const int realmIndex = lower.indexOf(QStringLiteral("realm="));
    if (realmIndex < 0) {
        return {};
    }
    QString realm = challengeValue.mid(realmIndex + 6).trimmed();
    if (realm.startsWith(QLatin1Char('"'))) {
        realm.remove(0, 1);
    }
    const int quoteEnd = realm.indexOf(QLatin1Char('"'));
    if (quoteEnd >= 0) {
        realm = realm.left(quoteEnd);
    } else {
        realm = realm.section(QLatin1Char(','), 0, 0).trimmed();
    }
    return realm.trimmed();
}

QStringList extractSetCookieFlags(const QString &setCookieValue)
{
    QStringList flags;
    const QString lower = setCookieValue.toLower();
    if (lower.contains(QStringLiteral("secure"))) {
        flags << QStringLiteral("Secure");
    }
    if (lower.contains(QStringLiteral("httponly"))) {
        flags << QStringLiteral("HttpOnly");
    }
    if (lower.contains(QStringLiteral("samesite="))) {
        flags << QStringLiteral("SameSite");
    }
    flags.removeDuplicates();
    return flags;
}

int countHeaderOccurrences(const QStringList &lines, const QString &headerName)
{
    int count = 0;
    for (const QString &line : lines) {
        if (line.startsWith(headerName, Qt::CaseInsensitive)) {
            ++count;
        }
    }
    return count;
}

QString endpointText(const QString &host, quint16 port)
{
    if (host.isEmpty() || host == QStringLiteral("invalid")) {
        return QStringLiteral("unknown");
    }
    if (port == 0) {
        return host;
    }
    return QStringLiteral("%1:%2").arg(host).arg(port);
}

QString tcpFlagsText(quint16 flags)
{
    QStringList names;
    if (flags & 0x100u) {
        names << QStringLiteral("NS");
    }
    if (flags & 0x080u) {
        names << QStringLiteral("CWR");
    }
    if (flags & 0x040u) {
        names << QStringLiteral("ECE");
    }
    if (flags & 0x020u) {
        names << QStringLiteral("URG");
    }
    if (flags & 0x010u) {
        names << QStringLiteral("ACK");
    }
    if (flags & 0x008u) {
        names << QStringLiteral("PSH");
    }
    if (flags & 0x004u) {
        names << QStringLiteral("RST");
    }
    if (flags & 0x002u) {
        names << QStringLiteral("SYN");
    }
    if (flags & 0x001u) {
        names << QStringLiteral("FIN");
    }
    return names.isEmpty() ? QStringLiteral("None") : names.join('|');
}

QString tlsRecordTypeName(quint8 type)
{
    switch (type) {
    case 20: return QStringLiteral("ChangeCipherSpec");
    case 21: return QStringLiteral("Alert");
    case 22: return QStringLiteral("Handshake");
    case 23: return QStringLiteral("ApplicationData");
    default: return QStringLiteral("Type-%1").arg(type);
    }
}

QString tlsVersionName(quint16 version)
{
    switch (version) {
    case 0x0300: return QStringLiteral("SSL 3.0");
    case 0x0301: return QStringLiteral("TLS 1.0");
    case 0x0302: return QStringLiteral("TLS 1.1");
    case 0x0303: return QStringLiteral("TLS 1.2");
    case 0x0304: return QStringLiteral("TLS 1.3");
    default: return QStringLiteral("0x%1").arg(version, 4, 16, QLatin1Char('0')).toUpper();
    }
}

QString tlsHandshakeTypeName(quint8 type)
{
    switch (type) {
    case 1: return QStringLiteral("ClientHello");
    case 2: return QStringLiteral("ServerHello");
    case 4: return QStringLiteral("NewSessionTicket");
    case 8: return QStringLiteral("EncryptedExtensions");
    case 11: return QStringLiteral("Certificate");
    case 13: return QStringLiteral("CertificateRequest");
    case 15: return QStringLiteral("CertificateVerify");
    case 20: return QStringLiteral("Finished");
    default: return QStringLiteral("Handshake-%1").arg(type);
    }
}

QString tlsExtensionTypeName(quint16 type)
{
    switch (type) {
    case 0: return QStringLiteral("server_name");
    case 10: return QStringLiteral("supported_groups");
    case 11: return QStringLiteral("ec_point_formats");
    case 13: return QStringLiteral("signature_algorithms");
    case 16: return QStringLiteral("application_layer_protocol_negotiation");
    case 21: return QStringLiteral("padding");
    case 35: return QStringLiteral("session_ticket");
    case 43: return QStringLiteral("supported_versions");
    case 45: return QStringLiteral("psk_key_exchange_modes");
    case 51: return QStringLiteral("key_share");
    default: return QStringLiteral("ext-%1").arg(type);
    }
}

QString tlsGroupName(quint16 group)
{
    switch (group) {
    case 0x0017: return QStringLiteral("secp256r1");
    case 0x0018: return QStringLiteral("secp384r1");
    case 0x0019: return QStringLiteral("secp521r1");
    case 0x001D: return QStringLiteral("x25519");
    case 0x001E: return QStringLiteral("x448");
    default: return QStringLiteral("0x%1").arg(group, 4, 16, QLatin1Char('0')).toUpper();
    }
}

QString tlsCipherSuiteName(quint16 suite)
{
    switch (suite) {
    case 0x1301: return QStringLiteral("TLS_AES_128_GCM_SHA256");
    case 0x1302: return QStringLiteral("TLS_AES_256_GCM_SHA384");
    case 0x1303: return QStringLiteral("TLS_CHACHA20_POLY1305_SHA256");
    case 0xC02F: return QStringLiteral("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    case 0xC030: return QStringLiteral("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    case 0x009C: return QStringLiteral("TLS_RSA_WITH_AES_128_GCM_SHA256");
    case 0x009D: return QStringLiteral("TLS_RSA_WITH_AES_256_GCM_SHA384");
    default: return QStringLiteral("0x%1").arg(suite, 4, 16, QLatin1Char('0')).toUpper();
    }
}

struct TlsClientHelloMetadata
{
    QString serverName;
    QString cipherSuite;
    QString supportedVersion;
    QString alpnProtocol;
    QString supportedGroup;
    QString keyShareGroup;
    QStringList extensions;
};

struct TlsCertificateMetadata
{
    quint32 certificateListLength = 0;
    int certificateCount = 0;
    quint32 firstCertificateLength = 0;
    QString firstCertificateSha256;
};

QString parseDnsRdataValue(const QByteArray &bytes, int rdataOffset, quint16 rdLength, quint16 answerType)
{
    if (rdataOffset < 0 || rdLength == 0 || rdataOffset + rdLength > bytes.size()) {
        return {};
    }

    if (answerType == 1 && rdLength == 4) {
        return formatIpv4(bytes, rdataOffset);
    }
    if (answerType == 28 && rdLength == 16) {
        QStringList groups;
        for (int i = 0; i < 16; i += 2) {
            groups << QStringLiteral("%1%2")
                          .arg(QStringLiteral("%1").arg(static_cast<quint8>(bytes[rdataOffset + i]), 2, 16, QLatin1Char('0')))
                          .arg(QStringLiteral("%1").arg(static_cast<quint8>(bytes[rdataOffset + i + 1]), 2, 16, QLatin1Char('0')));
        }
        QString joined = groups.join(':');
        joined.replace(QStringLiteral(":0000"), QStringLiteral(":0"));
        return joined.toUpper();
    }
    if (answerType == 5 || answerType == 2 || answerType == 12) {
        return parseDnsName(bytes, rdataOffset, bytes.size());
    }
    if (answerType == 15 && rdLength >= 3) {
        const quint16 preference = readBig16(bytes, rdataOffset);
        const QString exchange = parseDnsName(bytes, rdataOffset + 2, bytes.size());
        return exchange.isEmpty() ? QStringLiteral("pref=%1").arg(preference)
                                  : QStringLiteral("pref=%1 %2").arg(preference).arg(exchange);
    }
    if (answerType == 16 && rdLength >= 1) {
        const quint8 textLength = static_cast<quint8>(bytes[rdataOffset]);
        if (rdataOffset + 1 + textLength <= bytes.size()) {
            return QString::fromLatin1(bytes.mid(rdataOffset + 1, textLength));
        }
    }
    return QString::fromLatin1(bytes.mid(rdataOffset, qMin<int>(rdLength, 48)).toHex(' ')).toUpper();
}

int appendDnsResourceRecords(ProtocolLayer &dns,
                             const QByteArray &bytes,
                             int cursor,
                             quint16 recordCount,
                             const QString &prefix,
                             int maxRecordsToParse = 2)
{
    const int recordsToParse = qMin<int>(recordCount, maxRecordsToParse);
    for (int recordIndex = 0; recordIndex < recordsToParse; ++recordIndex) {
        int nameConsumed = 0;
        const QString name = parseDnsName(bytes, cursor, bytes.size(), &nameConsumed);
        const int metaOffset = cursor + nameConsumed;
        if (name.isEmpty() || bytes.size() < metaOffset + 10) {
            return cursor;
        }

        const quint16 type = readBig16(bytes, metaOffset);
        const quint16 dnsClass = readBig16(bytes, metaOffset + 2);
        const quint32 ttl = readBig32(bytes, metaOffset + 4);
        const quint16 rdLength = readBig16(bytes, metaOffset + 8);
        const int rdataOffset = metaOffset + 10;
        const QString fieldPrefix = QStringLiteral("%1 %2 ").arg(prefix).arg(recordIndex + 1);

        dns.fields.push_back({fieldPrefix + QStringLiteral("Name"), name, cursor, nameConsumed});
        dns.fields.push_back({fieldPrefix + QStringLiteral("Type"), dnsTypeName(type), metaOffset, 2});
        dns.fields.push_back({fieldPrefix + QStringLiteral("Class"), dnsClassName(dnsClass), metaOffset + 2, 2});
        dns.fields.push_back({fieldPrefix + QStringLiteral("TTL"), QString::number(ttl), metaOffset + 4, 4});

        const QString rdataValue = parseDnsRdataValue(bytes, rdataOffset, rdLength, type);
        if (!rdataValue.isEmpty()) {
            dns.fields.push_back({fieldPrefix + QStringLiteral("Data"), rdataValue, rdataOffset, rdLength});
        }

        cursor = rdataOffset + rdLength;
        if (cursor >= bytes.size()) {
            break;
        }
    }

    return cursor;
}

TlsClientHelloMetadata parseTlsClientHelloMetadata(const QByteArray &bytes, int payloadOffset)
{
    TlsClientHelloMetadata metadata;
    if (payloadOffset + 43 > bytes.size()) {
        return metadata;
    }

    const quint8 recordType = static_cast<quint8>(bytes[payloadOffset]);
    if (recordType != 22) {
        return metadata;
    }
    const quint8 handshakeType = static_cast<quint8>(bytes[payloadOffset + 5]);
    if (handshakeType != 1) {
        return metadata;
    }

    int cursor = payloadOffset + 9; // handshake header
    if (cursor + 2 + 32 + 1 > bytes.size()) {
        return metadata;
    }

    cursor += 2; // client version
    cursor += 32; // random

    const quint8 sessionIdLength = static_cast<quint8>(bytes[cursor]);
    ++cursor;
    cursor += sessionIdLength;
    if (cursor + 2 > bytes.size()) {
        return {};
    }

    const quint16 cipherSuitesLength = readBig16(bytes, cursor);
    if (cipherSuitesLength >= 2 && cursor + 2 + cipherSuitesLength <= bytes.size()) {
        metadata.cipherSuite = tlsCipherSuiteName(readBig16(bytes, cursor + 2));
    }
    cursor += 2 + cipherSuitesLength;
    if (cursor + 1 > bytes.size()) {
        return metadata;
    }

    const quint8 compressionLength = static_cast<quint8>(bytes[cursor]);
    ++cursor;
    cursor += compressionLength;
    if (cursor + 2 > bytes.size()) {
        return {};
    }

    const quint16 extensionsLength = readBig16(bytes, cursor);
    cursor += 2;
    const int extensionsEnd = qMin(cursor + static_cast<int>(extensionsLength), bytes.size());
    while (cursor + 4 <= extensionsEnd) {
        const quint16 extensionType = readBig16(bytes, cursor);
        const quint16 extensionLength = readBig16(bytes, cursor + 2);
        cursor += 4;
        if (cursor + extensionLength > extensionsEnd) {
            break;
        }

        metadata.extensions << tlsExtensionTypeName(extensionType);

        if (extensionType == 0 && extensionLength >= 5) {
            int sniCursor = cursor;
            const quint16 serverNameListLength = readBig16(bytes, sniCursor);
            sniCursor += 2;
            const int serverNameListEnd = qMin(sniCursor + static_cast<int>(serverNameListLength), cursor + static_cast<int>(extensionLength));
            while (sniCursor + 3 <= serverNameListEnd) {
                const quint8 nameType = static_cast<quint8>(bytes[sniCursor]);
                const quint16 nameLength = readBig16(bytes, sniCursor + 1);
                sniCursor += 3;
                if (sniCursor + nameLength > serverNameListEnd) {
                    break;
                }
                if (nameType == 0) {
                    metadata.serverName = QString::fromLatin1(bytes.mid(sniCursor, nameLength));
                    break;
                }
                sniCursor += nameLength;
            }
        } else if (extensionType == 16 && extensionLength >= 3) {
            int alpnCursor = cursor;
            const quint16 protocolNameListLength = readBig16(bytes, alpnCursor);
            alpnCursor += 2;
            const int alpnEnd = qMin(alpnCursor + static_cast<int>(protocolNameListLength), cursor + static_cast<int>(extensionLength));
            if (alpnCursor < alpnEnd) {
                const quint8 protocolLength = static_cast<quint8>(bytes[alpnCursor]);
                ++alpnCursor;
                if (alpnCursor + protocolLength <= alpnEnd) {
                    metadata.alpnProtocol = QString::fromLatin1(bytes.mid(alpnCursor, protocolLength));
                }
            }
        } else if (extensionType == 43 && extensionLength >= 3) {
            int versionsCursor = cursor;
            const quint8 versionsLength = static_cast<quint8>(bytes[versionsCursor]);
            ++versionsCursor;
            if (versionsLength >= 2 && versionsCursor + 2 <= cursor + static_cast<int>(extensionLength)) {
                metadata.supportedVersion = tlsVersionName(readBig16(bytes, versionsCursor));
            }
        } else if (extensionType == 10 && extensionLength >= 4) {
            const quint16 groupsLength = readBig16(bytes, cursor);
            if (groupsLength >= 2 && cursor + 2 + 2 <= cursor + static_cast<int>(extensionLength)) {
                metadata.supportedGroup = tlsGroupName(readBig16(bytes, cursor + 2));
            }
        } else if (extensionType == 51 && extensionLength >= 6) {
            const quint16 keyShareLength = readBig16(bytes, cursor);
            if (keyShareLength >= 4 && cursor + 2 + 2 <= cursor + static_cast<int>(extensionLength)) {
                metadata.keyShareGroup = tlsGroupName(readBig16(bytes, cursor + 2));
            }
        }

        cursor += extensionLength;
    }

    return metadata;
}

TlsCertificateMetadata parseTlsCertificateMetadata(const QByteArray &bytes, int payloadOffset)
{
    TlsCertificateMetadata metadata;
    if (payloadOffset + 12 > bytes.size()) {
        return metadata;
    }

    const int listOffset = payloadOffset + 9;
    metadata.certificateListLength =
        (static_cast<quint32>(static_cast<quint8>(bytes[listOffset])) << 16)
        | (static_cast<quint32>(static_cast<quint8>(bytes[listOffset + 1])) << 8)
        | static_cast<quint32>(static_cast<quint8>(bytes[listOffset + 2]));

    int cursor = listOffset + 3;
    const int listEnd = qMin(cursor + static_cast<int>(metadata.certificateListLength), bytes.size());
    while (cursor + 3 <= listEnd) {
        const quint32 certLength =
            (static_cast<quint32>(static_cast<quint8>(bytes[cursor])) << 16)
            | (static_cast<quint32>(static_cast<quint8>(bytes[cursor + 1])) << 8)
            | static_cast<quint32>(static_cast<quint8>(bytes[cursor + 2]));
        cursor += 3;
        if (metadata.certificateCount == 0) {
            metadata.firstCertificateLength = certLength;
            if (cursor + static_cast<int>(certLength) <= bytes.size()) {
                metadata.firstCertificateSha256 =
                    QString::fromLatin1(QCryptographicHash::hash(bytes.mid(cursor, certLength), QCryptographicHash::Sha256).toHex());
            }
        }
        if (cursor + static_cast<int>(certLength) > listEnd) {
            break;
        }
        ++metadata.certificateCount;
        cursor += static_cast<int>(certLength);
    }

    return metadata;
}

} // namespace

PacketRecord BasicFrameParser::parse(const RawFrame &frame) const
{
    PacketRecord record;
    record.rawFrame = frame;
    record.summary = QStringLiteral("Raw frame yuklendi, parser daha derin layer'lara hazirlaniyor.");
    record.sourceEndpoint = QStringLiteral("unknown");
    record.destinationEndpoint = QStringLiteral("unknown");

    ProtocolLayer meta;
    meta.name = QStringLiteral("Raw Frame");
    meta.fields.push_back({QStringLiteral("Frame Number"), QString::number(frame.frameNumber), -1, 0});
    meta.fields.push_back({QStringLiteral("Captured Length"), QString::number(frame.capturedLength), -1, 0});
    meta.fields.push_back({QStringLiteral("Original Length"), QString::number(frame.originalLength), -1, 0});
    meta.fields.push_back({QStringLiteral("Timestamp UTC"), frame.timestampUtc.toString(Qt::ISODateWithMs), -1, 0});
    record.layers.push_back(meta);

    if (frame.bytes.size() < 14) {
        record.warnings.push_back(QStringLiteral("Ethernet header icin yeterli veri yok."));
        record.summary = QStringLiteral("Kisa frame");
        return record;
    }

    const QString destinationMac = formatMac(frame.bytes, 0);
    const QString sourceMac = formatMac(frame.bytes, 6);
    const quint16 etherType = readBig16(frame.bytes, 12);

    ProtocolLayer ethernet;
    ethernet.name = QStringLiteral("Ethernet II");
    ethernet.fields.push_back({QStringLiteral("Destination"), destinationMac, 0, 6});
    ethernet.fields.push_back({QStringLiteral("Source"), sourceMac, 6, 6});
    ethernet.fields.push_back({QStringLiteral("EtherType"), QStringLiteral("0x%1").arg(etherType, 4, 16, QLatin1Char('0')).toUpper(), 12, 2});
    record.layers.push_back(ethernet);
    record.linkLayer = LinkLayerType::Ethernet;
    record.sourceEndpoint = sourceMac;
    record.destinationEndpoint = destinationMac;

    if (etherType == kEtherTypeArp) {
        record.networkLayer = NetworkLayerType::Arp;
        if (frame.bytes.size() < 42) {
            record.summary = QStringLiteral("Ethernet / ARP (eksik header)");
            record.warnings.push_back(QStringLiteral("ARP header icin yeterli veri yok."));
            return record;
        }

        const int arpOffset = 14;
        const quint16 hardwareType = readBig16(frame.bytes, arpOffset + 0);
        const quint16 protocolType = readBig16(frame.bytes, arpOffset + 2);
        const quint8 hardwareLength = static_cast<quint8>(frame.bytes[arpOffset + 4]);
        const quint8 protocolLength = static_cast<quint8>(frame.bytes[arpOffset + 5]);
        const quint16 operation = readBig16(frame.bytes, arpOffset + 6);
        const QString senderMac = formatMac(frame.bytes, arpOffset + 8);
        const QString senderIp = formatIpv4(frame.bytes, arpOffset + 14);
        const QString targetMac = formatMac(frame.bytes, arpOffset + 18);
        const QString targetIp = formatIpv4(frame.bytes, arpOffset + 24);

        ProtocolLayer arp;
        arp.name = QStringLiteral("ARP");
        arp.fields.push_back({QStringLiteral("Hardware Type"), QString::number(hardwareType), arpOffset + 0, 2});
        arp.fields.push_back({QStringLiteral("Protocol Type"), QStringLiteral("0x%1").arg(protocolType, 4, 16, QLatin1Char('0')).toUpper(), arpOffset + 2, 2});
        arp.fields.push_back({QStringLiteral("Hardware Length"), QString::number(hardwareLength), arpOffset + 4, 1});
        arp.fields.push_back({QStringLiteral("Protocol Length"), QString::number(protocolLength), arpOffset + 5, 1});
        arp.fields.push_back({QStringLiteral("Operation"), arpOperationName(operation), arpOffset + 6, 2});
        arp.fields.push_back({QStringLiteral("Sender MAC"), senderMac, arpOffset + 8, 6});
        arp.fields.push_back({QStringLiteral("Sender IP"), senderIp, arpOffset + 14, 4});
        arp.fields.push_back({QStringLiteral("Target MAC"), targetMac, arpOffset + 18, 6});
        arp.fields.push_back({QStringLiteral("Target IP"), targetIp, arpOffset + 24, 4});
        record.layers.push_back(arp);

        record.sourceEndpoint = senderIp;
        record.destinationEndpoint = targetIp;
        record.summary = QStringLiteral("Ethernet / ARP / %1  %2 -> %3")
                             .arg(arpOperationName(operation),
                                  senderIp,
                                  targetIp);
        return record;
    }

    if (etherType != kEtherTypeIpv4) {
        record.summary = QStringLiteral("Ethernet / EtherType 0x%1").arg(etherType, 4, 16, QLatin1Char('0')).toUpper();
        return record;
    }

    if (frame.bytes.size() < 34) {
        record.networkLayer = NetworkLayerType::IPv4;
        record.summary = QStringLiteral("Ethernet / IPv4 (eksik header)");
        record.warnings.push_back(QStringLiteral("IPv4 header icin yeterli veri yok."));
        return record;
    }

    const int ipOffset = 14;
    const quint8 versionIhl = static_cast<quint8>(frame.bytes[ipOffset]);
    const quint8 version = static_cast<quint8>(versionIhl >> 4);
    const quint8 ihlBytes = static_cast<quint8>((versionIhl & 0x0F) * 4);
    const quint8 protocol = static_cast<quint8>(frame.bytes[ipOffset + 9]);
    const QString sourceIp = formatIpv4(frame.bytes, ipOffset + 12);
    const QString destinationIp = formatIpv4(frame.bytes, ipOffset + 16);

    ProtocolLayer ipv4;
    ipv4.name = QStringLiteral("IPv4");
    ipv4.fields.push_back({QStringLiteral("Version"), QString::number(version), ipOffset, 1});
    ipv4.fields.push_back({QStringLiteral("Header Length"), QString::number(ihlBytes), ipOffset, 1});
    ipv4.fields.push_back({QStringLiteral("Protocol"), ipv4ProtocolName(protocol), ipOffset + 9, 1});
    ipv4.fields.push_back({QStringLiteral("Source"), sourceIp, ipOffset + 12, 4});
    ipv4.fields.push_back({QStringLiteral("Destination"), destinationIp, ipOffset + 16, 4});
    record.layers.push_back(ipv4);
    record.networkLayer = NetworkLayerType::IPv4;
    record.sourceEndpoint = sourceIp;
    record.destinationEndpoint = destinationIp;

    if (version != 4 || ihlBytes < 20) {
        record.warnings.push_back(QStringLiteral("Gecersiz IPv4 header uzunlugu bulundu."));
    }

    switch (protocol) {
    case 1:
        record.transportLayer = TransportLayerType::Icmp;
        break;
    case 6:
        record.transportLayer = TransportLayerType::Tcp;
        break;
    case 17:
        record.transportLayer = TransportLayerType::Udp;
        break;
    default:
        record.transportLayer = TransportLayerType::Unknown;
        break;
    }

    record.summary = QStringLiteral("Ethernet / IPv4 / %1").arg(ipv4ProtocolName(protocol));

    const int transportOffset = ipOffset + ihlBytes;
    if (transportOffset > frame.bytes.size()) {
        record.warnings.push_back(QStringLiteral("Transport header offset gecersiz."));
        return record;
    }

    if ((protocol == 6 || protocol == 17) && frame.bytes.size() >= transportOffset + 4) {
        const quint16 sourcePort = readBig16(frame.bytes, transportOffset);
        const quint16 destinationPort = readBig16(frame.bytes, transportOffset + 2);
        record.sourceEndpoint = endpointText(sourceIp, sourcePort);
        record.destinationEndpoint = endpointText(destinationIp, destinationPort);

        ProtocolLayer transport;
        transport.name = protocol == 6 ? QStringLiteral("TCP") : QStringLiteral("UDP");
        transport.fields.push_back({QStringLiteral("Source Port"), QString::number(sourcePort), transportOffset, 2});
        transport.fields.push_back({QStringLiteral("Destination Port"), QString::number(destinationPort), transportOffset + 2, 2});

        if (protocol == 6 && frame.bytes.size() >= transportOffset + 20) {
            const quint32 sequenceNumber = readBig32(frame.bytes, transportOffset + 4);
            const quint32 acknowledgmentNumber = readBig32(frame.bytes, transportOffset + 8);
            const quint8 dataOffset = static_cast<quint8>((static_cast<quint8>(frame.bytes[transportOffset + 12]) >> 4) * 4);
            const quint16 tcpFlags = static_cast<quint16>(((static_cast<quint8>(frame.bytes[transportOffset + 12]) & 0x01u) << 8)
                                                          | static_cast<quint8>(frame.bytes[transportOffset + 13]));
            const quint16 windowSize = readBig16(frame.bytes, transportOffset + 14);
            transport.fields.push_back({QStringLiteral("Sequence Number"), QString::number(sequenceNumber), transportOffset + 4, 4});
            transport.fields.push_back({QStringLiteral("Acknowledgment Number"), QString::number(acknowledgmentNumber), transportOffset + 8, 4});
            transport.fields.push_back({QStringLiteral("Header Length"), QString::number(dataOffset), transportOffset + 12, 1});
            transport.fields.push_back({QStringLiteral("Flags"), tcpFlagsText(tcpFlags), transportOffset + 12, 2});
            transport.fields.push_back({QStringLiteral("Window Size"), QString::number(windowSize), transportOffset + 14, 2});
            if (dataOffset < 20) {
                record.warnings.push_back(QStringLiteral("Gecersiz TCP header uzunlugu bulundu."));
            }

            const int payloadOffset = transportOffset + dataOffset;
            if ((sourcePort == 80 || destinationPort == 80 || sourcePort == 8080 || destinationPort == 8080)
                && payloadOffset < frame.bytes.size()) {
                const QByteArray payload = frame.bytes.mid(payloadOffset);
                const int firstLineEnd = payload.indexOf("\r\n");
                const QByteArray firstLineBytes = firstLineEnd >= 0 ? payload.left(firstLineEnd) : payload.left(120);
                const QString firstLine = QString::fromLatin1(firstLineBytes).trimmed();
                const QStringList headerLines = QString::fromLatin1(payload.left(1024)).split(QStringLiteral("\r\n"), Qt::SkipEmptyParts);

                if (!firstLine.isEmpty()) {
                    ProtocolLayer http;
                    http.name = QStringLiteral("HTTP");
                    http.fields.push_back({QStringLiteral("First Line"), firstLine, payloadOffset, static_cast<int>(firstLineBytes.size())});

                    if (firstLine.startsWith(QStringLiteral("HTTP/"), Qt::CaseInsensitive)) {
                        const QStringList parts = firstLine.split(' ', Qt::SkipEmptyParts);
                        if (parts.size() >= 2) {
                            http.fields.push_back({QStringLiteral("Type"), QStringLiteral("Response"), payloadOffset, 0});
                            http.fields.push_back({QStringLiteral("Status Code"), parts.at(1), payloadOffset, 0});
                            if (parts.size() >= 3) {
                                http.fields.push_back({QStringLiteral("Reason Phrase"), parts.mid(2).join(' '), payloadOffset, 0});
                            }
                            const QString contentType = extractHttpHeaderValue(headerLines, QStringLiteral("Content-Type"));
                            const QString server = extractHttpHeaderValue(headerLines, QStringLiteral("Server"));
                            const QString location = extractHttpHeaderValue(headerLines, QStringLiteral("Location"));
                            const QString contentLength = extractHttpHeaderValue(headerLines, QStringLiteral("Content-Length"));
                            const QString setCookie = extractHttpHeaderValue(headerLines, QStringLiteral("Set-Cookie"));
                            const QString wwwAuthenticate = extractHttpHeaderValue(headerLines, QStringLiteral("WWW-Authenticate"));
                            if (!contentType.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Content-Type"), contentType, payloadOffset, 0});
                            }
                            if (!server.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Server"), server, payloadOffset, 0});
                            }
                            if (!location.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Location"), location, payloadOffset, 0});
                            }
                            if (!contentLength.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Content-Length"), contentLength, payloadOffset, 0});
                            }
                            if (!setCookie.isEmpty()) {
                                const QStringList setCookieNames = extractCookieNames(setCookie);
                                http.fields.push_back({QStringLiteral("Set-Cookie"), setCookie, payloadOffset, 0});
                                http.fields.push_back({QStringLiteral("Set-Cookie Count"), QString::number(countHeaderOccurrences(headerLines, QStringLiteral("Set-Cookie"))), payloadOffset, 0});
                                http.fields.push_back({QStringLiteral("Set-Cookie Names"), setCookieNames.join(QStringLiteral(", ")), payloadOffset, 0});
                                if (!setCookieNames.isEmpty()) {
                                    http.fields.push_back({QStringLiteral("Set-Cookie Primary Name"), setCookieNames.first(), payloadOffset, 0});
                                    const QString primaryValue = extractCookieValue(setCookie, setCookieNames.first());
                                    if (!primaryValue.isEmpty()) {
                                        http.fields.push_back({QStringLiteral("Set-Cookie Primary Value"), primaryValue, payloadOffset, 0});
                                    }
                                }
                                const QStringList setCookieFlags = extractSetCookieFlags(setCookie);
                                if (!setCookieFlags.isEmpty()) {
                                    http.fields.push_back({QStringLiteral("Set-Cookie Flags"), setCookieFlags.join(QStringLiteral(", ")), payloadOffset, 0});
                                }
                            }
                            if (!wwwAuthenticate.isEmpty()) {
                                http.fields.push_back({QStringLiteral("WWW-Authenticate"), wwwAuthenticate, payloadOffset, 0});
                                http.fields.push_back({QStringLiteral("Auth Challenge Scheme"), extractAuthorizationScheme(wwwAuthenticate), payloadOffset, 0});
                                const QString authRealm = extractAuthRealm(wwwAuthenticate);
                                if (!authRealm.isEmpty()) {
                                    http.fields.push_back({QStringLiteral("Auth Realm"), authRealm, payloadOffset, 0});
                                }
                            }
                            const QString bodyPreview = previewHttpBody(payload);
                            if (!bodyPreview.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Body Preview"), bodyPreview, payloadOffset, 0});
                            }
                            record.summary = QStringLiteral("Ethernet / IPv4 / TCP / HTTP Response %1  %2 -> %3")
                                                 .arg(parts.at(1),
                                                      record.sourceEndpoint,
                                                      record.destinationEndpoint);
                        }
                    } else {
                        const QStringList parts = firstLine.split(' ', Qt::SkipEmptyParts);
                        if (parts.size() >= 2) {
                            http.fields.push_back({QStringLiteral("Type"), QStringLiteral("Request"), payloadOffset, 0});
                            http.fields.push_back({QStringLiteral("Method"), parts.at(0), payloadOffset, 0});
                            http.fields.push_back({QStringLiteral("Target"), parts.at(1), payloadOffset, 0});
                            const QString host = extractHttpHeaderValue(headerLines, QStringLiteral("Host"));
                            const QString userAgent = extractHttpHeaderValue(headerLines, QStringLiteral("User-Agent"));
                            const QString contentType = extractHttpHeaderValue(headerLines, QStringLiteral("Content-Type"));
                            const QString contentLength = extractHttpHeaderValue(headerLines, QStringLiteral("Content-Length"));
                            const QString accept = extractHttpHeaderValue(headerLines, QStringLiteral("Accept"));
                            const QString authorization = extractHttpHeaderValue(headerLines, QStringLiteral("Authorization"));
                            const QString cookie = extractHttpHeaderValue(headerLines, QStringLiteral("Cookie"));
                            if (!host.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Host"), host, payloadOffset, 0});
                            }
                            if (!userAgent.isEmpty()) {
                                http.fields.push_back({QStringLiteral("User-Agent"), userAgent, payloadOffset, 0});
                            }
                            if (!contentType.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Content-Type"), contentType, payloadOffset, 0});
                            }
                            if (!contentLength.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Content-Length"), contentLength, payloadOffset, 0});
                            }
                            if (!accept.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Accept"), accept, payloadOffset, 0});
                            }
                            if (!authorization.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Authorization"), authorization, payloadOffset, 0});
                                http.fields.push_back({QStringLiteral("Authorization Scheme"), extractAuthorizationScheme(authorization), payloadOffset, 0});
                            }
                            if (!cookie.isEmpty()) {
                                const QStringList cookieNames = extractCookieNames(cookie);
                                http.fields.push_back({QStringLiteral("Cookie"), cookie, payloadOffset, 0});
                                http.fields.push_back({QStringLiteral("Cookie Count"), QString::number(countCookiePairs(cookie)), payloadOffset, 0});
                                http.fields.push_back({QStringLiteral("Cookie Names"), cookieNames.join(QStringLiteral(", ")), payloadOffset, 0});
                                if (!cookieNames.isEmpty()) {
                                    http.fields.push_back({QStringLiteral("Cookie Primary Name"), cookieNames.first(), payloadOffset, 0});
                                    const QString primaryValue = extractCookieValue(cookie, cookieNames.first());
                                    if (!primaryValue.isEmpty()) {
                                        http.fields.push_back({QStringLiteral("Cookie Primary Value"), primaryValue, payloadOffset, 0});
                                    }
                                }
                            }
                            const QString bodyPreview = previewHttpBody(payload);
                            if (!bodyPreview.isEmpty()) {
                                http.fields.push_back({QStringLiteral("Body Preview"), bodyPreview, payloadOffset, 0});
                            }
                            record.summary = QStringLiteral("Ethernet / IPv4 / TCP / HTTP %1 %2  %3 -> %4")
                                                 .arg(parts.at(0),
                                                      parts.at(1),
                                                      record.sourceEndpoint,
                                                      record.destinationEndpoint);
                        }
                    }

                    record.layers.push_back(http);
                    if (!record.summary.contains(QStringLiteral("HTTP"))) {
                        record.summary = QStringLiteral("Ethernet / IPv4 / TCP / HTTP  %1 -> %2")
                                             .arg(record.sourceEndpoint,
                                                  record.destinationEndpoint);
                    }
                }
            } else if ((sourcePort == 443 || destinationPort == 443) && payloadOffset + 5 <= frame.bytes.size()) {
                const quint8 recordType = static_cast<quint8>(frame.bytes[payloadOffset]);
                const quint16 tlsVersion = readBig16(frame.bytes, payloadOffset + 1);
                const quint16 recordLength = readBig16(frame.bytes, payloadOffset + 3);

                ProtocolLayer tls;
                tls.name = QStringLiteral("TLS");
                tls.fields.push_back({QStringLiteral("Record Type"), tlsRecordTypeName(recordType), payloadOffset, 1});
                tls.fields.push_back({QStringLiteral("Version"), tlsVersionName(tlsVersion), payloadOffset + 1, 2});
                tls.fields.push_back({QStringLiteral("Record Length"), QString::number(recordLength), payloadOffset + 3, 2});

                if (recordType == 22 && payloadOffset + 9 <= frame.bytes.size()) {
                    const quint8 handshakeType = static_cast<quint8>(frame.bytes[payloadOffset + 5]);
                    const quint32 handshakeLength =
                        (static_cast<quint32>(static_cast<quint8>(frame.bytes[payloadOffset + 6])) << 16)
                        | (static_cast<quint32>(static_cast<quint8>(frame.bytes[payloadOffset + 7])) << 8)
                        | static_cast<quint32>(static_cast<quint8>(frame.bytes[payloadOffset + 8]));
                    tls.fields.push_back({QStringLiteral("Handshake Type"), tlsHandshakeTypeName(handshakeType), payloadOffset + 5, 1});
                    tls.fields.push_back({QStringLiteral("Handshake Length"), QString::number(handshakeLength), payloadOffset + 6, 3});
                    const TlsClientHelloMetadata clientHello = parseTlsClientHelloMetadata(frame.bytes, payloadOffset);
                    if (!clientHello.serverName.isEmpty()) {
                        tls.fields.push_back({QStringLiteral("Server Name"), clientHello.serverName, payloadOffset, 0});
                    }
                    if (!clientHello.cipherSuite.isEmpty()) {
                        tls.fields.push_back({QStringLiteral("Cipher Suite"), clientHello.cipherSuite, payloadOffset, 0});
                    }
                    if (!clientHello.supportedVersion.isEmpty()) {
                        tls.fields.push_back({QStringLiteral("Supported Version"), clientHello.supportedVersion, payloadOffset, 0});
                    }
                    if (!clientHello.alpnProtocol.isEmpty()) {
                        tls.fields.push_back({QStringLiteral("ALPN"), clientHello.alpnProtocol, payloadOffset, 0});
                    }
                    if (!clientHello.supportedGroup.isEmpty()) {
                        tls.fields.push_back({QStringLiteral("Supported Group"), clientHello.supportedGroup, payloadOffset, 0});
                    }
                    if (!clientHello.keyShareGroup.isEmpty()) {
                        tls.fields.push_back({QStringLiteral("Key Share Group"), clientHello.keyShareGroup, payloadOffset, 0});
                    }
                    if (!clientHello.extensions.isEmpty()) {
                        tls.fields.push_back({QStringLiteral("Extensions"), clientHello.extensions.join(QStringLiteral(", ")), payloadOffset, 0});
                    }
                    if (handshakeType == 2 && payloadOffset + 46 <= frame.bytes.size()) {
                        tls.fields.push_back({QStringLiteral("Server Version"), tlsVersionName(readBig16(frame.bytes, payloadOffset + 9)), payloadOffset + 9, 2});
                        tls.fields.push_back({QStringLiteral("Selected Cipher Suite"), tlsCipherSuiteName(readBig16(frame.bytes, payloadOffset + 44)), payloadOffset + 44, 2});
                    } else if (handshakeType == 11 && payloadOffset + 12 <= frame.bytes.size()) {
                        const TlsCertificateMetadata certificateMeta = parseTlsCertificateMetadata(frame.bytes, payloadOffset);
                        // TLS Certificate starts with a 3-byte certificate_list length.
                        tls.fields.push_back({QStringLiteral("Certificates Length"), QString::number(certificateMeta.certificateListLength), payloadOffset + 9, 3});
                        if (certificateMeta.certificateCount > 0) {
                            tls.fields.push_back({QStringLiteral("Certificate Count"), QString::number(certificateMeta.certificateCount), payloadOffset + 12, 0});
                            tls.fields.push_back({QStringLiteral("First Certificate Length"), QString::number(certificateMeta.firstCertificateLength), payloadOffset + 12, 3});
                            if (!certificateMeta.firstCertificateSha256.isEmpty()) {
                                tls.fields.push_back({QStringLiteral("First Certificate SHA256"), certificateMeta.firstCertificateSha256, payloadOffset + 12, 0});
                            }
                        }
                    }
                    record.summary = QStringLiteral("Ethernet / IPv4 / TCP / TLS %1  %2 -> %3")
                                         .arg(tlsHandshakeTypeName(handshakeType),
                                              record.sourceEndpoint,
                                              record.destinationEndpoint);
                } else {
                    record.summary = QStringLiteral("Ethernet / IPv4 / TCP / TLS %1  %2 -> %3")
                                         .arg(tlsRecordTypeName(recordType),
                                              record.sourceEndpoint,
                                              record.destinationEndpoint);
                }

                record.layers.push_back(tls);
            }
        } else if (protocol == 17 && frame.bytes.size() >= transportOffset + 8) {
            const quint16 udpLength = readBig16(frame.bytes, transportOffset + 4);
            transport.fields.push_back({QStringLiteral("Length"), QString::number(udpLength), transportOffset + 4, 2});
        }

        record.layers.push_back(transport);
        if (!record.summary.contains(QStringLiteral("HTTP"))) {
            record.summary = QStringLiteral("Ethernet / IPv4 / %1  %2 -> %3")
                                 .arg(protocol == 6 ? QStringLiteral("TCP") : QStringLiteral("UDP"),
                                      record.sourceEndpoint,
                                      record.destinationEndpoint);
        }

        if (protocol == 17 && (sourcePort == 53 || destinationPort == 53) && frame.bytes.size() >= transportOffset + 16) {
            const int dnsOffset = transportOffset + 8;
            if (frame.bytes.size() >= dnsOffset + 12) {
                const quint16 transactionId = readBig16(frame.bytes, dnsOffset + 0);
                const quint16 flags = readBig16(frame.bytes, dnsOffset + 2);
                const quint16 questionCount = readBig16(frame.bytes, dnsOffset + 4);
                const quint16 answerCount = readBig16(frame.bytes, dnsOffset + 6);
                const quint16 authorityCount = readBig16(frame.bytes, dnsOffset + 8);
                const quint16 additionalCount = readBig16(frame.bytes, dnsOffset + 10);

                ProtocolLayer dns;
                dns.name = QStringLiteral("DNS");
                dns.fields.push_back({QStringLiteral("Transaction ID"), QStringLiteral("0x%1").arg(transactionId, 4, 16, QLatin1Char('0')).toUpper(), dnsOffset + 0, 2});
                dns.fields.push_back({QStringLiteral("Message Type"), dnsMessageType(flags), dnsOffset + 2, 2});
                dns.fields.push_back({QStringLiteral("Flags"), QStringLiteral("0x%1").arg(flags, 4, 16, QLatin1Char('0')).toUpper(), dnsOffset + 2, 2});
                dns.fields.push_back({QStringLiteral("Questions"), QString::number(questionCount), dnsOffset + 4, 2});
                dns.fields.push_back({QStringLiteral("Answers"), QString::number(answerCount), dnsOffset + 6, 2});
                dns.fields.push_back({QStringLiteral("Authority RRs"), QString::number(authorityCount), dnsOffset + 8, 2});
                dns.fields.push_back({QStringLiteral("Additional RRs"), QString::number(additionalCount), dnsOffset + 10, 2});

                QString queryName;
                int queryConsumedBytes = 0;
                int queryMetaOffset = -1;
                if (questionCount > 0) {
                    queryName = parseDnsName(frame.bytes, dnsOffset + 12, frame.bytes.size(), &queryConsumedBytes);
                    if (!queryName.isEmpty()) {
                        dns.fields.push_back({QStringLiteral("Query Name"), queryName, dnsOffset + 12, queryConsumedBytes});
                        queryMetaOffset = dnsOffset + 12 + queryConsumedBytes;
                        if (frame.bytes.size() >= queryMetaOffset + 4) {
                            const quint16 queryType = readBig16(frame.bytes, queryMetaOffset);
                            const quint16 queryClass = readBig16(frame.bytes, queryMetaOffset + 2);
                            dns.fields.push_back({QStringLiteral("Query Type"), dnsTypeName(queryType), queryMetaOffset, 2});
                            dns.fields.push_back({QStringLiteral("Query Class"), dnsClassName(queryClass), queryMetaOffset + 2, 2});
                        }
                    } else {
                        record.warnings.push_back(QStringLiteral("DNS query name parse edilemedi."));
                    }
                }

                if (answerCount > 0 && queryMetaOffset >= 0) {
                    int answerCursor = queryMetaOffset + 4;
                    answerCursor = appendDnsResourceRecords(dns, frame.bytes, answerCursor, answerCount, QStringLiteral("Answer"), 3);
                    answerCursor = appendDnsResourceRecords(dns, frame.bytes, answerCursor, authorityCount, QStringLiteral("Authority"), 2);
                    answerCursor = appendDnsResourceRecords(dns, frame.bytes, answerCursor, additionalCount, QStringLiteral("Additional"), 2);
                }

                record.layers.push_back(dns);

                record.summary = queryName.isEmpty()
                                     ? QStringLiteral("Ethernet / IPv4 / UDP / DNS %1  %2 -> %3")
                                           .arg(dnsMessageType(flags),
                                                record.sourceEndpoint,
                                                record.destinationEndpoint)
                                     : QStringLiteral("Ethernet / IPv4 / UDP / DNS %1 %2  %3 -> %4")
                                           .arg(dnsMessageType(flags),
                                                queryName,
                                                record.sourceEndpoint,
                                                record.destinationEndpoint);
            }
        }

        return record;
    }

    if (protocol == 1) {
        record.sourceEndpoint = sourceIp;
        record.destinationEndpoint = destinationIp;

        ProtocolLayer icmp;
        icmp.name = QStringLiteral("ICMP");
        if (frame.bytes.size() >= transportOffset + 2) {
            const quint8 type = static_cast<quint8>(frame.bytes[transportOffset]);
            const quint8 code = static_cast<quint8>(frame.bytes[transportOffset + 1]);
            icmp.fields.push_back({QStringLiteral("Type"), QString::number(type), transportOffset, 1});
            icmp.fields.push_back({QStringLiteral("Code"), QString::number(code), transportOffset + 1, 1});
        }
        record.layers.push_back(icmp);
        record.summary = QStringLiteral("Ethernet / IPv4 / ICMP  %1 -> %2")
                             .arg(record.sourceEndpoint,
                                  record.destinationEndpoint);
        return record;
    }

    return record;
}

} // namespace pengufoce::pengucore
