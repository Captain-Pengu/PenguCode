#include "pengucore/capture/pcapfilereader.h"
#include "pengucore/capture/pcapfilewriter.h"
#include "pengucore/parser/basicframeparser.h"

#include <QCryptographicHash>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QStringList>
#include <QTemporaryDir>

#include <iostream>

using namespace pengufoce::pengucore;

namespace {

QString fixturePath(const QString &relativePath)
{
    return QDir(QStringLiteral(PENGUFOCE_SOURCE_ROOT)).absoluteFilePath(
        QStringLiteral("tests/fixtures/pengucore/%1").arg(relativePath));
}

bool require(bool condition, const QString &message)
{
    if (!condition) {
        std::cerr << message.toStdString() << std::endl;
    }
    return condition;
}

int testPcapReadAndTcpParse()
{
    PcapFileReader reader;
    const auto result = reader.readFile(fixturePath(QStringLiteral("tcp_ipv4_sample.pcap")));
    if (!require(result.success, QStringLiteral("tcp fixture okunamadi"))) {
        return 1;
    }
    if (!require(!result.frames.isEmpty(), QStringLiteral("tcp fixture frame icermiyor"))) {
        return 1;
    }

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(result.frames.front());

    if (!require(packet.sourceEndpoint.contains(QStringLiteral("192.168.1.10:51514")),
                 QStringLiteral("tcp source endpoint beklenen gibi degil"))) {
        return 1;
    }
    if (!require(packet.destinationEndpoint.contains(QStringLiteral("93.184.216.34:80")),
                 QStringLiteral("tcp destination endpoint beklenen gibi degil"))) {
        return 1;
    }
    if (!require(packet.summary.contains(QStringLiteral("TCP"), Qt::CaseInsensitive),
                 QStringLiteral("tcp summary parse edilmedi"))) {
        return 1;
    }

    bool sawFlags = false;
    bool sawWindow = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("TCP")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Flags") && !field.value.isEmpty()) {
                sawFlags = true;
            }
            if (field.name == QStringLiteral("Window Size") && !field.value.isEmpty()) {
                sawWindow = true;
            }
        }
    }
    if (!require(sawFlags, QStringLiteral("tcp flags parse edilmedi"))) {
        return 1;
    }
    if (!require(sawWindow, QStringLiteral("tcp window size parse edilmedi"))) {
        return 1;
    }

    return 0;
}

int testTcpHeaderMetadata()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex(
        "00112233445566778899AABB0800450000340001000040060000C0A8010A5DB8D822"
        "C93A01BB00001000000020015012FAF000000000");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawAck = false;
    bool sawFlags = false;
    bool sawWindow = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("TCP")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Acknowledgment Number") && field.value == QStringLiteral("8193")) {
                sawAck = true;
            }
            if (field.name == QStringLiteral("Flags") && field.value.contains(QStringLiteral("ACK"))) {
                sawFlags = true;
            }
            if (field.name == QStringLiteral("Window Size") && field.value == QStringLiteral("64240")) {
                sawWindow = true;
            }
        }
    }

    if (!require(sawAck, QStringLiteral("tcp acknowledgment parse edilmedi"))) {
        return 1;
    }
    if (!require(sawFlags, QStringLiteral("tcp metadata flags parse edilmedi"))) {
        return 1;
    }
    if (!require(sawWindow, QStringLiteral("tcp metadata window parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testDnsQueryParse()
{
    PcapFileReader reader;
    const auto result = reader.readFile(fixturePath(QStringLiteral("udp_ipv4_sample.pcap")));
    if (!require(result.success, QStringLiteral("dns fixture okunamadi"))) {
        return 1;
    }
    if (!require(!result.frames.isEmpty(), QStringLiteral("dns fixture frame icermiyor"))) {
        return 1;
    }

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(result.frames.front());

    bool sawDnsLayer = false;
    bool sawQueryName = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name == QStringLiteral("DNS")) {
            sawDnsLayer = true;
            for (const ProtocolField &field : layer.fields) {
                if (field.name == QStringLiteral("Query Name")
                    && field.value.contains(QStringLiteral("example.com"), Qt::CaseInsensitive)) {
                    sawQueryName = true;
                }
            }
        }
    }

    if (!require(sawDnsLayer, QStringLiteral("dns layer bulunamadi"))) {
        return 1;
    }
    if (!require(sawQueryName, QStringLiteral("dns query name parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testDnsAnswerParse()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex(
        "00112233445566778899AABB0800450000490001000040110000C0A8011408080808"
        "00350035003500001A2B81800001000100000000076578616D706C6503636F6D0000"
        "010001C00C000100010000003C00045DB8D822");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawAnswerData = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("DNS")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if ((field.name == QStringLiteral("Answer Data") || field.name == QStringLiteral("Answer 1 Data"))
                && field.value == QStringLiteral("93.184.216.34")) {
                sawAnswerData = true;
            }
        }
    }

    if (!require(sawAnswerData, QStringLiteral("dns answer parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testDnsAuthorityAdditionalParse()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex(
        "00112233445566778899AABB0800450000790001000040110000C0A8011408080808"
        "00350035006500001A2B81800001000100010001"
        "076578616D706C6503636F6D0000010001"
        "C00C000100010000003C00045DB8D822"
        "C00C000200010000003C0011036E7331076578616D706C6503636F6D00"
        "C051000100010000003C0004C633640A");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawAuthority = false;
    bool sawAdditional = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("DNS")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Authority 1 Data")
                && field.value.contains(QStringLiteral("ns1.example.com"), Qt::CaseInsensitive)) {
                sawAuthority = true;
            }
            if (field.name == QStringLiteral("Additional 1 Data")
                && field.value == QStringLiteral("198.51.100.10")) {
                sawAdditional = true;
            }
        }
    }

    if (!require(sawAuthority, QStringLiteral("dns authority parse edilmedi"))) {
        return 1;
    }
    if (!require(sawAdditional, QStringLiteral("dns additional parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testDnsRichRecordTypes()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex(
        "00112233445566778899AABB0800450000B90001000040110000C0A8011408080808"
        "0035003500A500001A2B81800001000300000000"
        "076578616D706C6503636F6D00001C0001"
        "C00C001C00010000003C001020010DB8000000000000000000000001"
        "C00C000F00010000003C0014000A046D61696C076578616D706C6503636F6D00"
        "C00C001000010000003C000F0E7665726966793D73756363657373");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawAaaa = false;
    bool sawMx = false;
    bool sawTxt = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("DNS")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Answer 1 Data")
                && field.value.contains(QStringLiteral("2001:0DB8"), Qt::CaseInsensitive)) {
                sawAaaa = true;
            }
            if (field.name == QStringLiteral("Answer 2 Data")
                && field.value.contains(QStringLiteral("mail.example.com"), Qt::CaseInsensitive)) {
                sawMx = true;
            }
            if ((field.name == QStringLiteral("Answer 3 Data")
                 && !field.value.trimmed().isEmpty())
                || (field.name == QStringLiteral("Answer 3 Type")
                    && field.value == QStringLiteral("TXT"))) {
                sawTxt = true;
            }
        }
    }

    if (!require(sawAaaa, QStringLiteral("dns aaaa parse edilmedi"))) {
        return 1;
    }
    if (!require(sawMx, QStringLiteral("dns mx parse edilmedi"))) {
        return 1;
    }
    if (!require(sawTxt, QStringLiteral("dns txt parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testPcapNgRead()
{
    PcapFileReader reader;
    const auto result = reader.readFile(fixturePath(QStringLiteral("pcapng_http_sample.pcapng")));
    if (!require(result.success, QStringLiteral("pcapng fixture okunamadi"))) {
        return 1;
    }
    if (!require(result.pcapngDetected, QStringLiteral("pcapng fixture dogru formatta algilanmadi"))) {
        return 1;
    }
    if (!require(!result.frames.isEmpty(), QStringLiteral("pcapng fixture frame icermiyor"))) {
        return 1;
    }
    return 0;
}

int testHttpResponseBodyPreview()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    const QByteArray headers =
        "00112233445566778899aabb08004500007b00010000400600005db8d822c0a8010a"
        "0050c93a00001000000020005018040000000000"
        "485454502f312e3120323030204f4b0d0a"
        "436f6e74656e742d547970653a20746578742f68746d6c0d0a"
        "5365727665723a2050656e6775466f63650d0a"
        "0d0a"
        "3c68746d6c3e3c626f64793e48656c6c6f20576f726c643c2f626f64793e3c2f68746d6c3e";
    frame.bytes = QByteArray::fromHex(headers);
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawBodyPreview = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("HTTP")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Body Preview") && !field.value.trimmed().isEmpty()) {
                sawBodyPreview = true;
            }
        }
    }

    if (!require(sawBodyPreview, QStringLiteral("http body preview parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testHttpRequestBodyPreview()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    const QByteArray headers =
        "00112233445566778899aabb08004500009d0001000040060000c0a8010a5db8d822"
        "c93a005000001000000020005018040000000000"
        "504f5354202f6170692f6c6f67696e20485454502f312e310d0a"
        "486f73743a206578616d706c652e636f6d0d0a"
        "557365722d4167656e743a2050656e6775466f63650d0a"
        "436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e0d0a"
        "0d0a"
        "7b2275736572223a2270656e6775222c2270617373223a22666f6365227d";
    frame.bytes = QByteArray::fromHex(headers);
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawBodyPreview = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("HTTP")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Body Preview")
                && field.value.contains(QStringLiteral("user"), Qt::CaseInsensitive)) {
                sawBodyPreview = true;
            }
        }
    }

    if (!require(sawBodyPreview, QStringLiteral("http request body preview parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testHttpRequestHeaderMetadata()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    const QByteArray headers =
        "00112233445566778899aabb0800450000c00001000040060000c0a8010a5db8d822"
        "c93a005000001000000020005018040000000000"
        "474554202f6170692f70726f66696c6520485454502f312e310d0a"
        "486f73743a206578616d706c652e636f6d0d0a"
        "557365722d4167656e743a2050656e6775466f63650d0a"
        "4163636570743a206170706c69636174696f6e2f6a736f6e0d0a"
        "417574686f72697A6174696F6E3A2042656172657220746F6B656E3132330d0a"
        "436F6F6B69653A2073657373696F6E3D6162633132330d0a0d0a";
    frame.bytes = QByteArray::fromHex(headers);
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawAuthorization = false;
    bool sawAuthorizationScheme = false;
    bool sawCookie = false;
    bool sawCookieCount = false;
    bool sawCookieNames = false;
    bool sawCookiePrimaryName = false;
    bool sawCookiePrimaryValue = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("HTTP")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Authorization") && field.value.contains(QStringLiteral("Bearer token123"))) {
                sawAuthorization = true;
            }
            if (field.name == QStringLiteral("Authorization Scheme") && field.value == QStringLiteral("Bearer")) {
                sawAuthorizationScheme = true;
            }
            if (field.name == QStringLiteral("Cookie") && field.value.contains(QStringLiteral("session=abc123"))) {
                sawCookie = true;
            }
            if (field.name == QStringLiteral("Cookie Count") && field.value == QStringLiteral("1")) {
                sawCookieCount = true;
            }
            if (field.name == QStringLiteral("Cookie Names") && field.value.contains(QStringLiteral("session"))) {
                sawCookieNames = true;
            }
            if (field.name == QStringLiteral("Cookie Primary Name") && field.value == QStringLiteral("session")) {
                sawCookiePrimaryName = true;
            }
            if (field.name == QStringLiteral("Cookie Primary Value") && field.value == QStringLiteral("abc123")) {
                sawCookiePrimaryValue = true;
            }
        }
    }

    if (!require(sawAuthorization, QStringLiteral("http authorization parse edilmedi"))) {
        return 1;
    }
    if (!require(sawCookie, QStringLiteral("http cookie parse edilmedi"))) {
        return 1;
    }
    if (!require(sawAuthorizationScheme, QStringLiteral("http authorization scheme parse edilmedi"))) {
        return 1;
    }
    if (!require(sawCookieCount, QStringLiteral("http cookie count parse edilmedi"))) {
        return 1;
    }
    if (!require(sawCookieNames, QStringLiteral("http cookie names parse edilmedi"))) {
        return 1;
    }
    if (!require(sawCookiePrimaryName, QStringLiteral("http cookie primary name parse edilmedi"))) {
        return 1;
    }
    if (!require(sawCookiePrimaryValue, QStringLiteral("http cookie primary value parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testHttpResponseHeaderMetadata()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    const QByteArray headers =
        "00112233445566778899aabb0800450000c000010000400600005db8d822c0a8010a"
        "0050c93a00001000000020005018040000000000"
        "485454502f312e312033303220466f756e640d0a"
        "436F6E74656E742d547970653A20746578742f68746D6C0d0a"
        "4C6F636174696F6E3A2068747470733A2F2F6578616D706C652E636F6D2F6C6F67696E0d0a"
        "5365742D436F6F6B69653A2073657373696F6E3D6E657778797A3B205365637572653B20487474704F6E6C790d0a"
        "5757572D41757468656E7469636174653A204261736963207265616C6D3D22617069220d0a0d0a";
    frame.bytes = QByteArray::fromHex(headers);
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawLocation = false;
    bool sawSetCookie = false;
    bool sawSetCookieCount = false;
    bool sawSetCookieNames = false;
    bool sawSetCookieFlags = false;
    bool sawSetCookiePrimaryName = false;
    bool sawSetCookiePrimaryValue = false;
    bool sawAuthenticate = false;
    bool sawAuthChallengeScheme = false;
    bool sawAuthRealm = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("HTTP")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Location")
                && field.value.contains(QStringLiteral("https://example.com/login"))) {
                sawLocation = true;
            }
            if (field.name == QStringLiteral("Set-Cookie")
                && field.value.contains(QStringLiteral("session=newxyz"))) {
                sawSetCookie = true;
            }
            if (field.name == QStringLiteral("Set-Cookie Count") && field.value == QStringLiteral("1")) {
                sawSetCookieCount = true;
            }
            if (field.name == QStringLiteral("Set-Cookie Names") && field.value.contains(QStringLiteral("session"))) {
                sawSetCookieNames = true;
            }
            if (field.name == QStringLiteral("Set-Cookie Primary Name") && field.value == QStringLiteral("session")) {
                sawSetCookiePrimaryName = true;
            }
            if (field.name == QStringLiteral("Set-Cookie Primary Value") && field.value == QStringLiteral("newxyz")) {
                sawSetCookiePrimaryValue = true;
            }
            if (field.name == QStringLiteral("Set-Cookie Flags")
                && field.value.contains(QStringLiteral("HttpOnly"))
                && field.value.contains(QStringLiteral("Secure"))) {
                sawSetCookieFlags = true;
            }
            if (field.name == QStringLiteral("WWW-Authenticate")
                && field.value.contains(QStringLiteral("Basic realm"))) {
                sawAuthenticate = true;
            }
            if (field.name == QStringLiteral("Auth Challenge Scheme") && field.value == QStringLiteral("Basic")) {
                sawAuthChallengeScheme = true;
            }
            if (field.name == QStringLiteral("Auth Realm") && field.value == QStringLiteral("api")) {
                sawAuthRealm = true;
            }
        }
    }

    if (!require(sawLocation, QStringLiteral("http location parse edilmedi"))) {
        return 1;
    }
    if (!require(sawSetCookie, QStringLiteral("http set-cookie parse edilmedi"))) {
        return 1;
    }
    if (!require(sawAuthenticate, QStringLiteral("http www-authenticate parse edilmedi"))) {
        return 1;
    }
    if (!require(sawSetCookieCount, QStringLiteral("http set-cookie count parse edilmedi"))) {
        return 1;
    }
    if (!require(sawAuthChallengeScheme, QStringLiteral("http auth challenge scheme parse edilmedi"))) {
        return 1;
    }
    if (!require(sawSetCookieFlags, QStringLiteral("http set-cookie flags parse edilmedi"))) {
        return 1;
    }
    if (!require(sawSetCookieNames, QStringLiteral("http set-cookie names parse edilmedi"))) {
        return 1;
    }
    if (!require(sawSetCookiePrimaryName, QStringLiteral("http set-cookie primary name parse edilmedi"))) {
        return 1;
    }
    if (!require(sawSetCookiePrimaryValue, QStringLiteral("http set-cookie primary value parse edilmedi"))) {
        return 1;
    }
    if (!require(sawAuthRealm, QStringLiteral("http auth realm parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testTlsHandshakeMetadata()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex(
        "00112233445566778899AABB08004500004C0001000040060000C0A8010A5DB8D822"
        "C93A01BB00001000000020005018040000000000"
        "16030300100100000C0303000000000000000000");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawTlsLayer = false;
    bool sawVersion = false;
    bool sawHandshake = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("TLS")) {
            continue;
        }
        sawTlsLayer = true;
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Version") && field.value == QStringLiteral("TLS 1.2")) {
                sawVersion = true;
            }
            if (field.name == QStringLiteral("Handshake Type") && field.value == QStringLiteral("ClientHello")) {
                sawHandshake = true;
            }
        }
    }

    if (!require(sawTlsLayer, QStringLiteral("tls layer parse edilmedi"))) {
        return 1;
    }
    if (!require(sawVersion, QStringLiteral("tls version parse edilmedi"))) {
        return 1;
    }
    if (!require(sawHandshake, QStringLiteral("tls handshake type parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testTlsServerNameParse()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex(
                      "00112233445566778899AABB08004500007F0001000040060000C0A8010A5DB8D822"
                      "C93A01BB00001000000020005018040000000000")
                  + QByteArray::fromHex("1603030057010000530303")
                  + QByteArray(32, '\0')
                  + QByteArray::fromHex("000002130101000028"
                                         "00000014001200000F")
                  + QByteArray("api.example.com")
                  + QByteArray::fromHex("001000050003026832"
                                         "002B0003020304");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawServerName = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("TLS")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Server Name")
                && field.value == QStringLiteral("api.example.com")) {
                sawServerName = true;
            }
        }
    }

    if (!require(sawServerName, QStringLiteral("tls server name parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testTlsClientHelloDetails()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex(
                      "00112233445566778899AABB08004500007F0001000040060000C0A8010A5DB8D822"
                      "C93A01BB00001000000020005018040000000000")
                  + QByteArray::fromHex("1603030057010000530303")
                  + QByteArray(32, '\0')
                  + QByteArray::fromHex("000002130101000028"
                                         "00000014001200000F")
                  + QByteArray("api.example.com")
                  + QByteArray::fromHex("001000050003026832"
                                         "002B0003020304");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawCipher = false;
    bool sawExtensions = false;
    bool sawSupportedVersion = false;
    bool sawAlpn = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("TLS")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Cipher Suite")
                && field.value == QStringLiteral("TLS_AES_128_GCM_SHA256")) {
                sawCipher = true;
            }
            if (field.name == QStringLiteral("Extensions")
                && field.value.contains(QStringLiteral("server_name"), Qt::CaseInsensitive)) {
                sawExtensions = true;
            }
            if (field.name == QStringLiteral("Supported Version")
                && field.value == QStringLiteral("TLS 1.3")) {
                sawSupportedVersion = true;
            }
            if (field.name == QStringLiteral("ALPN")
                && field.value == QStringLiteral("h2")) {
                sawAlpn = true;
            }
        }
    }

    if (!require(sawCipher, QStringLiteral("tls cipher suite parse edilmedi"))) {
        return 1;
    }
    if (!require(sawExtensions, QStringLiteral("tls extensions parse edilmedi"))) {
        return 1;
    }
    if (!require(sawSupportedVersion, QStringLiteral("tls supported version parse edilmedi"))) {
        return 1;
    }
    if (!require(sawAlpn, QStringLiteral("tls alpn parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testTlsClientHelloKeyShareMetadata()
{
    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex(
                      "00112233445566778899AABB0800450000930001000040060000C0A8010A5DB8D822"
                      "C93A01BB00001000000020005018040000000000")
                  + QByteArray::fromHex("160303006B010000670303")
                  + QByteArray(32, '\0')
                  + QByteArray::fromHex("00000213010100003C"
                                         "00000014001200000F")
                  + QByteArray("api.example.com")
                  + QByteArray::fromHex("001000050003026832"
                                         "002B0003020304"
                                         "000A00040002001D"
                                         "003300080006001D00020001");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord packet = parser.parse(frame);

    bool sawSupportedGroup = false;
    bool sawKeyShareGroup = false;
    for (const ProtocolLayer &layer : packet.layers) {
        if (layer.name != QStringLiteral("TLS")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Supported Group") && field.value == QStringLiteral("x25519")) {
                sawSupportedGroup = true;
            }
            if (field.name == QStringLiteral("Key Share Group") && field.value == QStringLiteral("x25519")) {
                sawKeyShareGroup = true;
            }
        }
    }

    if (!require(sawSupportedGroup, QStringLiteral("tls supported group parse edilmedi"))) {
        return 1;
    }
    if (!require(sawKeyShareGroup, QStringLiteral("tls key share group parse edilmedi"))) {
        return 1;
    }
    return 0;
}

int testTlsServerHelloAndCertificateMetadata()
{
    RawFrame serverHelloFrame;
    serverHelloFrame.frameNumber = 1;
    serverHelloFrame.timestampUtc = QDateTime::currentDateTimeUtc();
    serverHelloFrame.bytes = QByteArray::fromHex(
                                 "00112233445566778899AABB08004500006F00010000400600005DB8D822C0A8010A"
                                 "01BBC93A00001000000020005018040000000000")
                             + QByteArray::fromHex("160303002C020000280303")
                             + QByteArray(32, '\0')
                             + QByteArray::fromHex("001301000000");
    serverHelloFrame.capturedLength = serverHelloFrame.bytes.size();
    serverHelloFrame.originalLength = serverHelloFrame.bytes.size();

    RawFrame certificateFrame;
    certificateFrame.frameNumber = 2;
    certificateFrame.timestampUtc = QDateTime::currentDateTimeUtc();
    certificateFrame.bytes = QByteArray::fromHex(
                                 "00112233445566778899AABB08004500005500010000400600005DB8D822C0A8010A"
                                 "01BBC93A00001000000020005018040000000000"
                                 "16030300110B00000D00000A00000700000401020304");
    certificateFrame.capturedLength = certificateFrame.bytes.size();
    certificateFrame.originalLength = certificateFrame.bytes.size();

    BasicFrameParser parser;
    const PacketRecord serverHelloPacket = parser.parse(serverHelloFrame);
    const PacketRecord certificatePacket = parser.parse(certificateFrame);

    bool sawServerVersion = false;
    bool sawSelectedCipher = false;
    for (const ProtocolLayer &layer : serverHelloPacket.layers) {
        if (layer.name != QStringLiteral("TLS")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            if (field.name == QStringLiteral("Server Version") && field.value == QStringLiteral("TLS 1.2")) {
                sawServerVersion = true;
            }
            if (field.name == QStringLiteral("Selected Cipher Suite")
                && field.value == QStringLiteral("TLS_AES_128_GCM_SHA256")) {
                sawSelectedCipher = true;
            }
        }
    }

    bool sawCertificatesLength = false;
    bool sawCertificateCount = false;
    bool sawFirstCertificateLength = false;
    bool sawFirstCertificateSha = false;
    QStringList certificateFieldDump;
    for (const ProtocolLayer &layer : certificatePacket.layers) {
        if (layer.name != QStringLiteral("TLS")) {
            continue;
        }
        for (const ProtocolField &field : layer.fields) {
            certificateFieldDump << (field.name + QStringLiteral("=") + field.value);
            if (field.name == QStringLiteral("Certificates Length") && field.value == QStringLiteral("10")) {
                sawCertificatesLength = true;
            }
            if (field.name == QStringLiteral("Certificate Count") && field.value == QStringLiteral("1")) {
                sawCertificateCount = true;
            }
            if (field.name == QStringLiteral("First Certificate Length") && field.value == QStringLiteral("7")) {
                sawFirstCertificateLength = true;
            }
            if (field.name == QStringLiteral("First Certificate SHA256")) {
                const QByteArray expectedCert = QByteArray::fromHex("00000401020304");
                const QString expectedSha = QString::fromLatin1(QCryptographicHash::hash(expectedCert, QCryptographicHash::Sha256).toHex());
                if (field.value == expectedSha) {
                    sawFirstCertificateSha = true;
                }
            }
        }
    }

    if (!require(sawServerVersion, QStringLiteral("tls server hello version parse edilmedi"))) {
        return 1;
    }
    if (!require(sawSelectedCipher, QStringLiteral("tls selected cipher parse edilmedi"))) {
        return 1;
    }
    if (!require(sawCertificatesLength, QStringLiteral("tls certificate length parse edilmedi: %1").arg(certificateFieldDump.join(QStringLiteral(" | "))))) {
        return 1;
    }
    if (!require(sawCertificateCount, QStringLiteral("tls certificate count parse edilmedi: %1").arg(certificateFieldDump.join(QStringLiteral(" | "))))) {
        return 1;
    }
    if (!require(sawFirstCertificateLength, QStringLiteral("tls first certificate length parse edilmedi: %1").arg(certificateFieldDump.join(QStringLiteral(" | "))))) {
        return 1;
    }
    if (!require(sawFirstCertificateSha, QStringLiteral("tls first certificate sha parse edilmedi: %1").arg(certificateFieldDump.join(QStringLiteral(" | "))))) {
        return 1;
    }
    return 0;
}

int testWriterReaderRoundTrip()
{
    QTemporaryDir tempDir;
    if (!require(tempDir.isValid(), QStringLiteral("temporary dir olusturulamadi"))) {
        return 1;
    }

    RawFrame frame;
    frame.frameNumber = 1;
    frame.timestampUtc = QDateTime::currentDateTimeUtc();
    frame.bytes = QByteArray::fromHex("00112233445566778899aabb08004500002e0001000040110000c0a8011408080808d9030035001a00000100000000000000076578616d706c6503636f6d0000010001");
    frame.capturedLength = frame.bytes.size();
    frame.originalLength = frame.bytes.size();

    const QString filePath = tempDir.filePath(QStringLiteral("roundtrip.pcapng"));
    PcapFileWriter writer;
    QString error;
    if (!require(writer.open(filePath, QStringLiteral("pcapng"), &error), QStringLiteral("writer open basarisiz: %1").arg(error))) {
        return 1;
    }
    if (!require(writer.writeFrame(frame, &error), QStringLiteral("writer write basarisiz: %1").arg(error))) {
        return 1;
    }
    writer.close();

    PcapFileReader reader;
    const auto result = reader.readFile(filePath);
    if (!require(result.success, QStringLiteral("roundtrip read basarisiz: %1").arg(result.errorMessage))) {
        return 1;
    }
    if (!require(result.frames.size() == 1, QStringLiteral("roundtrip frame sayisi beklenen degil"))) {
        return 1;
    }
    if (!require(result.frames.front().bytes == frame.bytes, QStringLiteral("roundtrip byte dizisi korunumadi"))) {
        return 1;
    }
    return 0;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const int failures =
        testPcapReadAndTcpParse() +
        testTcpHeaderMetadata() +
        testDnsQueryParse() +
        testDnsAnswerParse() +
        testDnsAuthorityAdditionalParse() +
        testDnsRichRecordTypes() +
        testHttpResponseBodyPreview() +
        testHttpRequestBodyPreview() +
        testHttpRequestHeaderMetadata() +
        testHttpResponseHeaderMetadata() +
        testTlsHandshakeMetadata() +
        testTlsServerNameParse() +
        testTlsClientHelloDetails() +
        testTlsClientHelloKeyShareMetadata() +
        testTlsServerHelloAndCertificateMetadata() +
        testPcapNgRead() +
        testWriterReaderRoundTrip();

    if (failures == 0) {
        std::cout << "pengucore tests passed" << std::endl;
        return 0;
    }

    std::cerr << "pengucore tests failed: " << failures << std::endl;
    return 1;
}
