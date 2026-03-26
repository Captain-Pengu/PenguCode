#include "cdpclient.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QRandomGenerator>
#include <QTcpSocket>
#include <QUrl>

class CdpClient::Impl
{
public:
    QTcpSocket socket;
    int nextId = 1;
};

namespace {

QString websocketAcceptForKey(const QByteArray &key)
{
    const QByteArray magic = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    return QString::fromUtf8(QCryptographicHash::hash(magic, QCryptographicHash::Sha1).toBase64());
}

QByteArray buildMaskedFrame(const QByteArray &payload, quint8 opcode = 0x1)
{
    QByteArray frame;
    frame.append(char(0x80 | (opcode & 0x0F)));

    const quint8 maskBit = 0x80;
    const qsizetype size = payload.size();
    if (size < 126) {
        frame.append(char(maskBit | size));
    } else if (size <= 0xFFFF) {
        frame.append(char(maskBit | 126));
        frame.append(char((size >> 8) & 0xFF));
        frame.append(char(size & 0xFF));
    } else {
        frame.append(char(maskBit | 127));
        for (int shift = 56; shift >= 0; shift -= 8) {
            frame.append(char((quint64(size) >> shift) & 0xFF));
        }
    }

    QByteArray mask(4, '\0');
    for (int i = 0; i < 4; ++i) {
        mask[i] = char(QRandomGenerator::global()->bounded(256));
    }
    frame.append(mask);

    QByteArray masked = payload;
    for (qsizetype i = 0; i < masked.size(); ++i) {
        masked[i] = char(masked.at(i) ^ mask.at(i % 4));
    }
    frame.append(masked);
    return frame;
}

} // namespace

CdpClient::~CdpClient() = default;

bool CdpClient::connectToPage(const QString &wsUrl, int timeoutMs, QString *errorMessage)
{
    disconnect();
    const QUrl url(wsUrl);
    if (!url.isValid() || url.scheme() != QLatin1String("ws")) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Gecersiz websocket hedefi");
        }
        return false;
    }

    m_impl = new Impl();
    return performHandshake(url.host(),
                            quint16(url.port(80)),
                            url.path().isEmpty() ? QStringLiteral("/") : url.path() + (url.query().isEmpty() ? QString() : QStringLiteral("?") + url.query()),
                            timeoutMs,
                            errorMessage);
}

void CdpClient::disconnect()
{
    if (!m_impl) {
        return;
    }
    m_impl->socket.abort();
    delete m_impl;
    m_impl = nullptr;
}

bool CdpClient::isConnected() const
{
    return m_impl && m_impl->socket.state() == QAbstractSocket::ConnectedState;
}

bool CdpClient::performHandshake(const QString &host, quint16 port, const QString &path, int timeoutMs, QString *errorMessage)
{
    m_impl->socket.connectToHost(host, port);
    if (!m_impl->socket.waitForConnected(timeoutMs)) {
        if (errorMessage) {
            *errorMessage = m_impl->socket.errorString();
        }
        disconnect();
        return false;
    }

    const QByteArray key = QCryptographicHash::hash(QByteArray::number(QRandomGenerator::global()->generate64()),
                                                    QCryptographicHash::Sha1).toBase64();
    QByteArray request;
    request += "GET " + path.toUtf8() + " HTTP/1.1\r\n";
    request += "Host: " + host.toUtf8() + ":" + QByteArray::number(port) + "\r\n";
    request += "Upgrade: websocket\r\n";
    request += "Connection: Upgrade\r\n";
    request += "Sec-WebSocket-Key: " + key + "\r\n";
    request += "Sec-WebSocket-Version: 13\r\n\r\n";

    m_impl->socket.write(request);
    if (!m_impl->socket.waitForBytesWritten(timeoutMs)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("WebSocket istek yazilamadi");
        }
        disconnect();
        return false;
    }

    const QByteArray headers = readHttpHeaders(timeoutMs, errorMessage);
    if (headers.isEmpty()) {
        disconnect();
        return false;
    }

    const QString headerText = QString::fromUtf8(headers);
    if (!headerText.startsWith(QStringLiteral("HTTP/1.1 101"))) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("WebSocket handshake reddedildi");
        }
        disconnect();
        return false;
    }
    if (!headerText.contains(QStringLiteral("Sec-WebSocket-Accept: ") + websocketAcceptForKey(key), Qt::CaseInsensitive)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("WebSocket accept dogrulanamadi");
        }
        disconnect();
        return false;
    }
    return true;
}

QByteArray CdpClient::readHttpHeaders(int timeoutMs, QString *errorMessage)
{
    QByteArray buffer;
    while (!buffer.contains("\r\n\r\n")) {
        if (!m_impl->socket.waitForReadyRead(timeoutMs)) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("WebSocket handshake zaman asimi");
            }
            return {};
        }
        buffer += m_impl->socket.readAll();
    }
    return buffer;
}

bool CdpClient::writeTextFrame(const QByteArray &payload, int timeoutMs, QString *errorMessage)
{
    if (!isConnected()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("WebSocket bagli degil");
        }
        return false;
    }
    const QByteArray frame = buildMaskedFrame(payload);
    m_impl->socket.write(frame);
    if (!m_impl->socket.waitForBytesWritten(timeoutMs)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("WebSocket frame yazilamadi");
        }
        return false;
    }
    return true;
}

QByteArray CdpClient::readFrame(int timeoutMs, bool *isTextFrame, QString *errorMessage)
{
    QByteArray buffer;
    while (buffer.size() < 2) {
        if (!m_impl->socket.waitForReadyRead(timeoutMs)) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("WebSocket frame zaman asimi");
            }
            return {};
        }
        buffer += m_impl->socket.readAll();
    }

    const quint8 b0 = quint8(buffer[0]);
    const quint8 b1 = quint8(buffer[1]);
    const quint8 opcode = b0 & 0x0F;
    if (isTextFrame) {
        *isTextFrame = (opcode == 0x1);
    }

    int pos = 2;
    quint64 payloadLen = b1 & 0x7F;
    if (payloadLen == 126) {
        while (buffer.size() < pos + 2) {
            if (!m_impl->socket.waitForReadyRead(timeoutMs)) {
                if (errorMessage) *errorMessage = QStringLiteral("WebSocket frame eksik");
                return {};
            }
            buffer += m_impl->socket.readAll();
        }
        payloadLen = (quint8(buffer[pos]) << 8) | quint8(buffer[pos + 1]);
        pos += 2;
    } else if (payloadLen == 127) {
        while (buffer.size() < pos + 8) {
            if (!m_impl->socket.waitForReadyRead(timeoutMs)) {
                if (errorMessage) *errorMessage = QStringLiteral("WebSocket frame eksik");
                return {};
            }
            buffer += m_impl->socket.readAll();
        }
        payloadLen = 0;
        for (int i = 0; i < 8; ++i) {
            payloadLen = (payloadLen << 8) | quint8(buffer[pos + i]);
        }
        pos += 8;
    }

    const bool masked = (b1 & 0x80) != 0;
    QByteArray mask;
    if (masked) {
        while (buffer.size() < pos + 4) {
            if (!m_impl->socket.waitForReadyRead(timeoutMs)) {
                if (errorMessage) *errorMessage = QStringLiteral("WebSocket mask eksik");
                return {};
            }
            buffer += m_impl->socket.readAll();
        }
        mask = buffer.mid(pos, 4);
        pos += 4;
    }

    while (buffer.size() < pos + qsizetype(payloadLen)) {
        if (!m_impl->socket.waitForReadyRead(timeoutMs)) {
            if (errorMessage) *errorMessage = QStringLiteral("WebSocket payload eksik");
            return {};
        }
        buffer += m_impl->socket.readAll();
    }
    QByteArray payload = buffer.mid(pos, qsizetype(payloadLen));
    if (masked) {
        for (qsizetype i = 0; i < payload.size(); ++i) {
            payload[i] = char(payload.at(i) ^ mask.at(i % 4));
        }
    }

    if (opcode == 0x9) {
        const QByteArray pongFrame = buildMaskedFrame(payload, 0xA);
        m_impl->socket.write(pongFrame);
        m_impl->socket.waitForBytesWritten(timeoutMs);
        return readFrame(timeoutMs, isTextFrame, errorMessage);
    }
    return payload;
}

QJsonObject CdpClient::sendCommand(const QString &method,
                                   const QJsonObject &params,
                                   int timeoutMs,
                                   QString *errorMessage)
{
    QJsonObject command{
        {QStringLiteral("id"), m_impl ? m_impl->nextId++ : 0},
        {QStringLiteral("method"), method},
        {QStringLiteral("params"), params}
    };
    const int commandId = command.value(QStringLiteral("id")).toInt();
    if (!writeTextFrame(QJsonDocument(command).toJson(QJsonDocument::Compact), timeoutMs, errorMessage)) {
        return {};
    }

    const qint64 deadline = QDateTime::currentMSecsSinceEpoch() + timeoutMs;
    while (QDateTime::currentMSecsSinceEpoch() < deadline) {
        bool isText = false;
        const QByteArray payload = readFrame(timeoutMs, &isText, errorMessage);
        if (payload.isEmpty() || !isText) {
            continue;
        }
        const QJsonDocument doc = QJsonDocument::fromJson(payload);
        if (!doc.isObject()) {
            continue;
        }
        const QJsonObject obj = doc.object();
        if (obj.value(QStringLiteral("id")).toInt() == commandId) {
            return obj;
        }
    }
    if (errorMessage) {
        *errorMessage = QStringLiteral("CDP komut zaman asimi");
    }
    return {};
}

QString CdpClient::evaluateExpression(const QString &expression, int timeoutMs, QString *errorMessage)
{
    const QJsonObject response = sendCommand(QStringLiteral("Runtime.evaluate"),
                                             QJsonObject{
                                                 {QStringLiteral("expression"), expression},
                                                 {QStringLiteral("returnByValue"), true},
                                                 {QStringLiteral("awaitPromise"), true}
                                             },
                                             timeoutMs,
                                             errorMessage);
    const QJsonObject result = response.value(QStringLiteral("result")).toObject().value(QStringLiteral("result")).toObject();
    if (result.contains(QStringLiteral("value"))) {
        return result.value(QStringLiteral("value")).toVariant().toString();
    }
    return {};
}

QVariantList CdpClient::collectInteractiveSnapshot(int timeoutMs, QString *errorMessage)
{
    const QString script = QStringLiteral(R"JS(
(() => JSON.stringify(Array.from(document.querySelectorAll('button,a,[role="button"],[data-action],[data-url],[data-href],[onclick],[tabindex]'))
  .slice(0, 20)
  .map(el => ({
    tag: el.tagName.toLowerCase(),
    text: (el.innerText || el.getAttribute('aria-label') || '').trim().slice(0, 80),
    href: el.getAttribute('href') || el.getAttribute('data-url') || el.getAttribute('data-href') || el.getAttribute('data-action') || '',
    onclick: el.getAttribute('onclick') || '',
    id: el.id || '',
    cls: (el.className || '').toString().split(' ')[0] || '',
    role: el.getAttribute('role') || '',
    tabindex: el.getAttribute('tabindex') || ''
  }))))
() )JS");

    const QString json = evaluateExpression(script, timeoutMs, errorMessage);
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    QVariantList list;
    if (doc.isArray()) {
        for (const auto &value : doc.array()) {
            list << value.toObject().toVariantMap();
        }
    }
    return list;
}

QList<CdpClient::StatefulResult> CdpClient::runSafeStatefulExploration(int timeoutMs, QString *errorMessage)
{
    QList<StatefulResult> results;
    const QString script = QStringLiteral(R"JS(
(async () => {
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const selectors = [
    'a[href]:not([href^="#"])',
    'button[type="button"]',
    'button:not([type])',
    '[data-url]',
    '[data-href]',
    '[routerlink]',
    '[role="tab"]',
    '[data-bs-toggle="tab"]',
    '[data-toggle="tab"]',
    '[aria-controls]',
    '[data-target]',
    '[data-bs-target]',
    'a[href^="#"]'
  ];
  const nodes = [];
  const seen = new Set();
  for (const selector of selectors) {
    for (const el of document.querySelectorAll(selector)) {
      if (!el || !el.isConnected || el.disabled) continue;
      const key = (el.id || '') + '|' + (el.getAttribute('aria-controls') || '') + '|' + (el.getAttribute('data-target') || '') + '|' + (el.innerText || '').trim().slice(0, 40);
      if (seen.has(key)) continue;
      seen.add(key);
      nodes.push(el);
      if (nodes.length >= 8) break;
    }
    if (nodes.length >= 8) break;
  }

  const snapshots = [];
  const collectUrls = () => {
    const out = new Set();
    const attrs = ['href','src','action','data-href','data-url','data-src','routerlink','formaction','poster'];
    for (const el of document.querySelectorAll('*')) {
      for (const attr of attrs) {
        const value = el.getAttribute && el.getAttribute(attr);
        if (value && value.trim()) out.add(value.trim());
      }
      const srcset = el.getAttribute && (el.getAttribute('srcset') || el.getAttribute('data-srcset'));
      if (srcset) {
        for (const candidate of srcset.split(',')) {
          const raw = candidate.trim().split(/\s+/)[0];
          if (raw) out.add(raw);
        }
      }
    }
    return Array.from(out).slice(0, 80);
  };
  const collectFormActions = () => {
    const out = new Set();
    for (const form of document.querySelectorAll('form')) {
      const action = form.getAttribute('action');
      if (action && action.trim()) out.add(action.trim());
    }
    return Array.from(out).slice(0, 24);
  };
  const baselineUrls = collectUrls();
  const baselineSet = new Set(baselineUrls);

  for (let i = 0; i < nodes.length; ++i) {
    const el = nodes[i];
    try {
      el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window }));
      if (typeof el.click === 'function') el.click();
    } catch (_) {}
    await sleep(260);
    const afterUrls = collectUrls();
    const newUrls = afterUrls.filter(url => !baselineSet.has(url));
    snapshots.push({
      stepLabel: (el.innerText || el.getAttribute('aria-label') || el.id || el.tagName || '').trim().slice(0, 80),
      pageTitle: document.title || '',
      currentUrl: String(window.location.href || ''),
      urls: newUrls,
      formActions: collectFormActions()
    });
  }
  return JSON.stringify(snapshots);
})()
)JS");

    const QString json = evaluateExpression(script, timeoutMs, errorMessage);
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isArray()) {
        return results;
    }

    for (const QJsonValue &value : doc.array()) {
        if (!value.isObject()) {
            continue;
        }
        const QJsonObject obj = value.toObject();
        StatefulResult row;
        row.stepLabel = obj.value(QStringLiteral("stepLabel")).toString();
        row.pageTitle = obj.value(QStringLiteral("pageTitle")).toString();
        row.currentUrl = obj.value(QStringLiteral("currentUrl")).toString();
        for (const QJsonValue &urlValue : obj.value(QStringLiteral("urls")).toArray()) {
            const QString url = urlValue.toString().trimmed();
            if (!url.isEmpty() && !row.urls.contains(url)) {
                row.urls << url;
            }
        }
        for (const QJsonValue &actionValue : obj.value(QStringLiteral("formActions")).toArray()) {
            const QString action = actionValue.toString().trimmed();
            if (!action.isEmpty() && !row.formActions.contains(action)) {
                row.formActions << action;
            }
        }
        results << row;
    }
    return results;
}
