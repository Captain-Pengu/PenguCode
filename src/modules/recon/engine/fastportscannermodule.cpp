#include "fastportscannermodule.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QEventLoop>
#include <QMetaObject>
#include <QRegularExpression>
#include <QTcpSocket>
#include <QTimer>

namespace {

class PortProbeTask final : public QObject, public QRunnable
{
    Q_OBJECT

public:
    PortProbeTask(QString target,
                  int port,
                  int timeoutMs,
                  const std::atomic_bool *cancelled)
        : m_target(std::move(target))
        , m_port(port)
        , m_timeoutMs(timeoutMs)
        , m_cancelled(cancelled)
    {
        setAutoDelete(true);
    }

signals:
    void probeFinished(const ServiceFingerprint &fingerprint);

protected:
    void run() override
    {
        if (m_cancelled && m_cancelled->load()) {
            emit probeFinished(ServiceFingerprint{m_target, m_port, "tcp", {}, {}, {}, -1});
            return;
        }

        ServiceFingerprint fingerprint;
        fingerprint.host = m_target;
        fingerprint.port = m_port;
        fingerprint.protocol = "tcp";

        QTcpSocket socket;
        QTimer timeoutTimer;
        timeoutTimer.setSingleShot(true);
        QEventLoop connectLoop;
        bool connected = false;
        bool finished = false;
        qint64 startedAt = QDateTime::currentMSecsSinceEpoch();

        connect(&socket, &QTcpSocket::connected, &connectLoop, [&]() {
            connected = true;
            finished = true;
            connectLoop.quit();
        });
        connect(&socket,
                &QTcpSocket::errorOccurred,
                &connectLoop,
                [&](QAbstractSocket::SocketError) {
                    finished = true;
                    connectLoop.quit();
                });
        connect(&timeoutTimer, &QTimer::timeout, &connectLoop, [&]() {
            finished = true;
            connectLoop.quit();
        });

        socket.connectToHost(m_target, static_cast<quint16>(m_port));
        timeoutTimer.start(m_timeoutMs);
        if (!finished) {
            connectLoop.exec();
        }

        fingerprint.responseTimeMs = QDateTime::currentMSecsSinceEpoch() - startedAt;
        if (!connected) {
            socket.abort();
            emit probeFinished(fingerprint);
            return;
        }

        QByteArray probe;
        if (m_port == 80 || m_port == 8080 || m_port == 8000 || m_port == 8443) {
            probe = "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n";
        } else if (m_port == 25 || m_port == 587) {
            probe = "EHLO pengufoce.local\r\n";
        } else if (m_port == 21) {
            probe = "FEAT\r\n";
        } else if (m_port == 110) {
            probe = "CAPA\r\n";
        } else if (m_port == 143) {
            probe = "a1 CAPABILITY\r\n";
        } else if (m_port == 6379) {
            probe = "PING\r\n";
        }

        if (!probe.isEmpty()) {
            socket.write(probe);
            socket.flush();
        }

        QEventLoop bannerLoop;
        QTimer bannerTimer;
        bannerTimer.setSingleShot(true);
        connect(&socket, &QTcpSocket::readyRead, &bannerLoop, &QEventLoop::quit);
        connect(&bannerTimer, &QTimer::timeout, &bannerLoop, &QEventLoop::quit);
        bannerTimer.start(qMax(120, m_timeoutMs / 2));
        bannerLoop.exec();

        fingerprint.banner = QString::fromUtf8(socket.readAll()).simplified();
        socket.disconnectFromHost();
        emit probeFinished(fingerprint);
    }

private:
    QString m_target;
    int m_port = 0;
    int m_timeoutMs = 500;
    const std::atomic_bool *m_cancelled = nullptr;
};

} // namespace

FastPortScannerModule::FastPortScannerModule(QObject *parent)
    : QObject(parent)
{
}

FastPortScannerModule::~FastPortScannerModule()
{
    stop();
    m_threadPool.waitForDone();
}

void FastPortScannerModule::startScan(const QString &target, const QList<int> &ports, int timeoutMs, int concurrency)
{
    stop();
    m_cancelled.store(false);
    m_totalTasks = ports.size();
    m_completedTasks = 0;
    m_threadPool.setMaxThreadCount(qBound(4, concurrency, 512));

    emit statusMessage(QString("Fast scan started for %1 (%2 ports)").arg(target).arg(ports.size()));

    for (const int port : ports) {
        auto *task = new PortProbeTask(target, port, timeoutMs, &m_cancelled);
        connect(task, &PortProbeTask::probeFinished, this, &FastPortScannerModule::handleProbeFinished, Qt::QueuedConnection);
        m_threadPool.start(task);
    }
}

void FastPortScannerModule::stop()
{
    m_cancelled.store(true);
}

void FastPortScannerModule::handleProbeFinished(const ServiceFingerprint &fingerprint)
{
    ++m_completedTasks;

    if (!fingerprint.banner.isEmpty() || fingerprint.responseTimeMs >= 0) {
        ServiceFingerprint enriched = fingerprint;
        enriched.service = normalizedServiceName(fingerprint.port, fingerprint.banner);
        enriched.version = extractedVersion(fingerprint.banner);
        if (!enriched.service.isEmpty()) {
            emit portFound(enriched.port, enriched.service);
        }
        emit bannerGrabbed(enriched);
    }

    emit progressChanged(m_completedTasks, m_totalTasks);

    if (m_completedTasks >= m_totalTasks) {
        emit statusMessage(QString("Fast scan completed (%1/%2)").arg(m_completedTasks).arg(m_totalTasks));
        emit scanFinished();
    }
}

QString FastPortScannerModule::normalizedServiceName(int port, const QString &banner) const
{
    const QString lowerBanner = banner.toLower();
    if (lowerBanner.contains("ssh")) return "ssh";
    if (lowerBanner.contains("smtp")) return "smtp";
    if (lowerBanner.contains("http")) return port == 443 ? "https" : "http";
    if (lowerBanner.contains("imap")) return "imap";
    if (lowerBanner.contains("pop3")) return "pop3";
    if (lowerBanner.contains("redis")) return "redis";
    if (lowerBanner.contains("mysql")) return "mysql";
    if (lowerBanner.contains("postgres")) return "postgresql";

    switch (port) {
    case 21: return "ftp";
    case 22: return "ssh";
    case 25: return "smtp";
    case 53: return "dns";
    case 80: return "http";
    case 110: return "pop3";
    case 143: return "imap";
    case 443: return "https";
    case 3306: return "mysql";
    case 5432: return "postgresql";
    case 6379: return "redis";
    case 8080: return "http-proxy";
    default: return "unknown";
    }
}

QString FastPortScannerModule::extractedVersion(const QString &banner) const
{
    static const QRegularExpression versionRegex(QStringLiteral("((?:\\d+\\.){1,3}\\d+[a-z0-9\\-]*)"),
                                                 QRegularExpression::CaseInsensitiveOption);
    const auto match = versionRegex.match(banner);
    return match.hasMatch() ? match.captured(1) : QString();
}

#include "fastportscannermodule.moc"
