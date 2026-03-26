#include "pengucore/capture/livecaptureengine.h"

#ifdef PENGUFOCE_WITH_NPCAP
#include <pcap.h>
#endif

#include <QDateTime>
#include <QTimeZone>

namespace pengufoce::pengucore {

LiveCaptureEngine::LiveCaptureEngine(QObject *parent)
    : QObject(parent)
{
}

LiveCaptureEngine::~LiveCaptureEngine()
{
    stopCapture();
}

QVector<CaptureAdapterInfo> LiveCaptureEngine::adapters() const
{
    return m_adapters;
}

bool LiveCaptureEngine::refreshAdapters()
{
#ifndef PENGUFOCE_WITH_NPCAP
    setError(QStringLiteral("Npcap SDK bulunamadi; canli capture kullanilamaz."));
    emit adaptersChanged();
    return false;
#else
    char errorBuffer[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t *devices = nullptr;
    if (pcap_findalldevs(&devices, errorBuffer) != 0) {
        setError(QStringLiteral("Adapter listesi alinamadi: %1").arg(QString::fromLocal8Bit(errorBuffer)));
        emit adaptersChanged();
        return false;
    }

    m_adapters.clear();
    for (pcap_if_t *current = devices; current != nullptr; current = current->next) {
        CaptureAdapterInfo adapter;
        adapter.name = QString::fromLocal8Bit(current->name ? current->name : "");
        adapter.description = QString::fromLocal8Bit(current->description ? current->description : current->name);
        adapter.loopback = (current->flags & PCAP_IF_LOOPBACK) != 0;
        for (pcap_addr_t *address = current->addresses; address != nullptr; address = address->next) {
            if (address->addr == nullptr) {
                continue;
            }
            adapter.addresses.push_back(QStringLiteral("family:%1").arg(static_cast<int>(address->addr->sa_family)));
        }
        m_adapters.push_back(adapter);
    }

    pcap_freealldevs(devices);
    m_lastError.clear();
    emit adaptersChanged();
    emit captureStateChanged(m_running.load(), QStringLiteral("%1 adapter bulundu.").arg(m_adapters.size()));
    return true;
#endif
}

bool LiveCaptureEngine::startCapture(const QString &adapterName, const QString &captureFilter)
{
#ifndef PENGUFOCE_WITH_NPCAP
    Q_UNUSED(adapterName);
    Q_UNUSED(captureFilter);
    setError(QStringLiteral("Npcap SDK bulunamadi; canli capture baslatilamadi."));
    emit captureStateChanged(false, m_lastError);
    return false;
#else
    if (m_running.load()) {
        setError(QStringLiteral("Canli capture zaten calisiyor."));
        emit captureStateChanged(true, m_lastError);
        return false;
    }

    if (adapterName.trimmed().isEmpty()) {
        setError(QStringLiteral("Capture icin adapter secilmedi."));
        emit captureStateChanged(false, m_lastError);
        return false;
    }

    if (m_captureThread.joinable()) {
        m_captureThread.join();
    }

    m_lastError.clear();
    m_stopRequested = false;
    m_nextFrameNumber = 1;
    m_captureThread = std::thread(&LiveCaptureEngine::captureLoop, this, adapterName, captureFilter);
    return true;
#endif
}

void LiveCaptureEngine::stopCapture()
{
    m_stopRequested = true;
#ifdef PENGUFOCE_WITH_NPCAP
    {
        std::lock_guard<std::mutex> lock(m_handleMutex);
        if (m_activeHandle != nullptr) {
            pcap_breakloop(m_activeHandle);
        }
    }
#endif
    if (m_captureThread.joinable()) {
        m_captureThread.join();
    }
}

bool LiveCaptureEngine::isRunning() const
{
    return m_running.load();
}

QString LiveCaptureEngine::lastError() const
{
    return m_lastError;
}

void LiveCaptureEngine::captureLoop(QString adapterName, QString captureFilter)
{
#ifndef PENGUFOCE_WITH_NPCAP
    Q_UNUSED(adapterName);
    Q_UNUSED(captureFilter);
#else
    char errorBuffer[PCAP_ERRBUF_SIZE] = {};
    pcap *openedHandle = pcap_open_live(adapterName.toLocal8Bit().constData(), 65535, 1, 250, errorBuffer);
    if (openedHandle == nullptr) {
        setError(QStringLiteral("Capture baslatilamadi: %1").arg(QString::fromLocal8Bit(errorBuffer)));
        emit captureStateChanged(false, m_lastError);
        return;
    }

    const QString normalizedFilter = captureFilter.trimmed();
    if (!normalizedFilter.isEmpty()) {
        bpf_program filterProgram = {};
        const QByteArray filterUtf8 = normalizedFilter.toUtf8();
        if (pcap_compile(openedHandle, &filterProgram, filterUtf8.constData(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
            setError(QStringLiteral("Capture filtresi derlenemedi: %1").arg(QString::fromLocal8Bit(pcap_geterr(openedHandle))));
            pcap_close(openedHandle);
            emit captureStateChanged(false, m_lastError);
            return;
        }

        if (pcap_setfilter(openedHandle, &filterProgram) < 0) {
            setError(QStringLiteral("Capture filtresi uygulanamadi: %1").arg(QString::fromLocal8Bit(pcap_geterr(openedHandle))));
            pcap_freecode(&filterProgram);
            pcap_close(openedHandle);
            emit captureStateChanged(false, m_lastError);
            return;
        }

        pcap_freecode(&filterProgram);
    }

    {
        std::lock_guard<std::mutex> lock(m_handleMutex);
        m_activeHandle = openedHandle;
    }

    m_running = true;
    const QString stateMessage = normalizedFilter.isEmpty()
        ? QStringLiteral("Canli capture basladi: %1").arg(adapterName)
        : QStringLiteral("Canli capture basladi: %1 | Filter: %2").arg(adapterName, normalizedFilter);
    emit captureStateChanged(true, stateMessage);

    while (!m_stopRequested.load()) {
        struct pcap_pkthdr *header = nullptr;
        const u_char *packetData = nullptr;
        const int result = pcap_next_ex(openedHandle, &header, &packetData);
        if (result == 1 && header != nullptr && packetData != nullptr) {
            RawFrame frame;
            frame.frameNumber = m_nextFrameNumber++;
            frame.timestampUtc = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(header->ts.tv_sec), QTimeZone::UTC)
                                     .addMSecs(static_cast<int>(header->ts.tv_usec / 1000));
            frame.capturedLength = static_cast<int>(header->caplen);
            frame.originalLength = static_cast<int>(header->len);
            frame.bytes = QByteArray(reinterpret_cast<const char *>(packetData), static_cast<int>(header->caplen));
            emit packetCaptured(frame);
            continue;
        }

        if (result == 0) {
            continue;
        }

        if (result == PCAP_ERROR_BREAK && m_stopRequested.load()) {
            break;
        }

        if (result < 0) {
            setError(QStringLiteral("Capture okuma hatasi: %1").arg(QString::fromLocal8Bit(pcap_geterr(openedHandle))));
            emit captureStateChanged(true, m_lastError);
            break;
        }
    }

    pcap_close(openedHandle);
    {
        std::lock_guard<std::mutex> lock(m_handleMutex);
        if (m_activeHandle == openedHandle) {
            m_activeHandle = nullptr;
        }
    }
    m_running = false;
    emit captureStateChanged(false, m_lastError.isEmpty() ? QStringLiteral("Canli capture durdu.") : m_lastError);
#endif
}

void LiveCaptureEngine::setError(const QString &message)
{
    m_lastError = message;
}

} // namespace pengufoce::pengucore
