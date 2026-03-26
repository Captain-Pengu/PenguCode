#include "proxymodule.h"

#include "core/logging/logger.h"
#include "core/framework/moduleregistry.h"
#include "core/settings/settingsmanager.h"

#include <QHostAddress>

#ifdef PENGUFOCE_WITH_BOOST_PROXY
#include <algorithm>
#include <thread>
#endif

using pengufoce::proxy::localresearch::TelemetryBridge;
using pengufoce::proxy::localresearch::TransferSnapshot;

#ifdef PENGUFOCE_WITH_BOOST_PROXY
using pengufoce::proxy::localresearch::LocalAcceptor;
using pengufoce::proxy::localresearch::LocalAcceptorConfig;
#endif

ProxyModule::ProxyModule(QObject *parent)
    : ModuleInterface(parent)
{
    qRegisterMetaType<TransferSnapshot>("pengufoce::proxy::localresearch::TransferSnapshot");
}

QString ProxyModule::id() const
{
    return "proxy";
}

QString ProxyModule::name() const
{
    return "Proxy";
}

QString ProxyModule::description() const
{
    return "Yerel ag arastirma koprusu ve proxy kontrol paneli.";
}

QString ProxyModule::icon() const
{
    return "proxy";
}

QUrl ProxyModule::pageSource() const
{
    return QUrl("qrc:/qt/qml/PenguFoce/qml/pages/ProxyPage.qml");
}

void ProxyModule::initialize(SettingsManager *settings, Logger *logger)
{
    m_settings = settings;
    m_logger = logger;
    reloadSettings();
    if (m_logger) {
        m_logger->info(id(), "Proxy module initialized");
    }
}

QVariantMap ProxyModule::defaultSettings() const
{
    return {
        {"listenHost", "127.0.0.1"},
        {"listenPort", 8080},
        {"targetHost", "127.0.0.1"},
        {"targetPort", 18081},
        {"idleTimeoutSeconds", 30},
        {"workerThreads", 2},
        {"sharedSecret", "TB1RBS"},
        {"requireHandshake", true},
        {"interceptTls", false}
    };
}

QString ProxyModule::listenHost() const
{
    return m_listenHost;
}

int ProxyModule::listenPort() const
{
    return m_listenPort;
}

QString ProxyModule::targetHost() const
{
    return m_targetHost;
}

int ProxyModule::targetPort() const
{
    return m_targetPort;
}

int ProxyModule::idleTimeoutSeconds() const
{
    return m_idleTimeoutSeconds;
}

int ProxyModule::workerThreads() const
{
    return m_workerThreads;
}

QString ProxyModule::sharedSecret() const
{
    return m_sharedSecret;
}

bool ProxyModule::requireHandshake() const
{
    return m_requireHandshake;
}

bool ProxyModule::interceptTls() const
{
    return m_interceptTls;
}

bool ProxyModule::running() const
{
    return m_running;
}

TransferSnapshot ProxyModule::latestSnapshot() const
{
    return m_lastSnapshot;
}

void ProxyModule::reloadSettings()
{
    if (!m_settings) {
        return;
    }

    m_listenHost = m_settings->value("modules/proxy", "listenHost", "127.0.0.1").toString().trimmed();
    m_listenPort = m_settings->value("modules/proxy", "listenPort", 8080).toInt();
    m_targetHost = m_settings->value("modules/proxy", "targetHost", "127.0.0.1").toString().trimmed();
    m_targetPort = m_settings->value("modules/proxy", "targetPort", 18081).toInt();
    m_idleTimeoutSeconds = m_settings->value("modules/proxy", "idleTimeoutSeconds", 30).toInt();
    m_workerThreads = m_settings->value("modules/proxy", "workerThreads", 2).toInt();
    m_sharedSecret = m_settings->value("modules/proxy", "sharedSecret", "TB1RBS").toString();
    m_requireHandshake = m_settings->value("modules/proxy", "requireHandshake", true).toBool();
    m_interceptTls = m_settings->value("modules/proxy", "interceptTls", false).toBool();

    if (m_listenHost.isEmpty()) {
        m_listenHost = "127.0.0.1";
    }
    if (m_targetHost.isEmpty()) {
        m_targetHost = "127.0.0.1";
    }
    m_workerThreads = std::max(1, m_workerThreads);
    m_idleTimeoutSeconds = std::max(5, m_idleTimeoutSeconds);
}

void ProxyModule::start()
{
    if (m_running) {
        emitEvent(QString("Yerel arastirma koprusu zaten aktif: %1:%2 -> %3:%4")
                      .arg(m_listenHost)
                      .arg(m_listenPort)
                      .arg(m_targetHost)
                      .arg(m_targetPort));
        emit telemetryUpdated(m_lastSnapshot);
        return;
    }

    reloadSettings();

    const QHostAddress listenAddress(m_listenHost);
    const QHostAddress targetAddress(m_targetHost);
        
    // Sadece IP adreslerinin geçerli formatta olup olmadığını kontrol ediyoruz
    if (listenAddress.isNull() || targetAddress.isNull()) { 
        emit statusChanged(tr("Gecersiz IP adresi formati"));
        emitEvent(tr("Lutfen gecerli bir IP adresi girin (Orn: 0.0.0.0 veya 127.0.0.1)."));
        if (m_logger) {
                m_logger->warning(id(), "Gecersiz IP adresi girildi");
        }
        return;
    }

#ifdef PENGUFOCE_WITH_BOOST_PROXY
    try {
        m_lastSnapshot = {};
        m_localResearchContext = std::make_unique<boost::asio::io_context>();
        m_localResearchWork.emplace(boost::asio::make_work_guard(*m_localResearchContext));
        m_localResearchTelemetry = std::make_shared<TelemetryBridge>();
        connect(m_localResearchTelemetry.get(),
                &TelemetryBridge::snapshotReady,
                this,
                [this](const TransferSnapshot &snapshot) {
                    handleTelemetrySnapshot(snapshot);
                },
                Qt::QueuedConnection);

        LocalAcceptorConfig config;
        config.listenHost = m_listenHost.toStdString();
        config.listenPort = static_cast<unsigned short>(m_listenPort);
        config.targetHost = m_targetHost.toStdString();
        config.targetPort = static_cast<unsigned short>(m_targetPort);
        config.sharedSecret = m_sharedSecret.toStdString();
        config.requireHandshake = m_requireHandshake;
        config.idleTimeout = std::chrono::seconds(m_idleTimeoutSeconds);

        m_localResearchAcceptor = std::make_shared<LocalAcceptor>(*m_localResearchContext,
                                                                  config,
                                                                  m_localResearchTelemetry);
        if (!m_localResearchAcceptor->start()) {
            m_localResearchAcceptor.reset();
            m_localResearchWork.reset();
            m_localResearchTelemetry.reset();
            m_localResearchContext.reset();
            if (m_logger) {
                m_logger->error(id(), "Local research acceptor baslatilamadi");
            }
            emit statusChanged(tr("Yerel kopru baslatilamadi"));
            emitEvent(tr("Yerel arastirma koprusu baslatilamadi."));
            return;
        }

        const int threadCount = std::max(1, m_workerThreads);
        m_localResearchThreads.reserve(static_cast<std::size_t>(threadCount));
        for (int i = 0; i < threadCount; ++i) {
            m_localResearchThreads.emplace_back([ctx = m_localResearchContext.get()]() {
                ctx->run();
            });
        }

        m_running = true;
        emit runningChanged(true);
        emit statusChanged(tr("Yerel arastirma koprusu aktif"));
        emitEvent(tr("Yerel arastirma koprusu aktif: %1:%2 -> %3:%4")
                      .arg(m_listenHost)
                      .arg(m_listenPort)
                      .arg(m_targetHost)
                      .arg(m_targetPort));

        if (m_logger) {
            m_logger->info(id(),
                           QString("Local research bridge aktif: %1:%2 -> %3:%4 (%5 is parcacigi)")
                               .arg(m_listenHost)
                               .arg(m_listenPort)
                               .arg(m_targetHost)
                               .arg(m_targetPort)
                               .arg(threadCount));
        }
        return;
    } catch (const std::exception &ex) {
        if (m_logger) {
            m_logger->error(id(), QString("Local research core hatasi: %1").arg(QString::fromUtf8(ex.what())));
        }
        emit statusChanged(tr("Yerel kopru hatasi"));
        emitEvent(tr("Yerel arastirma koprusu hata verdi."));
    }
#else
    if (m_logger) {
        m_logger->warning(id(), "Boost.Asio local research core bulunamadi");
    }
    emit statusChanged(tr("Boost cekirdegi yok"));
    emitEvent(tr("Boost.Asio bulunamadigi icin yerel arastirma koprusu baslatilamadi."));
#endif
}

void ProxyModule::stop()
{
#ifdef PENGUFOCE_WITH_BOOST_PROXY
    if (m_localResearchAcceptor) {
        m_localResearchAcceptor->stop();
    }
    if (m_localResearchWork) {
        m_localResearchWork.reset();
    }
    if (m_localResearchContext) {
        m_localResearchContext->stop();
    }
    for (auto &thread : m_localResearchThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_localResearchThreads.clear();
    m_localResearchAcceptor.reset();
    m_localResearchTelemetry.reset();
    m_localResearchContext.reset();
#endif

    if (m_running) {
        m_running = false;
        emit runningChanged(false);
    }

    emit statusChanged(tr("Yerel arastirma koprusu durdu"));
    emitEvent(tr("Yerel arastirma koprusu durduruldu."));

    if (m_logger) {
        m_logger->warning(id(), "Proxy stopped");
    }
}

void ProxyModule::applyRuntimeSettings(const QString &listenHost,
                                       int listenPort,
                                       const QString &targetHost,
                                       int targetPort,
                                       int idleTimeoutSeconds,
                                       int workerThreads,
                                       const QString &sharedSecret,
                                       bool requireHandshake)
{
    if (!m_settings) {
        return;
    }

    m_settings->setValue("modules/proxy", "listenHost", listenHost.trimmed());
    m_settings->setValue("modules/proxy", "listenPort", listenPort);
    m_settings->setValue("modules/proxy", "targetHost", targetHost.trimmed());
    m_settings->setValue("modules/proxy", "targetPort", targetPort);
    m_settings->setValue("modules/proxy", "idleTimeoutSeconds", idleTimeoutSeconds);
    m_settings->setValue("modules/proxy", "workerThreads", workerThreads);
    m_settings->setValue("modules/proxy", "sharedSecret", sharedSecret);
    m_settings->setValue("modules/proxy", "requireHandshake", requireHandshake);
    reloadSettings();

    emitEvent(tr("Proxy ayarlari guncellendi: %1:%2 -> %3:%4")
                  .arg(m_listenHost)
                  .arg(m_listenPort)
                  .arg(m_targetHost)
                  .arg(m_targetPort));
    emit statusChanged(m_running
                           ? tr("Ayarlar kaydedildi, yeniden baslatinca uygulanir")
                           : tr("Ayarlar guncellendi"));
}

void ProxyModule::emitEvent(const QString &message)
{
    emit eventAppended(message);
    if (m_logger) {
        m_logger->info(id(), message);
    }
}

void ProxyModule::handleTelemetrySnapshot(const TransferSnapshot &snapshot)
{
    const auto previous = m_lastSnapshot;
    m_lastSnapshot = snapshot;
    emit telemetryUpdated(snapshot);

    if (!m_running) {
        return;
    }

    if (snapshot.totalAccepted > previous.totalAccepted) {
        emitEvent(tr("Yeni oturum kabul edildi. Toplam: %1").arg(snapshot.totalAccepted));
    }
    if (snapshot.timeoutClosures > previous.timeoutClosures) {
        emitEvent(tr("Idle timeout ile kapatilan oturum sayisi: %1").arg(snapshot.timeoutClosures));
    }
}

REGISTER_MODULE(ProxyModule, "proxy");
