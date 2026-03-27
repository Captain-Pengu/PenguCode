#include "pengucoremodule.h"

#include "core/framework/moduleregistry.h"
#include "core/logging/logger.h"

PenguCoreModule::PenguCoreModule(QObject *parent)
    : ModuleInterface(parent)
    , m_engine(this)
{
    connect(&m_engine, &pengufoce::pengucore::PenguCoreEngine::statusChanged, this, [this](const QString &message) {
        emit statusChanged(message);
        if (m_logger) {
            m_logger->info(id(), message);
        }
    });
}

QString PenguCoreModule::id() const
{
    return QStringLiteral("pengu_core");
}

QString PenguCoreModule::name() const
{
    return QStringLiteral("PenguCore");
}

QString PenguCoreModule::description() const
{
    return QStringLiteral("Kendi packet capture, parser ve flow cekirdegimizi buyutmek icin olusturulan analiz modulu.");
}

QString PenguCoreModule::icon() const
{
    return QStringLiteral("pcap");
}

QUrl PenguCoreModule::pageSource() const
{
    return QUrl(QStringLiteral("qrc:/qt/qml/PenguFoce/qml/pages/PenguCore.qml"));
}

void PenguCoreModule::initialize(SettingsManager *settings, Logger *logger)
{
    m_settings = settings;
    m_logger = logger;
    if (m_logger) {
        m_logger->info(id(), QStringLiteral("PenguCore module initialized"));
    }
}

QVariantMap PenguCoreModule::defaultSettings() const
{
    return {};
}

QVariantMap PenguCoreModule::saveState() const
{
    return {
        {"lastOpenedFile", m_engine.lastOpenedFile()},
        {"lastOpenedFormat", m_engine.lastOpenedFormat()},
        {"liveFilter", m_engine.liveCaptureFilter()},
        {"liveSaveFormat", m_engine.liveSaveFormat()},
        {"liveHealth", m_engine.liveHealthStatus()}
    };
}

bool PenguCoreModule::loadState(const QVariantMap &state)
{
    m_engine.setLiveCaptureFilter(state.value("liveFilter").toString());
    m_engine.setLiveSaveFormat(state.value("liveSaveFormat").toString());
    const QString lastOpenedFile = state.value("lastOpenedFile").toString();
    if (!lastOpenedFile.isEmpty()) {
        m_engine.openCaptureFile(lastOpenedFile);
    }
    return true;
}

void PenguCoreModule::reset()
{
    m_engine.clearSession();
}

QString PenguCoreModule::healthStatus() const
{
    return m_engine.isLiveCaptureRunning() ? m_engine.liveHealthStatus() : QStringLiteral("HEALTHY");
}

pengufoce::pengucore::PenguCoreEngine *PenguCoreModule::engine()
{
    return &m_engine;
}

void PenguCoreModule::start()
{
    emit statusChanged(m_engine.statusText());
}

void PenguCoreModule::stop()
{
}

REGISTER_MODULE(PenguCoreModule, "pengu_core");
