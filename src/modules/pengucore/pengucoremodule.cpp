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
