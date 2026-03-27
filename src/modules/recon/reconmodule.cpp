#include "reconmodule.h"

#include "core/logging/logger.h"
#include "core/framework/moduleregistry.h"
#include "core/settings/settingsmanager.h"
#include "modules/recon/engine/pengufoce_masterscanner.h"

ReconModule::ReconModule(QObject *parent)
    : ModuleInterface(parent)
{
}

ReconModule::~ReconModule() = default;

QString ReconModule::id() const
{
    return "recon";
}

QString ReconModule::name() const
{
    return "Recon";
}

QString ReconModule::description() const
{
    return "DNS enumeration, public leak checks ve servis bazli CVE eslestirme akisi.";
}

QString ReconModule::icon() const
{
    return "recon";
}

QUrl ReconModule::pageSource() const
{
    return QUrl("qrc:/qt/qml/PenguFoce/qml/pages/ReconPage.qml");
}

void ReconModule::initialize(SettingsManager *settings, Logger *logger)
{
    m_settings = settings;
    m_logger = logger;
    if (!m_masterScanner) {
        m_masterScanner = new PenguFoceMasterScanner(this);
        m_masterScanner->setLogger(logger);
    }
    m_logger->info(id(), "Recon module initialized");
}

QVariantMap ReconModule::defaultSettings() const
{
    return {
        {"defaultTarget", "scanme.nmap.org"},
        {"defaultEndpoint", ""}
    };
}

QVariantMap ReconModule::saveState() const
{
    return {
        {"defaultTarget", m_settings ? m_settings->value("modules/recon", "defaultTarget", QString()).toString() : QString()},
        {"defaultEndpoint", m_settings ? m_settings->value("modules/recon", "defaultEndpoint", QString()).toString() : QString()}
    };
}

bool ReconModule::loadState(const QVariantMap &state)
{
    if (!m_settings) {
        return false;
    }
    m_settings->setValue("modules/recon", "defaultTarget", state.value("defaultTarget").toString());
    m_settings->setValue("modules/recon", "defaultEndpoint", state.value("defaultEndpoint").toString());
    reloadSettings();
    return true;
}

void ReconModule::reset()
{
    if (m_masterScanner) {
        m_masterScanner->stop();
    }
}

QString ReconModule::healthStatus() const
{
    return QStringLiteral("HEALTHY");
}

PenguFoceMasterScanner *ReconModule::masterScanner() const
{
    return m_masterScanner;
}

SettingsManager *ReconModule::settingsManager() const
{
    return m_settings;
}

void ReconModule::reloadSettings()
{
}

void ReconModule::start()
{
    if (m_logger && m_settings) {
        m_logger->info(id(), "Recon module armed");
        if (m_masterScanner) {
            m_masterScanner->startScan(
                m_settings->value("modules/recon", "defaultTarget", "scanme.nmap.org").toString(),
                QUrl(m_settings->value("modules/recon", "defaultEndpoint", "").toString()));
        }
    }
}

void ReconModule::stop()
{
    if (m_logger) {
        m_logger->warning(id(), "Recon module halted");
    }
    if (m_masterScanner) {
        m_masterScanner->stop();
    }
}

REGISTER_MODULE(ReconModule, "recon");
