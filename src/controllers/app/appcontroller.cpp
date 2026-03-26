#include "appcontroller.h"

#include "core/logging/logger.h"
#include "core/framework/modulemanager.h"
#include "controllers/app/sessionmanager.h"
#include "core/settings/settingsmanager.h"
#include "core/theme/themeengine.h"

AppController::AppController(QObject *parent)
    : QObject(parent)
    , m_settingsManager(new SettingsManager(this))
    , m_logger(new Logger(this))
    , m_moduleManager(new ModuleManager(this))
    , m_sessionManager(new SessionManager(m_moduleManager, m_logger, this))
    , m_themeEngine(new ThemeEngine(this))
    , m_scanOrchestrator(new ScanOrchestrator(this))
{
    m_themeEngine->loadSettings(m_settingsManager);
    m_moduleManager->loadModules(m_settingsManager, m_logger);
    m_scanOrchestrator->setLogger(m_logger);
}

ModuleManager *AppController::moduleManager() const
{
    return m_moduleManager;
}

SettingsManager *AppController::settingsManager() const
{
    return m_settingsManager;
}

SessionManager *AppController::sessionManager() const
{
    return m_sessionManager;
}

Logger *AppController::logger() const
{
    return m_logger;
}

ThemeEngine *AppController::themeEngine() const
{
    return m_themeEngine;
}

ScanOrchestrator *AppController::scanOrchestrator() const
{
    return m_scanOrchestrator;
}
