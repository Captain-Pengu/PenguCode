#pragma once

#include <QObject>
#include "core/logging/logger.h"
#include "core/framework/modulemanager.h"
#include "modules/recon/engine/scanorchestrator.h"
#include "controllers/app/sessionmanager.h"
#include "core/settings/settingsmanager.h"
#include "core/theme/themeengine.h"

class AppController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(ModuleManager *moduleManager READ moduleManager CONSTANT)
    Q_PROPERTY(SettingsManager *settingsManager READ settingsManager CONSTANT)
    Q_PROPERTY(SessionManager *sessionManager READ sessionManager CONSTANT)
    Q_PROPERTY(Logger *logger READ logger CONSTANT)
    Q_PROPERTY(ThemeEngine *themeEngine READ themeEngine CONSTANT)
    Q_PROPERTY(ScanOrchestrator *scanOrchestrator READ scanOrchestrator CONSTANT)

public:
    explicit AppController(QObject *parent = nullptr);

    ModuleManager *moduleManager() const;
    SettingsManager *settingsManager() const;
    SessionManager *sessionManager() const;
    Logger *logger() const;
    ThemeEngine *themeEngine() const;
    ScanOrchestrator *scanOrchestrator() const;

private:
    SettingsManager *m_settingsManager;
    Logger *m_logger;
    ModuleManager *m_moduleManager;
    SessionManager *m_sessionManager;
    ThemeEngine *m_themeEngine;
    ScanOrchestrator *m_scanOrchestrator;
};
