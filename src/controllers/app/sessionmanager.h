#pragma once

#include <QObject>
#include <QVariantMap>

class ModuleManager;
class Logger;

class SessionManager : public QObject
{
    Q_OBJECT

public:
    explicit SessionManager(ModuleManager *moduleManager, Logger *logger, QObject *parent = nullptr);

    Q_INVOKABLE bool saveSession(const QString &filePath) const;
    Q_INVOKABLE QVariantMap loadSession(const QString &filePath);
    void setThemeEngine(QObject *themeEngine);
    void setSettingsManager(QObject *settingsManager);

private:
    ModuleManager *m_moduleManager;
    Logger *m_logger;
    QObject *m_themeEngine = nullptr;
    QObject *m_settingsManager = nullptr;
};
