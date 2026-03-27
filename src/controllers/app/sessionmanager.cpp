#include "sessionmanager.h"

#include "core/framework/moduleinterface.h"
#include "core/logging/logger.h"
#include "core/framework/modulemanager.h"
#include "core/theme/themeengine.h"
#include "core/settings/settingsmanager.h"

#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

SessionManager::SessionManager(ModuleManager *moduleManager, Logger *logger, QObject *parent)
    : QObject(parent)
    , m_moduleManager(moduleManager)
    , m_logger(logger)
{
}

void SessionManager::setThemeEngine(QObject *themeEngine)
{
    m_themeEngine = themeEngine;
}

void SessionManager::setSettingsManager(QObject *settingsManager)
{
    m_settingsManager = settingsManager;
}

bool SessionManager::saveSession(const QString &filePath) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        m_logger->error("session", QString("Failed to save session to %1").arg(filePath));
        return false;
    }

    QVariantList modules;
    if (m_moduleManager) {
        for (ModuleInterface *module : m_moduleManager->modules()) {
            modules.push_back(QVariantMap{
                {"id", module->id()},
                {"name", module->name()},
                {"health", module->healthStatus()},
                {"state", module->saveState()}
            });
        }
    }

    QVariantMap themeState;
    if (auto *themeEngine = qobject_cast<ThemeEngine *>(m_themeEngine)) {
        themeState = QVariantMap{
            {"currentTheme", themeEngine->currentTheme()},
            {"palette", themeEngine->palette()}
        };
    }

    QVariantMap settingsDump;
    if (auto *settings = qobject_cast<SettingsManager *>(m_settingsManager)) {
        settingsDump = settings->dumpAll();
    }

    const QVariantMap activeModule = m_moduleManager && m_moduleManager->activeModule()
        ? QVariantMap{
              {"id", m_moduleManager->activeModule()->id()},
              {"name", m_moduleManager->activeModule()->name()}
          }
        : QVariantMap{};

    QJsonObject root = QJsonObject::fromVariantMap(QVariantMap{
        {"savedAt", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
        {"moduleCount", modules.size()},
        {"activeModule", activeModule},
        {"theme", themeState},
        {"settings", settingsDump},
        {"modules", modules}
    });

    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    m_logger->info("session", QString("Session saved to %1").arg(filePath));
    return true;
}

QVariantMap SessionManager::loadSession(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        m_logger->error("session", QString("Failed to open session file %1").arg(filePath));
        return {};
    }

    const QVariantMap json = QJsonDocument::fromJson(file.readAll()).object().toVariantMap();

    if (auto *settings = qobject_cast<SettingsManager *>(m_settingsManager)) {
        const QVariantMap settingsDump = json.value("settings").toMap();
        for (auto groupIt = settingsDump.cbegin(); groupIt != settingsDump.cend(); ++groupIt) {
            const QVariantMap groupMap = groupIt.value().toMap();
            for (auto itemIt = groupMap.cbegin(); itemIt != groupMap.cend(); ++itemIt) {
                if (itemIt.value().canConvert<QVariantMap>()) {
                    const QVariantMap nested = itemIt.value().toMap();
                    for (auto nestedIt = nested.cbegin(); nestedIt != nested.cend(); ++nestedIt) {
                        settings->setValue(QStringLiteral("%1/%2").arg(groupIt.key(), itemIt.key()), nestedIt.key(), nestedIt.value());
                    }
                } else {
                    settings->setValue(groupIt.key(), itemIt.key(), itemIt.value());
                }
            }
        }
        settings->sync();
    }

    if (auto *themeEngine = qobject_cast<ThemeEngine *>(m_themeEngine)) {
        const QVariantMap theme = json.value("theme").toMap();
        const QVariantMap palette = theme.value("palette").toMap();
        const QString currentTheme = theme.value("currentTheme").toString();
        for (auto it = palette.cbegin(); it != palette.cend(); ++it) {
            themeEngine->setPaletteValue(currentTheme, it.key(), it.value().toString());
        }
        if (!currentTheme.isEmpty()) {
            themeEngine->setCurrentTheme(currentTheme);
        }
    }

    const QVariantList modules = json.value("modules").toList();
    for (const QVariant &moduleValue : modules) {
        const QVariantMap moduleMap = moduleValue.toMap();
        if (!m_moduleManager) {
            continue;
        }
        if (ModuleInterface *module = m_moduleManager->moduleById(moduleMap.value("id").toString())) {
            module->loadState(moduleMap.value("state").toMap());
        }
    }

    const QString activeModuleId = json.value("activeModule").toMap().value("id").toString();
    if (m_moduleManager && !activeModuleId.isEmpty()) {
        const auto modulesList = m_moduleManager->modules();
        for (int index = 0; index < modulesList.size(); ++index) {
            if (modulesList.at(index)->id() == activeModuleId) {
                m_moduleManager->setActiveIndex(index);
                break;
            }
        }
    }

    m_logger->info("session", QString("Session loaded from %1").arg(filePath));
    return json;
}
