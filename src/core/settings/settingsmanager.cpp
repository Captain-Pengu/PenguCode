#include "settingsmanager.h"

SettingsManager::SettingsManager(QObject *parent)
    : QObject(parent)
    , m_settings("PenguFoce", "PenguFoce")
{
}

QVariant SettingsManager::value(const QString &group, const QString &key, const QVariant &defaultValue) const
{
    m_settings.beginGroup(group);
    const QVariant result = m_settings.value(key, defaultValue);
    m_settings.endGroup();
    return result;
}

void SettingsManager::setValue(const QString &group, const QString &key, const QVariant &value)
{
    m_settings.beginGroup(group);
    m_settings.setValue(key, value);
    m_settings.endGroup();
}

QVariantMap SettingsManager::moduleSettings(const QString &moduleId) const
{
    QVariantMap result;
    const QString groupName = QStringLiteral("modules/%1").arg(moduleId);
    m_settings.beginGroup(groupName);
    const auto keys = m_settings.childKeys();
    for (const auto &key : keys) {
        result.insert(key, m_settings.value(key));
    }
    m_settings.endGroup();
    return result;
}

void SettingsManager::ensureModuleDefaults(const QString &moduleId, const QVariantMap &defaults)
{
    const QString groupName = QStringLiteral("modules/%1").arg(moduleId);
    m_settings.beginGroup(groupName);
    for (auto it = defaults.cbegin(); it != defaults.cend(); ++it) {
        if (!m_settings.contains(it.key())) {
            m_settings.setValue(it.key(), it.value());
        }
    }
    m_settings.endGroup();
}
