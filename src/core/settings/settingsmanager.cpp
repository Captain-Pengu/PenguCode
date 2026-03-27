#include "settingsmanager.h"

#include <QVariantList>

namespace {

QString normalizeTypeName(QString typeName)
{
    return typeName.trimmed().toLower();
}

}

SettingsManager::SettingsManager(QObject *parent)
    : QObject(parent)
    , m_settings("PenguFoce", "PenguFoce")
{
    runMigrations();
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

QVariant SettingsManager::typedValue(const QString &group,
                                     const QString &key,
                                     const QString &typeName,
                                     const QVariant &defaultValue) const
{
    const QVariant raw = value(group, key, defaultValue);
    return coerceValue(typeName, raw, defaultValue);
}

bool SettingsManager::setTypedValue(const QString &group,
                                    const QString &key,
                                    const QString &typeName,
                                    const QVariant &valueToStore)
{
    const QVariant coerced = coerceValue(typeName, valueToStore, {});
    if (!coerced.isValid() && valueToStore.isValid()) {
        return false;
    }
    setValue(group, key, coerced);
    return true;
}

int SettingsManager::schemaVersion() const
{
    return value(QStringLiteral("app"), QStringLiteral("schemaVersion"), 0).toInt();
}

void SettingsManager::setModuleSettings(const QString &moduleId, const QVariantMap &values)
{
    const QString groupName = QStringLiteral("modules/%1").arg(moduleId);
    m_settings.beginGroup(groupName);
    for (auto it = values.cbegin(); it != values.cend(); ++it) {
        m_settings.setValue(it.key(), it.value());
    }
    m_settings.endGroup();
}

QVariantMap SettingsManager::dumpAll() const
{
    QVariantMap result;
    const QStringList groups = m_settings.childGroups();
    for (const QString &group : groups) {
        m_settings.beginGroup(group);
        QVariantMap groupMap;
        const auto keys = m_settings.childKeys();
        for (const QString &key : keys) {
            groupMap.insert(key, m_settings.value(key));
        }
        const auto childGroups = m_settings.childGroups();
        for (const QString &child : childGroups) {
            m_settings.beginGroup(child);
            QVariantMap childMap;
            const auto childKeys = m_settings.childKeys();
            for (const QString &key : childKeys) {
                childMap.insert(key, m_settings.value(key));
            }
            m_settings.endGroup();
            groupMap.insert(child, childMap);
        }
        m_settings.endGroup();
        result.insert(group, groupMap);
    }
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

void SettingsManager::sync()
{
    m_settings.sync();
}

void SettingsManager::runMigrations()
{
    int version = schemaVersion();
    if (version < 1) {
        const QVariant legacyTheme = m_settings.value(QStringLiteral("theme/current"));
        if (legacyTheme.isValid() && !m_settings.contains(QStringLiteral("theme/currentTheme"))) {
            setValue(QStringLiteral("theme"), QStringLiteral("currentTheme"), legacyTheme.toString());
        }
        version = 1;
        setValue(QStringLiteral("app"), QStringLiteral("schemaVersion"), version);
    }

    if (version < 2) {
        const QString currentTheme = value(QStringLiteral("theme"), QStringLiteral("currentTheme"), QStringLiteral("dark")).toString();
        if (currentTheme != QLatin1String("dark") && currentTheme != QLatin1String("light")) {
            setValue(QStringLiteral("theme"), QStringLiteral("currentTheme"), QStringLiteral("dark"));
        }
        version = 2;
        setValue(QStringLiteral("app"), QStringLiteral("schemaVersion"), version);
    }

    sync();
}

QVariant SettingsManager::coerceValue(const QString &typeName, const QVariant &valueToConvert, const QVariant &defaultValue) const
{
    const QString normalized = normalizeTypeName(typeName);
    if (normalized.isEmpty()) {
        return valueToConvert.isValid() ? valueToConvert : defaultValue;
    }
    if (normalized == QLatin1String("string")) {
        return valueToConvert.toString();
    }
    if (normalized == QLatin1String("int")) {
        return valueToConvert.toInt();
    }
    if (normalized == QLatin1String("bool")) {
        return valueToConvert.toBool();
    }
    if (normalized == QLatin1String("double")) {
        return valueToConvert.toDouble();
    }
    if (normalized == QLatin1String("stringlist")) {
        return valueToConvert.toStringList();
    }
    if (normalized == QLatin1String("map")) {
        return valueToConvert.toMap();
    }
    if (normalized == QLatin1String("list")) {
        return valueToConvert.toList();
    }
    return valueToConvert.isValid() ? valueToConvert : defaultValue;
}
