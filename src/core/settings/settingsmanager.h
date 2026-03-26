#pragma once

#include <QObject>
#include <QSettings>
#include <QVariant>
#include <QVariantMap>

class SettingsManager : public QObject
{
    Q_OBJECT

public:
    explicit SettingsManager(QObject *parent = nullptr);

    Q_INVOKABLE QVariant value(const QString &group, const QString &key,
                               const QVariant &defaultValue = {}) const;
    Q_INVOKABLE void setValue(const QString &group, const QString &key, const QVariant &value);
    Q_INVOKABLE QVariantMap moduleSettings(const QString &moduleId) const;

    void ensureModuleDefaults(const QString &moduleId, const QVariantMap &defaults);

private:
    mutable QSettings m_settings;
};
