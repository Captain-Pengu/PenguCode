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

    static constexpr int kCurrentSchemaVersion = 2;

    Q_INVOKABLE QVariant value(const QString &group, const QString &key,
                               const QVariant &defaultValue = {}) const;
    Q_INVOKABLE void setValue(const QString &group, const QString &key, const QVariant &value);
    Q_INVOKABLE QVariantMap moduleSettings(const QString &moduleId) const;
    Q_INVOKABLE QVariant typedValue(const QString &group,
                                    const QString &key,
                                    const QString &typeName,
                                    const QVariant &defaultValue = {}) const;
    Q_INVOKABLE bool setTypedValue(const QString &group,
                                   const QString &key,
                                   const QString &typeName,
                                   const QVariant &value);
    Q_INVOKABLE int schemaVersion() const;
    Q_INVOKABLE void setModuleSettings(const QString &moduleId, const QVariantMap &values);
    Q_INVOKABLE QVariantMap dumpAll() const;

    void ensureModuleDefaults(const QString &moduleId, const QVariantMap &defaults);
    void sync();

private:
    void runMigrations();
    QVariant coerceValue(const QString &typeName, const QVariant &value, const QVariant &defaultValue) const;

    mutable QSettings m_settings;
};
