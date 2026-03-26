#pragma once

#include <QObject>
#include <QString>
#include <QUrl>
#include <QVariantMap>

class SettingsManager;
class Logger;

class ModuleInterface : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString id READ id CONSTANT)
    Q_PROPERTY(QString name READ name CONSTANT)
    Q_PROPERTY(QString description READ description CONSTANT)
    Q_PROPERTY(QString icon READ icon CONSTANT)
    Q_PROPERTY(QUrl pageSource READ pageSource CONSTANT)

public:
    explicit ModuleInterface(QObject *parent = nullptr) : QObject(parent) {}
    ~ModuleInterface() override = default;

    virtual QString id() const = 0;
    virtual QString name() const = 0;
    virtual QString description() const = 0;
    virtual QString icon() const = 0;
    virtual QUrl pageSource() const = 0;

    virtual void initialize(SettingsManager *settings, Logger *logger) = 0;
    virtual QVariantMap defaultSettings() const { return {}; }

public slots:
    virtual void start() = 0;
    virtual void stop() = 0;
};

Q_DECLARE_METATYPE(ModuleInterface *)
