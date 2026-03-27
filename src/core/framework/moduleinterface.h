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
    virtual QVariantMap saveState() const { return {}; }
    virtual bool loadState(const QVariantMap &state)
    {
        Q_UNUSED(state);
        return true;
    }
    virtual void reset() { stop(); }
    virtual QString healthStatus() const { return QStringLiteral("HEALTHY"); }

    void bindContext(SettingsManager *settings, Logger *logger)
    {
        m_settings = settings;
        m_logger = logger;
    }

protected:
    SettingsManager *settings() const { return m_settings; }
    Logger *logger() const { return m_logger; }

public slots:
    virtual void start() = 0;
    virtual void stop() = 0;

private:
    SettingsManager *m_settings = nullptr;
    Logger *m_logger = nullptr;
};

Q_DECLARE_METATYPE(ModuleInterface *)
