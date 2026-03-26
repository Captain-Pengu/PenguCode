#pragma once

#include "core/framework/moduleinterface.h"
#include "pengucore/api/pengucoreengine.h"

class SettingsManager;
class Logger;

class PenguCoreModule : public ModuleInterface
{
    Q_OBJECT

public:
    explicit PenguCoreModule(QObject *parent = nullptr);

    QString id() const override;
    QString name() const override;
    QString description() const override;
    QString icon() const override;
    QUrl pageSource() const override;

    void initialize(SettingsManager *settings, Logger *logger) override;
    QVariantMap defaultSettings() const override;

    pengufoce::pengucore::PenguCoreEngine *engine();

public slots:
    void start() override;
    void stop() override;

signals:
    void statusChanged(const QString &message);

private:
    SettingsManager *m_settings = nullptr;
    Logger *m_logger = nullptr;
    pengufoce::pengucore::PenguCoreEngine m_engine;
};
