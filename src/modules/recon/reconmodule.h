#pragma once

#include "core/framework/moduleinterface.h"

class SettingsManager;
class Logger;
class PenguFoceMasterScanner;
class SettingsManager;

class ReconModule : public ModuleInterface
{
    Q_OBJECT

public:
    explicit ReconModule(QObject *parent = nullptr);
    ~ReconModule() override;

    QString id() const override;
    QString name() const override;
    QString description() const override;
    QString icon() const override;
    QUrl pageSource() const override;

    void initialize(SettingsManager *settings, Logger *logger) override;
    QVariantMap defaultSettings() const override;

    PenguFoceMasterScanner *masterScanner() const;
    SettingsManager *settingsManager() const;
    void reloadSettings();

public slots:
    void start() override;
    void stop() override;

private:
    SettingsManager *m_settings = nullptr;
    Logger *m_logger = nullptr;
    PenguFoceMasterScanner *m_masterScanner = nullptr;
};
