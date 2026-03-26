#pragma once

#include "core/framework/moduleinterface.h"
#include "modules/proxy/engine/localresearchcore.h"

#include <memory>
#include <optional>
#include <thread>
#include <vector>

class SettingsManager;
class Logger;

#ifdef PENGUFOCE_WITH_BOOST_PROXY
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#endif

class ProxyModule : public ModuleInterface
{
    Q_OBJECT

public:
    explicit ProxyModule(QObject *parent = nullptr);

    QString id() const override;
    QString name() const override;
    QString description() const override;
    QString icon() const override;
    QUrl pageSource() const override;

    void initialize(SettingsManager *settings, Logger *logger) override;
    QVariantMap defaultSettings() const override;
    QString listenHost() const;
    int listenPort() const;
    QString targetHost() const;
    int targetPort() const;
    int idleTimeoutSeconds() const;
    int workerThreads() const;
    QString sharedSecret() const;
    bool requireHandshake() const;
    bool interceptTls() const;
    bool running() const;
    pengufoce::proxy::localresearch::TransferSnapshot latestSnapshot() const;
    void reloadSettings();

public slots:
    void start() override;
    void stop() override;
    void applyRuntimeSettings(const QString &listenHost,
                              int listenPort,
                              const QString &targetHost,
                              int targetPort,
                              int idleTimeoutSeconds,
                              int workerThreads,
                              const QString &sharedSecret,
                              bool requireHandshake);

signals:
    void statusChanged(const QString &status);
    void eventAppended(const QString &message);
    void telemetryUpdated(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot);
    void runningChanged(bool running);

private:
    void emitEvent(const QString &message);
    void handleTelemetrySnapshot(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot);

    SettingsManager *m_settings = nullptr;
    Logger *m_logger = nullptr;
    QString m_listenHost = "127.0.0.1";
    int m_listenPort = 8080;
    QString m_targetHost = "127.0.0.1";
    int m_targetPort = 18081;
    int m_idleTimeoutSeconds = 30;
    int m_workerThreads = 2;
    QString m_sharedSecret = "TB1RBS";
    bool m_requireHandshake = true;
    bool m_interceptTls = true;
    bool m_running = false;
    pengufoce::proxy::localresearch::TransferSnapshot m_lastSnapshot;
#ifdef PENGUFOCE_WITH_BOOST_PROXY
    std::unique_ptr<boost::asio::io_context> m_localResearchContext;
    std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> m_localResearchWork;
    std::shared_ptr<pengufoce::proxy::localresearch::TelemetryBridge> m_localResearchTelemetry;
    std::shared_ptr<pengufoce::proxy::localresearch::LocalAcceptor> m_localResearchAcceptor;
    std::vector<std::thread> m_localResearchThreads;
#endif
};
