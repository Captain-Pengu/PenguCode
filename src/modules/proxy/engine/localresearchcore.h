#pragma once

#include <QObject>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef PENGUFOCE_WITH_BOOST_PROXY
#include <boost/asio.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#endif

namespace pengufoce::proxy::localresearch {

struct TransferSnapshot
{
    std::size_t activeSessions = 0;
    std::size_t totalAccepted = 0;
    std::size_t bytesClientToTarget = 0;
    std::size_t bytesTargetToClient = 0;
    std::size_t timeoutClosures = 0;
    double bytesPerSecond = 0.0;
};

class TelemetryBridge : public QObject
{
    Q_OBJECT

public:
    explicit TelemetryBridge(QObject *parent = nullptr);

    void sessionAccepted();
    void sessionClosed();
    void recordClientToTarget(std::size_t bytes);
    void recordTargetToClient(std::size_t bytes);
    void recordTimeout();
    TransferSnapshot snapshot() const;

signals:
    void snapshotReady(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot);

private:
    void publishSnapshot();

    std::atomic<std::size_t> m_activeSessions{0};
    std::atomic<std::size_t> m_totalAccepted{0};
    std::atomic<std::size_t> m_bytesClientToTarget{0};
    std::atomic<std::size_t> m_bytesTargetToClient{0};
    std::atomic<std::size_t> m_timeoutClosures{0};
    std::chrono::steady_clock::time_point m_startedAt;
};

#ifdef PENGUFOCE_WITH_BOOST_PROXY

struct LocalAcceptorConfig
{
    // Bu alanlar UI tarafindan doldurulur; sabit IP yerine runtime kullanilir.
    std::string listenHost{"127.0.0.1"};
    unsigned short listenPort{18080};
    std::string targetHost{"127.0.0.1"};
    unsigned short targetPort{80};
    bool requireHandshake{true};
    std::string sharedSecret{"TB1RBS"};
    std::chrono::seconds idleTimeout{30};
    std::size_t maxBufferedBytes = 256 * 1024;
    std::size_t chunkBytes = 16 * 1024;

    std::optional<boost::asio::ip::tcp::endpoint> tryMakeListenEndpoint() const;

    std::optional<boost::asio::ip::tcp::endpoint> tryMakeTargetEndpoint() const;
};

class ResourceSupervisor
{
public:
    ResourceSupervisor(boost::asio::any_io_executor executor,
                       std::chrono::steady_clock::duration idleTimeout,
                       std::function<void()> onTimeout);

    void arm();
    void touch();
    void stop();

private:
    class Impl;
    std::shared_ptr<Impl> m_impl;
};

class LocalBridge : public std::enable_shared_from_this<LocalBridge>
{
public:
    using tcp = boost::asio::ip::tcp;

    LocalBridge(tcp::socket clientSocket,
                tcp::socket targetSocket,
                LocalAcceptorConfig config,
                std::shared_ptr<TelemetryBridge> telemetry);

    ~LocalBridge();

    void start();
    void stop();

private:
    void startClientRead();
    void startTargetRead();
    void flushClientToTarget();
    void flushTargetToClient();
    void onClientRead(const boost::system::error_code &ec, std::size_t bytesRead);
    void onTargetRead(const boost::system::error_code &ec, std::size_t bytesRead);
    void onClientToTargetWritten(const boost::system::error_code &ec, std::size_t bytesWritten);
    void onTargetToClientWritten(const boost::system::error_code &ec, std::size_t bytesWritten);
    void resumePausedReads();
    bool trySatisfyHandshake();
    void closeSockets();

    tcp::socket m_clientSocket;
    tcp::socket m_targetSocket;
    boost::asio::strand<boost::asio::any_io_executor> m_strand;
    std::unique_ptr<ResourceSupervisor> m_supervisor;
    LocalAcceptorConfig m_config;
    std::shared_ptr<TelemetryBridge> m_telemetry;
    boost::beast::flat_buffer m_clientToTarget;
    boost::beast::flat_buffer m_targetToClient;
    bool m_stopped = false;
    bool m_clientReadPaused = false;
    bool m_targetReadPaused = false;
    bool m_clientWriteActive = false;
    bool m_targetWriteActive = false;
    bool m_handshakeSatisfied = false;
};

class LocalAcceptor : public std::enable_shared_from_this<LocalAcceptor>
{
public:
    using tcp = boost::asio::ip::tcp;

    LocalAcceptor(boost::asio::io_context &ioc,
                  LocalAcceptorConfig config,
                  std::shared_ptr<TelemetryBridge> telemetry);

    bool start();
    void stop();

private:
    void acceptOnce();
    void onAccepted(const boost::system::error_code &ec);
    void connectTarget(std::shared_ptr<tcp::socket> clientSocket);

    boost::asio::io_context &m_ioc;
    tcp::acceptor m_acceptor;
    tcp::socket m_socket;
    LocalAcceptorConfig m_config;
    std::shared_ptr<TelemetryBridge> m_telemetry;
};

#endif

} // namespace pengufoce::proxy::localresearch

Q_DECLARE_METATYPE(pengufoce::proxy::localresearch::TransferSnapshot)
