#include "modules/proxy/engine/localresearchcore.h"

#include <QMetaObject>

#ifdef PENGUFOCE_WITH_BOOST_PROXY
#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/error_code.hpp>
#endif

namespace pengufoce::proxy::localresearch {

#ifdef PENGUFOCE_WITH_BOOST_PROXY
namespace {

std::optional<boost::asio::ip::address> parseRuntimeAddress(std::string_view value)
{
    if (value.empty()) {
        return std::nullopt;
    }
    if (value == "localhost") {
        return boost::asio::ip::make_address("127.0.0.1");
    }

    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(std::string(value), ec);
    if (ec) {
        return std::nullopt;
    }
    return address;
}

} // namespace
#endif

TelemetryBridge::TelemetryBridge(QObject *parent)
    : QObject(parent)
    , m_startedAt(std::chrono::steady_clock::now())
{
}

void TelemetryBridge::sessionAccepted()
{
    m_totalAccepted.fetch_add(1, std::memory_order_relaxed);
    m_activeSessions.fetch_add(1, std::memory_order_relaxed);
    publishSnapshot();
}

void TelemetryBridge::sessionClosed()
{
    auto current = m_activeSessions.load(std::memory_order_relaxed);
    while (current > 0 &&
           !m_activeSessions.compare_exchange_weak(current, current - 1, std::memory_order_relaxed)) {
    }
    publishSnapshot();
}

void TelemetryBridge::recordClientToTarget(std::size_t bytes)
{
    m_bytesClientToTarget.fetch_add(bytes, std::memory_order_relaxed);
    publishSnapshot();
}

void TelemetryBridge::recordTargetToClient(std::size_t bytes)
{
    m_bytesTargetToClient.fetch_add(bytes, std::memory_order_relaxed);
    publishSnapshot();
}

void TelemetryBridge::recordTimeout()
{
    m_timeoutClosures.fetch_add(1, std::memory_order_relaxed);
    publishSnapshot();
}

TransferSnapshot TelemetryBridge::snapshot() const
{
    TransferSnapshot result;
    result.activeSessions = m_activeSessions.load(std::memory_order_relaxed);
    result.totalAccepted = m_totalAccepted.load(std::memory_order_relaxed);
    result.bytesClientToTarget = m_bytesClientToTarget.load(std::memory_order_relaxed);
    result.bytesTargetToClient = m_bytesTargetToClient.load(std::memory_order_relaxed);
    result.timeoutClosures = m_timeoutClosures.load(std::memory_order_relaxed);

    const auto elapsedSeconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - m_startedAt).count();
    const auto totalBytes = static_cast<double>(result.bytesClientToTarget + result.bytesTargetToClient);
    result.bytesPerSecond = elapsedSeconds > 0.0 ? (totalBytes / elapsedSeconds) : 0.0;
    return result;
}

void TelemetryBridge::publishSnapshot()
{
    const auto current = snapshot();
    QMetaObject::invokeMethod(
        this,
        [this, current]() {
            emit snapshotReady(current);
        },
        Qt::QueuedConnection);
}

#ifdef PENGUFOCE_WITH_BOOST_PROXY

std::optional<boost::asio::ip::tcp::endpoint> LocalAcceptorConfig::tryMakeListenEndpoint() const
{
    const auto address = parseRuntimeAddress(listenHost);
    if (!address) {
        return std::nullopt;
    }
    return boost::asio::ip::tcp::endpoint(*address, listenPort);
}

std::optional<boost::asio::ip::tcp::endpoint> LocalAcceptorConfig::tryMakeTargetEndpoint() const
{
    const auto address = parseRuntimeAddress(targetHost);
    if (!address) {
        return std::nullopt;
    }
    return boost::asio::ip::tcp::endpoint(*address, targetPort);
}

class ResourceSupervisor::Impl : public std::enable_shared_from_this<ResourceSupervisor::Impl>
{
public:
    Impl(boost::asio::any_io_executor executor,
         std::chrono::steady_clock::duration timeout,
         std::function<void()> callback)
        : timer(executor)
        , idleTimeout(timeout)
        , onTimeout(std::move(callback))
    {
    }

    void arm()
    {
        schedule();
    }

    void touch()
    {
        schedule();
    }

    void stop()
    {
        timer.cancel();
    }

private:
    void schedule()
    {
        timer.expires_after(idleTimeout);
        auto self = shared_from_this();
        timer.async_wait([self](const boost::system::error_code &ec) {
            if (!ec && self->onTimeout) {
                self->onTimeout();
            }
        });
    }

public:
    boost::asio::steady_timer timer;
    std::chrono::steady_clock::duration idleTimeout;
    std::function<void()> onTimeout;
};

ResourceSupervisor::ResourceSupervisor(boost::asio::any_io_executor executor,
                                       std::chrono::steady_clock::duration idleTimeout,
                                       std::function<void()> onTimeout)
    : m_impl(std::make_shared<Impl>(executor, idleTimeout, std::move(onTimeout)))
{
}

void ResourceSupervisor::arm()
{
    m_impl->arm();
}

void ResourceSupervisor::touch()
{
    m_impl->touch();
}

void ResourceSupervisor::stop()
{
    m_impl->stop();
}

LocalBridge::LocalBridge(tcp::socket clientSocket,
                         tcp::socket targetSocket,
                         LocalAcceptorConfig config,
                         std::shared_ptr<TelemetryBridge> telemetry)
    : m_clientSocket(std::move(clientSocket))
    , m_targetSocket(std::move(targetSocket))
    , m_strand(boost::asio::make_strand(m_clientSocket.get_executor()))
    , m_config(std::move(config))
    , m_telemetry(std::move(telemetry))
{
}

LocalBridge::~LocalBridge()
{
    closeSockets();
}

void LocalBridge::start()
{
    auto self = shared_from_this();
    m_supervisor = std::make_unique<ResourceSupervisor>(
        m_strand,
        m_config.idleTimeout,
        [weak = std::weak_ptr<LocalBridge>(self)]() {
            if (auto locked = weak.lock()) {
                boost::asio::dispatch(locked->m_strand, [locked]() {
                    if (!locked->m_stopped && locked->m_telemetry) {
                        locked->m_telemetry->recordTimeout();
                    }
                    locked->stop();
                });
            }
        });

    if (m_telemetry) {
        m_telemetry->sessionAccepted();
    }
    m_supervisor->arm();
    m_handshakeSatisfied = !m_config.requireHandshake || m_config.sharedSecret.empty();

    boost::asio::dispatch(m_strand, [self]() {
        self->startClientRead();
        if (self->m_handshakeSatisfied) {
            self->startTargetRead();
        }
    });
}

void LocalBridge::stop()
{
    auto self = shared_from_this();
    boost::asio::dispatch(m_strand, [this, self]() {
        if (m_stopped) {
            return;
        }
        m_stopped = true;
        if (m_supervisor) {
            m_supervisor->stop();
        }
        closeSockets();
        if (m_telemetry) {
            m_telemetry->sessionClosed();
        }
    });
}

void LocalBridge::startClientRead()
{
    if (m_stopped || m_clientReadPaused) {
        return;
    }
    if (m_clientToTarget.size() >= m_config.maxBufferedBytes) {
        m_clientReadPaused = true;
        return;
    }

    const auto chunk = std::min<std::size_t>(m_config.chunkBytes, m_config.maxBufferedBytes - m_clientToTarget.size());
    auto self = shared_from_this();
    m_clientSocket.async_read_some(
        m_clientToTarget.prepare(chunk),
        boost::asio::bind_executor(
            m_strand,
            [this, self](const boost::system::error_code &ec, std::size_t bytesRead) {
                onClientRead(ec, bytesRead);
            }));
}

void LocalBridge::startTargetRead()
{
    if (m_stopped || m_targetReadPaused) {
        return;
    }
    if (m_targetToClient.size() >= m_config.maxBufferedBytes) {
        m_targetReadPaused = true;
        return;
    }

    const auto chunk = std::min<std::size_t>(m_config.chunkBytes, m_config.maxBufferedBytes - m_targetToClient.size());
    auto self = shared_from_this();
    m_targetSocket.async_read_some(
        m_targetToClient.prepare(chunk),
        boost::asio::bind_executor(
            m_strand,
            [this, self](const boost::system::error_code &ec, std::size_t bytesRead) {
                onTargetRead(ec, bytesRead);
            }));
}

void LocalBridge::flushClientToTarget()
{
    if (m_stopped || m_clientWriteActive || m_clientToTarget.size() == 0) {
        return;
    }

    m_clientWriteActive = true;
    auto self = shared_from_this();
    boost::asio::async_write(
        m_targetSocket,
        m_clientToTarget.data(),
        boost::asio::bind_executor(
            m_strand,
            [this, self](const boost::system::error_code &ec, std::size_t bytesWritten) {
                onClientToTargetWritten(ec, bytesWritten);
            }));
}

void LocalBridge::flushTargetToClient()
{
    if (m_stopped || m_targetWriteActive || m_targetToClient.size() == 0) {
        return;
    }

    m_targetWriteActive = true;
    auto self = shared_from_this();
    boost::asio::async_write(
        m_clientSocket,
        m_targetToClient.data(),
        boost::asio::bind_executor(
            m_strand,
            [this, self](const boost::system::error_code &ec, std::size_t bytesWritten) {
                onTargetToClientWritten(ec, bytesWritten);
            }));
}

void LocalBridge::onClientRead(const boost::system::error_code &ec, std::size_t bytesRead)
{
    if (ec) {
        stop();
        return;
    }

    m_clientToTarget.commit(bytesRead);
    if (m_telemetry) {
        m_telemetry->recordClientToTarget(bytesRead);
    }
    if (m_supervisor) {
        m_supervisor->touch();
    }

    if (!m_handshakeSatisfied) {
        if (!trySatisfyHandshake()) {
            stop();
            return;
        }
        if (!m_handshakeSatisfied) {
            startClientRead();
            return;
        }
        startTargetRead();
        if (m_clientToTarget.size() == 0) {
            startClientRead();
            return;
        }
    }

    flushClientToTarget();
    if (m_clientToTarget.size() < m_config.maxBufferedBytes) {
        startClientRead();
    } else {
        m_clientReadPaused = true;
    }
}

void LocalBridge::onTargetRead(const boost::system::error_code &ec, std::size_t bytesRead)
{
    if (ec) {
        stop();
        return;
    }

    m_targetToClient.commit(bytesRead);
    if (m_telemetry) {
        m_telemetry->recordTargetToClient(bytesRead);
    }
    if (m_supervisor) {
        m_supervisor->touch();
    }

    flushTargetToClient();
    if (m_targetToClient.size() < m_config.maxBufferedBytes) {
        startTargetRead();
    } else {
        m_targetReadPaused = true;
    }
}

void LocalBridge::onClientToTargetWritten(const boost::system::error_code &ec, std::size_t bytesWritten)
{
    m_clientWriteActive = false;
    if (ec) {
        stop();
        return;
    }

    m_clientToTarget.consume(bytesWritten);
    if (m_supervisor) {
        m_supervisor->touch();
    }
    if (m_clientToTarget.size() > 0) {
        flushClientToTarget();
    }
    resumePausedReads();
}

void LocalBridge::onTargetToClientWritten(const boost::system::error_code &ec, std::size_t bytesWritten)
{
    m_targetWriteActive = false;
    if (ec) {
        stop();
        return;
    }

    m_targetToClient.consume(bytesWritten);
    if (m_supervisor) {
        m_supervisor->touch();
    }
    if (m_targetToClient.size() > 0) {
        flushTargetToClient();
    }
    resumePausedReads();
}

void LocalBridge::resumePausedReads()
{
    if (m_clientReadPaused && m_clientToTarget.size() < (m_config.maxBufferedBytes / 2)) {
        m_clientReadPaused = false;
        startClientRead();
    }
    if (m_targetReadPaused && m_targetToClient.size() < (m_config.maxBufferedBytes / 2)) {
        m_targetReadPaused = false;
        startTargetRead();
    }
}

bool LocalBridge::trySatisfyHandshake()
{
    if (m_handshakeSatisfied) {
        return true;
    }
    if (m_clientToTarget.size() == 0) {
        return false;
    }

    const auto data = m_clientToTarget.data();
    std::string authProbe(boost::asio::buffers_begin(data), boost::asio::buffers_end(data));
    const auto secretPos = authProbe.find(m_config.sharedSecret);
    if (secretPos == std::string::npos) {
        return false;
    }

    const std::size_t consumeCount = secretPos + m_config.sharedSecret.size();
    m_clientToTarget.consume(consumeCount);

    while (m_clientToTarget.size() > 0) {
        const auto first = m_clientToTarget.data();
        const char ch = *boost::asio::buffers_begin(first);
        if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') {
            m_clientToTarget.consume(1);
            continue;
        }
        break;
    }

    m_handshakeSatisfied = true;
    return true;
}

void LocalBridge::closeSockets()
{
    boost::system::error_code ignored;
    if (m_clientSocket.is_open()) {
        m_clientSocket.shutdown(tcp::socket::shutdown_both, ignored);
        m_clientSocket.close(ignored);
    }
    if (m_targetSocket.is_open()) {
        m_targetSocket.shutdown(tcp::socket::shutdown_both, ignored);
        m_targetSocket.close(ignored);
    }
}

LocalAcceptor::LocalAcceptor(boost::asio::io_context &ioc,
                             LocalAcceptorConfig config,
                             std::shared_ptr<TelemetryBridge> telemetry)
    : m_ioc(ioc)
    , m_acceptor(ioc)
    , m_socket(ioc)
    , m_config(std::move(config))
    , m_telemetry(std::move(telemetry))
{
}

bool LocalAcceptor::start()
{
    boost::system::error_code ec;
    const auto listenEndpoint = m_config.tryMakeListenEndpoint();
    if (!listenEndpoint) {
        return false;
    }
    m_acceptor.open(listenEndpoint->protocol(), ec);
    if (ec) {
        return false;
    }
    m_acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
    if (ec) {
        return false;
    }
    m_acceptor.bind(*listenEndpoint, ec);
    if (ec) {
        return false;
    }
    m_acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        return false;
    }

    acceptOnce();
    return true;
}

void LocalAcceptor::stop()
{
    boost::system::error_code ignored;
    m_acceptor.cancel(ignored);
    m_acceptor.close(ignored);
    m_socket.close(ignored);
}

void LocalAcceptor::acceptOnce()
{
    auto self = shared_from_this();
    m_acceptor.async_accept(
        m_socket,
        [this, self](const boost::system::error_code &ec) {
            onAccepted(ec);
        });
}

void LocalAcceptor::onAccepted(const boost::system::error_code &ec)
{
    if (ec) {
        if (ec != boost::asio::error::operation_aborted && m_acceptor.is_open()) {
            acceptOnce();
        }
        return;
    }

    auto clientSocket = std::make_shared<tcp::socket>(std::move(m_socket));
    m_socket = tcp::socket(m_ioc);
    connectTarget(std::move(clientSocket));
    if (m_acceptor.is_open()) {
        acceptOnce();
    }
}

void LocalAcceptor::connectTarget(std::shared_ptr<tcp::socket> clientSocket)
{
    auto self = shared_from_this();
    auto targetSocket = std::make_shared<tcp::socket>(m_ioc);
    const auto targetEndpoint = m_config.tryMakeTargetEndpoint();
    if (!targetEndpoint) {
        boost::system::error_code ignored;
        clientSocket->close(ignored);
        targetSocket->close(ignored);
        return;
    }
    targetSocket->async_connect(
        *targetEndpoint,
        [this, self, clientSocket = std::move(clientSocket), targetSocket](const boost::system::error_code &ec) mutable {
            if (ec) {
                boost::system::error_code ignored;
                clientSocket->close(ignored);
                targetSocket->close(ignored);
                return;
            }

            std::make_shared<LocalBridge>(std::move(*clientSocket),
                                          std::move(*targetSocket),
                                          m_config,
                                          m_telemetry)
                ->start();
        });
}

#endif

} // namespace pengufoce::proxy::localresearch
