#include "proxycore.h"

#include <boost/asio.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <array>
#include <chrono>
#include <deque>
#include <optional>
#include <sstream>
#include <unordered_set>

namespace pengufoce::proxy {

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = net::ip::tcp;
using error_code = boost::system::error_code;

namespace {

std::string toString(const tcp::endpoint &endpoint)
{
    std::ostringstream stream;
    stream << endpoint.address().to_string() << ":" << endpoint.port();
    return stream.str();
}

bool isAllowedLocalHost(std::string host)
{
    for (char &ch : host) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
}

struct UpstreamTarget
{
    std::string host;
    std::string port;
    std::string requestTarget;
};

std::optional<UpstreamTarget> parseConnectTarget(const std::string &target)
{
    const auto colon = target.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= target.size()) {
        return std::nullopt;
    }

    return UpstreamTarget{target.substr(0, colon), target.substr(colon + 1), target};
}

std::optional<UpstreamTarget> parseHttpTarget(const http::request<http::dynamic_body> &request)
{
    const std::string rawTarget = std::string(request.target());
    if (rawTarget.empty()) {
        return std::nullopt;
    }

    if (rawTarget.rfind("http://", 0) == 0) {
        std::string authority = rawTarget.substr(7);
        const auto slash = authority.find('/');
        std::string path = slash == std::string::npos ? "/" : authority.substr(slash);
        authority = slash == std::string::npos ? authority : authority.substr(0, slash);

        const auto colon = authority.rfind(':');
        if (colon == std::string::npos) {
            return UpstreamTarget{authority, "80", path};
        }
        return UpstreamTarget{authority.substr(0, colon), authority.substr(colon + 1), path};
    }

    const std::string hostHeader = request[http::field::host].to_string();
    if (hostHeader.empty()) {
        return std::nullopt;
    }

    const auto colon = hostHeader.rfind(':');
    if (colon == std::string::npos) {
        return UpstreamTarget{hostHeader, "80", rawTarget};
    }
    return UpstreamTarget{hostHeader.substr(0, colon), hostHeader.substr(colon + 1), rawTarget};
}

class ProxySession : public std::enable_shared_from_this<ProxySession>
{
public:
    ProxySession(tcp::socket socket,
                 ProxyCoreConfig config,
                 ProxyCoreCallbacks callbacks)
        : clientSocket_(std::move(socket))
        , resolver_(clientSocket_.get_executor())
        , upstreamSocket_(clientSocket_.get_executor())
        , strand_(net::make_strand(clientSocket_.get_executor()))
        , config_(std::move(config))
        , callbacks_(std::move(callbacks))
    {
    }

    void start()
    {
        dispatch([self = shared_from_this()] {
            self->readClientRequest();
        });
    }

    void stop()
    {
        dispatch([self = shared_from_this()] {
            self->closed_ = true;
            error_code ignored;
            self->clientSocket_.shutdown(tcp::socket::shutdown_both, ignored);
            self->clientSocket_.close(ignored);
            self->upstreamSocket_.shutdown(tcp::socket::shutdown_both, ignored);
            self->upstreamSocket_.close(ignored);
        });
    }

private:
    void dispatch(std::function<void()> fn)
    {
        net::dispatch(strand_, std::move(fn));
    }

    void readClientRequest()
    {
        if (closed_) {
            return;
        }

        requestParser_.emplace();
        requestParser_->body_limit(8 * 1024 * 1024);
        http::async_read(clientSocket_,
                         clientBuffer_,
                         *requestParser_,
                         net::bind_executor(
                             strand_,
                             [self = shared_from_this()](const error_code &ec, std::size_t bytesRead) {
                                 self->onClientRequest(ec, bytesRead);
                             }));
    }

    void onClientRequest(const error_code &ec, std::size_t bytesRead)
    {
        if (closed_) {
            return;
        }
        if (ec) {
            logDebug("istemci istegi okunamadi: " + ec.message());
            stop();
            return;
        }

        inboundBytes_ += bytesRead;
        request_ = requestParser_->release();
        requestParser_.reset();

        if (request_.method() == http::verb::connect) {
            const auto target = parseConnectTarget(std::string(request_.target()));
            if (!target) {
                writeSimpleResponse(http::status::bad_request, "Gecersiz CONNECT hedefi");
                return;
            }
            if (config_.localOnlyTargets && !isAllowedLocalHost(target->host)) {
                writeSimpleResponse(http::status::forbidden, "Sadece localhost hedefleri izinli");
                return;
            }

            upstreamTarget_ = *target;
            logInfo("CONNECT " + target->host + ":" + target->port);
            resolveAndConnectUpstream();
            return;
        }

        const auto target = parseHttpTarget(request_);
        if (!target) {
            writeSimpleResponse(http::status::bad_request, "Hedef cozulmedi");
            return;
        }
        if (config_.localOnlyTargets && !isAllowedLocalHost(target->host)) {
            writeSimpleResponse(http::status::forbidden, "Sadece localhost hedefleri izinli");
            return;
        }

        upstreamTarget_ = *target;
        request_.target(upstreamTarget_->requestTarget);
        request_.prepare_payload();
        logInfo(std::string(request_.method_string()) + " " + upstreamTarget_->host + upstreamTarget_->requestTarget);
        resolveAndConnectUpstream();
    }

    void resolveAndConnectUpstream()
    {
        resolver_.async_resolve(
            upstreamTarget_->host,
            upstreamTarget_->port,
            net::bind_executor(
                strand_,
                [self = shared_from_this()](const error_code &ec, const tcp::resolver::results_type &results) {
                    self->onResolved(ec, results);
                }));
    }

    void onResolved(const error_code &ec, const tcp::resolver::results_type &results)
    {
        if (closed_) {
            return;
        }
        if (ec) {
            writeSimpleResponse(http::status::bad_gateway, "DNS cozumleme hatasi");
            return;
        }

        net::async_connect(upstreamSocket_,
                           results.begin(),
                           results.end(),
                           net::bind_executor(
                               strand_,
                               [self = shared_from_this()](const error_code &connectEc, const tcp::endpoint &endpoint) {
                                   self->onUpstreamConnected(connectEc, endpoint);
                               }));
    }

    void onUpstreamConnected(const error_code &ec, const tcp::endpoint &endpoint)
    {
        if (closed_) {
            return;
        }
        if (ec) {
            writeSimpleResponse(http::status::bad_gateway, "Upstream baglanti kurulamadi");
            return;
        }

        logDebug("upstream baglandi: " + toString(endpoint));

        if (request_.method() == http::verb::connect) {
            sendConnectEstablished();
            return;
        }

        requestSerializer_.emplace(request_);
        http::async_write(upstreamSocket_,
                          *requestSerializer_,
                          net::bind_executor(
                              strand_,
                              [self = shared_from_this()](const error_code &writeEc, std::size_t bytesWritten) {
                                  self->onHttpRequestForwarded(writeEc, bytesWritten);
                              }));
    }

    void onHttpRequestForwarded(const error_code &ec, std::size_t bytesWritten)
    {
        if (closed_) {
            return;
        }
        if (ec) {
            stop();
            return;
        }

        outboundBytes_ += bytesWritten;
        requestSerializer_.reset();
        responseParser_.emplace();
        responseParser_->body_limit(16 * 1024 * 1024);
        http::async_read(upstreamSocket_,
                         upstreamHttpBuffer_,
                         *responseParser_,
                         net::bind_executor(
                             strand_,
                             [self = shared_from_this()](const error_code &readEc, std::size_t bytesRead) {
                                 self->onHttpResponseRead(readEc, bytesRead);
                             }));
    }

    void onHttpResponseRead(const error_code &ec, std::size_t bytesRead)
    {
        if (closed_) {
            return;
        }
        if (ec) {
            stop();
            return;
        }

        inboundBytes_ += bytesRead;
        response_ = responseParser_->release();
        responseParser_.reset();
        responseSerializer_.emplace(response_);
        http::async_write(clientSocket_,
                          *responseSerializer_,
                          net::bind_executor(
                              strand_,
                              [self = shared_from_this()](const error_code &writeEc, std::size_t bytesWritten) {
                                  self->onHttpResponseForwarded(writeEc, bytesWritten);
                              }));
    }

    void onHttpResponseForwarded(const error_code &ec, std::size_t bytesWritten)
    {
        if (closed_) {
            return;
        }
        outboundBytes_ += bytesWritten;
        logInfo("HTTP tamamlandi | in=" + std::to_string(inboundBytes_) + "B out=" + std::to_string(outboundBytes_) + "B");
        stop();
    }

    void sendConnectEstablished()
    {
        connectResponse_ = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: PenguFoce\r\n\r\n";
        net::async_write(clientSocket_,
                         net::buffer(connectResponse_),
                         net::bind_executor(
                             strand_,
                             [self = shared_from_this()](const error_code &ec, std::size_t bytesWritten) {
                                 self->onConnectEstablished(ec, bytesWritten);
                             }));
    }

    void onConnectEstablished(const error_code &ec, std::size_t bytesWritten)
    {
        if (closed_) {
            return;
        }
        if (ec) {
            stop();
            return;
        }

        outboundBytes_ += bytesWritten;
        startTunnel();
    }

    void startTunnel()
    {
        clientReadPaused_ = false;
        upstreamReadPaused_ = false;
        clientWriteInProgress_ = false;
        upstreamWriteInProgress_ = false;
        readClientTunnel();
        readUpstreamTunnel();
    }

    void readClientTunnel()
    {
        if (closed_ || clientReadPaused_ || clientWriteInProgress_) {
            return;
        }
        if (clientToUpstream_.size() >= config_.maxTunnelBufferBytes) {
            clientReadPaused_ = true;
            return;
        }

        clientSocket_.async_read_some(
            clientToUpstream_.prepare(config_.tunnelChunkBytes),
            net::bind_executor(
                strand_,
                [self = shared_from_this()](const error_code &ec, std::size_t bytesRead) {
                    self->onClientTunnelRead(ec, bytesRead);
                }));
    }

    void onClientTunnelRead(const error_code &ec, std::size_t bytesRead)
    {
        if (closed_) {
            return;
        }
        if (ec) {
            stop();
            return;
        }

        inboundBytes_ += bytesRead;
        clientToUpstream_.commit(bytesRead);
        writeUpstreamTunnel();
        readClientTunnel();
    }

    void writeUpstreamTunnel()
    {
        if (closed_ || upstreamWriteInProgress_ || clientToUpstream_.size() == 0) {
            return;
        }

        upstreamWriteInProgress_ = true;
        net::async_write(
            upstreamSocket_,
            clientToUpstream_.data(),
            net::bind_executor(
                strand_,
                [self = shared_from_this()](const error_code &ec, std::size_t bytesWritten) {
                    self->onUpstreamTunnelWrite(ec, bytesWritten);
                }));
    }

    void onUpstreamTunnelWrite(const error_code &ec, std::size_t bytesWritten)
    {
        upstreamWriteInProgress_ = false;
        if (closed_) {
            return;
        }
        if (ec) {
            stop();
            return;
        }

        outboundBytes_ += bytesWritten;
        clientToUpstream_.consume(bytesWritten);
        if (clientReadPaused_ && clientToUpstream_.size() < (config_.maxTunnelBufferBytes / 2)) {
            clientReadPaused_ = false;
        }
        writeUpstreamTunnel();
        readClientTunnel();
    }

    void readUpstreamTunnel()
    {
        if (closed_ || upstreamReadPaused_ || clientWriteInProgress_) {
            return;
        }
        if (upstreamToClient_.size() >= config_.maxTunnelBufferBytes) {
            upstreamReadPaused_ = true;
            return;
        }

        upstreamSocket_.async_read_some(
            upstreamToClient_.prepare(config_.tunnelChunkBytes),
            net::bind_executor(
                strand_,
                [self = shared_from_this()](const error_code &ec, std::size_t bytesRead) {
                    self->onUpstreamTunnelRead(ec, bytesRead);
                }));
    }

    void onUpstreamTunnelRead(const error_code &ec, std::size_t bytesRead)
    {
        if (closed_) {
            return;
        }
        if (ec) {
            stop();
            return;
        }

        inboundBytes_ += bytesRead;
        upstreamToClient_.commit(bytesRead);
        writeClientTunnel();
        readUpstreamTunnel();
    }

    void writeClientTunnel()
    {
        if (closed_ || clientWriteInProgress_ || upstreamToClient_.size() == 0) {
            return;
        }

        clientWriteInProgress_ = true;
        net::async_write(
            clientSocket_,
            upstreamToClient_.data(),
            net::bind_executor(
                strand_,
                [self = shared_from_this()](const error_code &ec, std::size_t bytesWritten) {
                    self->onClientTunnelWrite(ec, bytesWritten);
                }));
    }

    void onClientTunnelWrite(const error_code &ec, std::size_t bytesWritten)
    {
        clientWriteInProgress_ = false;
        if (closed_) {
            return;
        }
        if (ec) {
            stop();
            return;
        }

        outboundBytes_ += bytesWritten;
        upstreamToClient_.consume(bytesWritten);
        if (upstreamReadPaused_ && upstreamToClient_.size() < (config_.maxTunnelBufferBytes / 2)) {
            upstreamReadPaused_ = false;
        }
        writeClientTunnel();
        readUpstreamTunnel();
    }

    void writeSimpleResponse(http::status status, const std::string &message)
    {
        auto response = std::make_shared<http::response<http::string_body>>(status, 11);
        response->set(http::field::server, "PenguFoce");
        response->set(http::field::content_type, "text/plain; charset=utf-8");
        response->body() = message;
        response->prepare_payload();
        http::async_write(
            clientSocket_,
            *response,
            net::bind_executor(
                strand_,
                [self = shared_from_this(), response](const error_code &, std::size_t) {
                    self->stop();
                }));
    }

    void logInfo(const std::string &message)
    {
        if (callbacks_.onInfo) {
            callbacks_.onInfo(message);
        }
    }

    void logDebug(const std::string &message)
    {
        if (callbacks_.onDebug) {
            callbacks_.onDebug(message);
        }
    }

    tcp::socket clientSocket_;
    tcp::resolver resolver_;
    tcp::socket upstreamSocket_;
    net::strand<net::any_io_executor> strand_;
    ProxyCoreConfig config_;
    ProxyCoreCallbacks callbacks_;
    beast::flat_buffer clientBuffer_;
    beast::flat_buffer upstreamHttpBuffer_;
    beast::flat_buffer clientToUpstream_;
    beast::flat_buffer upstreamToClient_;
    std::optional<http::request_parser<http::dynamic_body>> requestParser_;
    std::optional<http::response_parser<http::dynamic_body>> responseParser_;
    http::request<http::dynamic_body> request_;
    http::response<http::dynamic_body> response_;
    std::optional<http::serializer<false, http::dynamic_body>> requestSerializer_;
    std::optional<http::serializer<false, http::dynamic_body>> responseSerializer_;
    std::optional<UpstreamTarget> upstreamTarget_;
    std::string connectResponse_;
    std::size_t inboundBytes_ = 0;
    std::size_t outboundBytes_ = 0;
    bool closed_ = false;
    bool clientReadPaused_ = false;
    bool upstreamReadPaused_ = false;
    bool clientWriteInProgress_ = false;
    bool upstreamWriteInProgress_ = false;
};

class Listener : public std::enable_shared_from_this<Listener>
{
public:
    Listener(net::io_context &ioc, ProxyCoreConfig config, ProxyCoreCallbacks callbacks)
        : acceptor_(ioc)
        , socket_(ioc)
        , config_(std::move(config))
        , callbacks_(std::move(callbacks))
    {
    }

    bool start()
    {
        error_code ec;
        const auto address = net::ip::make_address(config_.bindHost, ec);
        if (ec) {
            logError("bind host gecersiz: " + ec.message());
            return false;
        }

        tcp::endpoint endpoint(address, config_.bindPort);
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            logError("acceptor open basarisiz: " + ec.message());
            return false;
        }
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        acceptor_.bind(endpoint, ec);
        if (ec) {
            logError("bind basarisiz: " + ec.message());
            return false;
        }
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            logError("listen basarisiz: " + ec.message());
            return false;
        }

        logInfo("Proxy core " + config_.bindHost + ":" + std::to_string(config_.bindPort) + " dinliyor");
        doAccept();
        return true;
    }

    void stop()
    {
        error_code ignored;
        acceptor_.close(ignored);
        socket_.close(ignored);
    }

private:
    void doAccept()
    {
        acceptor_.async_accept(
            socket_,
            [self = shared_from_this()](const error_code &ec) {
                self->onAccept(ec);
            });
    }

    void onAccept(const error_code &ec)
    {
        if (!acceptor_.is_open()) {
            return;
        }

        if (!ec) {
            std::make_shared<ProxySession>(std::move(socket_), config_, callbacks_)->start();
        } else {
            logWarning("accept hatasi: " + ec.message());
        }

        doAccept();
    }

    void logInfo(const std::string &message)
    {
        if (callbacks_.onInfo) {
            callbacks_.onInfo(message);
        }
    }

    void logWarning(const std::string &message)
    {
        if (callbacks_.onWarning) {
            callbacks_.onWarning(message);
        }
    }

    void logError(const std::string &message)
    {
        if (callbacks_.onError) {
            callbacks_.onError(message);
        }
    }

    tcp::acceptor acceptor_;
    tcp::socket socket_;
    ProxyCoreConfig config_;
    ProxyCoreCallbacks callbacks_;
};

class ProxyCore::Impl
{
public:
    Impl(ProxyCoreConfig config, ProxyCoreCallbacks callbacks)
        : config_(std::move(config))
        , callbacks_(std::move(callbacks))
    {
    }

    bool start()
    {
        if (running_.exchange(true)) {
            return true;
        }

        const std::size_t desiredThreads = config_.threadCount == 0
                                               ? std::max<std::size_t>(2, std::thread::hardware_concurrency())
                                               : config_.threadCount;

        listener_ = std::make_shared<Listener>(ioc_, config_, callbacks_);
        if (!listener_->start()) {
            running_ = false;
            listener_.reset();
            return false;
        }

        workGuard_.emplace(net::make_work_guard(ioc_));
        threads_.reserve(desiredThreads);
        for (std::size_t i = 0; i < desiredThreads; ++i) {
            threads_.emplace_back([this]() {
                ioc_.run();
            });
        }
        return true;
    }

    void stop()
    {
        if (!running_.exchange(false)) {
            return;
        }

        if (listener_) {
            listener_->stop();
        }
        workGuard_.reset();
        ioc_.stop();
        for (std::thread &thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        threads_.clear();
        listener_.reset();
        ioc_.restart();
    }

    bool isRunning() const noexcept
    {
        return running_.load();
    }

private:
    ProxyCoreConfig config_;
    ProxyCoreCallbacks callbacks_;
    net::io_context ioc_;
    std::optional<net::executor_work_guard<net::io_context::executor_type>> workGuard_;
    std::shared_ptr<Listener> listener_;
    std::vector<std::thread> threads_;
    std::atomic<bool> running_{false};
};

} // namespace

ProxyCore::ProxyCore(ProxyCoreConfig config, ProxyCoreCallbacks callbacks)
    : m_impl(std::make_unique<Impl>(std::move(config), std::move(callbacks)))
{
}

ProxyCore::~ProxyCore()
{
    stop();
}

bool ProxyCore::start()
{
    return m_impl->start();
}

void ProxyCore::stop()
{
    m_impl->stop();
}

bool ProxyCore::isRunning() const noexcept
{
    return m_impl->isRunning();
}

} // namespace pengufoce::proxy
