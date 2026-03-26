#pragma once

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace pengufoce::proxy {

struct ProxyCoreConfig
{
    std::string bindHost = "127.0.0.1";
    unsigned short bindPort = 8080;
    std::size_t maxTunnelBufferBytes = 256 * 1024;
    std::size_t tunnelChunkBytes = 16 * 1024;
    std::size_t threadCount = 0;
    bool localOnlyTargets = true;
};

struct ProxyCoreCallbacks
{
    std::function<void(const std::string &)> onInfo;
    std::function<void(const std::string &)> onWarning;
    std::function<void(const std::string &)> onError;
    std::function<void(const std::string &)> onDebug;
};

class ProxyCore
{
public:
    ProxyCore(ProxyCoreConfig config, ProxyCoreCallbacks callbacks);
    ~ProxyCore();

    ProxyCore(const ProxyCore &) = delete;
    ProxyCore &operator=(const ProxyCore &) = delete;

    bool start();
    void stop();
    bool isRunning() const noexcept;

private:
    class Impl;

    std::unique_ptr<Impl> m_impl;
};

} // namespace pengufoce::proxy
