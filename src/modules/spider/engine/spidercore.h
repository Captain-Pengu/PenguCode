#pragma once

#include "modules/spider/engine/htmlextractor.h"

#include <QByteArray>
#include <QDateTime>
#include <QStringList>
#include <QUrl>
#include <QVariantMap>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

struct SpiderFetchResult
{
    QUrl url;
    QUrl finalUrl;
    QUrl redirectTarget;
    int statusCode = 0;
    QString contentType;
    QVariantMap responseHeaders;
    QByteArray body;
    QString errorString;
    QString pageTitle;
    QStringList headingHints;

    bool ok() const { return errorString.isEmpty() && statusCode > 0 && statusCode < 500; }
};

struct SpiderDiscoveredEndpoint
{
    QUrl url;
    QString kind;
    QString source;
    int depth = 0;
    int statusCode = 0;
    QString contentType;
    QString sessionState;
    QString finalUrl;
    QString pageTitle;
};

struct SpiderDiscoveredParameter
{
    QString name;
    QUrl url;
    QString origin;
};

struct SpiderDiscoveredAsset
{
    QString kind;
    QString value;
    QString source;
};

struct SpiderAuthProfile
{
    struct Step {
        QString label;
        QUrl url;
        QString method = QStringLiteral("POST");
        QVariantMap fields;
        QVariantMap headers;
        bool fetchFormFirst = true;
        bool inheritCookies = true;
        bool optional = false;
        int pauseAfterMs = 0;
        int expectedStatusCode = -1;
        QString expectedUrlContains;
        QString expectedRedirectContains;
        QString expectedRedirectNotContains;
        QString expectedBodyContains;
        QString expectedHeaderContains;
        QString expectedCookieName;
        bool expectNotLogin = false;
    };

    bool enabled = false;
    QUrl loginUrl;
    QString username;
    QString password;
    QString usernameField = QStringLiteral("username");
    QString passwordField = QStringLiteral("password");
    QString csrfField = QStringLiteral("_token");
    QVariantMap extraFields;
    std::vector<Step> workflowSteps;
};

struct SpiderRenderResult
{
    bool available = false;
    bool ok = false;
    QString backendName;
    QString errorString;
    QString renderedHtml;
    QString debuggerHttpUrl;
    QString browserWsUrl;
    QString pageWsUrl;
};

struct SpiderRunOptions
{
    int maxPages = 40;
    int maxDepth = 4;
    int timeoutMs = 4000;
    int renderTimeoutMs = 6000;
    int maxInFlight = 24;
    int maxRetries = 2;
    int politenessDelayMs = 90;
    int maxWorkflowActions = 8;
    bool allowSubdomains = false;
    bool enableHeadlessRender = false;
    bool enableBrowserAutomation = false;
    bool followRenderedRoutes = true;
    bool enableSafeWorkflowReplay = true;
    QStringList includePatterns;
    QStringList excludePatterns;
    QStringList ignoredExtensions;
    SpiderAuthProfile auth;
};

class ISpiderFetcher
{
public:
    virtual ~ISpiderFetcher() = default;
    virtual SpiderFetchResult fetch(const QUrl &url, int timeoutMs, const QVariantMap &headers = {}) = 0;
    virtual SpiderFetchResult submitForm(const QUrl &url, const QVariantMap &fields, int timeoutMs, const QVariantMap &headers = {}) = 0;
    virtual int cookieCount() const = 0;
    virtual QStringList cookieNames() const = 0;
};

class ISpiderAsyncFetcher
{
public:
    using FetchCallback = std::function<void(SpiderFetchResult)>;

    virtual ~ISpiderAsyncFetcher() = default;
    virtual void fetchAsync(const QUrl &url, int timeoutMs, const QVariantMap &headers, FetchCallback callback) = 0;
    virtual void cancelAll() = 0;
};

class ISpiderDomRenderer
{
public:
    virtual ~ISpiderDomRenderer() = default;
    virtual bool available() const = 0;
    virtual QString backendName() const = 0;
    virtual SpiderRenderResult render(const QUrl &url, int timeoutMs) = 0;
};

class SpiderThreadPool
{
public:
    SpiderThreadPool();
    ~SpiderThreadPool();

    void enqueue(std::function<void()> task);
    void clearPendingTasks();
    void waitUntilIdle();

private:
    void workerLoop();

    std::vector<std::thread> m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::condition_variable m_idleCv;
    bool m_stopping = false;
    std::atomic<int> m_activeTasks = 0;
};

class SpiderCore
{
public:
    using EventCallback = std::function<void(QString)>;
    using EndpointCallback = std::function<void(SpiderDiscoveredEndpoint)>;
    using ParameterCallback = std::function<void(SpiderDiscoveredParameter)>;
    using AssetCallback = std::function<void(SpiderDiscoveredAsset)>;
    using FinishedCallback = std::function<void()>;

    explicit SpiderCore(std::unique_ptr<ISpiderFetcher> fetcher,
                        std::unique_ptr<ISpiderDomRenderer> renderer = nullptr,
                        std::unique_ptr<ISpiderHtmlExtractor> htmlExtractor = nullptr);
    ~SpiderCore();

    SpiderCore(const SpiderCore &) = delete;
    SpiderCore &operator=(const SpiderCore &) = delete;

    void setEventCallback(EventCallback callback);
    void setEndpointCallback(EndpointCallback callback);
    void setParameterCallback(ParameterCallback callback);
    void setAssetCallback(AssetCallback callback);
    void setFinishedCallback(FinishedCallback callback);

    void start(const QUrl &seedUrl, const SpiderRunOptions &options = {});
    void stop();

    int visitedCount() const;
    int queuedCount() const;
    bool running() const;

    static std::vector<QUrl> extractLinks(const QString &html, const QUrl &baseUrl);
    static std::vector<QString> extractParameters(const QUrl &url);

private:
    struct QueueEntry {
        QUrl url;
        QString kind;
        QString source;
        QString requestMethod = QStringLiteral("GET");
        QVariantMap requestFields;
        QVariantMap requestHeaders;
        std::string requestKey;
        int depth = 0;
        int retryCount = 0;
        qint64 earliestStartMs = 0;
    };

    void reset();
    void enqueue(const QUrl &url, const QString &kind, const QString &source, int depth = 0);
    void enqueueRequest(const QUrl &url,
                        const QString &kind,
                        const QString &source,
                        int depth,
                        const QString &requestMethod,
                        const QVariantMap &requestFields = {},
                        const QVariantMap &requestHeaders = {});
    void scheduleMore();
    void processOne(QueueEntry entry);
    void consumeFetchResult(QueueEntry entry, SpiderFetchResult result);
    void processHtml(const QUrl &url, const QString &html, int depth);
    void processJavaScript(const QUrl &url, const QString &body, int depth);
    void processRenderedWorkflowCandidates(const QUrl &pageUrl,
                                           const QString &html,
                                           int depth,
                                           const QString &sessionState);
    void processRobots(const QUrl &url, const QString &text);
    void processSitemap(const QUrl &url, const QString &text);
    void processManifest(const QUrl &url, const QString &text, int depth);
    bool authenticateIfNeeded();
    void captureAnonymousSurfaceBaseline();
    bool markVisited(const QueueEntry &entry);
    bool alreadyQueuedOrVisited(const QUrl &url,
                                const QString &requestMethod = QStringLiteral("GET"),
                                const QVariantMap &requestFields = {}) const;
    bool isInScope(const QUrl &url) const;
    bool matchesScopeRules(const QUrl &url) const;
    bool shouldCrawlByExtension(const QUrl &url, const QString &kind) const;
    QString sessionStateForUrl(const QUrl &url) const;
    std::string keyForUrl(const QUrl &url) const;
    std::string keyForRequest(const QUrl &url,
                              const QString &requestMethod,
                              const QVariantMap &requestFields) const;
    void finishIfDone();
    void notifyFetchStateChanged();
    void emitEvent(const QString &message) const;
    void emitEndpoint(SpiderDiscoveredEndpoint endpoint) const;
    void emitParameter(SpiderDiscoveredParameter parameter) const;
    void emitAsset(SpiderDiscoveredAsset asset) const;

    std::unique_ptr<ISpiderFetcher> m_fetcher;
    std::unique_ptr<ISpiderDomRenderer> m_renderer;
    std::unique_ptr<ISpiderHtmlExtractor> m_htmlExtractor;
    SpiderThreadPool m_pool;
    mutable std::shared_mutex m_seenMutex;
    std::unordered_set<std::string> m_visited;
    std::unordered_set<std::string> m_enqueued;
    std::unordered_set<std::string> m_contentFingerprints;
    std::unordered_set<std::string> m_loginFingerprints;
    std::unordered_set<std::string> m_preAuthSurface;
    std::unordered_map<std::string, qint64> m_hostNextAllowedAt;
    std::unordered_map<std::string, int> m_hostPressureScore;
    std::queue<QueueEntry> m_queue;
    mutable std::mutex m_queueMutex;
    mutable std::mutex m_stateMutex;
    mutable std::mutex m_fetchDrainMutex;
    std::condition_variable m_fetchDrainCv;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopping{false};
    std::atomic<bool> m_authenticated{false};
    std::atomic<bool> m_wakeScheduled{false};
    std::atomic<int> m_activeFetches{0};
    std::atomic<int> m_activeProcessing{0};
    std::atomic<int> m_visitedCount{0};
    std::atomic<int> m_workflowActionsUsed{0};
    std::atomic<qint64> m_lastProgressMs{0};
    std::atomic<qint64> m_lastSchedulerLogMs{0};
    std::atomic<int> m_stallRecoveryCount{0};
    std::thread m_watchdogThread;
    SpiderRunOptions m_options;
    QUrl m_seedUrl;

    EventCallback m_eventCallback;
    EndpointCallback m_endpointCallback;
    ParameterCallback m_parameterCallback;
    AssetCallback m_assetCallback;
    FinishedCallback m_finishedCallback;
};

std::unique_ptr<ISpiderFetcher> createBestSpiderFetcher();
std::unique_ptr<ISpiderDomRenderer> createBestSpiderRenderer();
