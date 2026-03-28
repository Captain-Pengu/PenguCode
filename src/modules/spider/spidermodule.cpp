#include "spidermodule.h"

#include "modules/spider/engine/spiderworkflow.h"
#include "modules/spider/engine/spiderscope.h"

#include "core/logging/logger.h"
#include "core/framework/moduleregistry.h"
#include "core/settings/settingsmanager.h"

#include <QMetaObject>
#include <QDateTime>
#include <QPointer>
#include <QRegularExpression>
#include <QSet>
#include <QUrlQuery>

namespace {

bool assetLooksLowSignal(const QString &kind, const QString &value)
{
    const QString trimmed = value.trimmed();
    if (trimmed.isEmpty()) {
        return true;
    }
    if (kind == QLatin1String("automation-live-title")) {
        return trimmed.compare(QStringLiteral("about:blank"), Qt::CaseInsensitive) == 0;
    }
    if (kind == QLatin1String("automation-live-action")) {
        return trimmed.size() < 18
            || trimmed == QLatin1String("a | text= | href= | onclick= | id= | class= | role=");
    }
    return false;
}

QSet<QString> endpointSignatureSet(const QVariantList &items)
{
    QSet<QString> set;
    for (const QVariant &value : items) {
        const QVariantMap row = value.toMap();
        set.insert(QStringLiteral("%1|%2").arg(row.value("kind").toString(), row.value("url").toString()));
    }
    return set;
}

QSet<QString> parameterSignatureSet(const QVariantList &items)
{
    QSet<QString> set;
    for (const QVariant &value : items) {
        const QVariantMap row = value.toMap();
        set.insert(QStringLiteral("%1|%2").arg(row.value("name").toString(), row.value("url").toString()));
    }
    return set;
}

QSet<QString> assetSignatureSet(const QVariantList &items)
{
    QSet<QString> set;
    for (const QVariant &value : items) {
        const QVariantMap row = value.toMap();
        set.insert(QStringLiteral("%1|%2").arg(row.value("kind").toString(), row.value("value").toString()));
    }
    return set;
}

int segmentEntryCount(const QVariantMap &segments, const QString &key)
{
    return segments.value(key).toList().size();
}

QString formatSegmentDiffSummary(const QVariantMap &previousBreakdown,
                                 const QVariantMap &currentBreakdown,
                                 const QVariantMap &previousSegments,
                                 const QVariantMap &currentSegments)
{
    const QStringList breakdownKeys = {
        QStringLiteral("auth"),
        QStringLiteral("admin"),
        QStringLiteral("upload"),
        QStringLiteral("render"),
        QStringLiteral("automation"),
        QStringLiteral("secret"),
        QStringLiteral("delta"),
        QStringLiteral("protected"),
        QStringLiteral("missing")
    };
    QStringList coverageParts;
    for (const QString &key : breakdownKeys) {
        const int delta = currentBreakdown.value(key).toInt() - previousBreakdown.value(key).toInt();
        if (delta != 0) {
            coverageParts << QStringLiteral("%1 %2%3")
                                 .arg(key,
                                      delta > 0 ? QStringLiteral("+") : QString(),
                                      QString::number(delta));
        }
    }

    const QStringList segmentKeys = {
        QStringLiteral("auth"),
        QStringLiteral("admin"),
        QStringLiteral("upload"),
        QStringLiteral("render"),
        QStringLiteral("automation"),
        QStringLiteral("secret")
    };
    QStringList segmentParts;
    for (const QString &key : segmentKeys) {
        const int delta = segmentEntryCount(currentSegments, key) - segmentEntryCount(previousSegments, key);
        if (delta != 0) {
            segmentParts << QStringLiteral("%1 %2%3")
                                .arg(key,
                                     delta > 0 ? QStringLiteral("+") : QString(),
                                     QString::number(delta));
        }
    }

    if (coverageParts.isEmpty() && segmentParts.isEmpty()) {
        return QObject::tr("Segmentlerde degisim yok");
    }

    QStringList summary;
    if (!coverageParts.isEmpty()) {
        summary << QObject::tr("Kapsam: %1").arg(coverageParts.join(", "));
    }
    if (!segmentParts.isEmpty()) {
        summary << QObject::tr("Kritik segment: %1").arg(segmentParts.join(", "));
    }
    return summary.join(QStringLiteral(" | "));
}

void appendTimelineEvent(QVariantList &timeline, const QString &stage, const QString &title, const QString &detail)
{
    timeline.prepend(QVariantMap{
        {"time", QDateTime::currentDateTime().toString("HH:mm:ss")},
        {"stage", stage},
        {"title", title},
        {"detail", detail}
    });
    while (timeline.size() > 40) {
        timeline.removeLast();
    }
}

}

SpiderModule::SpiderModule(QObject *parent)
    : ModuleInterface(parent)
{
}

SpiderModule::~SpiderModule()
{
    m_terminalTransition = true;
    m_scanning = false;
    if (m_idleGuardTimer) {
        m_idleGuardTimer->stop();
        m_idleGuardTimer->disconnect(this);
    }
    destroyCoreAsync();
}

void SpiderModule::createCore()
{
    QPointer<SpiderModule> self(this);
    m_core = std::make_unique<SpiderCore>(createBestSpiderFetcher(), createBestSpiderRenderer());
    m_core->setEventCallback([self](QString message) {
        if (!self) {
            return;
        }
        QMetaObject::invokeMethod(self, [self, message = std::move(message)]() {
            if (!self) {
                return;
            }
            if (!self->m_scanning && !message.startsWith(QStringLiteral("SpiderCore tamamlandi."))) {
                return;
            }
            if (!message.startsWith(QStringLiteral("[scheduler]"))) {
                self->bumpIdleGuard();
            }
            emit self->crawlEvent(message);
        }, Qt::QueuedConnection);
    });
    m_core->setEndpointCallback([self](SpiderDiscoveredEndpoint endpoint) {
        if (!self) {
            return;
        }
        QMetaObject::invokeMethod(self, [self, endpoint = std::move(endpoint)]() {
            if (!self || !self->m_scanning) {
                return;
            }
            self->recordEndpoint(endpoint.url,
                                 endpoint.kind,
                                 endpoint.source,
                                 endpoint.depth,
                                 endpoint.statusCode,
                                 endpoint.contentType,
                                 endpoint.sessionState,
                                 endpoint.finalUrl,
                                 endpoint.pageTitle);
        }, Qt::QueuedConnection);
    });
    m_core->setParameterCallback([self](SpiderDiscoveredParameter parameter) {
        if (!self) {
            return;
        }
        QMetaObject::invokeMethod(self, [self, parameter = std::move(parameter)]() {
            if (!self || !self->m_scanning) {
                return;
            }
            self->recordParameter(parameter.name, parameter.url, parameter.origin);
        }, Qt::QueuedConnection);
    });
    m_core->setAssetCallback([self](SpiderDiscoveredAsset asset) {
        if (!self) {
            return;
        }
        QMetaObject::invokeMethod(self, [self, asset = std::move(asset)]() {
            if (!self || !self->m_scanning) {
                return;
            }
            self->recordAsset(asset.kind, asset.value, asset.source);
        }, Qt::QueuedConnection);
    });
    m_core->setFinishedCallback([self]() {
        if (!self) {
            return;
        }
        QMetaObject::invokeMethod(self, &SpiderModule::handleCoreFinished, Qt::QueuedConnection);
    });
}

void SpiderModule::destroyCoreAsync()
{
    if (!m_core) {
        return;
    }
    auto core = std::move(m_core);
    core->setEventCallback({});
    core->setEndpointCallback({});
    core->setParameterCallback({});
    core->setAssetCallback({});
    core->setFinishedCallback({});
    core->stop();
    core.reset();
}

QString SpiderModule::id() const
{
    return "spider";
}

QString SpiderModule::name() const
{
    return "Spider";
}

QString SpiderModule::description() const
{
    return "Yuksek hizli web spider; robots, sitemap, link, form ve parametre kesfi yapar.";
}

QString SpiderModule::icon() const
{
    return "spider";
}

QUrl SpiderModule::pageSource() const
{
    return QUrl("qrc:/qt/qml/PenguFoce/qml/pages/SpiderPage.qml");
}

void SpiderModule::initialize(SettingsManager *settings, Logger *logger)
{
    m_settings = settings;
    m_logger = logger;
    reloadSettings();

    if (!m_idleGuardTimer) {
        m_idleGuardTimer = new QTimer(this);
        m_idleGuardTimer->setSingleShot(false);
        m_idleGuardTimer->setInterval(3000);
        connect(m_idleGuardTimer, &QTimer::timeout, this, [this]() {
            if (!m_scanning) {
                return;
            }

            const int queued = m_core ? m_core->queuedCount() : 0;
            const int visited = m_core ? m_core->visitedCount() : m_visitedCount;
            const bool coreRunning = m_core ? m_core->running() : false;
            const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
            const bool discoveryTimedOut = m_lastDiscoveryMs > 0 && (nowMs - m_lastDiscoveryMs) >= 12000;

            if (discoveryTimedOut) {
                forceFinishFromGuard(tr("yeni kesif verisi gelmedi"));
                return;
            }

            if (!coreRunning || (queued == 0 && visited == m_idleGuardLastVisited)) {
                forceFinishFromGuard(tr("cekirdek pasif veya kuyruk bos"));
                return;
            }

            if (visited == m_idleGuardLastVisited && queued == m_idleGuardLastQueued) {
                ++m_idleGuardStableTicks;
            } else {
                m_idleGuardStableTicks = 0;
            }
            m_idleGuardLastVisited = visited;
            m_idleGuardLastQueued = queued;

            if (m_idleGuardStableTicks < 5) {
                return;
            }

            const QString guardMessage = tr("[guard] Spider ilerlemiyor; eldeki verilerle sonlandiriliyor (gezilen: %1, kuyruk: %2)")
                                             .arg(visited)
                                             .arg(queued);
            emit crawlEvent(guardMessage);
            appendTimelineEvent(m_coverageTimeline,
                                tr("guard"),
                                tr("Idle guard devreye girdi"),
                                tr("Gezilen %1 | kuyruk %2").arg(visited).arg(queued));
            if (m_logger) {
                m_logger->warning(id(), guardMessage);
            }
            forceFinishFromGuard(tr("ilerleme algilanmadi"));
        });
    }

    if (m_logger) {
        m_logger->info(id(), "Spider module initialized");
    }
}

QVariantMap SpiderModule::defaultSettings() const
{
    return {
        {"targetUrl", "https://scanme.nmap.org"},
        {"maxPages", 40},
        {"maxDepth", 4},
        {"requestTimeoutMs", 4000},
        {"scanStage", 0},
        {"allowSubdomains", false},
        {"scopePreset", "dengeli"},
        {"includePatterns", ""},
        {"excludePatterns", "logout|signout"},
        {"loginUrl", ""},
        {"authUsername", ""},
        {"authPassword", ""},
        {"usernameField", "username"},
        {"passwordField", "password"},
        {"csrfField", "_token"},
        {"authWorkflow", ""}
    };
}

QVariantMap SpiderModule::saveState() const
{
    return {
        {"targetUrl", m_targetUrl},
        {"maxPages", m_maxPages},
        {"maxDepth", m_maxDepth},
        {"requestTimeoutMs", m_requestTimeoutMs},
        {"scanStage", m_scanStage},
        {"scopePreset", m_scopePreset},
        {"statusText", m_statusText},
        {"coverageScore", m_coverageScore},
        {"coverageSummary", m_coverageSummary},
        {"endpoints", m_endpoints},
        {"parameters", m_parameters},
        {"assets", m_assets}
    };
}

bool SpiderModule::loadState(const QVariantMap &state)
{
    m_targetUrl = state.value("targetUrl", m_targetUrl).toString();
    m_maxPages = state.value("maxPages", m_maxPages).toInt();
    m_maxDepth = state.value("maxDepth", m_maxDepth).toInt();
    m_requestTimeoutMs = state.value("requestTimeoutMs", m_requestTimeoutMs).toInt();
    m_scanStage = state.value("scanStage", m_scanStage).toInt();
    m_scopePreset = state.value("scopePreset", m_scopePreset).toString();
    m_statusText = state.value("statusText", m_statusText).toString();
    m_coverageScore = state.value("coverageScore", m_coverageScore).toInt();
    m_coverageSummary = state.value("coverageSummary", m_coverageSummary).toString();
    m_endpoints = state.value("endpoints").toList();
    m_parameters = state.value("parameters").toList();
    m_assets = state.value("assets").toList();
    emit statusChanged();
    emit resultsChanged();
    emit statsChanged();
    return true;
}

void SpiderModule::reset()
{
    stop();
    m_endpoints.clear();
    m_parameters.clear();
    m_assets.clear();
    m_statusText = tr("Hazir");
    emit statusChanged();
    emit resultsChanged();
}

QString SpiderModule::healthStatus() const
{
    if (m_scanning) {
        return QStringLiteral("BUSY");
    }
    if (m_assets.size() > 2000 || m_endpoints.size() > 2000) {
        return QStringLiteral("DEGRADED");
    }
    return QStringLiteral("HEALTHY");
}

QString SpiderModule::targetUrl() const
{
    return m_targetUrl;
}

int SpiderModule::maxPages() const
{
    return m_maxPages;
}

int SpiderModule::maxDepth() const
{
    return m_maxDepth;
}

int SpiderModule::requestTimeoutMs() const
{
    return m_requestTimeoutMs;
}

int SpiderModule::scanStage() const
{
    return m_scanStage;
}

bool SpiderModule::allowSubdomains() const
{
    return m_allowSubdomains;
}

QString SpiderModule::scopePreset() const
{
    return m_scopePreset;
}

QString SpiderModule::includePatterns() const
{
    return m_includePatterns;
}

QString SpiderModule::excludePatterns() const
{
    return m_excludePatterns;
}

QString SpiderModule::loginUrl() const
{
    return m_loginUrl;
}

QString SpiderModule::authUsername() const
{
    return m_authUsername;
}

QString SpiderModule::authPassword() const
{
    return m_authPassword;
}

QString SpiderModule::usernameField() const
{
    return m_usernameField;
}

QString SpiderModule::passwordField() const
{
    return m_passwordField;
}

QString SpiderModule::csrfField() const
{
    return m_csrfField;
}

QString SpiderModule::authWorkflow() const
{
    return m_authWorkflow;
}

bool SpiderModule::scanning() const
{
    return m_scanning;
}

QString SpiderModule::statusText() const
{
    return m_statusText;
}

int SpiderModule::visitedCount() const
{
    return m_visitedCount;
}

int SpiderModule::queuedCount() const
{
    return m_core ? m_core->queuedCount() : 0;
}

int SpiderModule::coverageScore() const
{
    return m_coverageScore;
}

QString SpiderModule::coverageSummary() const
{
    return m_coverageSummary;
}

QString SpiderModule::automationSafetyStatus() const
{
    return m_automationSafetyStatus;
}

QString SpiderModule::benchmarkSummary() const
{
    return m_benchmarkSummary;
}

QString SpiderModule::benchmarkDiffSummary() const
{
    return m_benchmarkDiffSummary;
}

QString SpiderModule::regressionSummary() const
{
    return m_regressionSummary;
}

QVariantMap SpiderModule::coverageBreakdown() const
{
    return m_coverageBreakdown;
}

QVariantMap SpiderModule::highValueSegments() const
{
    return m_highValueSegments;
}

QVariantList SpiderModule::benchmarkHistory() const
{
    return m_benchmarkHistory;
}

QVariantList SpiderModule::highValueTargets() const
{
    return m_highValueTargets;
}

QVariantList SpiderModule::coverageTimeline() const
{
    return m_coverageTimeline;
}

QVariantList SpiderModule::endpoints() const
{
    return m_endpoints;
}

QVariantList SpiderModule::parameters() const
{
    return m_parameters;
}

QVariantList SpiderModule::assets() const
{
    return m_assets;
}

void SpiderModule::reloadSettings()
{
    if (!m_settings) {
        return;
    }
    m_targetUrl = m_settings->value("modules/spider", "targetUrl", "https://scanme.nmap.org").toString();
    m_maxPages = m_settings->value("modules/spider", "maxPages", 40).toInt();
    m_maxDepth = m_settings->value("modules/spider", "maxDepth", 4).toInt();
    m_requestTimeoutMs = m_settings->value("modules/spider", "requestTimeoutMs", 4000).toInt();
    m_scanStage = m_settings->value("modules/spider", "scanStage", 0).toInt();
    m_allowSubdomains = m_settings->value("modules/spider", "allowSubdomains", false).toBool();
    m_scopePreset = m_settings->value("modules/spider", "scopePreset", "dengeli").toString();
    m_includePatterns = m_settings->value("modules/spider", "includePatterns", "").toString();
    m_excludePatterns = m_settings->value("modules/spider", "excludePatterns", "logout|signout").toString();
    m_loginUrl = m_settings->value("modules/spider", "loginUrl", "").toString();
    m_authUsername = m_settings->value("modules/spider", "authUsername", "").toString();
    m_authPassword = m_settings->value("modules/spider", "authPassword", "").toString();
    m_usernameField = m_settings->value("modules/spider", "usernameField", "username").toString();
    m_passwordField = m_settings->value("modules/spider", "passwordField", "password").toString();
    m_csrfField = m_settings->value("modules/spider", "csrfField", "_token").toString();
    m_authWorkflow = m_settings->value("modules/spider", "authWorkflow", "").toString();
    m_benchmarkSummary = m_settings->value("modules/spider_snapshot", "benchmarkSummary", "Benchmark ozeti hazir degil").toString();
    m_benchmarkDiffSummary = m_settings->value("modules/spider_snapshot", "benchmarkDiffSummary", "Kiyas ozeti hazir degil").toString();
    m_regressionSummary = m_settings->value("modules/spider_snapshot", "regressionSummary", "Regression ozeti hazir degil").toString();
    m_benchmarkHistory = m_settings->value("modules/spider_snapshot", "benchmarkHistory").toList();
    m_coverageBreakdown = m_settings->value("modules/spider_snapshot", "coverageBreakdown").toMap();
    m_highValueSegments = m_settings->value("modules/spider_snapshot", "highValueSegments").toMap();
    m_previousCoverageBreakdown = m_coverageBreakdown;
    m_previousHighValueSegments = m_highValueSegments;
}

void SpiderModule::start()
{
    if (m_scanning) {
        return;
    }
    if (!m_core) {
        createCore();
    }

    if (m_settings) {
        m_previousEndpoints = m_settings->value("modules/spider_snapshot", "endpoints").toList();
        m_previousParameters = m_settings->value("modules/spider_snapshot", "parameters").toList();
        m_previousAssets = m_settings->value("modules/spider_snapshot", "assets").toList();
        m_previousCoverageBreakdown = m_settings->value("modules/spider_snapshot", "coverageBreakdown").toMap();
        m_previousHighValueSegments = m_settings->value("modules/spider_snapshot", "highValueSegments").toMap();
    } else {
        m_previousEndpoints.clear();
        m_previousParameters.clear();
        m_previousAssets.clear();
        m_previousCoverageBreakdown.clear();
        m_previousHighValueSegments.clear();
    }

    m_endpointKeys.clear();
    m_parameterKeys.clear();
    m_assetKeys.clear();
    m_endpoints.clear();
    m_parameters.clear();
    m_assets.clear();
    m_visitedCount = 0;
    m_terminalTransition = false;
    m_coverageScore = 0;
    m_coverageSummary = tr("Tarama baslatildi, yuzey puani hesaplaniyor");
    m_benchmarkSummary = tr("Benchmark hazirlaniyor");
    m_benchmarkDiffSummary = tr("Kiyas hazirlaniyor");
    m_regressionSummary = tr("Regression hazirlaniyor");
    m_coverageBreakdown.clear();
    m_highValueTargets.clear();
    m_coverageTimeline.clear();
    m_scanTimer.restart();
    m_lastDiscoveryMs = QDateTime::currentMSecsSinceEpoch();
    m_idleGuardLastVisited = -1;
    m_idleGuardLastQueued = -1;
    m_idleGuardStableTicks = 0;
    appendTimelineEvent(m_coverageTimeline,
                        tr("baslangic"),
                        tr("Spider basladi"),
                        tr("Hedef: %1 | profil: %2").arg(m_targetUrl, m_scopePreset));
    persistSnapshot();
    m_scanning = true;
    m_statusText = tr("Spider calisiyor");
    bumpIdleGuard();
    emit scanningChanged();
    emit statusChanged();
    emit resultsChanged();
    emit statsChanged();

    if (m_logger) {
        m_logger->info(id(), QString("Spider baslatildi: %1").arg(m_targetUrl));
    }

    SpiderRunOptions options;
    options.maxPages = m_maxPages;
    options.maxDepth = m_maxDepth;
    options.timeoutMs = m_requestTimeoutMs;
    options.renderTimeoutMs = qMax(4000, m_requestTimeoutMs + 1800);
    options.maxInFlight = 24;
    options.maxRetries = 2;
    options.politenessDelayMs = 90;
    options.maxWorkflowActions = 8;
    options.enableSafeWorkflowReplay = (m_scanStage >= 2);
    options.allowSubdomains = m_allowSubdomains;
    if (m_scanStage <= 0) {
        options.maxPages = qMin(options.maxPages, 60);
        options.maxDepth = qMin(options.maxDepth, 3);
        options.enableHeadlessRender = false;
        options.enableBrowserAutomation = false;
        options.followRenderedRoutes = false;
        options.maxInFlight = 12;
        options.maxRetries = 1;
        options.politenessDelayMs = 140;
        options.maxWorkflowActions = 0;
        options.enableSafeWorkflowReplay = false;
    } else if (m_scanStage == 1) {
        options.maxPages = qMin(qMax(options.maxPages, 80), 100);
        options.maxDepth = qMin(qMax(options.maxDepth, 4), 5);
        options.enableHeadlessRender = false;
        options.enableBrowserAutomation = false;
        options.followRenderedRoutes = false;
        options.maxInFlight = 16;
        options.maxRetries = 2;
        options.politenessDelayMs = 110;
        options.maxWorkflowActions = 0;
        options.enableSafeWorkflowReplay = false;
    } else if (m_scopePreset == QLatin1String("guvenli")) {
        options.maxPages = qMin(options.maxPages, 70);
        options.maxDepth = qMin(options.maxDepth, 4);
        options.timeoutMs = qMax(options.timeoutMs, 2800);
        options.enableHeadlessRender = false;
        options.enableBrowserAutomation = false;
        options.followRenderedRoutes = false;
        options.maxInFlight = 12;
        options.maxRetries = 1;
        options.politenessDelayMs = 140;
        options.maxWorkflowActions = 2;
        options.enableSafeWorkflowReplay = false;
        options.ignoredExtensions = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "eot", "mp4", "mp3", "avi", "zip", "rar", "7z", "pdf", "map", "css", "webmanifest"};
    } else if (m_scopePreset == QLatin1String("agresif")) {
        options.maxPages = qMax(options.maxPages, 120);
        options.maxDepth = qMax(options.maxDepth, 5);
        options.timeoutMs = qMin(options.timeoutMs, 2200);
        options.enableHeadlessRender = true;
        options.enableBrowserAutomation = true;
        options.followRenderedRoutes = true;
        options.renderTimeoutMs = qMax(5000, options.renderTimeoutMs);
        options.maxInFlight = 48;
        options.maxRetries = 3;
        options.politenessDelayMs = 50;
        options.maxWorkflowActions = 16;
        options.enableSafeWorkflowReplay = true;
        options.ignoredExtensions = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "eot", "mp4", "mp3", "avi", "zip", "rar", "7z", "pdf", "map", "css", "webmanifest"};
    } else {
        options.maxPages = qBound(60, options.maxPages, 100);
        options.maxDepth = qBound(3, options.maxDepth, 5);
        options.timeoutMs = qBound(1800, options.timeoutMs, 3200);
        options.enableHeadlessRender = true;
        options.enableBrowserAutomation = true;
        options.followRenderedRoutes = true;
        options.maxInFlight = 24;
        options.maxRetries = 2;
        options.politenessDelayMs = 90;
        options.maxWorkflowActions = 8;
        options.enableSafeWorkflowReplay = true;
        options.ignoredExtensions = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "eot", "mp4", "mp3", "avi", "zip", "rar", "7z", "pdf", "map", "css", "webmanifest"};
    }
    if (!m_includePatterns.trimmed().isEmpty()) {
        options.includePatterns = m_includePatterns.split('\n', Qt::SkipEmptyParts);
    }
    const QString effectiveExcludePatterns = mergeSpiderExcludePatterns(m_excludePatterns, m_scopePreset);
    if (!effectiveExcludePatterns.trimmed().isEmpty()) {
        options.excludePatterns = effectiveExcludePatterns.split('\n', Qt::SkipEmptyParts);
    }
    if (!m_loginUrl.trimmed().isEmpty() && !m_authUsername.trimmed().isEmpty()) {
        options.auth.enabled = true;
        options.auth.loginUrl = QUrl::fromUserInput(m_loginUrl);
        options.auth.username = m_authUsername;
        options.auth.password = m_authPassword;
        options.auth.usernameField = m_usernameField;
        options.auth.passwordField = m_passwordField;
        options.auth.csrfField = m_csrfField;
        options.auth.workflowSteps = parseSpiderWorkflowSteps(m_authWorkflow);
    }

    const QUrl targetUrl = QUrl::fromUserInput(m_targetUrl);
    const bool localLabTarget = isLocalLabTarget(targetUrl);
    if (!localLabTarget) {
        options.enableSafeWorkflowReplay = false;
        options.maxWorkflowActions = 0;
    }
    if (options.enableHeadlessRender && !localLabTarget) {
        options.enableHeadlessRender = false;
        appendTimelineEvent(m_coverageTimeline,
                            tr("guvenlik"),
                            tr("Render korumasi aktif"),
                            tr("Hedef yerel lab disi oldugu icin headless render kapatildi"));
    }
    if (options.enableBrowserAutomation && !localLabTarget) {
        options.enableBrowserAutomation = false;
        m_automationSafetyStatus = tr("Public hedefte render ve browser automation kapali; yalnizca yerel lab hedeflerinde acilir");
        appendTimelineEvent(m_coverageTimeline,
                            tr("guvenlik"),
                            tr("Automation korumasi aktif"),
                            tr("Hedef yerel lab disi oldugu icin browser automation kapatildi"));
    } else if (!options.enableHeadlessRender && !localLabTarget) {
        m_automationSafetyStatus = tr("Public hedefte render kapali; browser automation yalnizca yerel lab hedeflerinde acilir");
    } else if (options.enableBrowserAutomation) {
        m_automationSafetyStatus = tr("Browser automation acik: yerel lab hedefi dogrulandi");
    } else {
        m_automationSafetyStatus = tr("Browser automation kapali: profil bu ozelligi acmiyor");
    }

    emit statsChanged();

    m_core->start(targetUrl, options);
}

void SpiderModule::stop()
{
    if (!m_scanning || !m_core || m_terminalTransition) {
        return;
    }
    m_terminalTransition = true;

    if (m_idleGuardTimer) {
        m_idleGuardTimer->stop();
    }
    destroyCoreAsync();
    m_scanning = false;
    m_statusText = tr("Spider durduruldu");
    appendTimelineEvent(m_coverageTimeline, tr("durduruldu"), tr("Spider durduruldu"), tr("Operator taramayi sonlandirdi."));
    emit scanningChanged();
    emit statusChanged();
    emit statsChanged();
    emit crawlEvent(tr("Spider operator tarafindan durduruldu"));
    emit crawlFinished();
}

void SpiderModule::finalizeStalledRun()
{
    if (!m_scanning) {
        return;
    }
    forceFinishFromGuard(tr("arayuz watchdog tetiklemesi"));
}

void SpiderModule::bumpIdleGuard()
{
    if (m_scanning && m_core) {
        m_idleGuardLastVisited = m_core->visitedCount();
        m_idleGuardLastQueued = m_core->queuedCount();
        m_idleGuardStableTicks = 0;
    }
    if (m_idleGuardTimer && m_scanning && !m_idleGuardTimer->isActive()) {
        m_idleGuardTimer->start();
    }
}

void SpiderModule::forceFinishFromGuard(const QString &reason)
{
    if (!m_scanning || m_terminalTransition) {
        return;
    }
    m_terminalTransition = true;

    if (m_idleGuardTimer) {
        m_idleGuardTimer->stop();
    }
    appendTimelineEvent(m_coverageTimeline,
                        tr("guard"),
                        tr("Tarama guard ile sonlandirildi"),
                        reason);
    emit crawlEvent(tr("[guard] Tarama %1 nedeniyle tamamlandi").arg(reason));
    m_scanning = false;
    m_statusText = tr("Spider tamamlandi");
    m_visitedCount = m_core ? m_core->visitedCount() : m_visitedCount;
    emit scanningChanged();
    emit statusChanged();
    emit statsChanged();
    emit crawlFinished();
    persistSnapshot();
    destroyCoreAsync();
}

void SpiderModule::setTargetUrl(const QString &value)
{
    if (value == m_targetUrl) {
        return;
    }
    m_targetUrl = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "targetUrl", value);
    }
    emit configurationChanged();
}

void SpiderModule::setMaxPages(int value)
{
    value = qBound(5, value, 250);
    if (value == m_maxPages) {
        return;
    }
    m_maxPages = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "maxPages", value);
    }
    emit configurationChanged();
}

void SpiderModule::setMaxDepth(int value)
{
    value = qBound(1, value, 10);
    if (value == m_maxDepth) {
        return;
    }
    m_maxDepth = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "maxDepth", value);
    }
    emit configurationChanged();
}

void SpiderModule::setRequestTimeoutMs(int value)
{
    value = qBound(800, value, 10000);
    if (value == m_requestTimeoutMs) {
        return;
    }
    m_requestTimeoutMs = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "requestTimeoutMs", value);
    }
    emit configurationChanged();
}

void SpiderModule::setScanStage(int value)
{
    value = qBound(0, value, 2);
    if (value == m_scanStage) {
        return;
    }
    m_scanStage = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "scanStage", value);
    }
    emit configurationChanged();
}

void SpiderModule::setAllowSubdomains(bool value)
{
    if (value == m_allowSubdomains) {
        return;
    }
    m_allowSubdomains = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "allowSubdomains", value);
    }
    emit configurationChanged();
}

void SpiderModule::setScopePreset(const QString &value)
{
    if (value == m_scopePreset) {
        return;
    }
    m_scopePreset = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "scopePreset", value);
    }
    emit configurationChanged();
}

void SpiderModule::setIncludePatterns(const QString &value)
{
    if (value == m_includePatterns) {
        return;
    }
    m_includePatterns = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "includePatterns", value);
    }
    emit configurationChanged();
}

void SpiderModule::setExcludePatterns(const QString &value)
{
    if (value == m_excludePatterns) {
        return;
    }
    m_excludePatterns = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "excludePatterns", value);
    }
    emit configurationChanged();
}

void SpiderModule::setLoginUrl(const QString &value)
{
    if (value == m_loginUrl) {
        return;
    }
    m_loginUrl = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "loginUrl", value);
    }
    emit configurationChanged();
}

void SpiderModule::setAuthUsername(const QString &value)
{
    if (value == m_authUsername) {
        return;
    }
    m_authUsername = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "authUsername", value);
    }
    emit configurationChanged();
}

void SpiderModule::setAuthPassword(const QString &value)
{
    if (value == m_authPassword) {
        return;
    }
    m_authPassword = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "authPassword", value);
    }
    emit configurationChanged();
}

void SpiderModule::setUsernameField(const QString &value)
{
    if (value == m_usernameField) {
        return;
    }
    m_usernameField = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "usernameField", value);
    }
    emit configurationChanged();
}

void SpiderModule::setPasswordField(const QString &value)
{
    if (value == m_passwordField) {
        return;
    }
    m_passwordField = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "passwordField", value);
    }
    emit configurationChanged();
}

void SpiderModule::setCsrfField(const QString &value)
{
    if (value == m_csrfField) {
        return;
    }
    m_csrfField = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "csrfField", value);
    }
    emit configurationChanged();
}

void SpiderModule::setAuthWorkflow(const QString &value)
{
    if (value == m_authWorkflow) {
        return;
    }
    m_authWorkflow = value;
    if (m_settings) {
        m_settings->setValue("modules/spider", "authWorkflow", value);
    }
    emit configurationChanged();
}

void SpiderModule::recordEndpoint(const QUrl &url,
                                  const QString &kind,
                                  const QString &source,
                                  int depth,
                                  int statusCode,
                                  const QString &contentType,
                                  const QString &sessionState,
                                  const QString &finalUrl,
                                  const QString &pageTitle)
{
    bumpIdleGuard();
    m_lastDiscoveryMs = QDateTime::currentMSecsSinceEpoch();
    if (!url.isValid() || url.toString().trimmed().isEmpty()) {
        return;
    }
    const QString key = QString("%1|%2|%3").arg(kind, sessionState, url.toString(QUrl::RemoveFragment));
    if (m_endpointKeys.contains(key)) {
        return;
    }
    m_endpointKeys.insert(key);
    m_endpoints.prepend(QVariantMap{
        {"url", url.toString()},
        {"kind", kind},
        {"source", source},
        {"depth", depth},
        {"statusCode", statusCode},
        {"contentType", contentType},
        {"sessionState", sessionState},
        {"finalUrl", finalUrl},
        {"pageTitle", pageTitle}
    });
    if (kind == QLatin1String("login-form") || kind == QLatin1String("login-wall")) {
        appendTimelineEvent(m_coverageTimeline, tr("auth"), tr("Kimlik yuzeyi bulundu"), url.toString());
    } else if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
        appendTimelineEvent(m_coverageTimeline, tr("delta"), tr("Oturum sonrasi yeni yuzey"), url.toString());
    } else if (kind == QLatin1String("js-route")) {
        appendTimelineEvent(m_coverageTimeline, tr("js"), tr("JS route bulundu"), url.toString());
    }
    m_visitedCount = m_core ? m_core->visitedCount() : m_visitedCount;
    emit endpointDiscovered(m_endpoints.first().toMap());
    emit resultsChanged();
    updateCoverageScore();
    emit statsChanged();
    persistSnapshot();
}

void SpiderModule::recordParameter(const QString &name, const QUrl &url, const QString &origin)
{
    bumpIdleGuard();
    m_lastDiscoveryMs = QDateTime::currentMSecsSinceEpoch();
    if (name.trimmed().isEmpty() || !url.isValid() || url.toString().trimmed().isEmpty()) {
        return;
    }
    const QString key = QString("%1|%2").arg(name, url.toString(QUrl::RemoveFragment));
    if (m_parameterKeys.contains(key)) {
        return;
    }
    m_parameterKeys.insert(key);
    m_parameters.prepend(QVariantMap{{"name", name}, {"url", url.toString()}, {"origin", origin}});
    if (origin.contains(QStringLiteral("dosya-yukleme"))) {
        appendTimelineEvent(m_coverageTimeline, tr("upload"), tr("Dosya yukleme girdisi"), url.toString());
    } else if (origin.contains(QStringLiteral("parola"))) {
        appendTimelineEvent(m_coverageTimeline, tr("auth"), tr("Parola alani"), url.toString());
    } else if (origin.contains(QStringLiteral("admin-filtresi"))) {
        appendTimelineEvent(m_coverageTimeline, tr("admin"), tr("Yonetim filtresi"), url.toString());
    }
    emit parameterDiscovered(m_parameters.first().toMap());
    emit resultsChanged();
    updateCoverageScore();
    emit statsChanged();
    persistSnapshot();
}

void SpiderModule::recordAsset(const QString &kind, const QString &value, const QString &source)
{
    bumpIdleGuard();
    m_lastDiscoveryMs = QDateTime::currentMSecsSinceEpoch();
    if (kind.trimmed().isEmpty() || value.trimmed().isEmpty()) {
        return;
    }
    if (assetLooksLowSignal(kind, value)) {
        return;
    }
    if (spiderAssetShouldBeSuppressed(kind, value, m_scopePreset)) {
        return;
    }
    const QString key = QString("%1|%2").arg(kind, value);
    if (m_assetKeys.contains(key)) {
        return;
    }
    m_assetKeys.insert(key);
    m_assets.prepend(QVariantMap{{"kind", kind}, {"value", value}, {"source", source}});
    if (kind == QLatin1String("auth-expectation-failed")) {
        appendTimelineEvent(m_coverageTimeline, tr("auth"), tr("Workflow beklentisi saglanmadi"), value);
    } else if (kind == QLatin1String("auth-cookie-jar")) {
        appendTimelineEvent(m_coverageTimeline, tr("auth"), tr("Cookie jar guncellendi"), value);
    } else if (kind == QLatin1String("auth-boundary")) {
        appendTimelineEvent(m_coverageTimeline, tr("auth"), tr("Oturum siniri guncellendi"), value);
    } else if (kind == QLatin1String("auth-surface-delta")) {
        appendTimelineEvent(m_coverageTimeline, tr("delta"), tr("Yeni oturum yuzeyi"), value);
    } else if (kind == QLatin1String("render-form-delta")) {
        appendTimelineEvent(m_coverageTimeline, tr("render"), tr("Rendered form yuzeyi"), value);
    } else if (kind == QLatin1String("render-route-delta")) {
        appendTimelineEvent(m_coverageTimeline, tr("render"), tr("Rendered rota yuzeyi"), value);
    } else if (kind == QLatin1String("render-action-delta")) {
        appendTimelineEvent(m_coverageTimeline, tr("render"), tr("Rendered etkileşim adayi"), value);
    } else if (kind == QLatin1String("workflow-submit-candidate")) {
        appendTimelineEvent(m_coverageTimeline, tr("workflow"), tr("Guvenli form replay adayi"), value);
    } else if (kind == QLatin1String("workflow-action-candidate")) {
        appendTimelineEvent(m_coverageTimeline, tr("workflow"), tr("Etkileşim replay adayi"), value);
    } else if (kind == QLatin1String("workflow-submit-result")) {
        appendTimelineEvent(m_coverageTimeline, tr("workflow"), tr("Form replay sonucu"), value);
    } else if (kind == QLatin1String("workflow-action-result")) {
        appendTimelineEvent(m_coverageTimeline, tr("workflow"), tr("Etkilesim replay sonucu"), value);
    } else if (kind == QLatin1String("waf-vendor")) {
        appendTimelineEvent(m_coverageTimeline, tr("waf"), tr("WAF saglayici ipucu"), value);
    } else if (kind == QLatin1String("host-pressure")) {
        appendTimelineEvent(m_coverageTimeline, tr("waf"), tr("Host pressure guncellendi"), value);
    } else if (kind == QLatin1String("automation-live-title")) {
        appendTimelineEvent(m_coverageTimeline, tr("automation"), tr("Canli browser basligi"), value);
    } else if (kind == QLatin1String("automation-live-action")) {
        appendTimelineEvent(m_coverageTimeline, tr("automation"), tr("Canli browser etkilesim adayi"), value);
    } else if (kind == QLatin1String("automation-cdp-failed")) {
        appendTimelineEvent(m_coverageTimeline, tr("automation"), tr("CDP baglanti hatasi"), value);
    } else if (kind.contains(QStringLiteral("secret")) || kind.contains(QStringLiteral("jwt")) || kind.contains(QStringLiteral("aws-key"))) {
        appendTimelineEvent(m_coverageTimeline, tr("secret"), tr("Gizli literal bulundu"), value);
    } else if (kind.startsWith(QStringLiteral("render-"))) {
        appendTimelineEvent(m_coverageTimeline, tr("render"), tr("Render kaniti"), value);
    }
    emit assetDiscovered(m_assets.first().toMap());
    emit resultsChanged();
    updateCoverageScore();
    emit statsChanged();
    persistSnapshot();
}

void SpiderModule::handleCoreFinished()
{
    if (!m_scanning || m_terminalTransition) {
        return;
    }
    m_terminalTransition = true;

    if (m_idleGuardTimer) {
        m_idleGuardTimer->stop();
    }
    m_scanning = false;
    m_statusText = tr("Spider tamamlandi");
    m_visitedCount = m_core ? m_core->visitedCount() : m_visitedCount;
    const qint64 elapsedMs = m_scanTimer.isValid() ? m_scanTimer.elapsed() : 0;
    const double elapsedSec = qMax(0.001, elapsedMs / 1000.0);
    const int totalFindings = m_endpoints.size() + m_parameters.size() + m_assets.size();
    const double rate = totalFindings / elapsedSec;
    int anonymousSurface = 0;
    int sessionSharedSurface = 0;
    int sessionDeltaSurface = 0;
    int formSurfaceCount = 0;
    int protectedSurface = 0;
    int missingSurface = 0;
    int renderHits = 0;
    int automationHits = 0;
    for (const QVariant &value : m_endpoints) {
        const QVariantMap row = value.toMap();
        const QString kind = row.value("kind").toString();
        const QString sessionState = row.value("sessionState").toString();
        const int statusCode = row.value("statusCode").toInt();
        if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            ++sessionDeltaSurface;
        } else if (sessionState == QLatin1String("oturumlu-ortak")) {
            ++sessionSharedSurface;
        } else {
            ++anonymousSurface;
        }
        if (kind.startsWith(QLatin1String("form:")) || kind == QLatin1String("login-form")) {
            ++formSurfaceCount;
        }
        if (kind == QLatin1String("login-wall")
            || kind == QLatin1String("access-denied")
            || kind == QLatin1String("waf-challenge")
            || statusCode == 401
            || statusCode == 403) {
            ++protectedSurface;
        }
        if (kind == QLatin1String("soft-404") || statusCode == 404) {
            ++missingSurface;
        }
    }
    for (const QVariant &value : m_assets) {
        const QString kind = value.toMap().value("kind").toString();
        if (kind.startsWith(QLatin1String("render-"))) {
            ++renderHits;
        }
        if (kind.startsWith(QLatin1String("automation-"))) {
            ++automationHits;
        }
    }
    m_benchmarkSummary = tr("%1 sn | %2 bulgu | %3 bulgu/sn | anonim %4 | oturum ortak %5 | oturum delta %6 | form %7 | render %8 | automation %9 | korunan %10 | 404 %11")
                             .arg(QString::number(elapsedSec, 'f', 1))
                             .arg(totalFindings)
                             .arg(QString::number(rate, 'f', 2))
                             .arg(anonymousSurface)
                             .arg(sessionSharedSurface)
                             .arg(sessionDeltaSurface)
                             .arg(formSurfaceCount)
                             .arg(renderHits)
                             .arg(automationHits)
                             .arg(protectedSurface)
                             .arg(missingSurface);
    const QSet<QString> previousEndpointSet = endpointSignatureSet(m_previousEndpoints);
    const QSet<QString> previousParameterSet = parameterSignatureSet(m_previousParameters);
    const QSet<QString> previousAssetSet = assetSignatureSet(m_previousAssets);
    const QSet<QString> currentEndpointSet = endpointSignatureSet(m_endpoints);
    const QSet<QString> currentParameterSet = parameterSignatureSet(m_parameters);
    const QSet<QString> currentAssetSet = assetSignatureSet(m_assets);
    const int endpointAdded = (currentEndpointSet - previousEndpointSet).size();
    const int endpointRemoved = (previousEndpointSet - currentEndpointSet).size();
    const int parameterAdded = (currentParameterSet - previousParameterSet).size();
    const int parameterRemoved = (previousParameterSet - currentParameterSet).size();
    const int assetAdded = (currentAssetSet - previousAssetSet).size();
    const int assetRemoved = (previousAssetSet - currentAssetSet).size();
    updateCoverageScore();
    const QString segmentDiffSummary = formatSegmentDiffSummary(m_previousCoverageBreakdown,
                                                               m_coverageBreakdown,
                                                               m_previousHighValueSegments,
                                                               m_highValueSegments);
    m_benchmarkDiffSummary = tr("Endpoint +%1/-%2 | Parametre +%3/-%4 | Asset +%5/-%6 | %7")
                                 .arg(endpointAdded)
                                 .arg(endpointRemoved)
                                 .arg(parameterAdded)
                                 .arg(parameterRemoved)
                                 .arg(assetAdded)
                                 .arg(assetRemoved)
                                 .arg(segmentDiffSummary);
    QStringList regressionFlags;
    const int previousCoverage = m_previousCoverageBreakdown.value(QStringLiteral("auth")).toInt()
        + m_previousCoverageBreakdown.value(QStringLiteral("form")).toInt()
        + m_previousCoverageBreakdown.value(QStringLiteral("js")).toInt()
        + m_previousCoverageBreakdown.value(QStringLiteral("secret")).toInt()
        + m_previousCoverageBreakdown.value(QStringLiteral("admin")).toInt()
        + m_previousCoverageBreakdown.value(QStringLiteral("upload")).toInt()
        + m_previousCoverageBreakdown.value(QStringLiteral("delta")).toInt()
        + m_previousCoverageBreakdown.value(QStringLiteral("render")).toInt()
        + m_previousCoverageBreakdown.value(QStringLiteral("automation")).toInt();
    const int currentCoverage = m_coverageBreakdown.value(QStringLiteral("auth")).toInt()
        + m_coverageBreakdown.value(QStringLiteral("form")).toInt()
        + m_coverageBreakdown.value(QStringLiteral("js")).toInt()
        + m_coverageBreakdown.value(QStringLiteral("secret")).toInt()
        + m_coverageBreakdown.value(QStringLiteral("admin")).toInt()
        + m_coverageBreakdown.value(QStringLiteral("upload")).toInt()
        + m_coverageBreakdown.value(QStringLiteral("delta")).toInt()
        + m_coverageBreakdown.value(QStringLiteral("render")).toInt()
        + m_coverageBreakdown.value(QStringLiteral("automation")).toInt();
    const int coverageDelta = currentCoverage - previousCoverage;
    regressionFlags << (coverageDelta > 0
                            ? tr("yuzey genisledi (+%1)").arg(coverageDelta)
                            : (coverageDelta < 0
                                   ? tr("yuzey daraldi (%1)").arg(coverageDelta)
                                   : tr("yuzey stabil")));
    if (segmentEntryCount(m_highValueSegments, QStringLiteral("secret")) > segmentEntryCount(m_previousHighValueSegments, QStringLiteral("secret"))) {
        regressionFlags << tr("yeni gizli literal izi");
    }
    if (segmentEntryCount(m_highValueSegments, QStringLiteral("automation")) > segmentEntryCount(m_previousHighValueSegments, QStringLiteral("automation"))) {
        regressionFlags << tr("automation ile yeni yuzey");
    }
    if (m_coverageBreakdown.value(QStringLiteral("protected")).toInt() > m_previousCoverageBreakdown.value(QStringLiteral("protected")).toInt()) {
        regressionFlags << tr("korunan yuzey artti");
    }
    if (m_coverageBreakdown.value(QStringLiteral("render")).toInt() > m_previousCoverageBreakdown.value(QStringLiteral("render")).toInt()) {
        regressionFlags << tr("render delta artti");
    }
    m_regressionSummary = regressionFlags.join(QStringLiteral(" | "));
    appendTimelineEvent(m_coverageTimeline,
                        tr("tamamlandi"),
                        tr("Spider tamamlandi"),
                        tr("%1 endpoint, %2 parametre, %3 asset").arg(m_endpoints.size()).arg(m_parameters.size()).arg(m_assets.size()));
    appendTimelineEvent(m_coverageTimeline,
                        tr("benchmark"),
                        tr("Tarama performans ozeti"),
                        m_benchmarkSummary);
    appendTimelineEvent(m_coverageTimeline,
                        tr("karsilastirma"),
                        tr("Onceki kosuya gore degisim"),
                        m_benchmarkDiffSummary);
    appendTimelineEvent(m_coverageTimeline,
                        tr("regression"),
                        tr("Regression ozeti"),
                        m_regressionSummary);
    m_benchmarkHistory.prepend(QVariantMap{
        {"capturedAt", QDateTime::currentDateTime().toString(Qt::ISODate)},
        {"target", m_targetUrl},
        {"profile", m_scopePreset},
        {"summary", m_benchmarkSummary},
        {"diffSummary", m_benchmarkDiffSummary},
        {"regressionSummary", m_regressionSummary},
        {"coverageScore", m_coverageScore},
        {"visited", m_visitedCount},
        {"findings", totalFindings}
    });
    while (m_benchmarkHistory.size() > 15) {
        m_benchmarkHistory.removeLast();
    }
    emit scanningChanged();
    emit statusChanged();
    emit statsChanged();
    emit crawlFinished();
    persistSnapshot();
    destroyCoreAsync();

    if (m_logger) {
        m_logger->info(id(), QString("Spider tamamlandi: %1 endpoint").arg(m_endpoints.size()));
    }
}

void SpiderModule::updateCoverageScore()
{
    int score = 0;
    int loginForms = 0;
    int authDelta = 0;
    int jsRoutes = 0;
    int secrets = 0;
    int uploadFields = 0;
    int adminSurface = 0;
    int formSurface = 0;
    int authSurface = 0;
    int jsSurface = 0;
    int secretSurface = 0;
    int protectedSurface = 0;
    int missingSurface = 0;
    int renderSurface = 0;
    int automationSurface = 0;
    QVariantList highValue;

    for (const QVariant &value : m_endpoints) {
        const QVariantMap row = value.toMap();
        const QString kind = row.value("kind").toString();
        const QString sessionState = row.value("sessionState").toString();
        score += 1;
        if (kind == QLatin1String("login-form") || kind == QLatin1String("login-wall")) {
            ++loginForms;
            ++authSurface;
            score += 4;
            highValue.prepend(QVariantMap{{"label", tr("Kimlik Yuzeyi")}, {"value", row.value("url").toString()}, {"kind", kind}});
        }
        if (kind == QLatin1String("js-route")) {
            ++jsRoutes;
            ++jsSurface;
            score += 2;
        }
        if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            ++authDelta;
            ++authSurface;
            score += 3;
            highValue.prepend(QVariantMap{{"label", tr("Oturum Sonrasi Yeni Yuzey")}, {"value", row.value("url").toString()}, {"kind", kind}});
        }
        if (kind.contains(QStringLiteral("admin"), Qt::CaseInsensitive)
            || row.value("url").toString().contains(QStringLiteral("admin"), Qt::CaseInsensitive)) {
            ++adminSurface;
            score += 3;
            highValue.prepend(QVariantMap{{"label", tr("Yonetim Yuzeyi")}, {"value", row.value("url").toString()}, {"kind", kind}});
        }
        if (kind.startsWith(QStringLiteral("form:"))) {
            ++formSurface;
        }
        const int statusCode = row.value("statusCode").toInt();
        if (kind == QLatin1String("login-wall")
            || kind == QLatin1String("access-denied")
            || kind == QLatin1String("waf-challenge")
            || statusCode == 401
            || statusCode == 403) {
            ++protectedSurface;
            score += 2;
        }
        if (kind == QLatin1String("soft-404") || statusCode == 404) {
            ++missingSurface;
        }
    }

    for (const QVariant &value : m_parameters) {
        const QVariantMap row = value.toMap();
        const QString origin = row.value("origin").toString();
        score += 1;
        if (origin.contains(QStringLiteral("dosya-yukleme"))) {
            ++uploadFields;
            score += 5;
            highValue.prepend(QVariantMap{{"label", tr("Dosya Yukleme Girdisi")}, {"value", row.value("url").toString()}, {"kind", tr("dosya-yukleme")}});
        }
        if (origin.contains(QStringLiteral("admin-filtresi"))) {
            ++adminSurface;
            score += 3;
            highValue.prepend(QVariantMap{{"label", tr("Admin Filtresi")}, {"value", row.value("url").toString()}, {"kind", tr("admin-filtresi")}});
        }
        if (origin.contains(QStringLiteral("form-field:"))) {
            ++formSurface;
        }
    }

    for (const QVariant &value : m_assets) {
        const QVariantMap row = value.toMap();
        const QString kind = row.value("kind").toString();
        if (kind == QLatin1String("auth-surface-delta")) {
            ++authDelta;
            ++authSurface;
            score += 3;
        } else if (kind == QLatin1String("login-form")) {
            ++loginForms;
            ++authSurface;
            score += 4;
        } else if (kind.contains(QStringLiteral("secret")) || kind.contains(QStringLiteral("jwt")) || kind.contains(QStringLiteral("aws-key"))) {
            ++secrets;
            ++secretSurface;
            score += 6;
            highValue.prepend(QVariantMap{{"label", tr("Gizli Literal")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind.startsWith(QStringLiteral("render-"))) {
            score += 2;
            ++jsSurface;
            ++renderSurface;
        } else if (kind == QLatin1String("render-state-delta")) {
            score += 4;
            ++jsSurface;
            ++authDelta;
            ++renderSurface;
            highValue.prepend(QVariantMap{{"label", tr("Render Sonrasi Yeni Yuzey")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("render-form-delta")) {
            score += 5;
            ++formSurface;
            ++jsSurface;
            ++renderSurface;
            highValue.prepend(QVariantMap{{"label", tr("Render Sonrasi Form Yuzeyi")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("render-route-delta")) {
            score += 4;
            ++jsSurface;
            ++renderSurface;
            highValue.prepend(QVariantMap{{"label", tr("Render Sonrasi Rota")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("render-action-delta")) {
            score += 5;
            ++jsSurface;
            ++formSurface;
            ++renderSurface;
            highValue.prepend(QVariantMap{{"label", tr("Render Sonrasi Etkileşim")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("workflow-submit-candidate")) {
            score += 4;
            ++formSurface;
            highValue.prepend(QVariantMap{{"label", tr("Replay Edilebilir Form Akisi")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("workflow-action-candidate")) {
            score += 4;
            ++jsSurface;
            highValue.prepend(QVariantMap{{"label", tr("Replay Edilebilir Etkileşim")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("workflow-submit-result")) {
            score += 2;
            ++formSurface;
            highValue.prepend(QVariantMap{{"label", tr("Replay Form Sonucu")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("workflow-action-result")) {
            score += 2;
            ++jsSurface;
            highValue.prepend(QVariantMap{{"label", tr("Replay Etkilesim Sonucu")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("waf-vendor")) {
            score += 2;
            ++protectedSurface;
            highValue.prepend(QVariantMap{{"label", tr("WAF Saglayici Ipuclari")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("host-pressure")) {
            score += 1;
            ++protectedSurface;
        } else if (kind == QLatin1String("automation-live-action")) {
            score += 6;
            ++jsSurface;
            ++formSurface;
            ++automationSurface;
            highValue.prepend(QVariantMap{{"label", tr("Canli Browser Etkilesim")}, {"value", row.value("value").toString()}, {"kind", kind}});
        } else if (kind == QLatin1String("automation-live-title")) {
            score += 1;
            ++automationSurface;
        } else if (kind == QLatin1String("automation-page-target") || kind == QLatin1String("automation-browser-target")) {
            score += 1;
            ++automationSurface;
        } else if (kind == QLatin1String("auth-boundary")) {
            score += 2;
            ++authSurface;
        }
    }

    m_coverageScore = qMin(score, 100);
    m_coverageSummary = tr("Yuzey %1/100 | login %2 | yeni oturum yuzeyi %3 | js route %4 | gizli literal %5 | dosya/admin girdisi %6 | korunan %7 | render %8 | automation %9")
                            .arg(m_coverageScore)
                            .arg(loginForms)
                            .arg(authDelta)
                            .arg(jsRoutes)
                            .arg(secrets)
                            .arg(uploadFields + adminSurface)
                            .arg(protectedSurface)
                            .arg(renderSurface)
                            .arg(automationSurface);
    m_coverageBreakdown = QVariantMap{
        {"auth", authSurface},
        {"form", formSurface},
        {"js", jsSurface},
        {"secret", secretSurface},
        {"admin", adminSurface},
        {"upload", uploadFields},
        {"delta", authDelta},
        {"protected", protectedSurface},
        {"missing", missingSurface},
        {"render", renderSurface},
        {"automation", automationSurface}
    };
    QVariantMap segments;
    QVariantList authSegment;
    QVariantList adminSegment;
    QVariantList uploadSegment;
    QVariantList renderSegment;
    QVariantList automationSegment;
    QVariantList secretSegment;
    for (const QVariant &entry : highValue) {
        const QVariantMap row = entry.toMap();
        const QString label = row.value("label").toString().toLower();
        if (label.contains("kimlik") || label.contains("oturum")) {
            authSegment << row;
        }
        if (label.contains("yonetim") || label.contains("admin")) {
            adminSegment << row;
        }
        if (label.contains("dosya")) {
            uploadSegment << row;
        }
        if (label.contains("render")) {
            renderSegment << row;
        }
        if (label.contains("browser") || label.contains("automation")) {
            automationSegment << row;
        }
        if (label.contains("gizli") || label.contains("secret")) {
            secretSegment << row;
        }
    }
    segments.insert("auth", authSegment);
    segments.insert("admin", adminSegment);
    segments.insert("upload", uploadSegment);
    segments.insert("render", renderSegment);
    segments.insert("automation", automationSegment);
    segments.insert("secret", secretSegment);

    while (highValue.size() > 20) {
        highValue.removeLast();
    }
    m_highValueSegments = segments;
    m_highValueTargets = highValue;
    if (!m_scanning) {
        appendTimelineEvent(m_coverageTimeline,
                            tr("coverage"),
                            tr("Yuzey puani guncellendi"),
                            m_coverageSummary);
    }
}

void SpiderModule::persistSnapshot() const
{
    if (!m_settings) {
        return;
    }

    m_settings->setValue("modules/spider_snapshot", "targetUrl", m_targetUrl);
    m_settings->setValue("modules/spider_snapshot", "capturedAt", QDateTime::currentDateTime().toString(Qt::ISODate));
    m_settings->setValue("modules/spider_snapshot", "coverageScore", m_coverageScore);
    m_settings->setValue("modules/spider_snapshot", "coverageSummary", m_coverageSummary);
    m_settings->setValue("modules/spider_snapshot", "automationSafetyStatus", m_automationSafetyStatus);
    m_settings->setValue("modules/spider_snapshot", "benchmarkSummary", m_benchmarkSummary);
    m_settings->setValue("modules/spider_snapshot", "benchmarkDiffSummary", m_benchmarkDiffSummary);
    m_settings->setValue("modules/spider_snapshot", "regressionSummary", m_regressionSummary);
    m_settings->setValue("modules/spider_snapshot", "coverageBreakdown", m_coverageBreakdown);
    m_settings->setValue("modules/spider_snapshot", "highValueSegments", m_highValueSegments);
    m_settings->setValue("modules/spider_snapshot", "benchmarkHistory", m_benchmarkHistory);
    m_settings->setValue("modules/spider_snapshot", "highValueTargets", m_highValueTargets);
    m_settings->setValue("modules/spider_snapshot", "coverageTimeline", m_coverageTimeline);
    m_settings->setValue("modules/spider_snapshot", "endpoints", m_endpoints);
    m_settings->setValue("modules/spider_snapshot", "parameters", m_parameters);
    m_settings->setValue("modules/spider_snapshot", "assets", m_assets);
}

bool SpiderModule::isLocalLabTarget(const QUrl &url)
{
    const QString host = url.host().trimmed().toLower();
    if (host.isEmpty()) {
        return false;
    }
    if (host == QLatin1String("localhost") || host == QLatin1String("127.0.0.1") || host == QLatin1String("::1")) {
        return true;
    }
    if (host.endsWith(QLatin1String(".local")) || host.endsWith(QLatin1String(".test"))) {
        return true;
    }
    if (host.startsWith(QLatin1String("10.")) || host.startsWith(QLatin1String("192.168."))) {
        return true;
    }
    if (host.startsWith(QLatin1String("172."))) {
        const QStringList parts = host.split('.');
        bool ok = false;
        const int secondOctet = parts.value(1).toInt(&ok);
        if (ok && secondOctet >= 16 && secondOctet <= 31) {
            return true;
        }
    }
    return false;
}

REGISTER_MODULE(SpiderModule, "spider");
