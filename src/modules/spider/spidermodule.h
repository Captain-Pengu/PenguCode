#pragma once

#include "core/framework/moduleinterface.h"
#include "modules/spider/engine/spidercore.h"

#include <QSet>
#include <QElapsedTimer>
#include <QTimer>
#include <QDateTime>
#include <QVariantList>
#include <memory>

class SettingsManager;
class Logger;

class SpiderModule : public ModuleInterface
{
    Q_OBJECT
    Q_PROPERTY(QString targetUrl READ targetUrl WRITE setTargetUrl NOTIFY configurationChanged)
    Q_PROPERTY(int maxPages READ maxPages WRITE setMaxPages NOTIFY configurationChanged)
    Q_PROPERTY(int maxDepth READ maxDepth WRITE setMaxDepth NOTIFY configurationChanged)
    Q_PROPERTY(int requestTimeoutMs READ requestTimeoutMs WRITE setRequestTimeoutMs NOTIFY configurationChanged)
    Q_PROPERTY(int scanStage READ scanStage WRITE setScanStage NOTIFY configurationChanged)
    Q_PROPERTY(bool allowSubdomains READ allowSubdomains WRITE setAllowSubdomains NOTIFY configurationChanged)
    Q_PROPERTY(QString scopePreset READ scopePreset WRITE setScopePreset NOTIFY configurationChanged)
    Q_PROPERTY(QString includePatterns READ includePatterns WRITE setIncludePatterns NOTIFY configurationChanged)
    Q_PROPERTY(QString excludePatterns READ excludePatterns WRITE setExcludePatterns NOTIFY configurationChanged)
    Q_PROPERTY(QString loginUrl READ loginUrl WRITE setLoginUrl NOTIFY configurationChanged)
    Q_PROPERTY(QString authUsername READ authUsername WRITE setAuthUsername NOTIFY configurationChanged)
    Q_PROPERTY(QString authPassword READ authPassword WRITE setAuthPassword NOTIFY configurationChanged)
    Q_PROPERTY(QString usernameField READ usernameField WRITE setUsernameField NOTIFY configurationChanged)
    Q_PROPERTY(QString passwordField READ passwordField WRITE setPasswordField NOTIFY configurationChanged)
    Q_PROPERTY(QString csrfField READ csrfField WRITE setCsrfField NOTIFY configurationChanged)
    Q_PROPERTY(QString authWorkflow READ authWorkflow WRITE setAuthWorkflow NOTIFY configurationChanged)
    Q_PROPERTY(bool scanning READ scanning NOTIFY scanningChanged)
    Q_PROPERTY(QString statusText READ statusText NOTIFY statusChanged)
    Q_PROPERTY(int visitedCount READ visitedCount NOTIFY statsChanged)
    Q_PROPERTY(int queuedCount READ queuedCount NOTIFY statsChanged)
    Q_PROPERTY(int coverageScore READ coverageScore NOTIFY statsChanged)
    Q_PROPERTY(QString coverageSummary READ coverageSummary NOTIFY statsChanged)
    Q_PROPERTY(QString automationSafetyStatus READ automationSafetyStatus NOTIFY statsChanged)
    Q_PROPERTY(QString benchmarkSummary READ benchmarkSummary NOTIFY statsChanged)
    Q_PROPERTY(QString benchmarkDiffSummary READ benchmarkDiffSummary NOTIFY statsChanged)
    Q_PROPERTY(QString regressionSummary READ regressionSummary NOTIFY statsChanged)
    Q_PROPERTY(QVariantMap coverageBreakdown READ coverageBreakdown NOTIFY statsChanged)
    Q_PROPERTY(QVariantMap highValueSegments READ highValueSegments NOTIFY statsChanged)
    Q_PROPERTY(QVariantList benchmarkHistory READ benchmarkHistory NOTIFY statsChanged)
    Q_PROPERTY(QVariantList highValueTargets READ highValueTargets NOTIFY statsChanged)
    Q_PROPERTY(QVariantList coverageTimeline READ coverageTimeline NOTIFY statsChanged)
    Q_PROPERTY(QVariantList endpoints READ endpoints NOTIFY resultsChanged)
    Q_PROPERTY(QVariantList parameters READ parameters NOTIFY resultsChanged)
    Q_PROPERTY(QVariantList assets READ assets NOTIFY resultsChanged)

public:
    explicit SpiderModule(QObject *parent = nullptr);

    QString id() const override;
    QString name() const override;
    QString description() const override;
    QString icon() const override;
    QUrl pageSource() const override;

    void initialize(SettingsManager *settings, Logger *logger) override;
    QVariantMap defaultSettings() const override;
    QVariantMap saveState() const override;
    bool loadState(const QVariantMap &state) override;
    void reset() override;
    QString healthStatus() const override;

    QString targetUrl() const;
    int maxPages() const;
    int maxDepth() const;
    int requestTimeoutMs() const;
    int scanStage() const;
    bool allowSubdomains() const;
    QString scopePreset() const;
    QString includePatterns() const;
    QString excludePatterns() const;
    QString loginUrl() const;
    QString authUsername() const;
    QString authPassword() const;
    QString usernameField() const;
    QString passwordField() const;
    QString csrfField() const;
    QString authWorkflow() const;
    bool scanning() const;
    QString statusText() const;
    int visitedCount() const;
    int queuedCount() const;
    int coverageScore() const;
    QString coverageSummary() const;
    QString automationSafetyStatus() const;
    QString benchmarkSummary() const;
    QString benchmarkDiffSummary() const;
    QString regressionSummary() const;
    QVariantMap coverageBreakdown() const;
    QVariantMap highValueSegments() const;
    QVariantList benchmarkHistory() const;
    QVariantList highValueTargets() const;
    QVariantList coverageTimeline() const;
    QVariantList endpoints() const;
    QVariantList parameters() const;
    QVariantList assets() const;
    void reloadSettings();

public slots:
    void start() override;
    void stop() override;
    void finalizeStalledRun();
    void setTargetUrl(const QString &value);
    void setMaxPages(int value);
    void setMaxDepth(int value);
    void setRequestTimeoutMs(int value);
    void setScanStage(int value);
    void setAllowSubdomains(bool value);
    void setScopePreset(const QString &value);
    void setIncludePatterns(const QString &value);
    void setExcludePatterns(const QString &value);
    void setLoginUrl(const QString &value);
    void setAuthUsername(const QString &value);
    void setAuthPassword(const QString &value);
    void setUsernameField(const QString &value);
    void setPasswordField(const QString &value);
    void setCsrfField(const QString &value);
    void setAuthWorkflow(const QString &value);

signals:
    void configurationChanged();
    void scanningChanged();
    void statusChanged();
    void statsChanged();
    void resultsChanged();
    void crawlEvent(const QString &message);
    void endpointDiscovered(const QVariantMap &endpoint);
    void parameterDiscovered(const QVariantMap &parameter);
    void assetDiscovered(const QVariantMap &asset);
    void crawlFinished();

private slots:
    void recordEndpoint(const QUrl &url,
                        const QString &kind,
                        const QString &source = QString(),
                        int depth = 0,
                        int statusCode = 0,
                        const QString &contentType = QString(),
                        const QString &sessionState = QString(),
                        const QString &finalUrl = QString(),
                        const QString &pageTitle = QString());
    void recordParameter(const QString &name, const QUrl &url, const QString &origin);
    void recordAsset(const QString &kind, const QString &value, const QString &source);
    void handleCoreFinished();

private:
    void createCore();
    void destroyCoreAsync();
    void bumpIdleGuard();
    void updateCoverageScore();
    void persistSnapshot() const;
    static bool isLocalLabTarget(const QUrl &url);
    void forceFinishFromGuard(const QString &reason);

    SettingsManager *m_settings = nullptr;
    Logger *m_logger = nullptr;
    std::unique_ptr<SpiderCore> m_core;
    QString m_targetUrl;
    int m_maxPages = 40;
    int m_maxDepth = 4;
    int m_requestTimeoutMs = 4000;
    int m_scanStage = 0;
    bool m_allowSubdomains = false;
    QString m_scopePreset = "dengeli";
    QString m_includePatterns;
    QString m_excludePatterns;
    QString m_loginUrl;
    QString m_authUsername;
    QString m_authPassword;
    QString m_usernameField = "username";
    QString m_passwordField = "password";
    QString m_csrfField = "_token";
    QString m_authWorkflow;
    bool m_scanning = false;
    QString m_statusText = "Hazir";
    int m_visitedCount = 0;
    int m_coverageScore = 0;
    QString m_coverageSummary = "Yuzey puani hazir degil";
    QString m_automationSafetyStatus = "Browser automation durumu hazir degil";
    QString m_benchmarkSummary = "Benchmark ozeti hazir degil";
    QString m_benchmarkDiffSummary = "Kiyas ozeti hazir degil";
    QString m_regressionSummary = "Regression ozeti hazir degil";
    QVariantMap m_coverageBreakdown;
    QVariantMap m_highValueSegments;
    QVariantList m_benchmarkHistory;
    QVariantList m_highValueTargets;
    QVariantList m_coverageTimeline;
    QSet<QString> m_endpointKeys;
    QSet<QString> m_parameterKeys;
    QSet<QString> m_assetKeys;
    QVariantList m_endpoints;
    QVariantList m_parameters;
    QVariantList m_assets;
    QVariantList m_previousEndpoints;
    QVariantList m_previousParameters;
    QVariantList m_previousAssets;
    QVariantMap m_previousCoverageBreakdown;
    QVariantMap m_previousHighValueSegments;
    QElapsedTimer m_scanTimer;
    QTimer *m_idleGuardTimer = nullptr;
    int m_idleGuardLastVisited = -1;
    int m_idleGuardLastQueued = -1;
    int m_idleGuardStableTicks = 0;
    qint64 m_lastDiscoveryMs = 0;
};
