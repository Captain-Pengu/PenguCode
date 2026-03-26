#pragma once

#include <QWidget>

class SpiderModule;
class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QComboBox;
class QCheckBox;
class QFrame;
class QTabWidget;
class QTextEdit;
class QDialog;
class QTimer;

class SpiderWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SpiderWidget(SpiderModule *module, QWidget *parent = nullptr);
    void reloadSettings();

private slots:
    void startSpider();
    void stopSpider();
    void appendEvent(const QString &message);
    void handleEndpoint(const QVariantMap &endpoint);
    void handleParameter(const QVariantMap &parameter);
    void handleAsset(const QVariantMap &asset);
    void handleFinished();
    void applyStagePreset(int index);
    void applyScopePreset();
    void applyWorkflowPreset(int index);
    void refreshWorkflowValidation();
    void updateEvidenceDetail();
    void exportReport();
    void scheduleStatsRefresh();
    void pollStalledState();

private:
    QWidget *createInfoLabel(const QString &title, const QString &tooltip) const;
    void refreshLiveHeader();
    void applyVisualCompletionFallback();
    void refreshStats();
    void refreshFilteredResults();
    bool endpointMatchesFilter(const QListWidgetItem *item) const;
    bool assetMatchesFilter(const QListWidgetItem *item) const;
    QString buildReportHtml() const;

    SpiderModule *m_module = nullptr;
    QLineEdit *m_targetEdit = nullptr;
    QComboBox *m_stageCombo = nullptr;
    QSpinBox *m_maxPagesSpin = nullptr;
    QSpinBox *m_maxDepthSpin = nullptr;
    QSpinBox *m_timeoutSpin = nullptr;
    QComboBox *m_scopePresetCombo = nullptr;
    QCheckBox *m_allowSubdomainsCheck = nullptr;
    QPlainTextEdit *m_includePatternsEdit = nullptr;
    QPlainTextEdit *m_excludePatternsEdit = nullptr;
    QLineEdit *m_loginUrlEdit = nullptr;
    QLineEdit *m_authUsernameEdit = nullptr;
    QLineEdit *m_authPasswordEdit = nullptr;
    QLineEdit *m_usernameFieldEdit = nullptr;
    QLineEdit *m_passwordFieldEdit = nullptr;
    QLineEdit *m_csrfFieldEdit = nullptr;
    QComboBox *m_authWorkflowPresetCombo = nullptr;
    QLabel *m_authWorkflowHintLabel = nullptr;
    QLabel *m_workflowValidationLabel = nullptr;
    QPushButton *m_applyWorkflowPresetButton = nullptr;
    QPlainTextEdit *m_authWorkflowEdit = nullptr;
    QFrame *m_scopeCard = nullptr;
    QFrame *m_authCard = nullptr;
    QFrame *m_advancedCard = nullptr;
    QTabWidget *m_workTabs = nullptr;
    QComboBox *m_endpointFilterCombo = nullptr;
    QComboBox *m_assetFilterCombo = nullptr;
    QLabel *m_statusValue = nullptr;
    QLabel *m_countsValue = nullptr;
    QLabel *m_coverageValue = nullptr;
    QLabel *m_coverageSummaryLabel = nullptr;
    QLabel *m_coverageBreakdownLabel = nullptr;
    QLabel *m_automationLabel = nullptr;
    QLabel *m_benchmarkLabel = nullptr;
    QLabel *m_benchmarkDiffLabel = nullptr;
    QLabel *m_regressionLabel = nullptr;
    QLabel *m_insightLabel = nullptr;
    QPlainTextEdit *m_console = nullptr;
    QListWidget *m_endpointList = nullptr;
    QListWidget *m_parameterList = nullptr;
    QListWidget *m_assetList = nullptr;
    QListWidget *m_highValueList = nullptr;
    QListWidget *m_segmentList = nullptr;
    QListWidget *m_benchmarkHistoryList = nullptr;
    QListWidget *m_timelineList = nullptr;
    QListWidget *m_evidenceList = nullptr;
    QListWidget *m_featureList = nullptr;
    QListWidget *m_hostHealthList = nullptr;
    QTextEdit *m_evidenceDetailView = nullptr;
    QPushButton *m_startButton = nullptr;
    QPushButton *m_stopButton = nullptr;
    QPushButton *m_previewReportButton = nullptr;
    QString m_lastReportHtml;
    QDialog *m_reportPreviewDialog = nullptr;
    QTimer *m_statsRefreshTimer = nullptr;
    QTimer *m_stateWatchdogTimer = nullptr;
    qint64 m_lastHeavyRefreshMs = 0;
    QString m_lastWatchdogProgressKey;
    int m_stalledPollTicks = 0;
    bool m_visualCompletionOverride = false;
};
