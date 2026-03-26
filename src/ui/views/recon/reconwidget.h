#pragma once

#include <QWidget>

class QElapsedTimer;
class ReconModule;
class PenguFoceMasterScanner;
struct ScanReport;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QComboBox;
class QTabWidget;
class QDialog;
class QTextEdit;
class QWidget;
class QTimer;

class ReconWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ReconWidget(ReconModule *module, QWidget *parent = nullptr);
    void reloadSettings();
    void setActiveView(bool active);

private slots:
    void startRecon();
    void stopRecon();
    void handleStatus(const QString &message);
    void handleProgress(int percent);
    void handleFinding(const QString &severity, const QString &title, const QString &description);
    void handleFinished(const ScanReport &report, int securityScore);
    void updateFindingDetail();
    void refreshSpiderEvidence();

private:
    void buildUi();
    void appendFeed(const QString &message);
    QWidget *createInfoLabel(const QString &title, const QString &tooltip) const;
    void insertSeverityItem(QListWidget *list, const QString &severity, const QString &title, const QString &description);
    void insertSeverityItem(QListWidget *list, const QString &severity, const QString &title, const QString &description, const QString &sourceTag);
    void removeTaggedItems(QListWidget *list, const QString &sourceTag);
    void rebuildSpiderWarnings(const QVariantList &endpoints,
                               const QVariantList &parameters,
                               const QVariantList &assets,
                               const QVariantList &highValueTargets,
                               const QVariantMap &coverageBreakdown,
                               int coverageScore);
    void refreshSummaryCards(const ScanReport *report = nullptr);
    void refreshCategoryCards(const ScanReport *report = nullptr);
    void refreshFindingFilters();
    void refreshEvidenceFilters();
    QString phaseLabelForMessage(const QString &message) const;
    QString buildDiffSummary(const QVariantMap &currentReport, const QVariantMap &baselineReport) const;
    void refreshRelationshipView(const QVariantMap &reportVariant);
    void applySessionVariant(const QVariantMap &reportVariant, int securityScore, const QStringList &phaseHistory, const QStringList &feedEntries);
    QString detailHtmlForFinding(const QString &severity, const QString &title, const QString &description) const;
    int severityRank(const QString &severity) const;
    QString buildReportHtml(const ScanReport &report, int securityScore) const;
    void exportReport();
    void exportCsvReport();
    void saveSession();
    void openSession();
    void loadRecentTargets();
    void loadRecentSessions();
    void saveRecentTarget(const QString &target);
    void saveRecentSessionPath(const QString &path);
    void refreshTimelineFilter();

    ReconModule *m_module = nullptr;
    PenguFoceMasterScanner *m_masterScanner = nullptr;
    QLineEdit *m_targetEdit = nullptr;
    QLineEdit *m_endpointEdit = nullptr;
    QLineEdit *m_companyEdit = nullptr;
    QLineEdit *m_clientEdit = nullptr;
    QLineEdit *m_testerEdit = nullptr;
    QLineEdit *m_classificationEdit = nullptr;
    QLineEdit *m_scopeEdit = nullptr;
    QComboBox *m_targetPresetCombo = nullptr;
    QComboBox *m_recentTargetCombo = nullptr;
    QComboBox *m_scanProfileCombo = nullptr;
    QComboBox *m_recentSessionCombo = nullptr;
    QComboBox *m_findingsSeverityFilter = nullptr;
    QComboBox *m_timelineFilterCombo = nullptr;
    QLineEdit *m_findingsSearchEdit = nullptr;
    QLineEdit *m_evidenceSearchEdit = nullptr;
    QLabel *m_statusValue = nullptr;
    QLabel *m_scoreValue = nullptr;
    QLabel *m_activityValue = nullptr;
    QLabel *m_findingsCountValue = nullptr;
    QLabel *m_portsCountValue = nullptr;
    QLabel *m_subdomainCountValue = nullptr;
    QLabel *m_archiveCountValue = nullptr;
    QLabel *m_dnsCountValue = nullptr;
    QLabel *m_surfaceCountValue = nullptr;
    QLabel *m_osintCountValue = nullptr;
    QLabel *m_spiderCountValue = nullptr;
    QLabel *m_phaseSummaryValue = nullptr;
    QProgressBar *m_progressBar = nullptr;
    QWidget *m_pulseWidget = nullptr;
    QListWidget *m_findingsList = nullptr;
    QTextEdit *m_findingDetailView = nullptr;
    QListWidget *m_dnsList = nullptr;
    QListWidget *m_surfaceList = nullptr;
    QListWidget *m_osintList = nullptr;
    QListWidget *m_subdomainList = nullptr;
    QListWidget *m_archiveList = nullptr;
    QListWidget *m_jsFindingList = nullptr;
    QListWidget *m_cveList = nullptr;
    QListWidget *m_spiderEndpointList = nullptr;
    QListWidget *m_spiderParameterList = nullptr;
    QListWidget *m_spiderAssetList = nullptr;
    QListWidget *m_spiderHighValueList = nullptr;
    QListWidget *m_spiderTimelineList = nullptr;
    QLabel *m_spiderCoverageLabel = nullptr;
    QTextEdit *m_whoisSummaryView = nullptr;
    QTextEdit *m_relationshipView = nullptr;
    QTextEdit *m_analystNotesEdit = nullptr;
    QTextEdit *m_findingNoteEdit = nullptr;
    QListWidget *m_analysisTimelineList = nullptr;
    QLabel *m_diffSummaryValue = nullptr;
    QPlainTextEdit *m_feedConsole = nullptr;
    QPushButton *m_startButton = nullptr;
    QPushButton *m_stopButton = nullptr;
    QPushButton *m_previewReportButton = nullptr;
    QPushButton *m_exportJsonButton = nullptr;
    QPushButton *m_exportCsvButton = nullptr;
    QPushButton *m_saveSessionButton = nullptr;
    QPushButton *m_openSessionButton = nullptr;
    QPushButton *m_copyDetailButton = nullptr;
    QPushButton *m_saveFindingNoteButton = nullptr;
    QPushButton *m_addManualFindingButton = nullptr;
    QString m_lastReportHtml;
    QString m_lastReportJson;
    QStringList m_phaseHistory;
    QVariantMap m_lastReportVariant;
    QVariantMap m_compareBaselineVariant;
    QVariantMap m_findingNotes;
    QDialog *m_reportPreviewDialog = nullptr;
    QTextEdit *m_reportPreviewView = nullptr;
    QElapsedTimer *m_scanTimer = nullptr;
    QTimer *m_spiderRefreshTimer = nullptr;
};
