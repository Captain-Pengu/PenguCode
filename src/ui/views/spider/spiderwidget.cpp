#include "spiderwidget.h"

#include "modules/spider/engine/spiderreportbuilder.h"
#include "modules/spider/engine/spiderhostinsights.h"
#include "modules/spider/engine/spiderworkflow.h"
#include "modules/spider/spidermodule.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"
#include "ui/views/spider/spiderhosthealthpanel.h"
#include "ui/views/spider/spiderresultspanel.h"
#include "ui/views/spider/spidersetuppanel.h"
#include "ui/widgets/reportpreviewdialog.h"

#include <QCursor>
#include <QDateTime>
#include <QDir>
#include <QDialog>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QListWidget>
#include <QPageLayout>
#include <QPageSize>
#include <QPlainTextEdit>
#include <QPdfWriter>
#include <QPushButton>
#include <QSaveFile>
#include <QCheckBox>
#include <QColor>
#include <QComboBox>
#include <QRegularExpression>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QStandardPaths>
#include <QStringConverter>
#include <QSpinBox>
#include <QTabWidget>
#include <QTextDocument>
#include <QTextEdit>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QToolTip>
#include <QVBoxLayout>
#include <QSet>

namespace {

QWidget *makeSpiderInfoBlock(QWidget *parent, const QString &title, QLabel **valueLabel)
{
    auto *card = new QFrame(parent);
    card->setObjectName("summaryCard");
    card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(6);
    auto *titleLabel = new QLabel(title, card);
    titleLabel->setObjectName("mutedText");
    *valueLabel = new QLabel("--", card);
    (*valueLabel)->setObjectName("statValue");
    (*valueLabel)->setWordWrap(true);
    layout->addWidget(titleLabel);
    layout->addWidget(*valueLabel);
    return card;
}

QFrame *makeListCard(QWidget *parent, const QString &title, const QString &description, QListWidget **list)
{
    auto *card = new QFrame(parent);
    card->setObjectName("cardPanel");
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(12);
    auto *titleLabel = new QLabel(title, card);
    titleLabel->setObjectName("sectionTitle");
    *list = new QListWidget(card);
    (*list)->setAlternatingRowColors(true);
    layout->addWidget(titleLabel);
    if (!description.isEmpty()) {
        auto *infoLabel = new QLabel(description, card);
        infoLabel->setObjectName("mutedText");
        infoLabel->setWordWrap(true);
        layout->addWidget(infoLabel);
    }
    layout->addWidget(*list);
    return card;
}

QString friendlyOrigin(QString origin)
{
    origin.replace(':', " / ");
    return origin;
}

QString scopePresetDescription(const QString &preset)
{
    const QString normalized = preset.trimmed().toLower();
    if (normalized == QLatin1String("guvenli")) {
        return QObject::tr("Google font, analytics, tag manager ve yaygin ucuncu taraf servisleri agresif sekilde filtreler.");
    }
    if (normalized == QLatin1String("agresif")) {
        return QObject::tr("En genis tarama kapsami. Sadece font benzeri belirgin gurultu kaynaklarini eler.");
    }
    return QObject::tr("Dengeli profil. Google font ve temel analiz/tracker gurultusunu engeller, faydali yuzeyi korur.");
}

QString workflowPresetDescription(const QString &preset)
{
    const QString normalized = preset.trimmed().toLower();
    if (normalized == QLatin1String("basic-login")) {
        return QObject::tr("Tek adimli giris formu icin hizli baslangic. Formu alir, username/password yollar ve panel benzeri bir URL bekler.");
    }
    if (normalized == QLatin1String("csrf-login")) {
        return QObject::tr("CSRF tokenli klasik login akislari icin. Login sonrasi panel veya dashboard benzeri bir URL bekler.");
    }
    if (normalized == QLatin1String("multi-panel")) {
        return QObject::tr("Cok adimli panel akislari icin. Login, current state, profile veya dashboard gecislerini birlikte surer.");
    }
    if (normalized == QLatin1String("api-console")) {
        return QObject::tr("Yonetim paneli veya API konsolu icin daha agresif current-state replay ornegi.");
    }
    return QObject::tr("Hazir workflow secerek auth akisini hizli kur. Ozel ihtiyacta editoru dogrudan duzenleyebilirsin.");
}

QString workflowPresetBody(const QString &preset)
{
    const QString normalized = preset.trimmed().toLower();
    if (normalized == QLatin1String("basic-login")) {
        return QStringLiteral(
            "/login|POST|form|label=login|username={{username}}|password={{password}}|expect=!login|expect=url:/panel");
    }
    if (normalized == QLatin1String("csrf-login")) {
        return QStringLiteral(
            "/login|POST|form|label=csrf-login|username={{username}}|password={{password}}|expect=!login|expect=cookie:session\n"
            "@current|GET|direct|label=landing-check|optional|expect=url:/dashboard");
    }
    if (normalized == QLatin1String("multi-panel")) {
        return QStringLiteral(
            "/login|POST|form|label=primary-login|username={{username}}|password={{password}}|expect=!login|expect=cookie:session\n"
            "@current|GET|direct|label=post-login-landing|delay=350|expect=!redirect:login\n"
            "/profile|GET|direct|label=profile-probe|optional|delay=250|expect=!login");
    }
    if (normalized == QLatin1String("api-console")) {
        return QStringLiteral(
            "/login|POST|form|label=console-login|username={{username}}|password={{password}}|expect=!login|expect=header:set-cookie\n"
            "@current|GET|direct|label=session-check|delay=400|expect=!redirect:login\n"
            "/api/me|GET|direct|label=api-probe|optional|header:Accept=application/json|expect=status:200");
    }
    return QString();
}

QString evidenceKindLabel(const QString &kind)
{
    if (kind.startsWith("auth-")) {
        return QObject::tr("Auth");
    }
    if (kind.startsWith("automation-")) {
        return QObject::tr("Automation");
    }
    if (kind == QLatin1String("redirect-chain")) {
        return QObject::tr("Redirect");
    }
    if (kind == QLatin1String("response-signature")) {
        return QObject::tr("Imza");
    }
    if (kind.startsWith("render-")) {
        return QObject::tr("Render");
    }
    return QObject::tr("Diger");
}

QColor endpointTone(const QVariantMap &endpoint)
{
    const QString kind = endpoint.value("kind").toString();
    const QString sessionState = endpoint.value("sessionState").toString();
    const int statusCode = endpoint.value("statusCode").toInt();
    if (kind == QLatin1String("login-wall") || kind == QLatin1String("access-denied") || kind == QLatin1String("waf-challenge")) {
        return QColor("#f2a65a");
    }
    if (kind == QLatin1String("soft-404") || statusCode == 404) {
        return QColor("#9aa4b2");
    }
    if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
        return QColor("#79d292");
    }
    if (kind == QLatin1String("js-route")) {
        return QColor("#72c7ff");
    }
    if (sessionState == QLatin1String("oturumlu-ortak")) {
        return QColor("#9dd8ff");
    }
    return QColor("#d7dde7");
}

QString endpointBadge(const QVariantMap &endpoint)
{
    const QString kind = endpoint.value("kind").toString();
    const QString sessionState = endpoint.value("sessionState").toString();
    const int statusCode = endpoint.value("statusCode").toInt();
    if (kind == QLatin1String("login-wall") || kind == QLatin1String("access-denied") || kind == QLatin1String("waf-challenge")) {
        return QObject::tr("KORUNAN");
    }
    if (kind == QLatin1String("soft-404") || statusCode == 404) {
        return QObject::tr("404");
    }
    if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
        return QObject::tr("YENI");
    }
    if (kind == QLatin1String("js-route")) {
        return QObject::tr("JS");
    }
    return QObject::tr("YUZEY");
}

QColor categoryTone(const QString &label)
{
    const QString normalized = label.trimmed().toLower();
    if (normalized.contains("admin") || normalized.contains("auth")) {
        return QColor("#f1a14b");
    }
    if (normalized.contains("render") || normalized.contains("automation")) {
        return QColor("#72c7ff");
    }
    if (normalized.contains("secret")) {
        return QColor("#d38cff");
    }
    if (normalized.contains("upload")) {
        return QColor("#79d292");
    }
    return QColor("#d7dde7");
}

QString sanitizedFileStem(QString text)
{
    text = text.trimmed();
    if (text.isEmpty()) {
        return QStringLiteral("pengufoce-spider-raporu");
    }

    text.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9]+")), QStringLiteral("-"));
    while (text.contains(QStringLiteral("--"))) {
        text.replace(QStringLiteral("--"), QStringLiteral("-"));
    }
    text.remove(QRegularExpression(QStringLiteral("^-+|-+$")));
    return text.isEmpty() ? QStringLiteral("pengufoce-spider-raporu") : text.toLower();
}

QString spiderReportFileName(const QString &target, const QString &extension)
{
    return ::spiderReportFileName(target, extension);
}

QString spiderReportDefaultPath(const QString &target, const QString &extension)
{
    return ::spiderReportDefaultPath(target, extension);
}

QString hostFromSpiderAsset(const QVariantMap &asset)
{
    const QString kind = asset.value("kind").toString();
    const QString sourceHost = QUrl(asset.value("source").toString()).host().toLower().trimmed();
    if (!sourceHost.isEmpty()) {
        return sourceHost;
    }

    const QString valueText = asset.value("value").toString();
    if (kind == QLatin1String("host-pressure")
        || kind == QLatin1String("retry-after")
        || kind == QLatin1String("retry-scheduled"))
    {
        const QRegularExpression hostRegex(QStringLiteral("host=([^|]+)"));
        const auto match = hostRegex.match(valueText);
        if (match.hasMatch()) {
            return match.captured(1).trimmed().toLower();
        }
    }

    return QObject::tr("(bilinmiyor)");
}

bool saveSpiderPdfReport(const QString &path, const QString &html, QString *errorMessage)
{
    return ::saveSpiderPdfReport(path, html, errorMessage);
}

bool shouldSuppressReportAsset(const QVariantMap &row)
{
    const QString kind = row.value("kind").toString();
    const QString value = row.value("value").toString();
    if ((kind == QLatin1String("literal") || kind == QLatin1String("js-literal"))
        && value.startsWith(QStringLiteral("jwt:"), Qt::CaseInsensitive)) {
        if (value.contains(QStringLiteral("beacon.min.js"), Qt::CaseInsensitive)
            || value.contains(QStringLiteral("static.cloudflare"), Qt::CaseInsensitive)
            || value.contains(QStringLiteral("document.body"), Qt::CaseInsensitive)
            || value.contains(QStringLiteral("a.style."), Qt::CaseInsensitive)
            || value.contains(QStringLiteral("www.w3.org"), Qt::CaseInsensitive)
            || value.contains(QStringLiteral("window.location"), Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

}

SpiderWidget::SpiderWidget(SpiderModule *module, QWidget *parent)
    : QWidget(parent)
    , m_module(module)
{
    m_statsRefreshTimer = new QTimer(this);
    m_statsRefreshTimer->setSingleShot(true);
    m_statsRefreshTimer->setInterval(80);
    connect(m_statsRefreshTimer, &QTimer::timeout, this, &SpiderWidget::refreshStats);

    m_stateWatchdogTimer = new QTimer(this);
    m_stateWatchdogTimer->setInterval(3000);
    connect(m_stateWatchdogTimer, &QTimer::timeout, this, &SpiderWidget::pollStalledState);
    m_stateWatchdogTimer->start();

    auto *outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    auto *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    auto *page = new QWidget(scrollArea);
    auto *root = new QVBoxLayout(page);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(18);

    auto *hero = pengufoce::ui::layout::createHeroCard(this);
    auto *heroLayout = qobject_cast<QVBoxLayout *>(hero->layout());

    auto *heroTopBar = new QHBoxLayout();
    heroTopBar->setSpacing(12);
    auto *title = new QLabel(tr("Spider Orbiti"), hero);
    title->setObjectName("heroTitle");
    auto *subtitle = new QLabel(tr("Hedef yuzeyi kesfeder."), hero);
    subtitle->setObjectName("mutedText");
    subtitle->setWordWrap(true);
    m_previewReportButton = new QPushButton(tr("PDF Onizle"), hero);
    m_previewReportButton->setEnabled(false);
    heroTopBar->addWidget(title);
    heroTopBar->addStretch();
    heroTopBar->addWidget(m_previewReportButton, 0, Qt::AlignTop);

    auto *summaryHost = new QWidget(hero);
    auto *summary = new FlowLayout(summaryHost, 0, 12, 12);
    auto *statusCard = makeSpiderInfoBlock(hero, tr("Durum"), &m_statusValue);
    auto *countsCard = makeSpiderInfoBlock(hero, tr("Gezilen / Kuyruk"), &m_countsValue);
    auto *coverageCard = makeSpiderInfoBlock(hero, tr("Yuzey Puani"), &m_coverageValue);
    statusCard->setMinimumWidth(116);
    countsCard->setMinimumWidth(116);
    coverageCard->setMinimumWidth(116);
    summary->addWidget(statusCard);
    summary->addWidget(countsCard);
    summary->addWidget(coverageCard);
    summaryHost->setLayout(summary);
    m_coverageSummaryLabel = new QLabel(hero);
    m_coverageSummaryLabel->setObjectName("mutedText");
    m_coverageSummaryLabel->setWordWrap(true);
    m_coverageBreakdownLabel = new QLabel(hero);
    m_coverageBreakdownLabel->setObjectName("mutedText");
    m_coverageBreakdownLabel->setWordWrap(true);
    m_automationLabel = new QLabel(hero);
    m_automationLabel->setObjectName("mutedText");
    m_automationLabel->setWordWrap(true);
    m_benchmarkLabel = new QLabel(hero);
    m_benchmarkLabel->setObjectName("mutedText");
    m_benchmarkLabel->setWordWrap(true);
    m_benchmarkLabel->setVisible(false);
    m_benchmarkDiffLabel = new QLabel(hero);
    m_benchmarkDiffLabel->setObjectName("mutedText");
    m_benchmarkDiffLabel->setWordWrap(true);
    m_benchmarkDiffLabel->setVisible(false);
    m_regressionLabel = new QLabel(hero);
    m_regressionLabel->setObjectName("mutedText");
    m_regressionLabel->setWordWrap(true);
    m_regressionLabel->setVisible(false);
    m_insightLabel = new QLabel(hero);
    m_insightLabel->setObjectName("mutedText");
    m_insightLabel->setWordWrap(true);
    heroLayout->addLayout(heroTopBar);
    heroLayout->addWidget(subtitle);
    heroLayout->addWidget(summaryHost);
    heroLayout->addWidget(m_coverageSummaryLabel);
    heroLayout->addWidget(m_coverageBreakdownLabel);
    heroLayout->addWidget(m_automationLabel);
    m_hostHealthSummaryLabel = new QLabel(hero);
    m_hostHealthSummaryLabel->setObjectName("mutedText");
    m_hostHealthSummaryLabel->setWordWrap(true);
    heroLayout->addWidget(m_hostHealthSummaryLabel);
    heroLayout->addWidget(m_insightLabel);

    auto *setupPanel = new SpiderSetupPanel(this);
    m_targetEdit = setupPanel->targetEdit();
    m_stageCombo = setupPanel->stageCombo();
    m_maxPagesSpin = setupPanel->maxPagesSpin();
    m_maxDepthSpin = setupPanel->maxDepthSpin();
    m_timeoutSpin = setupPanel->timeoutSpin();
    m_scopePresetCombo = setupPanel->scopePresetCombo();
    m_allowSubdomainsCheck = setupPanel->allowSubdomainsCheck();
    m_includePatternsEdit = setupPanel->includePatternsEdit();
    m_excludePatternsEdit = setupPanel->excludePatternsEdit();
    m_loginUrlEdit = setupPanel->loginUrlEdit();
    m_authUsernameEdit = setupPanel->authUsernameEdit();
    m_authPasswordEdit = setupPanel->authPasswordEdit();
    m_usernameFieldEdit = setupPanel->usernameFieldEdit();
    m_passwordFieldEdit = setupPanel->passwordFieldEdit();
    m_csrfFieldEdit = setupPanel->csrfFieldEdit();
    m_authWorkflowPresetCombo = setupPanel->authWorkflowPresetCombo();
    m_authWorkflowHintLabel = setupPanel->authWorkflowHintLabel();
    m_workflowValidationLabel = setupPanel->workflowValidationLabel();
    m_applyWorkflowPresetButton = setupPanel->applyWorkflowPresetButton();
    m_authWorkflowEdit = setupPanel->authWorkflowEdit();
    m_startButton = setupPanel->startButton();
    m_stopButton = setupPanel->stopButton();
    m_scopeCard = setupPanel->scopeCard();
    m_authCard = setupPanel->authCard();
    m_advancedCard = setupPanel->advancedCard();
    if (setupPanel->scopePresetInfoLabel()) {
        setupPanel->scopePresetInfoLabel()->setText(scopePresetDescription(QStringLiteral("dengeli")));
    }

    auto *setupTab = new QWidget(this);
    auto *setupTabLayout = new QVBoxLayout(setupTab);
    setupTabLayout->setContentsMargins(0, 0, 0, 0);
    setupTabLayout->setSpacing(14);
    setupTabLayout->addWidget(setupPanel);
    setupTabLayout->addStretch();

    auto *resultsPanel = new SpiderResultsPanel(this);
    m_console = resultsPanel->console();
    m_assetFilterCombo = resultsPanel->assetFilterCombo();
    m_evidenceList = resultsPanel->evidenceList();
    m_evidenceDetailView = resultsPanel->evidenceDetailView();
    m_endpointFilterCombo = resultsPanel->endpointFilterCombo();
    m_endpointList = resultsPanel->endpointList();
    m_parameterList = resultsPanel->parameterList();
    m_assetList = resultsPanel->assetList();
    m_highValueList = resultsPanel->highValueList();
    m_segmentList = resultsPanel->segmentList();
    m_benchmarkHistoryList = resultsPanel->benchmarkHistoryList();
    m_timelineList = resultsPanel->timelineList();
    m_featureList = resultsPanel->featureList();
    if (auto *hostCard = qobject_cast<SpiderHostHealthPanel *>(resultsPanel->hostPanel())) {
        m_hostHealthList = hostCard->hostHealthList();
        m_hostTimelineList = hostCard->hostTimelineList();
        m_hostFilterCombo = hostCard->hostFilterCombo();
        m_exportHostDiagnosticsButton = hostCard->exportHostDiagnosticsButton();
        m_hostStableValue = hostCard->hostStableValue();
        m_hostGuardedValue = hostCard->hostGuardedValue();
        m_hostWafValue = hostCard->hostWafValue();
        m_hostStressedValue = hostCard->hostStressedValue();
        m_hostReplayDiffLabel = hostCard->hostReplayDiffLabel();
        m_hostPressureTrendLabel = hostCard->hostPressureTrendLabel();
    }
    resultsPanel->setSetupTab(setupTab);
    m_workTabs = resultsPanel->workTabs();

    root->addWidget(hero);
    root->addWidget(resultsPanel, 1);
    page->setLayout(root);
    scrollArea->setWidget(page);
    outerLayout->addWidget(scrollArea);

    connect(m_startButton, &QPushButton::clicked, this, &SpiderWidget::startSpider);
    connect(m_stopButton, &QPushButton::clicked, this, &SpiderWidget::stopSpider);
    connect(m_stageCombo, &QComboBox::currentIndexChanged, this, &SpiderWidget::applyStagePreset);

    if (m_module) {
        connect(m_module, &SpiderModule::crawlEvent, this, &SpiderWidget::appendEvent);
        connect(m_module, &SpiderModule::endpointDiscovered, this, &SpiderWidget::handleEndpoint);
        connect(m_module, &SpiderModule::parameterDiscovered, this, &SpiderWidget::handleParameter);
        connect(m_module, &SpiderModule::assetDiscovered, this, &SpiderWidget::handleAsset);
        connect(m_module, &SpiderModule::crawlFinished, this, &SpiderWidget::handleFinished);
        connect(m_module, &SpiderModule::statsChanged, this, &SpiderWidget::scheduleStatsRefresh);
        connect(m_module, &SpiderModule::statusChanged, this, &SpiderWidget::scheduleStatsRefresh);
    }
    connect(m_evidenceList, &QListWidget::currentItemChanged, this, &SpiderWidget::updateEvidenceDetail);
    connect(m_scopePresetCombo, &QComboBox::currentIndexChanged, this, [this, setupPanel]() {
        if (setupPanel->scopePresetInfoLabel()) {
            setupPanel->scopePresetInfoLabel()->setText(scopePresetDescription(m_scopePresetCombo->currentData().toString()));
        }
    });
    connect(m_authWorkflowPresetCombo, &QComboBox::currentIndexChanged, this, &SpiderWidget::applyWorkflowPreset);
    connect(m_applyWorkflowPresetButton, &QPushButton::clicked, this, [this]() {
        applyWorkflowPreset(m_authWorkflowPresetCombo ? m_authWorkflowPresetCombo->currentIndex() : 0);
    });
    connect(m_authWorkflowEdit, &QPlainTextEdit::textChanged, this, &SpiderWidget::refreshWorkflowValidation);
    connect(m_scopePresetCombo, &QComboBox::currentIndexChanged, this, &SpiderWidget::applyScopePreset);
    connect(m_endpointFilterCombo, &QComboBox::currentIndexChanged, this, &SpiderWidget::refreshFilteredResults);
    connect(m_assetFilterCombo, &QComboBox::currentIndexChanged, this, &SpiderWidget::refreshFilteredResults);
    connect(m_previewReportButton, &QPushButton::clicked, this, &SpiderWidget::exportReport);
    if (m_hostFilterCombo) {
        connect(m_hostFilterCombo, &QComboBox::currentIndexChanged, this, &SpiderWidget::refreshStats);
    }
    if (m_exportHostDiagnosticsButton) {
        connect(m_exportHostDiagnosticsButton, &QPushButton::clicked, this, &SpiderWidget::exportHostDiagnostics);
    }

    reloadSettings();
}

void SpiderWidget::reloadSettings()
{
    if (!m_module) {
        return;
    }

    m_module->reloadSettings();
    m_targetEdit->setText(m_module->targetUrl());
    m_stageCombo->setCurrentIndex(qBound(0, m_module->scanStage(), 2));
    m_maxPagesSpin->setValue(m_module->maxPages());
    m_maxDepthSpin->setValue(m_module->maxDepth());
    m_timeoutSpin->setValue(m_module->requestTimeoutMs());
    const int scopePresetIndex = qMax(0, m_scopePresetCombo->findData(m_module->scopePreset()));
    m_scopePresetCombo->setCurrentIndex(scopePresetIndex);
    m_allowSubdomainsCheck->setChecked(m_module->allowSubdomains());
    m_includePatternsEdit->setPlainText(m_module->includePatterns());
    m_excludePatternsEdit->setPlainText(m_module->excludePatterns());
    m_loginUrlEdit->setText(m_module->loginUrl());
    m_authUsernameEdit->setText(m_module->authUsername());
    m_authPasswordEdit->setText(m_module->authPassword());
    m_usernameFieldEdit->setText(m_module->usernameField());
    m_passwordFieldEdit->setText(m_module->passwordField());
    m_csrfFieldEdit->setText(m_module->csrfField());
    m_authWorkflowEdit->setPlainText(m_module->authWorkflow());
    if (m_authWorkflowPresetCombo) {
        m_authWorkflowPresetCombo->setCurrentIndex(0);
    }
    if (m_authWorkflowHintLabel) {
        m_authWorkflowHintLabel->setText(workflowPresetDescription(QStringLiteral("custom")));
    }
    refreshWorkflowValidation();
    applyStagePreset(m_stageCombo->currentIndex());
    applyScopePreset();
    refreshStats();
    refreshFilteredResults();
}

void SpiderWidget::startSpider()
{
    if (!m_module) {
        return;
    }

    m_endpointList->clear();
    m_parameterList->clear();
    m_assetList->clear();
    m_evidenceList->clear();
    m_console->clear();
    m_lastReportHtml.clear();
    m_visualCompletionOverride = false;
    if (m_previewReportButton) {
        m_previewReportButton->setEnabled(false);
    }

    m_module->setTargetUrl(m_targetEdit->text().trimmed());
    m_module->setScanStage(m_stageCombo->currentIndex());
    m_module->setMaxPages(m_maxPagesSpin->value());
    m_module->setMaxDepth(m_maxDepthSpin->value());
    m_module->setRequestTimeoutMs(m_timeoutSpin->value());
    m_module->setScopePreset(m_scopePresetCombo->currentData().toString());
    m_module->setAllowSubdomains(m_allowSubdomainsCheck->isChecked());
    m_module->setIncludePatterns(m_includePatternsEdit->toPlainText().trimmed());
    m_module->setExcludePatterns(m_excludePatternsEdit->toPlainText().trimmed());
    m_module->setLoginUrl(m_loginUrlEdit->text().trimmed());
    m_module->setAuthUsername(m_authUsernameEdit->text().trimmed());
    m_module->setAuthPassword(m_authPasswordEdit->text());
    m_module->setUsernameField(m_usernameFieldEdit->text().trimmed());
    m_module->setPasswordField(m_passwordFieldEdit->text().trimmed());
    m_module->setCsrfField(m_csrfFieldEdit->text().trimmed());
    m_module->setAuthWorkflow(m_authWorkflowEdit->toPlainText().trimmed());
    m_module->start();
    refreshLiveHeader();
    scheduleStatsRefresh();
}

void SpiderWidget::stopSpider()
{
    if (!m_module) {
        return;
    }
    m_module->stop();
    refreshLiveHeader();
    scheduleStatsRefresh();
}

void SpiderWidget::appendEvent(const QString &message)
{
    if (message.startsWith(QStringLiteral("[scheduler]"))) {
        return;
    }
    m_console->appendPlainText(message);
    if (m_console->blockCount() > 500) {
        QTextCursor cursor(m_console->document());
        cursor.movePosition(QTextCursor::Start);
        cursor.select(QTextCursor::BlockUnderCursor);
        cursor.removeSelectedText();
        cursor.deleteChar();
    }
    refreshLiveHeader();
}

void SpiderWidget::handleEndpoint(const QVariantMap &endpoint)
{
    const QString sessionState = endpoint.value("sessionState").toString();
    const QString stateLabel = sessionState == QLatin1String("oturumlu-yeni-yuzey")
        ? tr("OTURUMLU-YENI")
        : (sessionState == QLatin1String("oturumlu-ortak") ? tr("OTURUMLU") : tr("ANONIM"));
    const QString contentType = endpoint.value("contentType").toString();
    const QString pageTitle = endpoint.value("pageTitle").toString();
    const QString meta = QString("%1  d%2  HTTP %3%4%5")
                             .arg(stateLabel)
                             .arg(endpoint.value("depth").toInt())
                             .arg(endpoint.value("statusCode").toInt())
                             .arg(contentType.isEmpty() ? QString() : QString("  %1").arg(contentType))
                             .arg(pageTitle.isEmpty() ? QString() : QString("  |  %1").arg(pageTitle));
    auto *item = new QListWidgetItem(QString("[%1] %2  |  %3")
                                         .arg(endpointBadge(endpoint),
                                              endpoint.value("url").toString(),
                                              meta));
    item->setData(Qt::UserRole, endpoint);
    item->setForeground(endpointTone(endpoint));
    m_endpointList->insertItem(0, item);
    item->setHidden(!endpointMatchesFilter(item));
    refreshLiveHeader();
}

void SpiderWidget::handleParameter(const QVariantMap &parameter)
{
    m_parameterList->insertItem(0, QString("%1  [%2]  ->  %3")
                                      .arg(parameter.value("name").toString(),
                                           friendlyOrigin(parameter.value("origin").toString()),
                                           parameter.value("url").toString()));
    refreshLiveHeader();
}

void SpiderWidget::handleAsset(const QVariantMap &asset)
{
    const QString kind = asset.value("kind").toString();
    const QString line = QString("[%1] %2").arg(kind, asset.value("value").toString());
    if (kind.startsWith("auth-")
        || kind.startsWith("workflow-")
        || kind == "redirect-chain"
        || kind == "response-signature"
        || kind == "waf-vendor"
        || kind == "waf-challenge"
        || kind == "crawl-suppressed"
        || kind == "scope-outlier"
        || kind == "scope-excluded"
        || kind.startsWith("render-")
        || kind.startsWith("automation-")) {
        auto *item = new QListWidgetItem(line);
        item->setData(Qt::UserRole, asset);
        if (kind.startsWith("auth-")) {
            item->setForeground(QColor("#f18f43"));
        } else if (kind.startsWith("workflow-")) {
            item->setForeground(QColor("#d6b0ff"));
        } else if (kind == "waf-vendor" || kind == "waf-challenge") {
            item->setForeground(QColor("#ffb26b"));
        } else if (kind == "crawl-suppressed" || kind == "scope-outlier" || kind == "scope-excluded") {
            item->setForeground(QColor("#9aa4b2"));
        } else if (kind.startsWith("render-")) {
            item->setForeground(QColor("#87d4a3"));
        } else if (kind.startsWith("automation-")) {
            item->setForeground(QColor("#7cc7ff"));
        }
        m_evidenceList->insertItem(0, item);
        item->setHidden(!assetMatchesFilter(item));
    } else {
        m_assetList->insertItem(0, line);
    }
    refreshLiveHeader();
}

void SpiderWidget::handleFinished()
{
    m_visualCompletionOverride = false;
    appendEvent(tr("Spider taramasi tamamlandi."));
    m_lastReportHtml = buildReportHtml();
    if (m_previewReportButton) {
        m_previewReportButton->setEnabled(!m_lastReportHtml.isEmpty());
    }
    refreshLiveHeader();
    refreshStats();
}

void SpiderWidget::applyStagePreset(int index)
{
    const bool showScope = index >= 1;
    const bool showAuth = index >= 1;
    const bool showAdvanced = index >= 2;

    if (m_scopeCard) {
        m_scopeCard->setVisible(showScope);
    }
    if (m_authCard) {
        m_authCard->setVisible(showAuth);
    }
    if (m_advancedCard) {
        m_advancedCard->setVisible(showAdvanced);
    }
    if (m_workTabs) {
        m_workTabs->setTabEnabled(1, true);
        m_workTabs->setTabEnabled(2, true);
        if (m_workTabs->currentIndex() < 0 || m_workTabs->currentIndex() > 2) {
            m_workTabs->setCurrentIndex(0);
        }
    }

    if (index == 0) {
        m_maxPagesSpin->setValue(qMin(m_maxPagesSpin->value(), 60));
        m_maxDepthSpin->setValue(qMin(m_maxDepthSpin->value(), 3));
    } else if (index == 1) {
        m_maxPagesSpin->setValue(qMax(m_maxPagesSpin->value(), 80));
        m_maxDepthSpin->setValue(qMax(m_maxDepthSpin->value(), 4));
    }
}

void SpiderWidget::applyScopePreset()
{
    if (!m_scopePresetCombo) {
        return;
    }

    const QString preset = m_scopePresetCombo->currentData().toString();
    if (preset == QLatin1String("guvenli")) {
        m_timeoutSpin->setValue(qMax(m_timeoutSpin->value(), 2800));
        m_maxDepthSpin->setValue(qMin(m_maxDepthSpin->value(), 4));
        m_maxPagesSpin->setValue(qMin(m_maxPagesSpin->value(), 70));
    } else if (preset == QLatin1String("agresif")) {
        m_timeoutSpin->setValue(qMin(m_timeoutSpin->value(), 2200));
        m_maxDepthSpin->setValue(qMax(m_maxDepthSpin->value(), 5));
        m_maxPagesSpin->setValue(qMax(m_maxPagesSpin->value(), 120));
    } else {
        m_timeoutSpin->setValue(qBound(1800, m_timeoutSpin->value(), 3200));
        m_maxDepthSpin->setValue(qBound(3, m_maxDepthSpin->value(), 5));
        m_maxPagesSpin->setValue(qBound(60, m_maxPagesSpin->value(), 100));
    }
}

void SpiderWidget::applyWorkflowPreset(int index)
{
    Q_UNUSED(index);
    if (!m_authWorkflowPresetCombo || !m_authWorkflowHintLabel) {
        return;
    }

    const QString preset = m_authWorkflowPresetCombo->currentData().toString();
    m_authWorkflowHintLabel->setText(workflowPresetDescription(preset));
    if (preset == QLatin1String("custom") || !m_authWorkflowEdit) {
        return;
    }

    const QString presetBody = workflowPresetBody(preset);
    if (!presetBody.trimmed().isEmpty()) {
        m_authWorkflowEdit->setPlainText(presetBody);
    }
}

void SpiderWidget::refreshWorkflowValidation()
{
    if (!m_authWorkflowEdit || !m_workflowValidationLabel) {
        return;
    }

    const QString text = m_authWorkflowEdit->toPlainText().trimmed();
    if (text.isEmpty()) {
        m_workflowValidationLabel->setText(tr("Workflow dogrulamasi: editor bos. Hazir preset secilebilir veya ozel akÄ±s yazilabilir."));
        return;
    }

    const SpiderWorkflowValidationResult validation = validateSpiderWorkflowText(text);
    if (validation.valid()) {
        m_workflowValidationLabel->setText(tr("Workflow dogrulamasi: %1 adim gecerli gorunuyor. Relative URL, @current, optional ve delay kullanilabilir.").arg(validation.validSteps));
    } else {
        m_workflowValidationLabel->setText(tr("Workflow dogrulamasi uyarilari: %1").arg(validation.issues.join(QStringLiteral(" | "))));
    }
}

void SpiderWidget::updateEvidenceDetail()
{
    if (!m_evidenceList || !m_evidenceDetailView) {
        return;
    }

    QListWidgetItem *item = m_evidenceList->currentItem();
    if (!item) {
        m_evidenceDetailView->setHtml(tr("<h3>Kanit detayi</h3><p>Bir kayit sec.</p>"));
        return;
    }

    const QVariantMap asset = item->data(Qt::UserRole).toMap();
    const QString kind = asset.value("kind").toString();
    const QString value = asset.value("value").toString();
    const QString source = asset.value("source").toString();
    QString extra;
    if (kind.startsWith(QStringLiteral("workflow-"))) {
        extra = tr("<p><b>Workflow:</b> Replay aday/sonuc zincirinin parcasi.</p>");
    } else if (kind == QLatin1String("waf-vendor")) {
        extra = tr("<p><b>Sinif:</b> WAF saglayici ipucu.</p>");
    } else if (kind == QLatin1String("host-pressure")) {
        extra = tr("<p><b>Sinif:</b> Host bazli baski ve backoff telemetrisi.</p>");
    } else if (kind == QLatin1String("crawl-suppressed")) {
        extra = tr("<p><b>Sinif:</b> Guvenlik nedeniyle baskilanan hedef.</p>");
    }
    m_evidenceDetailView->setHtml(QString(
        "<html><body style='font-family:Bahnschrift;padding:10px;font-size:11pt;'>"
        "<h3 style='margin:0 0 8px 0;'>%1</h3>"
        "<p><b>Kaynak:</b> %2</p>"
        "%4"
        "<p><b>Detay:</b></p>"
        "<pre style='white-space:pre-wrap;background:#111722;border:1px solid #334154;border-radius:8px;padding:10px;'>%3</pre>"
        "</body></html>")
        .arg(kind.toHtmlEscaped(),
             source.toHtmlEscaped(),
             value.toHtmlEscaped(),
             extra));
}

void SpiderWidget::refreshFilteredResults()
{
    if (m_endpointList && m_endpointFilterCombo) {
        for (int i = 0; i < m_endpointList->count(); ++i) {
            QListWidgetItem *item = m_endpointList->item(i);
            item->setHidden(!endpointMatchesFilter(item));
        }
    }
    if (m_evidenceList && m_assetFilterCombo) {
        for (int i = 0; i < m_evidenceList->count(); ++i) {
            QListWidgetItem *item = m_evidenceList->item(i);
            item->setHidden(!assetMatchesFilter(item));
        }
    }
}

bool SpiderWidget::endpointMatchesFilter(const QListWidgetItem *item) const
{
    if (!item || !m_endpointFilterCombo) {
        return true;
    }
    const QVariantMap endpoint = item->data(Qt::UserRole).toMap();
    const QString filter = m_endpointFilterCombo->currentData().toString();
    const QString kind = endpoint.value("kind").toString();
    const QString sessionState = endpoint.value("sessionState").toString();
    if (filter == QLatin1String("forms")) {
        return kind.startsWith("form:") || kind == QLatin1String("login-form") || kind == QLatin1String("login-wall");
    }
    if (filter == QLatin1String("delta")) {
        return sessionState == QLatin1String("oturumlu-yeni-yuzey");
    }
    if (filter == QLatin1String("js")) {
        return kind == QLatin1String("js-route");
    }
    if (filter == QLatin1String("protected")) {
        return kind == QLatin1String("login-wall")
            || kind == QLatin1String("access-denied")
            || kind == QLatin1String("waf-challenge");
    }
    if (filter == QLatin1String("missing")) {
        return kind == QLatin1String("soft-404")
            || endpoint.value("statusCode").toInt() == 404;
    }
    return true;
}

bool SpiderWidget::assetMatchesFilter(const QListWidgetItem *item) const
{
    if (!item || !m_assetFilterCombo) {
        return true;
    }
    const QVariantMap asset = item->data(Qt::UserRole).toMap();
    const QString kind = asset.value("kind").toString();
    const QString filter = m_assetFilterCombo->currentData().toString();
    if (filter == QLatin1String("auth")) {
        return kind.startsWith("auth-");
    }
    if (filter == QLatin1String("redirect")) {
        return kind == QLatin1String("redirect-chain");
    }
    if (filter == QLatin1String("signature")) {
        return kind == QLatin1String("response-signature");
    }
    if (filter == QLatin1String("workflow")) {
        return kind.startsWith(QStringLiteral("workflow-")) || kind.startsWith(QStringLiteral("auth-step-"));
    }
    if (filter == QLatin1String("waf")) {
        return kind == QLatin1String("waf-challenge")
            || kind == QLatin1String("waf-vendor")
            || kind == QLatin1String("host-pressure")
            || kind == QLatin1String("retry-after")
            || kind == QLatin1String("retry-scheduled");
    }
    if (filter == QLatin1String("pressure")) {
        return kind == QLatin1String("host-pressure")
            || kind == QLatin1String("retry-after")
            || kind == QLatin1String("retry-scheduled");
    }
    if (filter == QLatin1String("suppressed")) {
        return kind == QLatin1String("crawl-suppressed")
            || kind == QLatin1String("scope-outlier")
            || kind == QLatin1String("scope-excluded");
    }
    if (filter == QLatin1String("render")) {
        return kind.startsWith("render-");
    }
    if (filter == QLatin1String("automation")) {
        return kind.startsWith("automation-");
    }
    return true;
}

QWidget *SpiderWidget::createInfoLabel(const QString &title, const QString &tooltip) const
{
    auto *container = new QWidget(const_cast<SpiderWidget *>(this));
    auto *layout = new QHBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);
    auto *label = new QLabel(title, container);
    label->setObjectName("mutedText");
    auto *button = new QToolButton(container);
    button->setObjectName("infoButton");
    button->setText("i");
    button->setFixedSize(18, 18);
    button->setCursor(Qt::PointingHandCursor);
    button->setToolTip(tooltip);
    connect(button, &QToolButton::clicked, button, [button, tooltip]() {
        QToolTip::showText(QCursor::pos(), tooltip, button);
    });
    layout->addWidget(label);
    layout->addWidget(button);
    layout->addStretch();
    return container;
}

void SpiderWidget::refreshLiveHeader()
{
    if (!m_module) {
        return;
    }

    if (m_visualCompletionOverride) {
        m_statusValue->setText(tr("Spider tamamlandi"));
    } else {
        m_statusValue->setText(m_module->statusText());
    }
    m_countsValue->setText(QString("%1 / %2").arg(m_module->visitedCount()).arg(m_module->queuedCount()));
    m_coverageValue->setText(QString::number(m_module->coverageScore()));
    if (m_coverageSummaryLabel) {
        m_coverageSummaryLabel->setText(m_module->coverageSummary());
    }
    const QVariantMap breakdown = m_module->coverageBreakdown();
    int workflowCandidates = 0;
    int workflowResults = 0;
    int wafHits = 0;
    int suppressedHits = 0;
    int pressureHits = 0;
    for (const QVariant &value : m_module->assets()) {
        const QString kind = value.toMap().value("kind").toString();
        if (kind == QLatin1String("workflow-submit-candidate") || kind == QLatin1String("workflow-action-candidate")) {
            ++workflowCandidates;
        } else if (kind == QLatin1String("workflow-submit-result") || kind == QLatin1String("workflow-action-result")) {
            ++workflowResults;
        } else if (kind == QLatin1String("waf-vendor") || kind == QLatin1String("waf-challenge")) {
            ++wafHits;
        } else if (kind == QLatin1String("host-pressure") || kind == QLatin1String("retry-after") || kind == QLatin1String("retry-scheduled")) {
            ++pressureHits;
        } else if (kind == QLatin1String("crawl-suppressed")
                   || kind == QLatin1String("scope-outlier")
                   || kind == QLatin1String("scope-excluded")) {
            ++suppressedHits;
        }
    }
    m_coverageBreakdownLabel->setText(
        tr("auth %1  form %2  js %3  secret %4  admin %5  upload %6  delta %7  korunan %8  404 %9  render %10  automation %11")
            .arg(breakdown.value("auth").toInt())
            .arg(breakdown.value("form").toInt())
            .arg(breakdown.value("js").toInt())
            .arg(breakdown.value("secret").toInt())
            .arg(breakdown.value("admin").toInt())
            .arg(breakdown.value("upload").toInt())
            .arg(breakdown.value("delta").toInt())
            .arg(breakdown.value("protected").toInt())
            .arg(breakdown.value("missing").toInt())
            .arg(breakdown.value("render").toInt())
            .arg(breakdown.value("automation").toInt()));
    m_automationLabel->setText(tr("Workflow aday %1 | replay sonuc %2 | WAF %3 | pressure %4 | baskilanan hedef %5 | %6")
                                   .arg(workflowCandidates)
                                   .arg(workflowResults)
                                   .arg(wafHits)
                                   .arg(pressureHits)
                                   .arg(suppressedHits)
                                   .arg(m_module->automationSafetyStatus()));
    if (m_hostHealthSummaryLabel) {
        m_hostHealthSummaryLabel->setText(tr("Host telemetrisi: WAF %1 | pressure %2 | retry/backoff olaylari canli host sagligi paneline islenir.")
                                              .arg(wafHits)
                                              .arg(pressureHits));
    }
    m_benchmarkLabel->setText(m_module->benchmarkSummary());
    m_benchmarkDiffLabel->setText(m_module->benchmarkDiffSummary());
    m_regressionLabel->setText(m_module->regressionSummary());
    if (m_insightLabel) {
        m_insightLabel->setText(QString("%1\n%2\n%3")
                                    .arg(m_benchmarkLabel->text(),
                                         m_benchmarkDiffLabel->text(),
                                         m_regressionLabel->text()));
    }
}

void SpiderWidget::applyVisualCompletionFallback()
{
    if (!m_module) {
        return;
    }

    m_visualCompletionOverride = true;
    appendEvent(tr("[ui] Spider gorunur ilerleme tamamlandigi icin arayuz tamamlanmis moda gecirildi."));
    m_lastReportHtml = buildReportHtml();
    if (m_previewReportButton) {
        m_previewReportButton->setEnabled(!m_lastReportHtml.isEmpty());
    }
    refreshLiveHeader();
    refreshStats();
}

void SpiderWidget::refreshStats()
{
    if (!m_module) {
        return;
    }

    refreshLiveHeader();
    if (m_previewReportButton) {
        const bool hasData = !m_module->endpoints().isEmpty() || !m_module->assets().isEmpty() || !m_module->parameters().isEmpty();
        if (!m_module->scanning() && hasData) {
            m_lastReportHtml = buildReportHtml();
            m_previewReportButton->setEnabled(!m_lastReportHtml.isEmpty());
        } else {
            m_previewReportButton->setEnabled(false);
        }
    }

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const bool allowHeavyRefresh = !m_module->scanning() || (nowMs - m_lastHeavyRefreshMs) >= 900;
    if (!allowHeavyRefresh) {
        return;
    }
    m_lastHeavyRefreshMs = nowMs;

    if (m_highValueList) {
        m_highValueList->clear();
        for (const QVariant &value : m_module->highValueTargets()) {
            const QVariantMap row = value.toMap();
            auto *item = new QListWidgetItem(QString("[%1] %2").arg(row.value("label").toString(), row.value("value").toString()));
            item->setForeground(categoryTone(row.value("label").toString()));
            m_highValueList->addItem(item);
        }
    }

    if (m_segmentList) {
        m_segmentList->clear();
        const QVariantMap segments = m_module->highValueSegments();
        const QStringList orderedKeys = {"auth", "admin", "upload", "render", "automation", "secret"};
        for (const QString &key : orderedKeys) {
            const QVariantList entries = segments.value(key).toList();
            if (entries.isEmpty()) {
                continue;
            }
            auto *headerItem = new QListWidgetItem(QString("[%1] %2 adet").arg(key.toUpper(), QString::number(entries.size())));
            headerItem->setForeground(categoryTone(key));
            m_segmentList->addItem(headerItem);
            for (const QVariant &entry : entries) {
                const QVariantMap row = entry.toMap();
                auto *entryItem = new QListWidgetItem(QString("  - [%1] %2").arg(row.value("label").toString(), row.value("value").toString()));
                entryItem->setForeground(categoryTone(row.value("label").toString()));
                m_segmentList->addItem(entryItem);
            }
        }
    }

    if (m_benchmarkHistoryList) {
        m_benchmarkHistoryList->clear();
        for (const QVariant &value : m_module->benchmarkHistory()) {
            const QVariantMap row = value.toMap();
            m_benchmarkHistoryList->addItem(QString("[%1] %2 | %3 | skor %4 | %5 bulgu")
                                                .arg(row.value("capturedAt").toString(),
                                                     row.value("profile").toString(),
                                                     row.value("target").toString(),
                                                     row.value("coverageScore").toString(),
                                                     row.value("findings").toString()));
            m_benchmarkHistoryList->addItem(QString("  %1").arg(row.value("summary").toString()));
            const QString diffSummary = row.value("diffSummary").toString();
            if (!diffSummary.isEmpty()) {
                m_benchmarkHistoryList->addItem(QString("  %1").arg(diffSummary));
            }
            const QString regressionSummary = row.value("regressionSummary").toString();
            if (!regressionSummary.isEmpty()) {
                m_benchmarkHistoryList->addItem(QString("  %1").arg(regressionSummary));
            }
        }
    }

    if (m_timelineList) {
        m_timelineList->clear();
        for (const QVariant &value : m_module->coverageTimeline()) {
            const QVariantMap row = value.toMap();
            m_timelineList->addItem(QString("[%1] [%2] %3 -> %4")
                                        .arg(row.value("time").toString(),
                                             row.value("stage").toString(),
                                             row.value("title").toString(),
                                             row.value("detail").toString()));
        }
    }

    if (m_featureList) {
        m_featureList->clear();
        const QStringList features = {
            tr("Asenkron crawl motoru ve ayni anda coklu istek yurutme"),
            tr("Robots.txt ve sitemap.xml kaynakli yuzey kesfi"),
            tr("Dahili link, form action, parametre ve asset toplama"),
            tr("Kimlik dogrulama ve workflow tabanli oturumlu tarama"),
            tr("Cookie, redirect, header ve expectation tabanli auth kaniti"),
            tr("JS route, rendered route ve rendered form fark analizi"),
            tr("Headless render, automation hedef tespiti ve guvenli local-lab automation guard"),
            tr("Scope profili ile Google font, analytics ve tracker gurultu filtreleme"),
            tr("Coverage puani, kritik segmentler ve yuksek degerli yuzey modeli"),
            tr("Benchmark ozeti, benchmark gecmisi ve onceki kosa gore diff analizi"),
            tr("Recon ekranina ve resmi PDF rapora aktarilabilen Spider kaniti")
        };
        for (const QString &feature : features) {
            m_featureList->addItem(feature);
        }
    }

    if (m_hostHealthList) {
        const SpiderHostInsightsSummary hostInsights = buildSpiderHostInsights(m_module->endpoints(), m_module->assets());

        QString selectedHost = QStringLiteral("all");
        if (m_hostFilterCombo) {
            selectedHost = m_hostFilterCombo->currentData().toString();
            QSignalBlocker blocker(m_hostFilterCombo);
            m_hostFilterCombo->clear();
            m_hostFilterCombo->addItem(tr("Tum Host'lar"), QStringLiteral("all"));
            for (const SpiderHostInsightRow &row : hostInsights.rows) {
                m_hostFilterCombo->addItem(row.host, row.host);
            }
            const int index = qMax(0, m_hostFilterCombo->findData(selectedHost));
            m_hostFilterCombo->setCurrentIndex(index);
            selectedHost = m_hostFilterCombo->currentData().toString();
        }

        m_hostHealthList->clear();
        QStringList replayDiffParts;
        QStringList pressureTrendParts;
        for (const SpiderHostInsightRow &row : hostInsights.rows) {
            if (selectedHost != QLatin1String("all") && row.host != selectedHost) {
                continue;
            }

            const QString pressureState = row.pressureState.isEmpty()
                ? (row.pressureScore >= 8 ? tr("STRESSED")
                   : (row.wafHits > 0 || row.pressureScore >= 5 ? tr("WAF")
                      : (row.scopeOutliers > 0 ? tr("SCOPE")
                         : ((row.suppressedHits > 0 || row.pressureScore > 0) ? tr("GUARDED") : tr("STABLE")))))
                : row.pressureState;
            QColor tone = QColor("#87d4a3");
            if (pressureState == QLatin1String("STRESSED")) {
                tone = QColor("#ff8f8f");
            } else if (pressureState == QLatin1String("WAF")) {
                tone = QColor("#ffb26b");
            } else if (pressureState == QLatin1String("SCOPE")) {
                tone = QColor("#9aa4b2");
            } else if (pressureState == QLatin1String("GUARDED")) {
                tone = QColor("#c8d0db");
            }

            auto *item = new QListWidgetItem(QString("[%1] %2 | endpoint %3 | workflow %4 | waf %5 | pressure %6 (%7) | retry %8 | suppressed %9 | scope %10")
                                                 .arg(pressureState,
                                                      row.host,
                                                      QString::number(row.endpoints),
                                                      QString::number(row.workflowHits),
                                                      QString::number(row.wafHits),
                                                      QString::number(row.pressureScore),
                                                      pressureState,
                                                      QString::number(row.retryScheduledCount),
                                                      QString::number(row.suppressedHits),
                                                      QString::number(row.scopeOutliers)));
            QStringList tooltipLines;
            if (!row.vendorHint.isEmpty()) {
                tooltipLines << tr("WAF vendor: %1").arg(row.vendorHint);
            }
            if (!row.pressureReason.isEmpty()) {
                tooltipLines << tr("Son pressure nedeni: %1").arg(row.pressureReason);
            }
            if (!row.retryDelay.isEmpty()) {
                tooltipLines << tr("Son Retry-After: %1").arg(row.retryDelay);
            }
            if (!tooltipLines.isEmpty()) {
                item->setToolTip(tooltipLines.join('\n'));
            }
            item->setForeground(tone);
            m_hostHealthList->addItem(item);

            if (row.workflowHits > 0 || row.workflowResultHits > 0) {
                replayDiffParts << QStringLiteral("%1: aday %2 / sonuc %3")
                                       .arg(row.host,
                                            QString::number(row.workflowHits),
                                            QString::number(row.workflowResultHits));
            }
            if (row.pressureScore > 0 || row.retryScheduledCount > 0) {
                pressureTrendParts << QStringLiteral("%1: %2 (%3), retry %4")
                                          .arg(row.host,
                                               QString::number(row.pressureScore),
                                               pressureState,
                                               QString::number(row.retryScheduledCount));
            }
        }

        if (m_hostStableValue) {
            m_hostStableValue->setText(QString::number(hostInsights.stableHosts));
        }
        if (m_hostGuardedValue) {
            m_hostGuardedValue->setText(QString::number(hostInsights.guardedHosts));
        }
        if (m_hostWafValue) {
            m_hostWafValue->setText(QString::number(hostInsights.wafHosts));
        }
        if (m_hostStressedValue) {
            m_hostStressedValue->setText(QString::number(hostInsights.stressedHosts));
        }
        if (m_hostReplayDiffLabel) {
            m_hostReplayDiffLabel->setText(replayDiffParts.isEmpty()
                                               ? tr("Replay farki: secili hostta sonuc ureten akÄ±s yok.")
                                               : tr("Replay farki: %1").arg(replayDiffParts.join(QStringLiteral(" | "))));
        }
        if (m_hostPressureTrendLabel) {
            m_hostPressureTrendLabel->setText(pressureTrendParts.isEmpty()
                                                  ? tr("Pressure trend: secili host stabil.")
                                                  : tr("Pressure trend: %1").arg(pressureTrendParts.join(QStringLiteral(" | "))));
        }
        if (m_hostTimelineList) {
            m_hostTimelineList->clear();
            if (selectedHost == QLatin1String("all")) {
                for (const QString &entry : hostInsights.timelineEntries) {
                    m_hostTimelineList->addItem(entry);
                }
            } else {
                for (const SpiderHostInsightRow &row : hostInsights.rows) {
                    if (row.host == selectedHost) {
                        for (const QString &entry : row.timelineEntries) {
                            m_hostTimelineList->addItem(entry);
                        }
                        break;
                    }
                }
            }
        }
    }
}

void SpiderWidget::scheduleStatsRefresh()
{
    refreshLiveHeader();
    if (!m_statsRefreshTimer) {
        refreshStats();
        return;
    }
    m_statsRefreshTimer->start();
}

void SpiderWidget::pollStalledState()
{
    if (!m_module || !m_module->scanning()) {
        m_lastWatchdogProgressKey.clear();
        m_stalledPollTicks = 0;
        m_visualCompletionOverride = false;
        return;
    }

    const QString progressKey = QStringLiteral("%1|%2|%3|%4|%5|%6")
                                    .arg(m_module->visitedCount())
                                    .arg(m_module->queuedCount())
                                    .arg(m_endpointList ? m_endpointList->count() : 0)
                                    .arg(m_parameterList ? m_parameterList->count() : 0)
                                    .arg(m_assetList ? m_assetList->count() : 0)
                                    .arg(m_evidenceList ? m_evidenceList->count() : 0);

    if (progressKey == m_lastWatchdogProgressKey) {
        ++m_stalledPollTicks;
    } else {
        m_stalledPollTicks = 0;
    }
    m_lastWatchdogProgressKey = progressKey;

    if (m_stalledPollTicks < 5) {
        return;
    }

    m_stalledPollTicks = 0;
    appendEvent(tr("[ui-watchdog] Spider durumu degismiyor; tarama eldeki verilerle sonlandiriliyor"));
    m_module->finalizeStalledRun();
    applyVisualCompletionFallback();
}

QString SpiderWidget::buildReportHtml() const
{
    if (!m_module) {
        return {};
    }

    QStringList features;
    if (m_featureList) {
        for (int i = 0; i < m_featureList->count(); ++i) {
            features.push_back(m_featureList->item(i)->text());
        }
    }
    return buildSpiderReportHtml(*m_module, features);
}

void SpiderWidget::exportHostDiagnostics()
{
    if (!m_module) {
        return;
    }

    const SpiderHostInsightsSummary hostInsights = buildSpiderHostInsights(m_module->endpoints(), m_module->assets());
    if (hostInsights.rows.isEmpty()) {
        appendEvent(tr("Host tanilari icin once veri uretilmeli."));
        return;
    }

    const QString selectedHost = m_hostFilterCombo ? m_hostFilterCombo->currentData().toString() : QStringLiteral("all");
    const QString suffix = selectedHost == QLatin1String("all") ? QStringLiteral("all-hosts") : sanitizedFileStem(selectedHost);
    const QString defaultPath = ::spiderReportDefaultPath(m_module->targetUrl(), QStringLiteral("host-%1.json").arg(suffix));
    const QString path = QFileDialog::getSaveFileName(this,
                                                      tr("Host tanilarini disa aktar"),
                                                      defaultPath,
                                                      tr("JSON Dosyalari (*.json)"));
    if (path.isEmpty()) {
        return;
    }

    QJsonArray rows;
    for (const SpiderHostInsightRow &row : hostInsights.rows) {
        if (selectedHost != QLatin1String("all") && row.host != selectedHost) {
            continue;
        }

        QJsonObject item;
        item.insert(QStringLiteral("host"), row.host);
        item.insert(QStringLiteral("endpoints"), row.endpoints);
        item.insert(QStringLiteral("workflow_hits"), row.workflowHits);
        item.insert(QStringLiteral("workflow_result_hits"), row.workflowResultHits);
        item.insert(QStringLiteral("waf_hits"), row.wafHits);
        item.insert(QStringLiteral("suppressed_hits"), row.suppressedHits);
        item.insert(QStringLiteral("scope_outliers"), row.scopeOutliers);
        item.insert(QStringLiteral("pressure_score"), row.pressureScore);
        item.insert(QStringLiteral("pressure_state"), row.pressureState);
        item.insert(QStringLiteral("pressure_reason"), row.pressureReason);
        item.insert(QStringLiteral("retry_after_count"), row.retryAfterCount);
        item.insert(QStringLiteral("retry_scheduled_count"), row.retryScheduledCount);
        item.insert(QStringLiteral("retry_delay"), row.retryDelay);
        item.insert(QStringLiteral("vendor_hint"), row.vendorHint);

        QJsonArray timeline;
        for (const QString &entry : row.timelineEntries) {
            timeline.append(entry);
        }
        item.insert(QStringLiteral("timeline"), timeline);
        rows.append(item);
    }

    QJsonObject root;
    root.insert(QStringLiteral("target"), m_module->targetUrl());
    root.insert(QStringLiteral("selected_host"), selectedHost);
    root.insert(QStringLiteral("exported_at"), QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    root.insert(QStringLiteral("stable_hosts"), hostInsights.stableHosts);
    root.insert(QStringLiteral("guarded_hosts"), hostInsights.guardedHosts);
    root.insert(QStringLiteral("waf_hosts"), hostInsights.wafHosts);
    root.insert(QStringLiteral("stressed_hosts"), hostInsights.stressedHosts);
    root.insert(QStringLiteral("hosts"), rows);

    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        appendEvent(tr("Host tanilari yazilamadi: %1").arg(path));
        return;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    if (!file.commit()) {
        appendEvent(tr("Host tanilari kaydedilemedi: %1").arg(path));
        return;
    }

    appendEvent(tr("Host tanilari disa aktarıldı: %1").arg(path));
}

void SpiderWidget::exportReport()
{
    m_lastReportHtml = buildReportHtml();
    if (m_lastReportHtml.isEmpty()) {
        appendEvent(tr("Spider raporu olusturulamadi; once veri uretilmeli."));
        return;
    }

    delete m_reportPreviewDialog;
    auto *dialog = new ReportPreviewDialog(tr("Spider PDF Onizleme"),
                                           tr("Bu pencere Spider kesif raporunun PDF onizlemesini gosterir. Kaydetme islemleri sadece burada yapilir."),
                                           tr("PDF Kaydet"),
                                           tr("HTML Kaydet"),
                                           this);
    m_reportPreviewDialog = dialog;
    connect(dialog, &QDialog::finished, this, [this]() {
        m_reportPreviewDialog = nullptr;
    });
    dialog->view()->setHtml(m_lastReportHtml);
    const QString target = m_module ? m_module->targetUrl() : QString();
    const QString pdfDefaultPath = ::spiderReportDefaultPath(target, QStringLiteral("pdf"));
    const QString htmlDefaultPath = ::spiderReportDefaultPath(target, QStringLiteral("html"));

    connect(dialog->savePdfButton(), &QPushButton::clicked, dialog, [this, dialog, pdfDefaultPath]() {
        const QString path = QFileDialog::getSaveFileName(dialog,
                                                          tr("Spider PDF Kaydet"),
                                                          pdfDefaultPath,
                                                          tr("PDF (*.pdf)"));
        if (path.isEmpty()) {
            return;
        }

        QString errorMessage;
        if (!::saveSpiderPdfReport(path, m_lastReportHtml, &errorMessage)) {
            appendEvent(tr("Spider PDF raporu kaydedilemedi: %1").arg(errorMessage));
            return;
        }
        appendEvent(tr("Spider PDF raporu kaydedildi: %1").arg(path));
    });

    connect(dialog->saveHtmlButton(), &QPushButton::clicked, dialog, [this, dialog, htmlDefaultPath]() {
        const QString path = QFileDialog::getSaveFileName(dialog,
                                                          tr("Spider HTML Kaydet"),
                                                          htmlDefaultPath,
                                                          tr("HTML (*.html)"));
        if (path.isEmpty()) {
            return;
        }
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
            appendEvent(tr("HTML raporu kaydedilemedi: %1").arg(path));
            return;
        }
        QTextStream stream(&file);
        stream.setEncoding(QStringConverter::Utf8);
        stream << m_lastReportHtml;
        if (!file.commit()) {
            appendEvent(tr("HTML raporu kaydedilemedi: %1").arg(path));
            return;
        }
        appendEvent(tr("Spider HTML raporu kaydedildi: %1").arg(path));
    });

    dialog->exec();
}
