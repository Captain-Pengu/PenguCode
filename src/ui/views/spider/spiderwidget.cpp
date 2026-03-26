#include "spiderwidget.h"

#include "modules/spider/engine/spiderworkflow.h"
#include "modules/spider/spidermodule.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"

#include <QCursor>
#include <QDateTime>
#include <QDialog>
#include <QFile>
#include <QFileDialog>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPageLayout>
#include <QPageSize>
#include <QPlainTextEdit>
#include <QPdfWriter>
#include <QPushButton>
#include <QCheckBox>
#include <QColor>
#include <QComboBox>
#include <QRegularExpression>
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
    return QStringLiteral("pengufoce-spider-kesif-raporu-%1-v1.0-%2.%3")
        .arg(sanitizedFileStem(target),
             QDate::currentDate().toString(QStringLiteral("yyyyMMdd")),
             extension);
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

class SpiderReportPreviewDialog : public QDialog
{
public:
    explicit SpiderReportPreviewDialog(QWidget *parent = nullptr)
        : QDialog(parent)
    {
        setWindowTitle(QObject::tr("Spider PDF Onizleme"));
        resize(980, 780);

        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(16, 16, 16, 16);
        layout->setSpacing(12);

        auto *title = new QLabel(QObject::tr("Spider Kesif Raporu Onizlemesi"), this);
        title->setObjectName("sectionTitle");
        auto *info = new QLabel(QObject::tr("Bu pencere Spider kesif raporunun PDF onizlemesini gosterir. Kaydetme islemleri sadece burada yapilir."), this);
        info->setObjectName("mutedText");
        info->setWordWrap(true);
        layout->addWidget(title);
        layout->addWidget(info);

        m_view = new QTextEdit(this);
        m_view->setReadOnly(true);
        m_view->setStyleSheet("QTextEdit { background: #ffffff; color: #171a20; border: 1px solid #c7cdd8; border-radius: 10px; padding: 20px; }");
        layout->addWidget(m_view, 1);

        auto *buttons = new QHBoxLayout();
        m_savePdfButton = new QPushButton(QObject::tr("PDF Kaydet"), this);
        m_saveHtmlButton = new QPushButton(QObject::tr("HTML Kaydet"), this);
        auto *closeButton = new QPushButton(QObject::tr("Kapat"), this);
        buttons->addStretch();
        buttons->addWidget(m_savePdfButton);
        buttons->addWidget(m_saveHtmlButton);
        buttons->addWidget(closeButton);
        layout->addLayout(buttons);

        connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    }

    QTextEdit *view() const { return m_view; }
    QPushButton *savePdfButton() const { return m_savePdfButton; }
    QPushButton *saveHtmlButton() const { return m_saveHtmlButton; }

private:
    QTextEdit *m_view = nullptr;
    QPushButton *m_savePdfButton = nullptr;
    QPushButton *m_saveHtmlButton = nullptr;
};

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

    auto *root = new QVBoxLayout(this);
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
    statusCard->setMinimumWidth(150);
    countsCard->setMinimumWidth(150);
    coverageCard->setMinimumWidth(150);
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
    heroLayout->addWidget(m_insightLabel);

    auto *setupCard = new QFrame(this);
    setupCard->setObjectName("cardPanel");
    auto *setupLayout = new QGridLayout(setupCard);
    setupLayout->setContentsMargins(20, 20, 20, 20);
    setupLayout->setHorizontalSpacing(16);
    setupLayout->setVerticalSpacing(12);
    setupLayout->setColumnStretch(1, 1);

    m_targetEdit = new QLineEdit(setupCard);
    m_stageCombo = new QComboBox(setupCard);
    m_maxPagesSpin = new QSpinBox(setupCard);
    m_maxDepthSpin = new QSpinBox(setupCard);
    m_timeoutSpin = new QSpinBox(setupCard);
    m_scopePresetCombo = new QComboBox(setupCard);
    m_allowSubdomainsCheck = new QCheckBox(tr("Alt alan adlarini da tara"), setupCard);
    m_includePatternsEdit = new QPlainTextEdit(setupCard);
    m_excludePatternsEdit = new QPlainTextEdit(setupCard);
    m_loginUrlEdit = new QLineEdit(setupCard);
    m_authUsernameEdit = new QLineEdit(setupCard);
    m_authPasswordEdit = new QLineEdit(setupCard);
    m_usernameFieldEdit = new QLineEdit(setupCard);
    m_passwordFieldEdit = new QLineEdit(setupCard);
    m_csrfFieldEdit = new QLineEdit(setupCard);
    m_authWorkflowPresetCombo = new QComboBox(setupCard);
    m_authWorkflowHintLabel = new QLabel(setupCard);
    m_workflowValidationLabel = new QLabel(setupCard);
    m_applyWorkflowPresetButton = new QPushButton(tr("Workflow Uygula"), setupCard);
    m_authWorkflowEdit = new QPlainTextEdit(setupCard);
    m_stageCombo->addItem(tr("1. Asama - Hizli Kesif"));
    m_stageCombo->addItem(tr("2. Asama - Oturumlu Tarama"));
    m_stageCombo->addItem(tr("3. Asama - Uzman Politikasi"));
    m_scopePresetCombo->addItem(tr("Guvenli"), QStringLiteral("guvenli"));
    m_scopePresetCombo->addItem(tr("Dengeli"), QStringLiteral("dengeli"));
    m_scopePresetCombo->addItem(tr("Agresif"), QStringLiteral("agresif"));
    m_maxPagesSpin->setRange(5, 250);
    m_maxPagesSpin->setSingleStep(5);
    m_maxDepthSpin->setRange(1, 10);
    m_timeoutSpin->setRange(800, 10000);
    m_timeoutSpin->setSingleStep(200);
    m_authPasswordEdit->setEchoMode(QLineEdit::Password);
    m_authWorkflowPresetCombo->addItem(tr("Ozel Workflow"), QStringLiteral("custom"));
    m_authWorkflowPresetCombo->addItem(tr("Temel Login"), QStringLiteral("basic-login"));
    m_authWorkflowPresetCombo->addItem(tr("CSRF Login"), QStringLiteral("csrf-login"));
    m_authWorkflowPresetCombo->addItem(tr("Cok Adimli Panel"), QStringLiteral("multi-panel"));
    m_authWorkflowPresetCombo->addItem(tr("API Console"), QStringLiteral("api-console"));
    m_authWorkflowHintLabel->setObjectName("mutedText");
    m_authWorkflowHintLabel->setWordWrap(true);
    m_workflowValidationLabel->setObjectName("mutedText");
    m_workflowValidationLabel->setWordWrap(true);
    m_includePatternsEdit->setMaximumHeight(82);
    m_excludePatternsEdit->setMaximumHeight(82);
    m_authWorkflowEdit->setMaximumHeight(110);
    m_includePatternsEdit->setPlaceholderText(tr("Her satira bir regex include kurali"));
    m_excludePatternsEdit->setPlaceholderText(tr("Her satira bir regex exclude kurali"));
    m_authWorkflowEdit->setPlaceholderText(tr("Her satir: url|POST|form|username={{username}}|password={{password}}|header:X-Test=1|expect=!login|expect=header:location|expect=cookie:PHPSESSID|expect=redirect:/panel|expect=!redirect:login"));
    setupLayout->addWidget(createInfoLabel(tr("Seed URL"), tr("Spider taramaya bu URL ile baslar ve yalnizca ayni hedef kapsaminda kalir.")), 0, 0);
    setupLayout->addWidget(m_targetEdit, 0, 1);
    setupLayout->addWidget(createInfoLabel(tr("Tarama Asamasi"), tr("1. asama hizli link kesfi, 2. asama oturum ve cookie, 3. asama tam politika ve field mapping icindir.")), 0, 2);
    setupLayout->addWidget(m_stageCombo, 0, 3);
    setupLayout->addWidget(createInfoLabel(tr("Maksimum Sayfa"), tr("Sonsuz donguleri sinirlamak icin gezilecek ust limit.")), 1, 0);
    setupLayout->addWidget(m_maxPagesSpin, 1, 1);
    setupLayout->addWidget(createInfoLabel(tr("Derinlik"), tr("Seed URL'den sonra kac seviye ic link takip edilecegini belirler.")), 1, 2);
    setupLayout->addWidget(m_maxDepthSpin, 1, 3);
    setupLayout->addWidget(createInfoLabel(tr("Timeout ms"), tr("Yavas hedeflerde spider'in takilmamasi icin istek zaman asimi.")), 2, 0);
    setupLayout->addWidget(m_timeoutSpin, 2, 1);
    setupLayout->addWidget(createInfoLabel(tr("Scope Profili"), tr("Google font, analytics ve benzeri ucuncu taraf gurultuyu otomatik filtreleyen hazir politika seti.")), 2, 2);
    setupLayout->addWidget(m_scopePresetCombo, 2, 3);

    m_scopeCard = new QFrame(setupCard);
    m_scopeCard->setObjectName("summaryCard");
    m_scopeCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    auto *scopeLayout = new QGridLayout(m_scopeCard);
    scopeLayout->setContentsMargins(14, 14, 14, 14);
    scopeLayout->setHorizontalSpacing(12);
    scopeLayout->setVerticalSpacing(10);
    scopeLayout->setColumnStretch(1, 1);
    scopeLayout->addWidget(createInfoLabel(tr("Alt Alan Adlari"), tr("Ayni ana host altindaki subdomain'ler de kapsam icine alinabilir.")), 0, 0);
    scopeLayout->addWidget(m_allowSubdomainsCheck, 0, 1);
    auto *scopePresetInfo = new QLabel(scopePresetDescription(QStringLiteral("dengeli")), m_scopeCard);
    scopePresetInfo->setObjectName("mutedText");
    scopePresetInfo->setWordWrap(true);
    scopeLayout->addWidget(createInfoLabel(tr("Filtre Aciklamasi"), tr("Hazir scope profili ucuncu taraf servisleri ve gosterim gurultusunu temizler.")), 1, 0);
    scopeLayout->addWidget(scopePresetInfo, 1, 1);
    scopeLayout->addWidget(createInfoLabel(tr("Include Kurallari"), tr("Bos birakilirsa tum scope taranir. Her satir bir regex include kuralidir.")), 2, 0);
    scopeLayout->addWidget(m_includePatternsEdit, 2, 1);
    scopeLayout->addWidget(createInfoLabel(tr("Exclude Kurallari"), tr("Logout, signout, destroy ve hassas cikis akislari burada dislanabilir. Scope profili secildiginde Google font benzeri gurultu filtreleri de otomatik eklenir.")), 3, 0);
    scopeLayout->addWidget(m_excludePatternsEdit, 3, 1);
    scopeLayout->setRowStretch(4, 1);

    m_authCard = new QFrame(setupCard);
    m_authCard->setObjectName("summaryCard");
    m_authCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    auto *authLayout = new QGridLayout(m_authCard);
    authLayout->setContentsMargins(14, 14, 14, 14);
    authLayout->setHorizontalSpacing(12);
    authLayout->setVerticalSpacing(10);
    authLayout->setColumnStretch(1, 1);
    authLayout->addWidget(createInfoLabel(tr("Login URL"), tr("Kimlik dogrulama gerekiyorsa spider once bu sayfada giris akisini dener.")), 0, 0);
    authLayout->addWidget(m_loginUrlEdit, 0, 1);
    authLayout->addWidget(createInfoLabel(tr("Kullanici"), tr("Auth-aware crawl icin kullanici adi veya e-posta alani.")), 1, 0);
    authLayout->addWidget(m_authUsernameEdit, 1, 1);
    authLayout->addWidget(createInfoLabel(tr("Parola"), tr("Sadece gerekli test ortamlarinda kullan. Mevcut oturum ve cookie devamliligi icin kullanilir.")), 2, 0);
    authLayout->addWidget(m_authPasswordEdit, 2, 1);
    authLayout->setRowStretch(3, 1);

    m_advancedCard = new QFrame(setupCard);
    m_advancedCard->setObjectName("summaryCard");
    m_advancedCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    auto *advancedLayout = new QGridLayout(m_advancedCard);
    advancedLayout->setContentsMargins(14, 14, 14, 14);
    advancedLayout->setHorizontalSpacing(12);
    advancedLayout->setVerticalSpacing(10);
    advancedLayout->setColumnStretch(1, 1);
    advancedLayout->addWidget(createInfoLabel(tr("Kullanici Alan Adi"), tr("Login formundaki username alaninin name degeri.")), 0, 0);
    advancedLayout->addWidget(m_usernameFieldEdit, 0, 1);
    advancedLayout->addWidget(createInfoLabel(tr("Parola Alan Adi"), tr("Login formundaki password alaninin name degeri.")), 1, 0);
    advancedLayout->addWidget(m_passwordFieldEdit, 1, 1);
    advancedLayout->addWidget(createInfoLabel(tr("CSRF Alan Adi"), tr("Login formunda anti-CSRF token varsa name degeri.")), 2, 0);
    advancedLayout->addWidget(m_csrfFieldEdit, 2, 1);
    advancedLayout->addWidget(createInfoLabel(tr("Workflow Preseti"), tr("Hazir auth akisi secip editoru doldurur. Relative URL, @current, optional, delay ve label desteklenir.")), 3, 0);
    auto *workflowPresetHost = new QWidget(setupCard);
    auto *workflowPresetRow = new FlowLayout(workflowPresetHost, 0, 8, 8);
    workflowPresetRow->addWidget(m_authWorkflowPresetCombo);
    workflowPresetRow->addWidget(m_applyWorkflowPresetButton);
    workflowPresetHost->setLayout(workflowPresetRow);
    advancedLayout->addWidget(workflowPresetHost, 3, 1);
    advancedLayout->addWidget(m_authWorkflowHintLabel, 4, 1);
    advancedLayout->addWidget(m_workflowValidationLabel, 5, 1);
    advancedLayout->addWidget(createInfoLabel(tr("Workflow Adimlari"), tr("Cok adimli auth icin her satira bir adim yaz. Ek kurallar: label=..., delay=350, optional, expect=status:302, expect=url:/panel, expect=body:Welcome, expect=!login")), 6, 0);
    advancedLayout->addWidget(m_authWorkflowEdit, 6, 1);
    advancedLayout->setRowStretch(7, 1);

    auto *buttonHost = new QWidget(setupCard);
    auto *buttonRow = new FlowLayout(buttonHost, 0, 10, 10);
    m_startButton = new QPushButton(tr("Spider Baslat"), setupCard);
    m_startButton->setObjectName("accentButton");
    m_stopButton = new QPushButton(tr("Durdur"), setupCard);
    buttonRow->addWidget(m_startButton);
    buttonRow->addWidget(m_stopButton);
    buttonHost->setLayout(buttonRow);
    setupLayout->addWidget(buttonHost, 3, 0, 1, 4);

    auto *consoleCard = new QFrame(this);
    consoleCard->setObjectName("cardPanel");
    auto *consoleLayout = new QVBoxLayout(consoleCard);
    consoleLayout->setContentsMargins(20, 20, 20, 20);
    consoleLayout->setSpacing(12);
    auto *consoleTitle = new QLabel(tr("Canli Spider Konsolu"), consoleCard);
    consoleTitle->setObjectName("sectionTitle");
    auto *consoleInfo = new QLabel(tr("Canli akis"), consoleCard);
    consoleInfo->setObjectName("mutedText");
    consoleInfo->setWordWrap(true);
    m_console = new QPlainTextEdit(consoleCard);
    m_console->setReadOnly(true);
    m_console->setMinimumHeight(180);
    m_console->setLineWrapMode(QPlainTextEdit::NoWrap);
    consoleLayout->addWidget(consoleTitle);
    consoleLayout->addWidget(consoleInfo);
    consoleLayout->addWidget(m_console);

    auto *evidenceCard = makeListCard(this,
                                      tr("Oturum ve Kanit Izleri"),
                                      tr("Auth denemeleri, request/response ozetleri, redirect zinciri ve response imzalari burada gorunur."),
                                      &m_evidenceList);
    auto *evidenceCardLayout = qobject_cast<QVBoxLayout *>(evidenceCard->layout());
    m_assetFilterCombo = new QComboBox(evidenceCard);
    m_assetFilterCombo->addItem(tr("Tum Kanitlar"), QStringLiteral("all"));
    m_assetFilterCombo->addItem(tr("Sadece Auth"), QStringLiteral("auth"));
    m_assetFilterCombo->addItem(tr("Sadece Redirect"), QStringLiteral("redirect"));
    m_assetFilterCombo->addItem(tr("Sadece Imza"), QStringLiteral("signature"));
    m_assetFilterCombo->addItem(tr("Sadece Workflow"), QStringLiteral("workflow"));
    m_assetFilterCombo->addItem(tr("Sadece WAF"), QStringLiteral("waf"));
    m_assetFilterCombo->addItem(tr("Sadece Baskilanan"), QStringLiteral("suppressed"));
    m_assetFilterCombo->addItem(tr("Sadece Render"), QStringLiteral("render"));
    m_assetFilterCombo->addItem(tr("Sadece Automation"), QStringLiteral("automation"));
    evidenceCardLayout->insertWidget(2, m_assetFilterCombo);
    m_evidenceDetailView = new QTextEdit(evidenceCard);
    m_evidenceDetailView->setReadOnly(true);
    m_evidenceDetailView->setMinimumHeight(150);
    m_evidenceDetailView->setHtml(tr("<h3>Kanit detayi</h3><p>Bir kayit sec.</p>"));
    evidenceCardLayout->addWidget(m_evidenceDetailView);

    auto *resultsTabs = new QTabWidget(this);
    resultsTabs->setDocumentMode(true);
    resultsTabs->setUsesScrollButtons(true);
    auto *endpointCard = makeListCard(this,
                                      tr("Bulunan Endpoint'ler"),
                                      tr("Href, form action, robots ve sitemap kaynakli endpoint listesi."),
                                      &m_endpointList);
    auto *endpointCardLayout = qobject_cast<QVBoxLayout *>(endpointCard->layout());
    m_endpointFilterCombo = new QComboBox(endpointCard);
    m_endpointFilterCombo->addItem(tr("Tum Endpoint'ler"), QStringLiteral("all"));
    m_endpointFilterCombo->addItem(tr("Sadece Login/Form"), QStringLiteral("forms"));
    m_endpointFilterCombo->addItem(tr("Sadece Oturum Sonrasi"), QStringLiteral("delta"));
    m_endpointFilterCombo->addItem(tr("Sadece JS Route"), QStringLiteral("js"));
    m_endpointFilterCombo->addItem(tr("Sadece Korunan Yuzey"), QStringLiteral("protected"));
    m_endpointFilterCombo->addItem(tr("Sadece Bulunamayan Yollar"), QStringLiteral("missing"));
    endpointCardLayout->insertWidget(2, m_endpointFilterCombo);
    resultsTabs->addTab(endpointCard, tr("Yuzey"));
    resultsTabs->addTab(makeListCard(this,
                                     tr("Parametreler"),
                                     QString(),
                                     &m_parameterList),
                        tr("Girdi"));
    resultsTabs->addTab(makeListCard(this,
                                     tr("Asset ve Scriptler"),
                                     QString(),
                                     &m_assetList),
                        tr("Asset"));
    resultsTabs->addTab(makeListCard(this,
                                     tr("Kritik Yuzey"),
                                     QString(),
                                     &m_highValueList),
                        tr("Kritik"));
    resultsTabs->addTab(makeListCard(this,
                                     tr("Segmentler"),
                                     QString(),
                                     &m_segmentList),
                        tr("Segmentler"));
    resultsTabs->addTab(makeListCard(this,
                                     tr("Benchmark"),
                                     QString(),
                                     &m_benchmarkHistoryList),
                        tr("Benchmark"));
    resultsTabs->addTab(makeListCard(this,
                                     tr("Timeline"),
                                     QString(),
                                     &m_timelineList),
                        tr("Timeline"));
    resultsTabs->addTab(makeListCard(this,
                                     tr("Host Sagligi"),
                                     tr("WAF, baskilama ve scope disi davranislara gore host bazli ozet."),
                                     &m_hostHealthList),
                        tr("Host"));
    resultsTabs->addTab(makeListCard(this,
                                     tr("Ozellikler"),
                                     QString(),
                                     &m_featureList),
                        tr("Ozellikler"));

    auto *liveTab = new QWidget(this);
    auto *liveLayout = new QHBoxLayout(liveTab);
    liveLayout->setContentsMargins(0, 0, 0, 0);
    liveLayout->setSpacing(18);
    liveLayout->addWidget(consoleCard, 3);
    liveLayout->addWidget(evidenceCard, 2);

    auto *setupTab = new QWidget(this);
    auto *setupTabLayout = new QVBoxLayout(setupTab);
    setupTabLayout->setContentsMargins(0, 0, 0, 0);
    setupTabLayout->setSpacing(14);
    auto *detailHost = new QWidget(setupTab);
    auto *detailRow = new FlowLayout(detailHost, 0, 14, 14);
    m_scopeCard->setMinimumWidth(260);
    m_authCard->setMinimumWidth(260);
    m_advancedCard->setMinimumWidth(320);
    detailRow->addWidget(m_scopeCard);
    detailRow->addWidget(m_authCard);
    detailHost->setLayout(detailRow);
    setupTabLayout->addWidget(setupCard);
    setupTabLayout->addWidget(detailHost);
    setupTabLayout->addWidget(m_advancedCard);
    setupTabLayout->addStretch();

    m_workTabs = new QTabWidget(this);
    m_workTabs->setDocumentMode(true);
    m_workTabs->setUsesScrollButtons(true);
    m_workTabs->addTab(setupTab, tr("Kurulum"));
    m_workTabs->addTab(liveTab, tr("Canli"));
    m_workTabs->addTab(resultsTabs, tr("Sonuclar"));

    root->addWidget(hero);
    root->addWidget(m_workTabs, 1);

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
    connect(m_scopePresetCombo, &QComboBox::currentIndexChanged, this, [this, scopePresetInfo]() {
        scopePresetInfo->setText(scopePresetDescription(m_scopePresetCombo->currentData().toString()));
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
        return kind == QLatin1String("waf-challenge") || kind == QLatin1String("waf-vendor");
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
    for (const QVariant &value : m_module->assets()) {
        const QString kind = value.toMap().value("kind").toString();
        if (kind == QLatin1String("workflow-submit-candidate") || kind == QLatin1String("workflow-action-candidate")) {
            ++workflowCandidates;
        } else if (kind == QLatin1String("workflow-submit-result") || kind == QLatin1String("workflow-action-result")) {
            ++workflowResults;
        } else if (kind == QLatin1String("waf-vendor") || kind == QLatin1String("waf-challenge")) {
            ++wafHits;
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
    m_automationLabel->setText(tr("Workflow aday %1 | replay sonuc %2 | WAF %3 | baskilanan hedef %4 | %5")
                                   .arg(workflowCandidates)
                                   .arg(workflowResults)
                                   .arg(wafHits)
                                   .arg(suppressedHits)
                                   .arg(m_module->automationSafetyStatus()));
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
        m_hostHealthList->clear();
        struct HostRow {
            int endpoints = 0;
            int workflowHits = 0;
            int wafHits = 0;
            int suppressedHits = 0;
            int scopeOutliers = 0;
        };
        QMap<QString, HostRow> hostRows;
        for (const QVariant &value : m_module->endpoints()) {
            const QVariantMap row = value.toMap();
            const QUrl url(row.value("url").toString());
            const QString host = url.host().trimmed().isEmpty() ? tr("(bilinmiyor)") : url.host().toLower();
            hostRows[host].endpoints += 1;
        }
        for (const QVariant &value : m_module->assets()) {
            const QVariantMap row = value.toMap();
            const QString kind = row.value("kind").toString();
            QString host = QUrl(row.value("source").toString()).host().toLower();
            if (host.trimmed().isEmpty()) {
                host = tr("(bilinmiyor)");
            }
            if (kind.startsWith(QStringLiteral("workflow-")) || kind.startsWith(QStringLiteral("auth-step-"))) {
                hostRows[host].workflowHits += 1;
            } else if (kind == QLatin1String("waf-vendor") || kind == QLatin1String("waf-challenge")) {
                hostRows[host].wafHits += 1;
            } else if (kind == QLatin1String("crawl-suppressed")) {
                hostRows[host].suppressedHits += 1;
            } else if (kind == QLatin1String("scope-outlier") || kind == QLatin1String("scope-excluded")) {
                hostRows[host].scopeOutliers += 1;
            }
        }

        for (auto it = hostRows.cbegin(); it != hostRows.cend(); ++it) {
            const HostRow &row = it.value();
            QString health = tr("STABLE");
            QColor tone = QColor("#87d4a3");
            if (row.wafHits > 0) {
                health = tr("WAF");
                tone = QColor("#ffb26b");
            } else if (row.scopeOutliers > 0) {
                health = tr("SCOPE");
                tone = QColor("#9aa4b2");
            } else if (row.suppressedHits > 0) {
                health = tr("GUARDED");
                tone = QColor("#c8d0db");
            }

            auto *item = new QListWidgetItem(QString("[%1] %2 | endpoint %3 | workflow %4 | waf %5 | suppressed %6 | scope %7")
                                                 .arg(health,
                                                      it.key(),
                                                      QString::number(row.endpoints),
                                                      QString::number(row.workflowHits),
                                                      QString::number(row.wafHits),
                                                      QString::number(row.suppressedHits),
                                                      QString::number(row.scopeOutliers)));
            item->setForeground(tone);
            m_hostHealthList->addItem(item);
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

    QSet<QString> seenHighValue;
    QString endpointHtml;
    QSet<QString> seenEndpoints;
    int protectedCount = 0;
    int authDeltaCount = 0;
    int missingCount = 0;
    for (const QVariant &value : m_module->endpoints()) {
        const QVariantMap row = value.toMap();
        const QString key = QStringLiteral("%1|%2").arg(row.value("kind").toString(), row.value("url").toString());
        if (seenEndpoints.contains(key)) {
            continue;
        }
        seenEndpoints.insert(key);
        const QString kind = row.value("kind").toString();
        const int statusCode = row.value("statusCode").toInt();
        const QString sessionState = row.value("sessionState").toString();
        if (kind == QLatin1String("login-wall") || kind == QLatin1String("access-denied") || kind == QLatin1String("waf-challenge") || statusCode == 401 || statusCode == 403) {
            ++protectedCount;
        }
        if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            ++authDeltaCount;
        }
        if (kind == QLatin1String("soft-404") || statusCode == 404) {
            ++missingCount;
        }
        endpointHtml += QString("<li><b>%1</b> - %2 (d%3, HTTP %4, %5)</li>")
                            .arg(row.value("kind").toString().toHtmlEscaped(),
                                 row.value("url").toString().toHtmlEscaped(),
                                 row.value("depth").toString().toHtmlEscaped(),
                                 row.value("statusCode").toString().toHtmlEscaped(),
                                 row.value("sessionState").toString().toHtmlEscaped());
    }
    if (endpointHtml.isEmpty()) {
        endpointHtml = QStringLiteral("<li>Endpoint kaydi bulunmadi.</li>");
    }

    QString parameterHtml;
    for (const QVariant &value : m_module->parameters()) {
        const QVariantMap row = value.toMap();
        parameterHtml += QString("<li><b>%1</b> - %2 (%3)</li>")
                             .arg(row.value("name").toString().toHtmlEscaped(),
                                  row.value("url").toString().toHtmlEscaped(),
                                  row.value("origin").toString().toHtmlEscaped());
    }
    if (parameterHtml.isEmpty()) {
        parameterHtml = QStringLiteral("<li>Parametre veya form girdisi kaydi bulunmadi.</li>");
    }

    QString assetHtml;
    QSet<QString> seenAssets;
    int workflowCandidates = 0;
    int workflowResults = 0;
    int wafHits = 0;
    int suppressedHits = 0;
    for (const QVariant &value : m_module->assets()) {
        const QVariantMap row = value.toMap();
        if (shouldSuppressReportAsset(row)) {
            continue;
        }
        const QString kind = row.value("kind").toString();
        if (kind == QLatin1String("workflow-submit-candidate") || kind == QLatin1String("workflow-action-candidate")) {
            ++workflowCandidates;
        } else if (kind == QLatin1String("workflow-submit-result") || kind == QLatin1String("workflow-action-result")) {
            ++workflowResults;
        } else if (kind == QLatin1String("waf-vendor") || kind == QLatin1String("waf-challenge")) {
            ++wafHits;
        } else if (kind == QLatin1String("crawl-suppressed")
                   || kind == QLatin1String("scope-outlier")
                   || kind == QLatin1String("scope-excluded")) {
            ++suppressedHits;
        }
        const QString key = QStringLiteral("%1|%2").arg(row.value("kind").toString(), row.value("value").toString());
        if (seenAssets.contains(key)) {
            continue;
        }
        seenAssets.insert(key);
        assetHtml += QString("<li><b>%1</b> - %2 <span style='color:#5b6677'>(%3)</span></li>")
                         .arg(row.value("kind").toString().toHtmlEscaped(),
                              row.value("value").toString().toHtmlEscaped(),
                              row.value("source").toString().toHtmlEscaped());
    }
    if (assetHtml.isEmpty()) {
        assetHtml = QStringLiteral("<li>Asset veya literal kaydi bulunmadi.</li>");
    }

    QString highValueHtml;
    for (const QVariant &value : m_module->highValueTargets()) {
        const QVariantMap row = value.toMap();
        const QString key = QStringLiteral("%1|%2").arg(row.value("label").toString(), row.value("value").toString());
        if (seenHighValue.contains(key)) {
            continue;
        }
        seenHighValue.insert(key);
        highValueHtml += QString("<li><b>%1</b> - %2</li>")
                             .arg(row.value("label").toString().toHtmlEscaped(),
                                  row.value("value").toString().toHtmlEscaped());
    }
    if (highValueHtml.isEmpty()) {
        highValueHtml = QStringLiteral("<li>Kritik yuzey kaydi bulunmadi.</li>");
    }

    QString timelineHtml;
    for (const QVariant &value : m_module->coverageTimeline()) {
        const QVariantMap row = value.toMap();
        timelineHtml += QString("<li>[%1] <b>%2</b> - %3 <span style='color:#5b6677'>(%4)</span></li>")
                            .arg(row.value("time").toString().toHtmlEscaped(),
                                 row.value("title").toString().toHtmlEscaped(),
                                 row.value("detail").toString().toHtmlEscaped(),
                                 row.value("stage").toString().toHtmlEscaped());
    }
    if (timelineHtml.isEmpty()) {
        timelineHtml = QStringLiteral("<li>Timeline kaydi bulunmadi.</li>");
    }

    QString historyHtml;
    for (const QVariant &value : m_module->benchmarkHistory()) {
        const QVariantMap row = value.toMap();
        historyHtml += QString("<li><b>%1</b> - %2 | skor %3 | %4</li>")
                           .arg(row.value("capturedAt").toString().toHtmlEscaped(),
                                row.value("profile").toString().toHtmlEscaped(),
                                row.value("coverageScore").toString().toHtmlEscaped(),
                                row.value("summary").toString().toHtmlEscaped());
        const QString diffSummary = row.value("diffSummary").toString();
        if (!diffSummary.isEmpty()) {
            historyHtml += QString("<li style='margin-left:18px;color:#5b6677;'>%1</li>").arg(diffSummary.toHtmlEscaped());
        }
        const QString regressionSummary = row.value("regressionSummary").toString();
        if (!regressionSummary.isEmpty()) {
            historyHtml += QString("<li style='margin-left:18px;color:#8f1732;'>%1</li>").arg(regressionSummary.toHtmlEscaped());
        }
    }
    if (historyHtml.isEmpty()) {
        historyHtml = QStringLiteral("<li>Benchmark gecmisi bulunmadi.</li>");
    }

    QString featureHtml;
    if (m_featureList && m_featureList->count() > 0) {
        for (int i = 0; i < m_featureList->count(); ++i) {
            featureHtml += QString("<li>%1</li>").arg(m_featureList->item(i)->text().toHtmlEscaped());
        }
    }
    if (featureHtml.isEmpty()) {
        featureHtml = QStringLiteral("<li>Ozellik listesi hazir degil.</li>");
    }

    const QVariantMap breakdown = m_module->coverageBreakdown();
    const QString operationalSummary = QStringLiteral("Korunan yuzey %1 | oturum sonrasi yeni yuzey %2 | 404/soft-404 %3")
                                           .arg(protectedCount)
                                           .arg(authDeltaCount)
                                           .arg(missingCount);
    const QString workflowSummary = QStringLiteral("Workflow aday %1 | replay sonuc %2 | WAF %3 | baskilanan/scope %4")
                                        .arg(workflowCandidates)
                                        .arg(workflowResults)
                                        .arg(wafHits)
                                        .arg(suppressedHits);
    return QString(
        "<html><body style='font-family:Bahnschrift;font-size:12pt;line-height:1.45;padding:0;color:#171a20;'>"
        "<div style='border-bottom:2px solid #8f1732;padding-bottom:12px;margin-bottom:18px;'>"
        "<h1 style='margin:0;font-size:24pt;'>PenguFoce Spider Kesif Raporu</h1>"
        "<p style='margin:8px 0 0 0;font-size:11pt;'><b>Hedef:</b> %1<br><b>Rapor Tarihi:</b> %2<br><b>Scope Profili:</b> %3</p>"
        "</div>"
        "<h2 style='font-size:16pt;'>1. Yonetici Ozeti</h2>"
        "<p>Spider modulu hedef yuzeyi asenkron crawl, oturum fark analizi ve rendered DOM kesfi ile taradi. Son coverage puani <b>%4/100</b> olarak hesaplandi.</p>"
        "<p><b>Coverage Ozeti:</b> %5<br><b>Automation:</b> %6<br><b>Benchmark:</b> %7<br><b>Kiyas:</b> %8<br><b>Regression:</b> %9</p>"
        "<p><b>Operasyonel Ozet:</b> %10<br><b>Workflow/WAF Ozeti:</b> %29</p>"
        "<h2 style='font-size:16pt;'>2. Aktif Spider Yetenekleri</h2><ul>%11</ul>"
        "<h2 style='font-size:16pt;'>3. Coverage Kirilimi</h2>"
        "<p>auth %12 | form %13 | js %14 | secret %15 | admin %16 | upload %17 | delta %18 | korunan %19 | 404 %20 | render %21 | automation %22</p>"
        "<h2 style='font-size:16pt;'>4. Yuksek Degerli Yuzey</h2><ul>%23</ul>"
        "<h2 style='font-size:16pt;'>5. Endpoint Ozetleri</h2><ul>%24</ul>"
        "<h2 style='font-size:16pt;'>6. Parametre ve Form Girdileri</h2><ul>%25</ul>"
        "<h2 style='font-size:16pt;'>7. Asset, Render ve Automation Bulgulari</h2><ul>%26</ul>"
        "<h2 style='font-size:16pt;'>8. Coverage Timeline</h2><ul>%27</ul>"
        "<h2 style='font-size:16pt;'>9. Benchmark Gecmisi ve Karsilastirma</h2><ul>%28</ul>"
        "</body></html>")
        .arg(m_module->targetUrl().toHtmlEscaped(),
             QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm"),
             m_module->scopePreset().toHtmlEscaped(),
             QString::number(m_module->coverageScore()),
             m_module->coverageSummary().toHtmlEscaped(),
             m_module->automationSafetyStatus().toHtmlEscaped(),
             m_module->benchmarkSummary().toHtmlEscaped(),
             m_module->benchmarkDiffSummary().toHtmlEscaped(),
             m_module->regressionSummary().toHtmlEscaped(),
             operationalSummary.toHtmlEscaped(),
             featureHtml,
             QString::number(breakdown.value("auth").toInt()),
             QString::number(breakdown.value("form").toInt()),
             QString::number(breakdown.value("js").toInt()),
             QString::number(breakdown.value("secret").toInt()),
             QString::number(breakdown.value("admin").toInt()),
             QString::number(breakdown.value("upload").toInt()),
             QString::number(breakdown.value("delta").toInt()),
             QString::number(breakdown.value("protected").toInt()),
             QString::number(breakdown.value("missing").toInt()),
             QString::number(breakdown.value("render").toInt()),
             QString::number(breakdown.value("automation").toInt()),
             highValueHtml,
             endpointHtml,
             parameterHtml,
             assetHtml,
             timelineHtml,
             historyHtml,
             workflowSummary.toHtmlEscaped());
}

void SpiderWidget::exportReport()
{
    m_lastReportHtml = buildReportHtml();
    if (m_lastReportHtml.isEmpty()) {
        appendEvent(tr("Spider raporu olusturulamadi; once veri uretilmeli."));
        return;
    }

    delete m_reportPreviewDialog;
    auto *dialog = new SpiderReportPreviewDialog(this);
    m_reportPreviewDialog = dialog;
    dialog->view()->setHtml(m_lastReportHtml);
    const QString pdfDefaultName = spiderReportFileName(m_module ? m_module->targetUrl() : QString(), QStringLiteral("pdf"));
    const QString htmlDefaultName = spiderReportFileName(m_module ? m_module->targetUrl() : QString(), QStringLiteral("html"));

    connect(dialog->savePdfButton(), &QPushButton::clicked, dialog, [this, dialog, pdfDefaultName]() {
        const QString path = QFileDialog::getSaveFileName(dialog,
                                                          tr("Spider PDF Kaydet"),
                                                          pdfDefaultName,
                                                          tr("PDF (*.pdf)"));
        if (path.isEmpty()) {
            return;
        }

        QPdfWriter writer(path);
        writer.setResolution(144);
        writer.setPageSize(QPageSize(QPageSize::A4));
        writer.setPageMargins(QMarginsF(18, 18, 18, 18), QPageLayout::Millimeter);
        writer.setTitle(tr("PenguFoce Spider Kesif Raporu"));

        QTextDocument document;
        document.setDocumentMargin(18.0);
        document.setHtml(m_lastReportHtml);
        document.setPageSize(writer.pageLayout().paintRectPixels(writer.resolution()).size());
        document.print(&writer);
        appendEvent(tr("Spider PDF raporu kaydedildi: %1").arg(path));
    });

    connect(dialog->saveHtmlButton(), &QPushButton::clicked, dialog, [this, dialog, htmlDefaultName]() {
        const QString path = QFileDialog::getSaveFileName(dialog,
                                                          tr("Spider HTML Kaydet"),
                                                          htmlDefaultName,
                                                          tr("HTML (*.html)"));
        if (path.isEmpty()) {
            return;
        }
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
            appendEvent(tr("HTML raporu kaydedilemedi: %1").arg(path));
            return;
        }
        QTextStream stream(&file);
        stream.setEncoding(QStringConverter::Utf8);
        stream << m_lastReportHtml;
        appendEvent(tr("Spider HTML raporu kaydedildi: %1").arg(path));
    });

    dialog->exec();
}
