#include "ui/views/spider/spidersetuppanel.h"

#include "ui/layout/flowlayout.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QToolButton>
#include <QToolTip>
#include <QVBoxLayout>

namespace {

class SpiderInfoButton : public QToolButton
{
public:
    explicit SpiderInfoButton(const QString &tooltipText, QWidget *parent = nullptr)
        : QToolButton(parent)
        , m_tooltip(tooltipText)
    {
        setObjectName(QStringLiteral("infoButton"));
        setText(QStringLiteral("i"));
        setCursor(Qt::WhatsThisCursor);
        setAutoRaise(true);
        setFixedSize(18, 18);
    }

protected:
    void enterEvent(QEnterEvent *event) override
    {
        QToolTip::showText(mapToGlobal(rect().bottomLeft()), m_tooltip, this);
        QToolButton::enterEvent(event);
    }

private:
    QString m_tooltip;
};

}

SpiderSetupPanel::SpiderSetupPanel(QWidget *parent)
    : QFrame(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(14);

    auto *setupCard = new QFrame(this);
    setupCard->setObjectName(QStringLiteral("cardPanel"));
    auto *setupLayout = new QGridLayout(setupCard);
    setupLayout->setContentsMargins(20, 20, 20, 20);
    setupLayout->setHorizontalSpacing(12);
    setupLayout->setVerticalSpacing(10);
    setupLayout->setColumnMinimumWidth(0, 70);
    setupLayout->setColumnMinimumWidth(1, 120);
    setupLayout->setColumnMinimumWidth(2, 70);
    setupLayout->setColumnMinimumWidth(3, 120);
    setupLayout->setColumnStretch(1, 1);
    setupLayout->setColumnStretch(3, 1);

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
    m_authWorkflowHintLabel->setObjectName(QStringLiteral("mutedText"));
    m_authWorkflowHintLabel->setWordWrap(true);
    m_workflowValidationLabel->setObjectName(QStringLiteral("mutedText"));
    m_workflowValidationLabel->setWordWrap(true);
    m_includePatternsEdit->setMaximumHeight(72);
    m_excludePatternsEdit->setMaximumHeight(72);
    m_authWorkflowEdit->setMaximumHeight(96);
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
    m_scopeCard->setObjectName(QStringLiteral("summaryCard"));
    auto *scopeLayout = new QGridLayout(m_scopeCard);
    scopeLayout->setContentsMargins(14, 14, 14, 14);
    scopeLayout->setHorizontalSpacing(12);
    scopeLayout->setVerticalSpacing(10);
    scopeLayout->setColumnStretch(1, 1);
    scopeLayout->addWidget(createInfoLabel(tr("Alt Alan Adlari"), tr("Ayni ana host altindaki subdomain'ler de kapsam icine alinabilir.")), 0, 0);
    scopeLayout->addWidget(m_allowSubdomainsCheck, 0, 1);
    m_scopePresetInfoLabel = new QLabel(m_scopeCard);
    m_scopePresetInfoLabel->setObjectName(QStringLiteral("mutedText"));
    m_scopePresetInfoLabel->setWordWrap(true);
    scopeLayout->addWidget(createInfoLabel(tr("Filtre Aciklamasi"), tr("Hazir scope profili ucuncu taraf servisleri ve gosterim gurultusunu temizler.")), 1, 0);
    scopeLayout->addWidget(m_scopePresetInfoLabel, 1, 1);
    scopeLayout->addWidget(createInfoLabel(tr("Include Kurallari"), tr("Bos birakilirsa tum scope taranir. Her satir bir regex include kuralidir.")), 2, 0);
    scopeLayout->addWidget(m_includePatternsEdit, 2, 1);
    scopeLayout->addWidget(createInfoLabel(tr("Exclude Kurallari"), tr("Logout, signout, destroy ve hassas cikis akislari burada dislanabilir. Scope profili secildiginde Google font benzeri gurultu filtreleri de otomatik eklenir.")), 3, 0);
    scopeLayout->addWidget(m_excludePatternsEdit, 3, 1);

    m_authCard = new QFrame(setupCard);
    m_authCard->setObjectName(QStringLiteral("summaryCard"));
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

    m_advancedCard = new QFrame(setupCard);
    m_advancedCard->setObjectName(QStringLiteral("summaryCard"));
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

    auto *buttonHost = new QWidget(setupCard);
    auto *buttonRow = new FlowLayout(buttonHost, 0, 10, 10);
    m_startButton = new QPushButton(tr("Spider Baslat"), setupCard);
    m_startButton->setObjectName(QStringLiteral("accentButton"));
    m_stopButton = new QPushButton(tr("Durdur"), setupCard);
    buttonRow->addWidget(m_startButton);
    buttonRow->addWidget(m_stopButton);
    buttonHost->setLayout(buttonRow);
    setupLayout->addWidget(buttonHost, 3, 0, 1, 4);

    auto *detailHost = new QWidget(this);
    auto *detailRow = new FlowLayout(detailHost, 0, 12, 12);
    m_scopeCard->setMinimumWidth(180);
    m_authCard->setMinimumWidth(180);
    m_advancedCard->setMinimumWidth(220);
    detailRow->addWidget(m_scopeCard);
    detailRow->addWidget(m_authCard);
    detailRow->addWidget(m_advancedCard);
    detailHost->setLayout(detailRow);

    layout->addWidget(setupCard);
    layout->addWidget(detailHost);
}

QWidget *SpiderSetupPanel::createInfoLabel(const QString &title, const QString &tooltip) const
{
    auto *host = new QWidget();
    auto *layout = new QHBoxLayout(host);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);
    auto *label = new QLabel(title, host);
    label->setObjectName(QStringLiteral("mutedText"));
    auto *infoButton = new SpiderInfoButton(tooltip, host);
    layout->addWidget(label);
    layout->addWidget(infoButton);
    layout->addStretch(1);
    return host;
}
