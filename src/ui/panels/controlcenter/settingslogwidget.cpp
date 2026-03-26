#include "settingslogwidget.h"

#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"

#include "controllers/app/appcontroller.h"
#include "core/logging/logmodel.h"
#include "core/settings/settingsmanager.h"
#include "core/theme/themeengine.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>

namespace {

QWidget *makeInfoCard(QWidget *parent, const QString &title, QLabel **valueLabel, const QString &help = {})
{
    auto *card = new QFrame(parent);
    card->setObjectName("summaryCard");
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
    if (!help.isEmpty()) {
        auto *helpLabel = new QLabel(help, card);
        helpLabel->setObjectName("mutedText");
        helpLabel->setWordWrap(true);
        layout->addWidget(helpLabel);
    }
    return card;
}

QFrame *makeSectionCard(QWidget *parent, const QString &title, const QString &description)
{
    auto *card = new QFrame(parent);
    card->setObjectName("cardPanel");
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(12);
    auto *titleLabel = new QLabel(title, card);
    titleLabel->setObjectName("sectionTitle");
    layout->addWidget(titleLabel);
    if (!description.isEmpty()) {
        auto *descLabel = new QLabel(description, card);
        descLabel->setObjectName("mutedText");
        descLabel->setWordWrap(true);
        layout->addWidget(descLabel);
    }
    return card;
}

void addField(QGridLayout *grid, int row, const QString &label, QWidget *field, int fieldColumnSpan = 1)
{
    auto *title = new QLabel(label);
    title->setObjectName("mutedText");
    grid->addWidget(title, row, 0);
    grid->addWidget(field, row, 1, 1, fieldColumnSpan);
}

}

SettingsLogWidget::SettingsLogWidget(AppController *controller, LogModel *logModel, QWidget *parent)
    : QWidget(parent)
    , m_controller(controller)
    , m_logModel(logModel)
{
    buildUi();
    loadFromSettings();
    reloadThemeInfo();
}

void SettingsLogWidget::reloadThemeInfo()
{
    if (!m_controller || !m_controller->themeEngine()) {
        return;
    }

    const QString themeKey = m_controller->themeEngine()->currentTheme();
    const QString presetId = m_controller->settingsManager()
                                 ? m_controller->settingsManager()->value(QStringLiteral("theme/%1").arg(themeKey),
                                                                         QStringLiteral("presetId"),
                                                                         themeKey == QLatin1String("light")
                                                                             ? QStringLiteral("paper_ash")
                                                                             : QStringLiteral("tactical_crimson"))
                                       .toString()
                                 : QString();
    const QString spacedPreset = QString(presetId).replace(QLatin1Char('_'), QLatin1Char(' '));
    m_themeModeValue->setText(themeKey == QLatin1String("light") ? tr("Acik tema aktif") : tr("Koyu tema aktif"));
    m_presetHintValue->setText(tr("Aktif tema ailesi: %1").arg(spacedPreset));
    m_logCountValue->setText(QString::number(m_logModel ? m_logModel->rowCount() : 0));
}

void SettingsLogWidget::appendLogLine(const QString &line)
{
    if (!m_logConsole) {
        return;
    }

    m_logConsole->appendPlainText(line);
    reloadThemeInfo();
}

void SettingsLogWidget::appendExistingLogs()
{
    if (!m_logConsole || !m_logModel) {
        return;
    }

    m_logConsole->clear();
    for (int row = 0; row < m_logModel->rowCount(); ++row) {
        const QModelIndex index = m_logModel->index(row, 0);
        m_logConsole->appendPlainText(m_logModel->data(index, LogModel::FormattedRole).toString());
    }
    reloadThemeInfo();
}

QVariantMap SettingsLogWidget::presetPalette(const QString &theme, const QString &presetId) const
{
    if (theme == QLatin1String("light")) {
        if (presetId == QLatin1String("mint_console")) {
            return {{"window", "#e8f3ef"}, {"panel", "#f8fffc"}, {"panelAlt", "#dcece6"}, {"border", "#b4cbc1"}, {"text", "#15221d"}, {"mutedText", "#5f7168"}, {"accent", "#1d7f68"}, {"accentSoft", "#d4ebe4"}, {"success", "#2f8f57"}, {"warning", "#af7d1a"}, {"danger", "#c14b4f"}};
        }
        if (presetId == QLatin1String("ivory_blue")) {
            return {{"window", "#f2f4f7"}, {"panel", "#ffffff"}, {"panelAlt", "#e5ebf3"}, {"border", "#c4cfde"}, {"text", "#192432"}, {"mutedText", "#667488"}, {"accent", "#2b5f9e"}, {"accentSoft", "#dae6f6"}, {"success", "#1f7f63"}, {"warning", "#b47d16"}, {"danger", "#ca4752"}};
        }
        if (presetId == QLatin1String("rose_paper")) {
            return {{"window", "#f6edea"}, {"panel", "#fff8f5"}, {"panelAlt", "#f0dfd8"}, {"border", "#d3bbb1"}, {"text", "#2c1f21"}, {"mutedText", "#796267"}, {"accent", "#a64d64"}, {"accentSoft", "#f1d6de"}, {"success", "#478453"}, {"warning", "#b57a22"}, {"danger", "#c84a4a"}};
        }
        if (presetId == QLatin1String("sandstone")) {
            return {{"window", "#f3ede3"}, {"panel", "#fffaf2"}, {"panelAlt", "#efe4d2"}, {"border", "#c8b89f"}, {"text", "#2a241d"}, {"mutedText", "#6d6253"}, {"accent", "#9a3f24"}, {"accentSoft", "#efd4c4"}, {"success", "#3f7f4a"}, {"warning", "#b7771b"}, {"danger", "#c24130"}};
        }
        if (presetId == QLatin1String("slate_light")) {
            return {{"window", "#e8edf3"}, {"panel", "#f8fbff"}, {"panelAlt", "#dde6f0"}, {"border", "#b7c3d1"}, {"text", "#16202b"}, {"mutedText", "#61707f"}, {"accent", "#27567a"}, {"accentSoft", "#d8e5f0"}, {"success", "#1f7a58"}, {"warning", "#ad7a15"}, {"danger", "#c03b4e"}};
        }
        return {{"window", "#eceef1"}, {"panel", "#ffffff"}, {"panelAlt", "#f3f4f6"}, {"border", "#ced4dd"}, {"text", "#161a20"}, {"mutedText", "#596273"}, {"accent", "#a61b3f"}, {"accentSoft", "#f4d9e1"}, {"success", "#15803d"}, {"warning", "#b45309"}, {"danger", "#dc2626"}};
    }

    if (presetId == QLatin1String("steel_blue")) {
        return {{"window", "#09111a"}, {"panel", "#101c28"}, {"panelAlt", "#162636"}, {"border", "#2c455d"}, {"text", "#e3edf7"}, {"mutedText", "#91a7bb"}, {"accent", "#1d6fa5"}, {"accentSoft", "#112635"}, {"success", "#1fa971"}, {"warning", "#d79a24"}, {"danger", "#dd4f5f"}};
    }
    if (presetId == QLatin1String("olive_ops")) {
        return {{"window", "#0d100d"}, {"panel", "#171c17"}, {"panelAlt", "#212921"}, {"border", "#475448"}, {"text", "#e8eadf"}, {"mutedText", "#a4ab98"}, {"accent", "#627d2c"}, {"accentSoft", "#222919"}, {"success", "#67b34d"}, {"warning", "#c8a33a"}, {"danger", "#c45144"}};
    }
    if (presetId == QLatin1String("amber_grid")) {
        return {{"window", "#0d0f11"}, {"panel", "#171a1e"}, {"panelAlt", "#22262b"}, {"border", "#4a4032"}, {"text", "#f1eadf"}, {"mutedText", "#ada58f"}, {"accent", "#b8701f"}, {"accentSoft", "#2f2112"}, {"success", "#4eb26f"}, {"warning", "#d19b2b"}, {"danger", "#cc5a4c"}};
    }
    if (presetId == QLatin1String("polar_night")) {
        return {{"window", "#081019"}, {"panel", "#101b28"}, {"panelAlt", "#172433"}, {"border", "#35516d"}, {"text", "#edf5ff"}, {"mutedText", "#8fa8c0"}, {"accent", "#4d87c7"}, {"accentSoft", "#132233"}, {"success", "#31b47c"}, {"warning", "#d6a12f"}, {"danger", "#dc5f67"}};
    }
    if (presetId == QLatin1String("ember_wire")) {
        return {{"window", "#110b0c"}, {"panel", "#1b1215"}, {"panelAlt", "#26191d"}, {"border", "#5a343b"}, {"text", "#f5e8e5"}, {"mutedText", "#b7a19c"}, {"accent", "#c14332"}, {"accentSoft", "#321515"}, {"success", "#54b26b"}, {"warning", "#d89b25"}, {"danger", "#ea5447"}};
    }
    return {{"window", "#0a0d12"}, {"panel", "#121720"}, {"panelAlt", "#1a2230"}, {"border", "#2f3846"}, {"text", "#ece7e2"}, {"mutedText", "#a5acb8"}, {"accent", "#8f1732"}, {"accentSoft", "#261018"}, {"success", "#22c55e"}, {"warning", "#f59e0b"}, {"danger", "#ef4444"}};
}

void SettingsLogWidget::applyPreset()
{
    if (!m_controller) {
        return;
    }

    const QString theme = m_themeModeCombo->currentData().toString();
    const QVariantMap palette = presetPalette(theme, m_themePresetCombo->currentData().toString());
    auto *settings = m_controller->settingsManager();
    auto *themeEngine = m_controller->themeEngine();
    for (auto it = palette.cbegin(); it != palette.cend(); ++it) {
        settings->setValue(QStringLiteral("theme/%1").arg(theme), it.key(), it.value());
        themeEngine->setPaletteValue(theme, it.key(), it.value().toString());
    }
    settings->setValue(QStringLiteral("theme/%1").arg(theme),
                       QStringLiteral("presetId"),
                       m_themePresetCombo->currentData().toString());
    settings->setValue(QStringLiteral("theme"), QStringLiteral("currentTheme"), theme);
    themeEngine->setCurrentTheme(theme);
    reloadThemeInfo();
    emit settingsApplied();
}

void SettingsLogWidget::applyAllSettings()
{
    if (!m_controller) {
        return;
    }

    auto *settings = m_controller->settingsManager();
    auto *themeEngine = m_controller->themeEngine();
    const QString theme = m_themeModeCombo->currentData().toString();
    settings->setValue(QStringLiteral("theme/%1").arg(theme),
                       QStringLiteral("presetId"),
                       m_themePresetCombo->currentData().toString());
    settings->setValue(QStringLiteral("theme"), QStringLiteral("currentTheme"), theme);
    themeEngine->setCurrentTheme(theme);

    settings->setValue(QStringLiteral("modules/port_scanner"), QStringLiteral("defaultHost"), m_portTargetEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/port_scanner"), QStringLiteral("defaultPorts"), m_portPortsEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/port_scanner"), QStringLiteral("scanType"), m_portScanTypeCombo->currentText());
    settings->setValue(QStringLiteral("modules/port_scanner"), QStringLiteral("threadCount"), m_portThreadSpin->value());
    settings->setValue(QStringLiteral("modules/port_scanner"), QStringLiteral("timeoutMs"), m_portTimeoutSpin->value());
    settings->setValue(QStringLiteral("modules/port_scanner"), QStringLiteral("retryCount"), m_portRetrySpin->value());
    settings->setValue(QStringLiteral("modules/port_scanner"), QStringLiteral("serviceDetection"), m_portServiceCheck->isChecked());
    settings->setValue(QStringLiteral("modules/port_scanner"), QStringLiteral("osFingerprinting"), m_portOsCheck->isChecked());

    settings->setValue(QStringLiteral("modules/proxy"), QStringLiteral("listenHost"), m_proxyHostEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/proxy"), QStringLiteral("listenPort"), m_proxyPortSpin->value());
    settings->setValue(QStringLiteral("modules/proxy"), QStringLiteral("targetHost"), m_proxyTargetHostEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/proxy"), QStringLiteral("targetPort"), m_proxyTargetPortSpin->value());
    settings->setValue(QStringLiteral("modules/proxy"), QStringLiteral("idleTimeoutSeconds"), m_proxyIdleTimeoutSpin->value());
    settings->setValue(QStringLiteral("modules/proxy"), QStringLiteral("workerThreads"), m_proxyWorkerSpin->value());
    settings->setValue(QStringLiteral("modules/proxy"), QStringLiteral("interceptTls"), m_proxyTlsCheck->isChecked());

    settings->setValue(QStringLiteral("modules/recon"), QStringLiteral("defaultTarget"), m_reconTargetEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/recon"), QStringLiteral("defaultEndpoint"), m_reconEndpointEdit->text().trimmed());

    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("targetUrl"), m_spiderTargetEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("maxPages"), m_spiderMaxPagesSpin->value());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("maxDepth"), m_spiderMaxDepthSpin->value());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("requestTimeoutMs"), m_spiderTimeoutSpin->value());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("scanStage"), m_spiderStageCombo->currentIndex());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("scopePreset"), m_spiderScopeCombo->currentData().toString());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("allowSubdomains"), m_spiderSubdomainsCheck->isChecked());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("loginUrl"), m_spiderLoginUrlEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("authUsername"), m_spiderUserEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("authPassword"), m_spiderPassEdit->text());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("usernameField"), m_spiderUserFieldEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("passwordField"), m_spiderPassFieldEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("csrfField"), m_spiderCsrfFieldEdit->text().trimmed());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("includePatterns"), m_spiderIncludeEdit->toPlainText().trimmed());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("excludePatterns"), m_spiderExcludeEdit->toPlainText().trimmed());
    settings->setValue(QStringLiteral("modules/spider"), QStringLiteral("authWorkflow"), m_spiderWorkflowEdit->toPlainText().trimmed());

    reloadThemeInfo();
    emit settingsApplied();
}

void SettingsLogWidget::loadFromSettings()
{
    if (!m_controller) {
        return;
    }

    auto *settings = m_controller->settingsManager();
    const QString theme = settings->value(QStringLiteral("theme"), QStringLiteral("currentTheme"), QStringLiteral("dark")).toString();
    {
        const QSignalBlocker blockMode(m_themeModeCombo);
        m_themeModeCombo->setCurrentIndex(qMax(0, m_themeModeCombo->findData(theme)));
    }
    m_themePresetCombo->setCurrentIndex(qMax(0,
                                             m_themePresetCombo->findData(
                                                 settings->value(QStringLiteral("theme/%1").arg(theme),
                                                                 QStringLiteral("presetId"),
                                                                 theme == QLatin1String("light")
                                                                     ? QStringLiteral("paper_ash")
                                                                     : QStringLiteral("tactical_crimson"))
                                                     .toString())));

    m_portTargetEdit->setText(settings->value(QStringLiteral("modules/port_scanner"), QStringLiteral("defaultHost"), QStringLiteral("127.0.0.1")).toString());
    m_portPortsEdit->setText(settings->value(QStringLiteral("modules/port_scanner"), QStringLiteral("defaultPorts"), QStringLiteral("common")).toString());
    m_portScanTypeCombo->setCurrentText(settings->value(QStringLiteral("modules/port_scanner"), QStringLiteral("scanType"), QStringLiteral("TCP Connect")).toString());
    m_portThreadSpin->setValue(settings->value(QStringLiteral("modules/port_scanner"), QStringLiteral("threadCount"), 64).toInt());
    m_portTimeoutSpin->setValue(settings->value(QStringLiteral("modules/port_scanner"), QStringLiteral("timeoutMs"), 600).toInt());
    m_portRetrySpin->setValue(settings->value(QStringLiteral("modules/port_scanner"), QStringLiteral("retryCount"), 1).toInt());
    m_portServiceCheck->setChecked(settings->value(QStringLiteral("modules/port_scanner"), QStringLiteral("serviceDetection"), true).toBool());
    m_portOsCheck->setChecked(settings->value(QStringLiteral("modules/port_scanner"), QStringLiteral("osFingerprinting"), false).toBool());

    m_proxyHostEdit->setText(settings->value(QStringLiteral("modules/proxy"), QStringLiteral("listenHost"), QStringLiteral("127.0.0.1")).toString());
    m_proxyPortSpin->setValue(settings->value(QStringLiteral("modules/proxy"), QStringLiteral("listenPort"), 8080).toInt());
    m_proxyTargetHostEdit->setText(settings->value(QStringLiteral("modules/proxy"), QStringLiteral("targetHost"), QStringLiteral("127.0.0.1")).toString());
    m_proxyTargetPortSpin->setValue(settings->value(QStringLiteral("modules/proxy"), QStringLiteral("targetPort"), 18081).toInt());
    m_proxyIdleTimeoutSpin->setValue(settings->value(QStringLiteral("modules/proxy"), QStringLiteral("idleTimeoutSeconds"), 30).toInt());
    m_proxyWorkerSpin->setValue(settings->value(QStringLiteral("modules/proxy"), QStringLiteral("workerThreads"), 2).toInt());
    m_proxyTlsCheck->setChecked(settings->value(QStringLiteral("modules/proxy"), QStringLiteral("interceptTls"), false).toBool());

    m_reconTargetEdit->setText(settings->value(QStringLiteral("modules/recon"), QStringLiteral("defaultTarget"), QStringLiteral("scanme.nmap.org")).toString());
    m_reconEndpointEdit->setText(settings->value(QStringLiteral("modules/recon"), QStringLiteral("defaultEndpoint"), QString()).toString());

    m_spiderTargetEdit->setText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("targetUrl"), QStringLiteral("https://scanme.nmap.org")).toString());
    m_spiderMaxPagesSpin->setValue(settings->value(QStringLiteral("modules/spider"), QStringLiteral("maxPages"), 40).toInt());
    m_spiderMaxDepthSpin->setValue(settings->value(QStringLiteral("modules/spider"), QStringLiteral("maxDepth"), 4).toInt());
    m_spiderTimeoutSpin->setValue(settings->value(QStringLiteral("modules/spider"), QStringLiteral("requestTimeoutMs"), 4000).toInt());
    m_spiderStageCombo->setCurrentIndex(settings->value(QStringLiteral("modules/spider"), QStringLiteral("scanStage"), 0).toInt());
    m_spiderScopeCombo->setCurrentIndex(qMax(0, m_spiderScopeCombo->findData(settings->value(QStringLiteral("modules/spider"), QStringLiteral("scopePreset"), QStringLiteral("dengeli")).toString())));
    m_spiderSubdomainsCheck->setChecked(settings->value(QStringLiteral("modules/spider"), QStringLiteral("allowSubdomains"), false).toBool());
    m_spiderLoginUrlEdit->setText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("loginUrl"), QString()).toString());
    m_spiderUserEdit->setText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("authUsername"), QString()).toString());
    m_spiderPassEdit->setText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("authPassword"), QString()).toString());
    m_spiderUserFieldEdit->setText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("usernameField"), QStringLiteral("username")).toString());
    m_spiderPassFieldEdit->setText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("passwordField"), QStringLiteral("password")).toString());
    m_spiderCsrfFieldEdit->setText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("csrfField"), QStringLiteral("_token")).toString());
    m_spiderIncludeEdit->setPlainText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("includePatterns"), QString()).toString());
    m_spiderExcludeEdit->setPlainText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("excludePatterns"), QStringLiteral("logout|signout")).toString());
    m_spiderWorkflowEdit->setPlainText(settings->value(QStringLiteral("modules/spider"), QStringLiteral("authWorkflow"), QString()).toString());
}

void SettingsLogWidget::buildUi()
{
    auto *root = pengufoce::ui::layout::createPageRoot(this, 18);

    auto *hero = pengufoce::ui::layout::createHeroCard(this);
    auto *heroLayout = qobject_cast<QVBoxLayout *>(hero->layout());

    auto *titleRow = new QHBoxLayout();
    auto *title = new QLabel(tr("Ayarlar ve Gunlukler"), hero);
    title->setObjectName("heroTitle");
    m_applySettingsButton = new QPushButton(tr("Tum Ayarlari Uygula"), hero);
    m_applySettingsButton->setObjectName("accentButton");
    titleRow->addWidget(title);
    titleRow->addStretch();
    titleRow->addWidget(m_applySettingsButton);

    auto *subtitle = new QLabel(tr("Tema, varsayilanlar ve gunlukler."), hero);
    subtitle->setObjectName("mutedText");
    subtitle->setWordWrap(true);

    auto *summaryHost = new QWidget(hero);
    auto *summaryRow = new FlowLayout(summaryHost, 0, 12, 12);
    auto *themeInfoCard = makeInfoCard(hero, tr("Tema Modu"), &m_themeModeValue);
    auto *presetInfoCard = makeInfoCard(hero, tr("Ayar Merkezi"), &m_presetHintValue);
    auto *logInfoCard = makeInfoCard(hero, tr("Toplam Log"), &m_logCountValue);
    themeInfoCard->setMinimumWidth(180);
    presetInfoCard->setMinimumWidth(180);
    logInfoCard->setMinimumWidth(180);
    summaryRow->addWidget(themeInfoCard);
    summaryRow->addWidget(presetInfoCard);
    summaryRow->addWidget(logInfoCard);
    summaryHost->setLayout(summaryRow);

    heroLayout->addLayout(titleRow);
    heroLayout->addWidget(subtitle);
    heroLayout->addWidget(summaryHost);

    auto *tabs = new QTabWidget(this);
    tabs->setDocumentMode(true);
    tabs->setUsesScrollButtons(true);

    auto *themePage = new QWidget(this);
    auto *themeLayout = new QVBoxLayout(themePage);
    themeLayout->setContentsMargins(0, 0, 0, 0);
    auto *themeCard = makeSectionCard(themePage, tr("Tema"), QString());
    auto *themeCardLayout = qobject_cast<QVBoxLayout *>(themeCard->layout());
    auto *themeGrid = new QGridLayout();
    themeGrid->setHorizontalSpacing(14);
    themeGrid->setVerticalSpacing(12);
    m_themeModeCombo = new QComboBox(themeCard);
    m_themeModeCombo->addItem(tr("Koyu"), QStringLiteral("dark"));
    m_themeModeCombo->addItem(tr("Acik"), QStringLiteral("light"));
    m_themePresetCombo = new QComboBox(themeCard);
    m_themePresetCombo->addItem(tr("Tactical Crimson"), QStringLiteral("tactical_crimson"));
    m_themePresetCombo->addItem(tr("Steel Blue"), QStringLiteral("steel_blue"));
    m_themePresetCombo->addItem(tr("Olive Ops"), QStringLiteral("olive_ops"));
    m_themePresetCombo->addItem(tr("Amber Grid"), QStringLiteral("amber_grid"));
    m_themePresetCombo->addItem(tr("Polar Night"), QStringLiteral("polar_night"));
    m_themePresetCombo->addItem(tr("Ember Wire"), QStringLiteral("ember_wire"));
    m_themePresetCombo->addItem(tr("Paper Ash"), QStringLiteral("paper_ash"));
    m_themePresetCombo->addItem(tr("Sandstone"), QStringLiteral("sandstone"));
    m_themePresetCombo->addItem(tr("Slate Light"), QStringLiteral("slate_light"));
    m_themePresetCombo->addItem(tr("Mint Console"), QStringLiteral("mint_console"));
    m_themePresetCombo->addItem(tr("Ivory Blue"), QStringLiteral("ivory_blue"));
    m_themePresetCombo->addItem(tr("Rose Paper"), QStringLiteral("rose_paper"));
    auto *applyPresetButton = new QPushButton(tr("Hazir Paleti Uygula"), themeCard);
    m_openSettingsButton = new QPushButton(tr("Detayli Renk Editoru"), themeCard);
    addField(themeGrid, 0, tr("Tema modu"), m_themeModeCombo);
    addField(themeGrid, 1, tr("Hazir palet"), m_themePresetCombo);
    themeGrid->addWidget(applyPresetButton, 2, 1);
    themeGrid->addWidget(m_openSettingsButton, 3, 1);
    themeCardLayout->addLayout(themeGrid);
    themeLayout->addWidget(themeCard);
    themeLayout->addStretch();

    auto *opsPage = new QWidget(this);
    auto *opsLayout = new QVBoxLayout(opsPage);
    opsLayout->setContentsMargins(0, 0, 0, 0);
    opsLayout->setSpacing(14);

    auto *portCard = makeSectionCard(opsPage, tr("Port Scanner"), QString());
    auto *portCardLayout = qobject_cast<QVBoxLayout *>(portCard->layout());
    auto *portGrid = new QGridLayout();
    portGrid->setHorizontalSpacing(14);
    portGrid->setVerticalSpacing(12);
    m_portTargetEdit = new QLineEdit(portCard);
    m_portPortsEdit = new QLineEdit(portCard);
    m_portScanTypeCombo = new QComboBox(portCard);
    m_portScanTypeCombo->addItems({tr("TCP Connect"), tr("UDP"), tr("Service/Version"), tr("OS Fingerprint")});
    m_portThreadSpin = new QSpinBox(portCard);
    m_portThreadSpin->setRange(1, 2048);
    m_portTimeoutSpin = new QSpinBox(portCard);
    m_portTimeoutSpin->setRange(50, 10000);
    m_portTimeoutSpin->setSuffix(tr(" ms"));
    m_portRetrySpin = new QSpinBox(portCard);
    m_portRetrySpin->setRange(0, 10);
    m_portServiceCheck = new QCheckBox(tr("Servis ve banner tespiti"), portCard);
    m_portOsCheck = new QCheckBox(tr("OS tahmini"), portCard);
    addField(portGrid, 0, tr("Varsayilan hedef"), m_portTargetEdit);
    addField(portGrid, 1, tr("Varsayilan portlar"), m_portPortsEdit);
    addField(portGrid, 2, tr("Tarama tipi"), m_portScanTypeCombo);
    addField(portGrid, 3, tr("Thread"), m_portThreadSpin);
    addField(portGrid, 4, tr("Zaman asimi"), m_portTimeoutSpin);
    addField(portGrid, 5, tr("Tekrar"), m_portRetrySpin);
    portGrid->addWidget(m_portServiceCheck, 6, 1);
    portGrid->addWidget(m_portOsCheck, 7, 1);
    portCardLayout->addLayout(portGrid);

    auto *proxyCard = makeSectionCard(opsPage, tr("Proxy"), QString());
    auto *proxyCardLayout = qobject_cast<QVBoxLayout *>(proxyCard->layout());
    auto *proxyGrid = new QGridLayout();
    proxyGrid->setHorizontalSpacing(14);
    proxyGrid->setVerticalSpacing(12);
    m_proxyHostEdit = new QLineEdit(proxyCard);
    m_proxyPortSpin = new QSpinBox(proxyCard);
    m_proxyPortSpin->setRange(1, 65535);
    m_proxyTargetHostEdit = new QLineEdit(proxyCard);
    m_proxyTargetPortSpin = new QSpinBox(proxyCard);
    m_proxyTargetPortSpin->setRange(1, 65535);
    m_proxyIdleTimeoutSpin = new QSpinBox(proxyCard);
    m_proxyIdleTimeoutSpin->setRange(5, 300);
    m_proxyIdleTimeoutSpin->setSuffix(tr(" sn"));
    m_proxyWorkerSpin = new QSpinBox(proxyCard);
    m_proxyWorkerSpin->setRange(1, 16);
    m_proxyTlsCheck = new QCheckBox(tr("TLS metadata etiketi acik"), proxyCard);
    addField(proxyGrid, 0, tr("Dinleme host"), m_proxyHostEdit);
    addField(proxyGrid, 1, tr("Dinleme port"), m_proxyPortSpin);
    addField(proxyGrid, 2, tr("Hedef host"), m_proxyTargetHostEdit);
    addField(proxyGrid, 3, tr("Hedef port"), m_proxyTargetPortSpin);
    addField(proxyGrid, 4, tr("Idle timeout"), m_proxyIdleTimeoutSpin);
    addField(proxyGrid, 5, tr("Worker"), m_proxyWorkerSpin);
    proxyGrid->addWidget(m_proxyTlsCheck, 6, 1);
    proxyCardLayout->addLayout(proxyGrid);

    auto *reconCard = makeSectionCard(opsPage, tr("Recon"), QString());
    auto *reconCardLayout = qobject_cast<QVBoxLayout *>(reconCard->layout());
    auto *reconGrid = new QGridLayout();
    reconGrid->setHorizontalSpacing(14);
    reconGrid->setVerticalSpacing(12);
    m_reconTargetEdit = new QLineEdit(reconCard);
    m_reconEndpointEdit = new QLineEdit(reconCard);
    addField(reconGrid, 0, tr("Varsayilan hedef"), m_reconTargetEdit);
    addField(reconGrid, 1, tr("OSINT / endpoint"), m_reconEndpointEdit);
    reconCardLayout->addLayout(reconGrid);

    opsLayout->addWidget(portCard);
    opsLayout->addWidget(proxyCard);
    opsLayout->addWidget(reconCard);
    opsLayout->addStretch();

    auto *spiderPage = new QWidget(this);
    auto *spiderLayout = new QVBoxLayout(spiderPage);
    spiderLayout->setContentsMargins(0, 0, 0, 0);
    spiderLayout->setSpacing(14);
    auto *spiderCard = makeSectionCard(spiderPage, tr("Spider"), QString());
    auto *spiderCardLayout = qobject_cast<QVBoxLayout *>(spiderCard->layout());
    auto *spiderGrid = new QGridLayout();
    spiderGrid->setHorizontalSpacing(14);
    spiderGrid->setVerticalSpacing(12);
    m_spiderTargetEdit = new QLineEdit(spiderCard);
    m_spiderMaxPagesSpin = new QSpinBox(spiderCard);
    m_spiderMaxPagesSpin->setRange(5, 250);
    m_spiderMaxDepthSpin = new QSpinBox(spiderCard);
    m_spiderMaxDepthSpin->setRange(1, 10);
    m_spiderTimeoutSpin = new QSpinBox(spiderCard);
    m_spiderTimeoutSpin->setRange(800, 10000);
    m_spiderTimeoutSpin->setSuffix(tr(" ms"));
    m_spiderStageCombo = new QComboBox(spiderCard);
    m_spiderStageCombo->addItems({tr("1. Asama - Hizli Kesif"), tr("2. Asama - Oturumlu Tarama"), tr("3. Asama - Uzman Politikasi")});
    m_spiderScopeCombo = new QComboBox(spiderCard);
    m_spiderScopeCombo->addItem(tr("Guvenli"), QStringLiteral("guvenli"));
    m_spiderScopeCombo->addItem(tr("Dengeli"), QStringLiteral("dengeli"));
    m_spiderScopeCombo->addItem(tr("Agresif"), QStringLiteral("agresif"));
    m_spiderSubdomainsCheck = new QCheckBox(tr("Alt alan adlarini tara"), spiderCard);
    m_spiderLoginUrlEdit = new QLineEdit(spiderCard);
    m_spiderUserEdit = new QLineEdit(spiderCard);
    m_spiderPassEdit = new QLineEdit(spiderCard);
    m_spiderPassEdit->setEchoMode(QLineEdit::Password);
    m_spiderUserFieldEdit = new QLineEdit(spiderCard);
    m_spiderPassFieldEdit = new QLineEdit(spiderCard);
    m_spiderCsrfFieldEdit = new QLineEdit(spiderCard);
    m_spiderIncludeEdit = new QPlainTextEdit(spiderCard);
    m_spiderIncludeEdit->setMaximumHeight(80);
    m_spiderExcludeEdit = new QPlainTextEdit(spiderCard);
    m_spiderExcludeEdit->setMaximumHeight(80);
    m_spiderWorkflowEdit = new QPlainTextEdit(spiderCard);
    m_spiderWorkflowEdit->setMaximumHeight(120);
    addField(spiderGrid, 0, tr("Seed URL"), m_spiderTargetEdit);
    addField(spiderGrid, 1, tr("Maksimum sayfa"), m_spiderMaxPagesSpin);
    addField(spiderGrid, 2, tr("Derinlik"), m_spiderMaxDepthSpin);
    addField(spiderGrid, 3, tr("Zaman asimi"), m_spiderTimeoutSpin);
    addField(spiderGrid, 4, tr("Tarama asamasi"), m_spiderStageCombo);
    addField(spiderGrid, 5, tr("Scope profili"), m_spiderScopeCombo);
    spiderGrid->addWidget(m_spiderSubdomainsCheck, 6, 1);
    addField(spiderGrid, 7, tr("Login URL"), m_spiderLoginUrlEdit);
    addField(spiderGrid, 8, tr("Kullanici"), m_spiderUserEdit);
    addField(spiderGrid, 9, tr("Parola"), m_spiderPassEdit);
    addField(spiderGrid, 10, tr("Username field"), m_spiderUserFieldEdit);
    addField(spiderGrid, 11, tr("Password field"), m_spiderPassFieldEdit);
    addField(spiderGrid, 12, tr("CSRF field"), m_spiderCsrfFieldEdit);
    addField(spiderGrid, 13, tr("Include kurallari"), m_spiderIncludeEdit);
    addField(spiderGrid, 14, tr("Exclude kurallari"), m_spiderExcludeEdit);
    addField(spiderGrid, 15, tr("Workflow"), m_spiderWorkflowEdit);
    spiderCardLayout->addLayout(spiderGrid);
    spiderLayout->addWidget(spiderCard);
    spiderLayout->addStretch();

    auto *logsPage = new QWidget(this);
    auto *logsLayout = new QVBoxLayout(logsPage);
    logsLayout->setContentsMargins(0, 0, 0, 0);
    auto *logCard = makeSectionCard(logsPage, tr("Gunlukler"), QString());
    auto *logCardLayout = qobject_cast<QVBoxLayout *>(logCard->layout());
    m_logConsole = new QPlainTextEdit(logCard);
    m_logConsole->setReadOnly(true);
    m_logConsole->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_logConsole->setMinimumHeight(420);
    logCardLayout->addWidget(m_logConsole, 1);
    logsLayout->addWidget(logCard);

    tabs->addTab(themePage, tr("Tema"));
    tabs->addTab(opsPage, tr("Moduller"));
    tabs->addTab(spiderPage, tr("Spider"));
    tabs->addTab(logsPage, tr("Gunlukler"));

    root->addWidget(hero);
    root->addWidget(tabs, 1);

    connect(m_applySettingsButton, &QPushButton::clicked, this, &SettingsLogWidget::applyAllSettings);
    connect(applyPresetButton, &QPushButton::clicked, this, &SettingsLogWidget::applyPreset);
    connect(m_openSettingsButton, &QPushButton::clicked, this, &SettingsLogWidget::openSettingsRequested);
}
