#include "mainwindow.h"

#include "controllers/app/appcontroller.h"
#include "core/logging/logmodel.h"
#include "core/framework/moduleinterface.h"
#include "core/framework/modulemanager.h"
#include "controllers/app/sessionmanager.h"
#include "core/theme/themeengine.h"
#include "core/settings/settingsmanager.h"
#include "modules/portscanner/portscannermodule.h"
#include "modules/proxy/proxymodule.h"
#include "modules/recon/reconmodule.h"
#include "modules/spider/spidermodule.h"
#include "modules/pengucore/pengucoremodule.h"
#include "bladesidebar.h"
#include "ui/views/portscanner/portscannerwidget.h"
#include "ui/views/proxy/proxywidget.h"
#include "ui/views/recon/reconwidget.h"
#include "settingsdialog.h"
#include "ui/panels/controlcenter/settingslogwidget.h"
#include "ui/views/spider/spiderwidget.h"
#include "ui/views/pengucore/pengucorewidget.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"

#include <QDateTime>
#include <QFileDialog>
#include <QFrame>
#include <QApplication>
#include <QAbstractSpinBox>
#include <QColor>
#include <QComboBox>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QTabBar>
#include <QEvent>
#include <QStatusBar>
#include <QScrollBar>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>
#include <QEasingCurve>

namespace {

QString defaultPresetForTheme(const QString &theme)
{
    return theme == QLatin1String("light") ? QStringLiteral("paper_ash")
                                           : QStringLiteral("tactical_crimson");
}

QString currentPresetId(const AppController *controller)
{
    if (!controller || !controller->settingsManager() || !controller->themeEngine()) {
        return QStringLiteral("tactical_crimson");
    }

    const QString theme = controller->themeEngine()->currentTheme();
    return controller->settingsManager()
        ->value(QStringLiteral("theme/%1").arg(theme),
                QStringLiteral("presetId"),
                defaultPresetForTheme(theme))
        .toString();
}

struct ThemeScheme
{
    QString heroGradient;
    QString heroBorder;
    QString cardGradient;
    QString cardBorder;
    QString buttonGradient;
    QString buttonHover;
    QString accentGradient;
    QString tabGradient;
    QString railGradient;
    QString tooltipFill;
    QString inputFill;
    int largeRadius = 16;
    int smallRadius = 12;
    int tabRadius = 10;
};

ThemeScheme buildThemeScheme(const QString &presetId,
                             const QColor &windowColor,
                             const QColor &panelColor,
                             const QColor &panelAltColor,
                             const QColor &accentColor,
                             const QColor &accentSoftColor,
                             const QColor &textColor)
{
    ThemeScheme scheme;
    scheme.heroGradient = QStringLiteral(
                              "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 %1, stop:0.48 %2, stop:1 %3)")
                              .arg(QColor::fromRgbF((panelColor.redF() * 0.52) + (accentSoftColor.redF() * 0.48),
                                                    (panelColor.greenF() * 0.52) + (accentSoftColor.greenF() * 0.48),
                                                    (panelColor.blueF() * 0.52) + (accentSoftColor.blueF() * 0.48),
                                                    1.0)
                                       .name(),
                                   panelColor.name(),
                                   QColor::fromRgbF((panelAltColor.redF() * 0.76) + (windowColor.redF() * 0.24),
                                                    (panelAltColor.greenF() * 0.76) + (windowColor.greenF() * 0.24),
                                                    (panelAltColor.blueF() * 0.76) + (windowColor.blueF() * 0.24),
                                                    1.0)
                                       .name());
    scheme.heroBorder = accentColor.lighter(120).name();
    scheme.cardGradient = QStringLiteral(
                              "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 %1, stop:1 %2)")
                              .arg(QColor::fromRgbF((panelAltColor.redF() * 0.78) + (accentSoftColor.redF() * 0.22),
                                                    (panelAltColor.greenF() * 0.78) + (accentSoftColor.greenF() * 0.22),
                                                    (panelAltColor.blueF() * 0.78) + (accentSoftColor.blueF() * 0.22),
                                                    1.0)
                                       .name(),
                                   panelColor.name());
    scheme.cardBorder = QColor::fromRgbF((accentSoftColor.redF() * 0.36) + (textColor.redF() * 0.12),
                                         (accentSoftColor.greenF() * 0.36) + (textColor.greenF() * 0.12),
                                         (accentSoftColor.blueF() * 0.36) + (textColor.blueF() * 0.12),
                                         1.0)
                            .name();
    scheme.buttonGradient = QStringLiteral(
                                "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 %1, stop:1 %2)")
                                .arg(QColor::fromRgbF((panelAltColor.redF() * 0.82) + (accentSoftColor.redF() * 0.18),
                                                      (panelAltColor.greenF() * 0.82) + (accentSoftColor.greenF() * 0.18),
                                                      (panelAltColor.blueF() * 0.82) + (accentSoftColor.blueF() * 0.18),
                                                      1.0)
                                         .name(),
                                     QColor::fromRgbF((panelColor.redF() * 0.9) + (windowColor.redF() * 0.1),
                                                      (panelColor.greenF() * 0.9) + (windowColor.greenF() * 0.1),
                                                      (panelColor.blueF() * 0.9) + (windowColor.blueF() * 0.1),
                                                      1.0)
                                         .name());
    scheme.buttonHover = QColor::fromRgbF((panelAltColor.redF() * 0.48) + (accentSoftColor.redF() * 0.52),
                                          (panelAltColor.greenF() * 0.48) + (accentSoftColor.greenF() * 0.52),
                                          (panelAltColor.blueF() * 0.48) + (accentSoftColor.blueF() * 0.52),
                                          1.0)
                             .name();
    scheme.accentGradient = QStringLiteral(
                                "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 %1, stop:1 %2)")
                                .arg(accentColor.lighter(126).name(),
                                     accentColor.darker(138).name());
    scheme.tabGradient = QStringLiteral(
                             "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 %1, stop:1 %2)")
                             .arg(QColor::fromRgbF((panelColor.redF() * 0.68) + (accentSoftColor.redF() * 0.32),
                                                   (panelColor.greenF() * 0.68) + (accentSoftColor.greenF() * 0.32),
                                                   (panelColor.blueF() * 0.68) + (accentSoftColor.blueF() * 0.32),
                                                   1.0)
                                      .name(),
                                  panelAltColor.name());
    scheme.railGradient = QStringLiteral(
                              "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 %1, stop:1 %2)")
                              .arg(QColor::fromRgbF((panelColor.redF() * 0.64) + (accentSoftColor.redF() * 0.36),
                                                    (panelColor.greenF() * 0.64) + (accentSoftColor.greenF() * 0.36),
                                                    (panelColor.blueF() * 0.64) + (accentSoftColor.blueF() * 0.36),
                                                    1.0)
                                       .name(),
                                   panelAltColor.name());
    scheme.tooltipFill = QColor::fromRgbF((accentColor.redF() * 0.42) + (panelColor.redF() * 0.58),
                                          (accentColor.greenF() * 0.42) + (panelColor.greenF() * 0.58),
                                          (accentColor.blueF() * 0.42) + (panelColor.blueF() * 0.58),
                                          0.96)
                             .name(QColor::HexArgb);
    scheme.inputFill = panelAltColor.name();

    if (presetId == QLatin1String("amber_grid") || presetId == QLatin1String("olive_ops")) {
        scheme.heroGradient = QStringLiteral(
                                  "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 %1, stop:0.55 %2, stop:1 %3)")
                                  .arg(QColor::fromRgbF((windowColor.redF() * 0.52) + (accentSoftColor.redF() * 0.48),
                                                        (windowColor.greenF() * 0.52) + (accentSoftColor.greenF() * 0.48),
                                                        (windowColor.blueF() * 0.52) + (accentSoftColor.blueF() * 0.48),
                                                        1.0)
                                           .name(),
                                       panelColor.name(),
                                       QColor::fromRgbF((panelColor.redF() * 0.76) + (accentColor.redF() * 0.24),
                                                        (panelColor.greenF() * 0.76) + (accentColor.greenF() * 0.24),
                                                        (panelColor.blueF() * 0.76) + (accentColor.blueF() * 0.24),
                                                        1.0)
                                           .name());
        scheme.cardGradient = QStringLiteral(
                                  "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 %1, stop:1 %2)")
                                  .arg(panelColor.name(),
                                       QColor::fromRgbF((panelAltColor.redF() * 0.86) + (accentSoftColor.redF() * 0.14),
                                                        (panelAltColor.greenF() * 0.86) + (accentSoftColor.greenF() * 0.14),
                                                        (panelAltColor.blueF() * 0.86) + (accentSoftColor.blueF() * 0.14),
                                                        1.0)
                                           .name());
        scheme.largeRadius = 10;
        scheme.smallRadius = 9;
        scheme.tabRadius = 8;
    } else if (presetId == QLatin1String("polar_night") || presetId == QLatin1String("steel_blue")) {
        scheme.heroGradient = QStringLiteral(
                                  "qradialgradient(cx:0.18, cy:0.08, radius:1.05, fx:0.18, fy:0.08, stop:0 %1, stop:0.4 %2, stop:1 %3)")
                                  .arg(accentSoftColor.lighter(108).name(),
                                       panelColor.name(),
                                       windowColor.name());
        scheme.cardGradient = QStringLiteral(
                                  "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 %1, stop:1 %2)")
                                  .arg(QColor::fromRgbF((panelAltColor.redF() * 0.68) + (accentSoftColor.redF() * 0.32),
                                                        (panelAltColor.greenF() * 0.68) + (accentSoftColor.greenF() * 0.32),
                                                        (panelAltColor.blueF() * 0.68) + (accentSoftColor.blueF() * 0.32),
                                                        1.0)
                                           .name(),
                                       panelColor.name());
        scheme.largeRadius = 20;
        scheme.smallRadius = 14;
    } else if (presetId == QLatin1String("ember_wire") || presetId == QLatin1String("tactical_crimson")) {
        scheme.heroGradient = QStringLiteral(
                                  "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 %1, stop:0.45 %2, stop:1 %3)")
                                  .arg(QColor::fromRgbF((accentSoftColor.redF() * 0.64) + (windowColor.redF() * 0.36),
                                                        (accentSoftColor.greenF() * 0.64) + (windowColor.greenF() * 0.36),
                                                        (accentSoftColor.blueF() * 0.64) + (windowColor.blueF() * 0.36),
                                                        1.0)
                                           .name(),
                                       panelColor.name(),
                                       QColor::fromRgbF((accentColor.redF() * 0.18) + (panelAltColor.redF() * 0.82),
                                                        (accentColor.greenF() * 0.18) + (panelAltColor.greenF() * 0.82),
                                                        (accentColor.blueF() * 0.18) + (panelAltColor.blueF() * 0.82),
                                                        1.0)
                                           .name());
        scheme.accentGradient = QStringLiteral(
                                    "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 %1, stop:1 %2)")
                                    .arg(accentColor.lighter(132).name(),
                                         accentColor.darker(150).name());
    } else if (presetId == QLatin1String("rose_paper") || presetId == QLatin1String("sandstone") || presetId == QLatin1String("paper_ash")) {
        scheme.heroGradient = QStringLiteral(
                                  "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 %1, stop:0.52 %2, stop:1 %3)")
                                  .arg(QColor::fromRgbF((accentSoftColor.redF() * 0.52) + (windowColor.redF() * 0.48),
                                                        (accentSoftColor.greenF() * 0.52) + (windowColor.greenF() * 0.48),
                                                        (accentSoftColor.blueF() * 0.52) + (windowColor.blueF() * 0.48),
                                                        1.0)
                                           .name(),
                                       panelColor.name(),
                                       panelAltColor.name());
    }

    return scheme;
}

}

MainWindow::MainWindow(AppController *controller, QWidget *parent)
    : QMainWindow(parent)
    , m_controller(controller)
    , m_moduleManager(controller->moduleManager())
    , m_logModel(controller->logger()->model())
{
    buildUi();
    populateModules();
    appendExistingLogs();
    syncTheme();
    qApp->installEventFilter(this);

    connect(m_logModel, &QAbstractItemModel::rowsInserted, this, [this](const QModelIndex &, int, int) {
        handleLogRowsInserted();
    });
}

bool MainWindow::eventFilter(QObject *watched, QEvent *event)
{
    if (event && event->type() == QEvent::Wheel) {
        if (qobject_cast<QTabBar *>(watched)) {
            return true;
        }
        if (qobject_cast<QComboBox *>(watched) || qobject_cast<QAbstractSpinBox *>(watched)) {
            return true;
        }
    }

    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::handleModuleSelectionChanged(int row)
{
    setActiveModuleIndex(row);
}

void MainWindow::handleLogRowsInserted()
{
    const int lastRow = m_logModel->rowCount() - 1;
    if (lastRow < 0) {
        return;
    }

    const QModelIndex index = m_logModel->index(lastRow, 0);
    if (m_settingsLogWidget) {
        m_settingsLogWidget->appendLogLine(m_logModel->data(index, LogModel::FormattedRole).toString());
    }
}

void MainWindow::syncTheme()
{
    setStyleSheet(buildStyleSheet());
    setWindowTitle(tr("PenguFoce Control Center"));
    statusBar()->showMessage(tr("Arayuz hazir"), 2000);
}

void MainWindow::openSettings()
{
    delete m_settingsDialog;
    m_settingsDialog = new SettingsDialog(m_controller, this);
    connect(m_settingsDialog, &SettingsDialog::settingsApplied, this, [this]() {
        if (m_portScannerWidget) {
            m_portScannerWidget->reloadSettings();
        }
        if (m_proxyWidget) {
            m_proxyWidget->reloadSettings();
        }
        if (m_proxyWaterfallPage) {
            m_proxyWaterfallPage->reloadSettings();
        }
        if (m_reconWidget) {
            m_reconWidget->reloadSettings();
        }
        if (m_spiderWidget) {
            m_spiderWidget->reloadSettings();
        }
        if (m_settingsLogWidget) {
            m_settingsLogWidget->reloadThemeInfo();
        }
        syncTheme();
        statusBar()->showMessage(tr("Ayarlar guncellendi"), 3000);
    });
    m_settingsDialog->exec();
}

void MainWindow::saveSession()
{
    const QString path = QFileDialog::getSaveFileName(this,
                                                      tr("Oturumu Kaydet"),
                                                      QString("pengufoce-session-%1.json").arg(QDateTime::currentDateTime().toString("yyyyMMdd-hhmmss")),
                                                      tr("JSON (*.json)"));
    if (!path.isEmpty()) {
        m_controller->sessionManager()->saveSession(path);
    }
}

void MainWindow::loadSession()
{
    const QString path = QFileDialog::getOpenFileName(this, tr("Oturum Yukle"), QString(), tr("JSON (*.json)"));
    if (!path.isEmpty()) {
        m_controller->sessionManager()->loadSession(path);
    }
}

void MainWindow::buildUi()
{
    resize(1560, 980);
    setMinimumSize(1240, 840);
    setWindowTitle(tr("PenguFoce Control Center"));

    auto *fileMenu = menuBar()->addMenu(tr("Dosya"));
    fileMenu->addAction(tr("Oturumu Kaydet"), this, &MainWindow::saveSession);
    fileMenu->addAction(tr("Oturum Yukle"), this, &MainWindow::loadSession);
    fileMenu->addAction(tr("Ayarlar"), this, &MainWindow::openSettings);
    fileMenu->addSeparator();
    fileMenu->addAction(tr("Cikis"), this, &QWidget::close);

    auto *penguCoreMenu = menuBar()->addMenu(tr("PenguCore"));
    penguCoreMenu->addAction(tr("Capture Dosyasi Ac"), this, [this]() {
        if (m_penguCoreWidget) {
            m_penguCoreWidget->openCaptureDialog();
        }
    });
    penguCoreMenu->addAction(tr("Son Live Kaydi Ac"), this, [this]() {
        if (m_penguCoreWidget) {
            m_penguCoreWidget->openLastLiveCaptureWindow();
        }
    });

    auto *central = new QWidget(this);
    central->setObjectName("appRoot");
    auto *rootLayout = new QHBoxLayout(central);
    rootLayout->setContentsMargins(18, 18, 18, 18);
    rootLayout->setSpacing(18);

    auto *leftRail = new QWidget(central);
    auto *leftRailLayout = new QVBoxLayout(leftRail);
    leftRailLayout->setContentsMargins(0, 0, 0, 0);
    leftRailLayout->setSpacing(12);

    m_sidebar = new BladeSidebar(leftRail);
    m_sidebar->setFixedWidth(400);
    connect(m_sidebar, &BladeSidebar::moduleSelected, this, &MainWindow::handleModuleSelectionChanged);

    leftRailLayout->addWidget(m_sidebar, 1);

    auto *scrollArea = new QScrollArea(central);
    scrollArea->setObjectName("mainScrollArea");
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    m_mainContentWidget = new QWidget(scrollArea);
    auto *mainColumn = pengufoce::ui::layout::createPageRoot(m_mainContentWidget, 18);

    auto *heroFrame = pengufoce::ui::layout::createHeroCard(central, QMargins(26, 24, 26, 24), 12);
    auto *heroLayout = qobject_cast<QVBoxLayout *>(heroFrame->layout());

    auto *topBar = new QHBoxLayout();
    auto *brand = new QLabel(tr("PenguFoce"), heroFrame);
    brand->setObjectName("brandTitle");
    auto *topHint = new QLabel(tr("Kontrol merkezi"), heroFrame);
    topHint->setObjectName("mutedText");
    topHint->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    topHint->setWordWrap(true);
    topBar->addWidget(brand);
    topBar->addStretch();
    topBar->addWidget(topHint);

    m_headerTitle = new QLabel(tr("Calisma Alani"), heroFrame);
    m_headerTitle->setObjectName("heroTitle");
    m_headerDescription = new QLabel(tr("Moduller arasi hizli gecis."), heroFrame);
    m_headerDescription->setObjectName("heroLead");
    m_headerDescription->setWordWrap(true);

    auto *summaryHost = new QWidget(heroFrame);
    auto *summaryRow = new FlowLayout(summaryHost, 0, 12, 12);

    auto *summaryCard = new QFrame(heroFrame);
    summaryCard->setObjectName("summaryCard");
    auto *summaryCardLayout = new QVBoxLayout(summaryCard);
    summaryCardLayout->setContentsMargins(18, 16, 18, 16);
    summaryCardLayout->setSpacing(4);
    auto *modulesLabel = new QLabel(tr("Yuklu Moduller"), summaryCard);
    modulesLabel->setObjectName("summaryKicker");
    m_moduleCountValue = new QLabel("0", summaryCard);
    m_moduleCountValue->setObjectName("heroValue");
    summaryCardLayout->addWidget(modulesLabel);
    summaryCardLayout->addWidget(m_moduleCountValue);

    auto *activeCard = new QFrame(heroFrame);
    activeCard->setObjectName("summaryCard");
    activeCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    auto *activeCardLayout = new QVBoxLayout(activeCard);
    activeCardLayout->setContentsMargins(18, 16, 18, 16);
    activeCardLayout->setSpacing(4);
    auto *activeLabel = new QLabel(tr("Etkin Odak"), activeCard);
    activeLabel->setObjectName("summaryKicker");
    m_activeModuleValue = new QLabel("--", activeCard);
    m_activeModuleValue->setObjectName("activeFocus");
    m_statusHint = new QLabel(tr("Canli veri ve yardim aciklamalari burada gunluk akisa gore sekillenir."), activeCard);
    m_statusHint->setWordWrap(true);
    m_statusHint->setObjectName("heroMeta");
    activeCardLayout->addWidget(activeLabel);
    activeCardLayout->addWidget(m_activeModuleValue);
    activeCardLayout->addWidget(m_statusHint);

    summaryCard->setMinimumWidth(160);
    activeCard->setMinimumWidth(220);
    summaryRow->addWidget(summaryCard);
    summaryRow->addWidget(activeCard);
    summaryHost->setLayout(summaryRow);

    heroLayout->addLayout(topBar);
    heroLayout->addWidget(m_headerTitle);
    heroLayout->addWidget(m_headerDescription);
    heroLayout->addWidget(summaryHost);

    m_contentStack = new QStackedWidget(central);
    m_contentStack->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    m_pageOpacityEffect = new QGraphicsOpacityEffect(m_contentStack);
    m_pageOpacityEffect->setOpacity(1.0);
    m_contentStack->setGraphicsEffect(m_pageOpacityEffect);
    m_pageFadeAnimation = new QPropertyAnimation(m_pageOpacityEffect, "opacity", this);
    m_pageFadeAnimation->setDuration(220);
    m_pageFadeAnimation->setStartValue(0.72);
    m_pageFadeAnimation->setEndValue(1.0);
    m_pageFadeAnimation->setEasingCurve(QEasingCurve::OutCubic);

    mainColumn->addWidget(heroFrame);
    mainColumn->addWidget(m_contentStack, 1);
    mainColumn->addStretch(0);

    scrollArea->setWidget(m_mainContentWidget);

    rootLayout->addWidget(leftRail);
    rootLayout->addWidget(scrollArea, 1);

    setCentralWidget(central);
    statusBar()->showMessage(tr("Hazir"));
}

void MainWindow::populateModules()
{
    while (m_contentStack->count() > 0) {
        QWidget *page = m_contentStack->widget(0);
        m_contentStack->removeWidget(page);
        page->deleteLater();
    }

    m_sidebar->clearModules();

    for (int row = 0; row < m_moduleManager->rowCount(); ++row) {
        const QVariantMap moduleData = m_moduleManager->get(row);
        m_sidebar->addModule(moduleData.value("name").toString(), moduleData.value("description").toString(), row);

        QWidget *page = nullptr;
        auto *moduleObject = qvariant_cast<ModuleInterface *>(moduleData.value("moduleObject"));
        if (auto *scanner = qobject_cast<PortScannerModule *>(moduleObject)) {
            page = new PortScannerWidget(scanner, m_contentStack);
            m_portScannerWidget = static_cast<PortScannerWidget *>(page);
        } else if (auto *recon = qobject_cast<ReconModule *>(moduleObject)) {
            page = new ReconWidget(recon, m_contentStack);
            m_reconWidget = static_cast<ReconWidget *>(page);
        } else if (auto *spider = qobject_cast<SpiderModule *>(moduleObject)) {
            page = new SpiderWidget(spider, m_contentStack);
            m_spiderWidget = static_cast<SpiderWidget *>(page);
        } else if (auto *penguCore = qobject_cast<PenguCoreModule *>(moduleObject)) {
            page = new PenguCoreWidget(penguCore, m_contentStack);
            m_penguCoreWidget = static_cast<PenguCoreWidget *>(page);
        } else if (auto *proxy = qobject_cast<ProxyModule *>(moduleObject)) {
            page = new ProxyWidget(proxy, m_contentStack);
            m_proxyWidget = static_cast<ProxyWidget *>(page);
            m_proxyWaterfallPage = new ProxyWaterfallPage(proxy, m_contentStack);
            m_contentStack->addWidget(m_proxyWaterfallPage);
            m_sidebar->addUtilityOrb(tr("Traffic Waterfall"),
                                     tr("Proxy telemetrisi icin genis spektrum ekrani."),
                                     m_contentStack->indexOf(m_proxyWaterfallPage));
        } else {
            auto *placeholder = new QLabel(tr("Bu modul icin henuz ozel bir calisma alani hazir degil."), m_contentStack);
            placeholder->setAlignment(Qt::AlignCenter);
            page = placeholder;
        }

        m_contentStack->addWidget(page);
    }

    const int utilityIndex = m_contentStack->count();
    m_sidebar->addUtilityOrb(tr("Ayarlar / Gunlukler"),
                             tr("Tema paleti, arayuz ayarlari ve tum etkinlik gunlukleri burada toplanir."),
                             utilityIndex);
    m_settingsLogWidget = new SettingsLogWidget(m_controller, m_logModel, m_contentStack);
    connect(m_settingsLogWidget, &SettingsLogWidget::openSettingsRequested, this, &MainWindow::openSettings);
    connect(m_settingsLogWidget, &SettingsLogWidget::settingsApplied, this, [this]() {
        if (m_portScannerWidget) {
            m_portScannerWidget->reloadSettings();
        }
        if (m_proxyWidget) {
            m_proxyWidget->reloadSettings();
        }
        if (m_proxyWaterfallPage) {
            m_proxyWaterfallPage->reloadSettings();
        }
        if (m_reconWidget) {
            m_reconWidget->reloadSettings();
        }
        if (m_spiderWidget) {
            m_spiderWidget->reloadSettings();
        }
        if (m_settingsLogWidget) {
            m_settingsLogWidget->reloadThemeInfo();
        }
        syncTheme();
        statusBar()->showMessage(tr("Ayar merkezi guncellendi"), 3000);
    });
    m_contentStack->addWidget(m_settingsLogWidget);

    m_moduleCountValue->setText(QString::number(m_moduleManager->rowCount()));
    if (m_moduleManager->rowCount() > 0) {
        setActiveModuleIndex(0);
    }
}

void MainWindow::appendExistingLogs()
{
    if (m_settingsLogWidget) {
        m_settingsLogWidget->appendExistingLogs();
    }
}

void MainWindow::setActiveModuleIndex(int row)
{
    if (row < 0 || row >= m_contentStack->count()) {
        return;
    }

    if (m_proxyWidget) {
        m_proxyWidget->setActiveView(false);
    }
    if (m_proxyWaterfallPage) {
        m_proxyWaterfallPage->setActiveView(false);
    }
    if (m_reconWidget) {
        m_reconWidget->setActiveView(false);
    }

    m_sidebar->setActiveIndex(row);
    m_contentStack->setCurrentIndex(row);
    animateCurrentPage();

    if (row < m_moduleManager->rowCount()) {
        m_moduleManager->setActiveIndex(row);
        const QVariantMap moduleData = m_moduleManager->get(row);
        m_headerTitle->setText(moduleData.value("name").toString());
        m_headerDescription->setText(moduleData.value("description").toString());
        m_activeModuleValue->setText(moduleData.value("name").toString());
        m_statusHint->setText(tr("%1 aktif.").arg(moduleData.value("name").toString()));
        if (m_contentStack->currentWidget() == m_proxyWidget && m_proxyWidget) {
            m_proxyWidget->setActiveView(true);
        }
        if (m_contentStack->currentWidget() == m_proxyWaterfallPage && m_proxyWaterfallPage) {
            m_proxyWaterfallPage->setActiveView(true);
        }
        if (m_contentStack->currentWidget() == m_reconWidget && m_reconWidget) {
            m_reconWidget->setActiveView(true);
        }
        return;
    }

    if (m_proxyWaterfallPage && row == m_contentStack->indexOf(m_proxyWaterfallPage)) {
        m_headerTitle->setText(tr("Traffic Waterfall"));
        m_headerDescription->setText(tr("Proxy telemetrisini genis spektrum ekraninda izle."));
        m_activeModuleValue->setText(tr("Waterfall"));
        m_statusHint->setText(tr("Canli trafik yogunlugu zaman ekseninde akiyor."));
        m_proxyWaterfallPage->reloadSettings();
        m_proxyWaterfallPage->setActiveView(true);
        return;
    }

    m_headerTitle->setText(tr("Ayarlar / Gunlukler"));
    m_headerDescription->setText(tr("Tema, varsayilanlar ve gunlukler."));
    m_activeModuleValue->setText(tr("Kontrol Merkezi"));
    m_statusHint->setText(tr("Ayarlar ve gunlukler."));
    if (m_settingsLogWidget) {
        m_settingsLogWidget->reloadThemeInfo();
    }
}

void MainWindow::animateCurrentPage()
{
    if (!m_pageFadeAnimation || !m_pageOpacityEffect) {
        return;
    }

    m_pageFadeAnimation->stop();
    m_pageOpacityEffect->setOpacity(0.72);
    m_pageFadeAnimation->start();
}

QString MainWindow::buildStyleSheet() const
{
    const QVariantMap palette = m_controller->themeEngine()->palette();
    const QString presetId = currentPresetId(m_controller);
    const QString window = palette.value("window").toString();
    const QString panel = palette.value("panel").toString();
    const QString panelAlt = palette.value("panelAlt").toString();
    const QString border = palette.value("border").toString();
    const QString text = palette.value("text").toString();
    const QString mutedText = palette.value("mutedText").toString();
    const QString accent = palette.value("accent").toString();
    const QString accentSoft = palette.value("accentSoft").toString();
    const QColor windowColor(window);
    const QColor panelColor(panel);
    const QColor panelAltColor(panelAlt);
    const QColor textColor(text);
    const QColor accentColor(accent);
    const QColor accentSoftColor(accentSoft);
    const QString accentStrong = accentColor.lighter(130).name();
    const ThemeScheme scheme = buildThemeScheme(presetId,
                                                windowColor,
                                                panelColor,
                                                panelAltColor,
                                                accentColor,
                                                accentSoftColor,
                                                textColor);
    const QString edgeGlow = textColor.lighter(108).name();

    if (m_sidebar) {
        m_sidebar->setColors(QColor(window), QColor(panel), QColor(accent), QColor(edgeGlow), QColor(mutedText));
    }

    return QString(
               "QMainWindow, QWidget#appRoot {"
               "background-color: %1;"
               "color: %2;"
               "font-family: 'Bahnschrift SemiCondensed';"
               "font-size: 11pt;"
                "}"
               "QWidget { color: %2; }"
               "* { margin: 0px; }"
               "QLabel { background: transparent; }"
               "QLabel#bladeTitle { font-size: 17pt; font-weight: 700; color: #f3ece7; }"
               "QLabel#bladeSubtitle { font-size: 9.5pt; color: %4; letter-spacing: 1px; text-transform: uppercase; }"
               "QMenuBar, QMenu { background: %3; color: %2; border: none; }"
               "QMenuBar::item { padding: 8px 12px; background: transparent; border-radius: 8px; }"
               "QMenuBar::item:selected, QMenu::item:selected { background: %8; color: %2; }"
               "QStatusBar { background: %3; color: %4; border-top: 1px solid %5; min-height: 28px; }"
               "QDialog { background: %1; color: %2; }"
               "QFrame#cardPanel, QFrame#summaryCard {"
               "background: %9;"
               "border: 1px solid %10;"
               "border-radius: %16px;"
                "}"
               "QFrame#heroPanel {"
               "background: %11;"
               "border: 1px solid %12;"
               "border-radius: %17px;"
                "}"
               "QLabel#brandTitle { font-size: 22pt; font-weight: 700; }"
               "QLabel#heroTitle { font-size: 20pt; font-weight: 700; letter-spacing: 0.3px; }"
               "QLabel#heroLead { color: %2; font-size: 11.4pt; font-weight: 500; }"
               "QLabel#heroMeta { color: %4; font-size: 10.3pt; }"
               "QLabel#summaryKicker { color: %4; font-size: 9.8pt; letter-spacing: 0.9px; text-transform: uppercase; }"
               "QLabel#sectionTitle { font-size: 14.8pt; font-weight: 700; }"
               "QLabel#cardTitle { font-size: 13.6pt; font-weight: 600; }"
               "QLabel#activeFocus { font-size: 18pt; font-weight: 700; color: %2; }"
               "QLabel#heroValue { font-size: 26pt; font-weight: 700; }"
               "QLabel#statValue { font-size: 16pt; font-weight: 700; }"
               "QLabel#mutedText { color: %4; font-size: 11pt; line-height: 1.35; }"
               "QLineEdit, QPlainTextEdit, QTableWidget, QListWidget {"
               "background: %13;"
               "color: %2;"
               "border: 1px solid %5;"
               "border-radius: %18px;"
               "padding: 14px;"
               "min-height: 34px;"
               "selection-background-color: %6;"
               "}"
               "QComboBox, QSpinBox {"
               "background: %13;"
               "color: %2;"
               "border: 1px solid %5;"
               "border-radius: %18px;"
               "padding: 8px 46px 8px 14px;"
               "min-height: 38px;"
                "}"
               "QListWidget::item { padding: 12px 12px; border-radius: 10px; margin: 4px 0; min-height: 30px; }"
               "QListWidget::item:selected { background: %8; color: %2; }"
               "QListWidget::item:hover { background: %14; }"
               "QTabWidget::pane { background: %3; border: 1px solid %5; border-radius: %18px; top: -1px; }"
               "QTabBar::tab { background: %15; color: %4; border: 1px solid %5; padding: 12px 18px; border-top-left-radius: %19px; border-top-right-radius: %19px; margin-right: 4px; min-width: 110px; min-height: 26px; }"
               "QTabBar::tab:selected { background: %8; color: %2; }"
               "QTabBar::tab:hover:!selected { background: %14; color: %2; }"
               "QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 38px; border: none; background: transparent; }"
               "QComboBox QAbstractItemView {"
               "background: %3;"
               "color: %2;"
               "border: 1px solid %5;"
               "border-radius: 10px;"
               "padding: 6px;"
               "selection-background-color: %8;"
               "selection-color: %2;"
               "outline: 0;"
               "}"
               "QComboBox QAbstractItemView::item { min-height: 34px; padding: 8px 12px; background: %3; }"
               "QComboBox QAbstractItemView::item:selected { background: %8; color: %2; }"
               "QSpinBox::up-button, QSpinBox::down-button { subcontrol-origin: border; width: 20px; border: none; background: transparent; margin-right: 6px; }"
               "QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QListWidget:focus, QTableWidget:focus { border: 2px solid %6; }"
               "QPushButton {"
               "background: %20;"
               "color: %2;"
               "border: 1px solid %5;"
               "border-radius: %18px;"
                "padding: 13px 18px;"
               "min-height: 32px;"
               "font-weight: 600;"
                "}"
               "QPushButton:hover { border-color: %21; background: %14; }"
               "QPushButton:pressed { padding-top: 13px; padding-bottom: 11px; border-color: %6; background: %8; }"
               "QPushButton#accentButton { background: %22; border-color: %21; color: white; }"
               "QPushButton#accentButton:hover { background: %6; border-color: %21; }"
               "QPushButton#accentButton:pressed { background: %21; }"
               "QPushButton#bevelButton { background: %15; border-color: %21; color: #f8ecee; }"
               "QPushButton#bevelButton:hover { background: %14; border-color: %6; }"
               "QPushButton#bevelButton:pressed { background: %8; }"
               "QPushButton#railButton { min-width: 104px; background: %23; border-color: %5; }"
                "QToolButton#infoButton { background: %8; border: 1px solid %5; border-radius: 9px; color: %2; font-weight: 700; }"
               "QToolButton#infoButton:hover { border-color: %21; background: %21; color: white; }"
                "QHeaderView::section { background: %8; color: %2; border: none; padding: 10px 12px; font-weight: 600; }"
               "QProgressBar { background: %7; border: 1px solid %5; border-radius: 12px; min-height: 14px; }"
               "QProgressBar::chunk { background: %6; border-radius: 10px; }"
               "QTableWidget { gridline-color: %5; alternate-background-color: %3; }"
               "QPlainTextEdit, QListWidget { font-family: 'Cascadia Mono'; font-size: 10pt; }"
               "QToolButton#orbButton {"
               "background: transparent;"
               "border: none;"
               "padding: 4px;"
               "min-width: 50px;"
               "min-height: 50px;"
               "color: %2;"
                "}"
               "QToolTip {"
               "background: %24;"
               "color: #f4f6fb;"
               "border: 1px solid %21;"
               "border-radius: 10px;"
               "padding: 8px 12px;"
               "font-family: 'Cascadia Mono';"
               "font-size: 10pt;"
               "}"
               "QScrollArea#mainScrollArea { background: transparent; border: none; }"
                "QScrollBar:vertical { background: %3; width: 12px; margin: 6px 0 6px 0; }"
               "QScrollBar::handle:vertical { background: %5; border-radius: 6px; min-height: 24px; }"
               "QScrollBar::handle:vertical:hover { background: %21; }"
               "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }")
        .arg(window,
             text,
             panel,
             mutedText,
             border,
             accent,
             panelAlt,
             accentSoft,
             scheme.cardGradient,
             scheme.cardBorder,
             scheme.heroGradient,
             scheme.heroBorder,
             scheme.inputFill,
             scheme.buttonHover,
             scheme.tabGradient,
             QString::number(scheme.largeRadius),
             QString::number(scheme.largeRadius + 2),
             QString::number(scheme.smallRadius),
             QString::number(scheme.tabRadius),
             scheme.buttonGradient,
             accentStrong,
             scheme.accentGradient,
             scheme.railGradient,
             scheme.tooltipFill);
}
