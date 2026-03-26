#include "portscannerwidget.h"

#include "modules/portscanner/portscannermodule.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"

#include <QCursor>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QProgressBar>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolButton>
#include <QToolTip>
#include <QVBoxLayout>

PortScannerWidget::PortScannerWidget(PortScannerModule *module, QWidget *parent)
    : QWidget(parent)
    , m_module(module)
{
    buildUi();
    refreshFromModule();
    refreshResults();

    connect(m_module, &PortScannerModule::configurationChanged, this, &PortScannerWidget::refreshFromModule);
    connect(m_module, &PortScannerModule::resultsChanged, this, &PortScannerWidget::refreshResults);
    connect(m_module, &PortScannerModule::statsChanged, this, &PortScannerWidget::refreshFromModule);
    connect(m_module, &PortScannerModule::scanningChanged, this, &PortScannerWidget::refreshFromModule);
    connect(m_module, &PortScannerModule::statusTextChanged, this, &PortScannerWidget::refreshFromModule);
    connect(m_module, &PortScannerModule::portFound, this, &PortScannerWidget::handlePortFound);
    connect(m_module, &PortScannerModule::serviceDetected, this, &PortScannerWidget::handleServiceDetected);
    connect(m_module, &PortScannerModule::scanFinished, this, &PortScannerWidget::handleScanFinished);
}

void PortScannerWidget::reloadSettings()
{
    if (!m_module) {
        return;
    }

    m_module->reloadSettings();
    refreshFromModule();
}

void PortScannerWidget::applyFormToModule()
{
    if (!m_module) {
        return;
    }

    m_module->configureScan(m_targetEdit->text(),
                            m_portsEdit->text(),
                            m_scanTypeCombo->currentText(),
                            m_threadsSpin->value(),
                            m_timeoutSpin->value(),
                            m_retrySpin->value(),
                            m_serviceCheck->isChecked(),
                            m_osCheck->isChecked());
}

void PortScannerWidget::refreshFromModule()
{
    if (!m_module) {
        return;
    }

    const bool oldState = blockSignals(true);

    m_targetEdit->setText(m_module->targetSpec());
    m_portsEdit->setText(m_module->portSpec());
    m_scanTypeCombo->setCurrentText(m_module->scanType());
    m_threadsSpin->setValue(m_module->threadCount());
    m_timeoutSpin->setValue(m_module->timeoutMs());
    m_retrySpin->setValue(m_module->retryCount());
    m_serviceCheck->setChecked(m_module->serviceDetectionEnabled());
    m_osCheck->setChecked(m_module->osFingerprintingEnabled());

    m_statusValue->setText(m_module->statusText());
    m_progressValue->setText(QString("%1 / %2").arg(m_module->scannedCount()).arg(m_module->totalTasks()));
    m_rateValue->setText(QString::number(m_module->portsPerSecond(), 'f', 1) + " p/s");
    m_etaValue->setText(m_module->etaText());
    m_elapsedValue->setText(m_module->elapsedText());
    m_openPortsValue->setText(QString::number(m_module->openPorts()));
    m_progressBar->setValue(static_cast<int>(m_module->progress() * 100.0));

    m_targetsSummaryValue->setText(m_module->targetSpec().isEmpty() ? tr("No targets") : m_module->targetSpec());
    m_scanModeSummaryValue->setText(QString("%1  |  %2 threads  |  %3 ms")
                                        .arg(m_module->scanType())
                                        .arg(m_module->threadCount())
                                        .arg(m_module->timeoutMs()));
    m_resultsSummaryValue->setText(tr("%1 sonuc, %2 acik port")
                                       .arg(m_module->results().size())
                                       .arg(m_module->openPorts()));

    if (m_module->scanning()) {
        m_liveHintLabel->setText(tr("Tarama aktif. Veriler canli olarak tabloda ve olay akisinda yenileniyor."));
    } else if (m_module->results().isEmpty()) {
        m_liveHintLabel->setText(tr("Hazir. Hedefleri girip taramayi baslattiginda tum ilerleme canli akacak."));
    } else {
        m_liveHintLabel->setText(tr("Tarama tamamlandi. Sonuclari inceleyebilir, kopyalayabilir veya disari aktarabilirsin."));
    }

    m_startButton->setEnabled(!m_module->scanning());
    m_stopButton->setEnabled(m_module->scanning());

    blockSignals(oldState);
}

void PortScannerWidget::refreshResults()
{
    if (!m_module) {
        return;
    }

    const QVariantList rows = m_module->results();
    m_resultsTable->setRowCount(rows.size());
    for (int rowIndex = 0; rowIndex < rows.size(); ++rowIndex) {
        const QVariantMap row = rows.at(rowIndex).toMap();
        const QStringList fields = {
            row.value("ip").toString(),
            row.value("port").toString(),
            row.value("protocol").toString(),
            row.value("state").toString(),
            row.value("service").toString(),
            row.value("responseTime").toString(),
            row.value("osFingerprint").toString()
        };

        for (int column = 0; column < fields.size(); ++column) {
            auto *item = new QTableWidgetItem(fields.at(column));
            m_resultsTable->setItem(rowIndex, column, item);
        }
    }

    m_resultsTable->setVisible(rows.size() > 0);
    m_resultsTable->resizeRowsToContents();
    refreshFromModule();
}

void PortScannerWidget::startScan()
{
    applyFormToModule();
    m_eventFeed->clear();
    appendEvent(tr("Tarama kuyruga alindi: %1 / %2").arg(m_targetEdit->text(), m_portsEdit->text()));
    m_module->start();
}

void PortScannerWidget::stopScan()
{
    if (m_module) {
        m_module->stop();
        appendEvent(tr("Operator durdurma istegi gonderdi."));
    }
}

void PortScannerWidget::exportResults()
{
    if (!m_module) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(this,
                                                          tr("Tarama Sonuclarini Disa Aktar"),
                                                          QString(),
                                                          tr("JSON (*.json);;CSV (*.csv);;Metin (*.txt)"));
    if (filePath.isEmpty()) {
        return;
    }

    QString format = "json";
    if (filePath.endsWith(".csv", Qt::CaseInsensitive)) {
        format = "csv";
    } else if (filePath.endsWith(".txt", Qt::CaseInsensitive)) {
        format = "txt";
    }

    m_module->exportResults(filePath, format);
    appendEvent(tr("Sonuclar disa aktarildi: %1").arg(filePath));
}

void PortScannerWidget::copySelectedRow()
{
    if (!m_module) {
        return;
    }

    const QVariantMap row = selectedRow();
    if (!row.isEmpty()) {
        m_module->copyRow(row);
        appendEvent(tr("Panoya kopyalandi: %1:%2").arg(row.value("ip").toString(), row.value("port").toString()));
    }
}

void PortScannerWidget::appendEvent(const QString &message)
{
    m_eventFeed->insertItem(0, message);
    while (m_eventFeed->count() > 14) {
        delete m_eventFeed->takeItem(m_eventFeed->count() - 1);
    }
}

void PortScannerWidget::handlePortFound(const QVariantMap &row)
{
    appendEvent(tr("Acik port bulundu: %1:%2 (%3)")
                    .arg(row.value("ip").toString(),
                         row.value("port").toString(),
                         row.value("service").toString()));
}

void PortScannerWidget::handleServiceDetected(const QString &ip, int port, const QString &serviceName, const QString &banner)
{
    appendEvent(tr("Servis algilandi: %1:%2 -> %3 %4")
                    .arg(ip)
                    .arg(port)
                    .arg(serviceName, banner.left(36)));
}

void PortScannerWidget::handleScanFinished()
{
    appendEvent(tr("Tarama tamamlandi. Toplam %1 sonuc toplandi.").arg(m_module->results().size()));
    refreshFromModule();
}

void PortScannerWidget::buildUi()
{
    auto *rootLayout = pengufoce::ui::layout::createPageRoot(this, 18);

    auto *hero = pengufoce::ui::layout::createHeroCard(this, QMargins(24, 22, 24, 22), 10);
    auto *heroLayout = qobject_cast<QVBoxLayout *>(hero->layout());

    auto *heroTitle = new QLabel(tr("Port Scanner"), hero);
    heroTitle->setObjectName("heroTitle");
    auto *heroText = new QLabel(tr("Hedeflerini gir, tarama tipini sec ve tum ilerlemeyi tek ekranda canli takip et."), hero);
    heroText->setObjectName("mutedText");
    heroText->setWordWrap(true);

    auto *heroSummaryHost = new QWidget(hero);
    auto *heroSummaryRow = new FlowLayout(heroSummaryHost, 0, 12, 12);
    auto *targetsCard = createMetricCard(tr("Hedef kapsami"), &m_targetsSummaryValue, tr("Tarama yapilacak hedefleri burada ozetler."));
    auto *modeCard = createMetricCard(tr("Tarama profili"), &m_scanModeSummaryValue, tr("Tarama modu, thread sayisi ve timeout bilgisi."));
    auto *resultsCard = createMetricCard(tr("Canli sonuc"), &m_resultsSummaryValue, tr("Toplam sonuc ve acik port ozetini gosterir."));
    targetsCard->setMinimumWidth(180);
    modeCard->setMinimumWidth(180);
    resultsCard->setMinimumWidth(180);
    heroSummaryRow->addWidget(targetsCard);
    heroSummaryRow->addWidget(modeCard);
    heroSummaryRow->addWidget(resultsCard);
    heroSummaryHost->setLayout(heroSummaryRow);

    heroLayout->addWidget(heroTitle);
    heroLayout->addWidget(heroText);
    heroLayout->addWidget(heroSummaryHost);

    auto *workRow = new QHBoxLayout();
    workRow->setSpacing(18);
    workRow->setAlignment(Qt::AlignTop);

    auto *controlCard = pengufoce::ui::layout::createCard(this, QStringLiteral("cardPanel"), QMargins(20, 20, 20, 20), 16);
    auto *controlLayout = qobject_cast<QVBoxLayout *>(controlCard->layout());

    auto *controlsHeader = new QHBoxLayout();
    auto *controlsTitle = new QLabel(tr("Tarama Kurulumu"), controlCard);
    controlsTitle->setObjectName("sectionTitle");
    controlsHeader->addWidget(controlsTitle);
    controlsHeader->addStretch();
    controlLayout->addLayout(controlsHeader);

    auto *grid = pengufoce::ui::layout::createGrid(14, 12);
    grid->setColumnStretch(1, 1);
    grid->setColumnStretch(3, 1);

    m_targetEdit = new QLineEdit(controlCard);
    m_targetEdit->setPlaceholderText(tr("127.0.0.1, 192.168.1.0/24, scanme.nmap.org"));
    m_portsEdit = new QLineEdit(controlCard);
    m_portsEdit->setPlaceholderText(tr("common, 80,443,8000-8100"));
    m_scanTypeCombo = new QComboBox(controlCard);
    m_scanTypeCombo->setMinimumContentsLength(16);
    for (const QVariant &option : m_module->scanTypeOptions()) {
        m_scanTypeCombo->addItem(option.toString());
    }
    m_threadsSpin = new QSpinBox(controlCard);
    m_threadsSpin->setRange(1, 2048);
    m_timeoutSpin = new QSpinBox(controlCard);
    m_timeoutSpin->setRange(50, 10000);
    m_timeoutSpin->setSuffix(" ms");
    m_retrySpin = new QSpinBox(controlCard);
    m_retrySpin->setRange(0, 10);
    m_serviceCheck = new QCheckBox(tr("Servis ve banner tespiti"), controlCard);
    m_osCheck = new QCheckBox(tr("OS tahmini"), controlCard);

    auto addField = [this, controlCard, grid](int row, int column, const QString &labelText, const QString &tooltip, QWidget *field) {
        grid->addWidget(createInfoLabel(labelText, tooltip), row, column);
        grid->addWidget(field, row, column + 1);
    };

    addField(0, 0, tr("Hedefler"), tr("Tek IP, host adi, IP araligi veya CIDR girebilirsin."), m_targetEdit);
    addField(0, 2, tr("Portlar"), tr("Port listesi, aralik veya common/web/database/full presetleri kullanilabilir."), m_portsEdit);
    addField(1, 0, tr("Tarama tipi"), tr("TCP, UDP, servis tespiti veya temel OS tahmini arasindan secim yapar."), m_scanTypeCombo);
    addField(1, 2, tr("Thread"), tr("Ayni anda kac tarama gorevinin paralel isleyecegini belirler."), m_threadsSpin);
    addField(2, 0, tr("Zaman asimi"), tr("Bir porttan cevap bekleme suresi. Daha dusuk deger daha hizli ama daha sert tarama yapar."), m_timeoutSpin);
    addField(2, 2, tr("Tekrar"), tr("Cevap gelmeyen portlari tekrar deneme sayisi."), m_retrySpin);
    grid->addWidget(m_serviceCheck, 3, 1, 1, 3);
    grid->addWidget(m_osCheck, 4, 1, 1, 3);

    auto *actionHost = new QWidget(controlCard);
    auto *actionRow = new FlowLayout(actionHost, 0, 10, 10);
    m_startButton = new QPushButton(tr("Taramayi Baslat"), controlCard);
    m_startButton->setObjectName("accentButton");
    m_stopButton = new QPushButton(tr("Durdur"), controlCard);
    auto *exportButton = new QPushButton(tr("Disa Aktar"), controlCard);
    auto *copyButton = new QPushButton(tr("Secileni Kopyala"), controlCard);
    actionRow->addWidget(m_startButton);
    actionRow->addWidget(m_stopButton);
    actionRow->addWidget(exportButton);
    actionRow->addWidget(copyButton);
    actionHost->setLayout(actionRow);

    m_liveHintLabel = new QLabel(controlCard);
    m_liveHintLabel->setObjectName("mutedText");
    m_liveHintLabel->setWordWrap(true);

    controlLayout->addLayout(grid);
    controlLayout->addWidget(actionHost);
    controlLayout->addWidget(m_liveHintLabel);
    controlLayout->addStretch();

    auto *opsCard = pengufoce::ui::layout::createCard(this, QStringLiteral("cardPanel"), QMargins(20, 20, 20, 20), 16);
    auto *opsLayout = qobject_cast<QVBoxLayout *>(opsCard->layout());

    auto *opsTitle = new QLabel(tr("Canli Operasyon"), opsCard);
    opsTitle->setObjectName("sectionTitle");
    opsLayout->addWidget(opsTitle);

    auto *metricsGrid = pengufoce::ui::layout::createGrid(12, 12);
    metricsGrid->addWidget(createMetricCard(tr("Durum"), &m_statusValue), 0, 0);
    metricsGrid->addWidget(createMetricCard(tr("Ilerleme"), &m_progressValue), 0, 1);
    metricsGrid->addWidget(createMetricCard(tr("Acik Portlar"), &m_openPortsValue), 1, 0);
    metricsGrid->addWidget(createMetricCard(tr("Hiz"), &m_rateValue), 1, 1);
    metricsGrid->addWidget(createMetricCard(tr("Tahmini bitis"), &m_etaValue), 2, 0);
    metricsGrid->addWidget(createMetricCard(tr("Gecen sure"), &m_elapsedValue), 2, 1);

    m_progressBar = new QProgressBar(opsCard);
    m_progressBar->setRange(0, 100);
    m_progressBar->setTextVisible(false);

    auto *feedTitle = new QLabel(tr("Anlik Olaylar"), opsCard);
    feedTitle->setObjectName("cardTitle");
    m_eventFeed = new QListWidget(opsCard);
    m_eventFeed->setAlternatingRowColors(true);
    m_eventFeed->setSelectionMode(QAbstractItemView::NoSelection);
    m_eventFeed->setMinimumHeight(180);

    opsLayout->addLayout(metricsGrid);
    opsLayout->addWidget(m_progressBar);
    opsLayout->addWidget(feedTitle);
    opsLayout->addWidget(m_eventFeed, 1);

    workRow->addWidget(controlCard, 3);
    workRow->addWidget(opsCard, 2);

    auto *resultsCardFrame = pengufoce::ui::layout::createCard(this);
    auto *resultsLayout = qobject_cast<QVBoxLayout *>(resultsCardFrame->layout());

    auto *resultsTitle = new QLabel(tr("Canli Sonuclar"), resultsCardFrame);
    resultsTitle->setObjectName("sectionTitle");
    auto *resultsInfo = new QLabel(tr("Tarama ilerledikce acik portlar, servis tahminleri ve gecikme degerleri burada aninda gorunur."), resultsCardFrame);
    resultsInfo->setObjectName("mutedText");
    resultsInfo->setWordWrap(true);

    m_resultsTable = new QTableWidget(resultsCardFrame);
    m_resultsTable->setColumnCount(7);
    m_resultsTable->setHorizontalHeaderLabels({tr("IP"), tr("Port"), tr("Proto"), tr("State"), tr("Service"), tr("Latency"), tr("OS")});
    m_resultsTable->setAlternatingRowColors(true);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_resultsTable->verticalHeader()->setVisible(false);
    m_resultsTable->verticalHeader()->setDefaultSectionSize(36);
    m_resultsTable->setMinimumHeight(240);

    resultsLayout->addWidget(resultsTitle);
    resultsLayout->addWidget(resultsInfo);
    resultsLayout->addWidget(m_resultsTable);

    rootLayout->addWidget(hero);
    rootLayout->addLayout(workRow);
    rootLayout->addWidget(resultsCardFrame, 1);

    connect(m_targetEdit, &QLineEdit::editingFinished, this, &PortScannerWidget::applyFormToModule);
    connect(m_portsEdit, &QLineEdit::editingFinished, this, &PortScannerWidget::applyFormToModule);
    connect(m_scanTypeCombo, &QComboBox::currentTextChanged, this, &PortScannerWidget::applyFormToModule);
    connect(m_threadsSpin, &QSpinBox::valueChanged, this, [this](int) { applyFormToModule(); });
    connect(m_timeoutSpin, &QSpinBox::valueChanged, this, [this](int) { applyFormToModule(); });
    connect(m_retrySpin, &QSpinBox::valueChanged, this, [this](int) { applyFormToModule(); });
    connect(m_serviceCheck, &QCheckBox::checkStateChanged, this, [this](Qt::CheckState) { applyFormToModule(); });
    connect(m_osCheck, &QCheckBox::checkStateChanged, this, [this](Qt::CheckState) { applyFormToModule(); });
    connect(m_startButton, &QPushButton::clicked, this, &PortScannerWidget::startScan);
    connect(m_stopButton, &QPushButton::clicked, this, &PortScannerWidget::stopScan);
    connect(exportButton, &QPushButton::clicked, this, &PortScannerWidget::exportResults);
    connect(copyButton, &QPushButton::clicked, this, &PortScannerWidget::copySelectedRow);

    appendEvent(tr("Calisma alani hazir. Hedefleri girip taramayi baslatabilirsin."));
}

QVariantMap PortScannerWidget::selectedRow() const
{
    const int rowIndex = m_resultsTable->currentRow();
    const QVariantList rows = m_module->results();
    if (rowIndex < 0 || rowIndex >= rows.size()) {
        return {};
    }

    return rows.at(rowIndex).toMap();
}

QWidget *PortScannerWidget::createMetricCard(const QString &title, QLabel **valueLabel, const QString &helperText)
{
    auto *card = new QFrame(this);
    card->setObjectName("summaryCard");
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(6);

    auto *titleLabel = new QLabel(title, card);
    titleLabel->setObjectName("mutedText");
    *valueLabel = new QLabel("--", card);
    (*valueLabel)->setObjectName("statValue");
    layout->addWidget(titleLabel);
    layout->addWidget(*valueLabel);

    if (!helperText.isEmpty()) {
        auto *helpLabel = new QLabel(helperText, card);
        helpLabel->setObjectName("mutedText");
        helpLabel->setWordWrap(true);
        layout->addWidget(helpLabel);
    }

    return card;
}

QWidget *PortScannerWidget::createInfoLabel(const QString &title, const QString &tooltip) const
{
    auto *container = new QWidget(const_cast<PortScannerWidget *>(this));
    auto *layout = new QHBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    auto *label = new QLabel(title, container);
    label->setObjectName("mutedText");
    auto *infoButton = new QToolButton(container);
    infoButton->setText("i");
    infoButton->setToolTip(tooltip);
    infoButton->setAutoRaise(true);
    infoButton->setCursor(Qt::PointingHandCursor);
    infoButton->setObjectName("infoButton");
    infoButton->setFixedSize(18, 18);
    connect(infoButton, &QToolButton::clicked, infoButton, [infoButton, tooltip]() {
        QToolTip::showText(QCursor::pos(), tooltip, infoButton);
    });

    layout->addWidget(label);
    layout->addWidget(infoButton);
    layout->addStretch();
    return container;
}
