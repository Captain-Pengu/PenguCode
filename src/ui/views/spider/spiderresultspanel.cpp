#include "spiderresultspanel.h"

#include "ui/views/spider/spiderhosthealthpanel.h"

#include <QComboBox>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>

QFrame *SpiderResultsPanel::makeListCard(const QString &title, const QString &description, QListWidget **list)
{
    auto *card = new QFrame(this);
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

SpiderResultsPanel::SpiderResultsPanel(QWidget *parent)
    : QFrame(parent)
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

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
    m_console->setMinimumHeight(148);
    m_console->setLineWrapMode(QPlainTextEdit::NoWrap);
    consoleLayout->addWidget(consoleTitle);
    consoleLayout->addWidget(consoleInfo);
    consoleLayout->addWidget(m_console);

    auto *evidenceCard = makeListCard(tr("Oturum ve Kanit Izleri"),
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
    m_assetFilterCombo->addItem(tr("Sadece Pressure"), QStringLiteral("pressure"));
    m_assetFilterCombo->addItem(tr("Sadece Baskilanan"), QStringLiteral("suppressed"));
    m_assetFilterCombo->addItem(tr("Sadece Render"), QStringLiteral("render"));
    m_assetFilterCombo->addItem(tr("Sadece Automation"), QStringLiteral("automation"));
    evidenceCardLayout->insertWidget(2, m_assetFilterCombo);
    m_evidenceDetailView = new QTextEdit(evidenceCard);
    m_evidenceDetailView->setReadOnly(true);
    m_evidenceDetailView->setMinimumHeight(120);
    m_evidenceDetailView->setHtml(tr("<h3>Kanit detayi</h3><p>Bir kayit sec.</p>"));
    evidenceCardLayout->addWidget(m_evidenceDetailView);

    auto *liveTab = new QWidget(this);
    auto *liveLayout = new QHBoxLayout(liveTab);
    liveLayout->setContentsMargins(0, 0, 0, 0);
    liveLayout->setSpacing(18);
    liveLayout->addWidget(consoleCard, 3);
    liveLayout->addWidget(evidenceCard, 2);

    auto *resultsTabs = new QTabWidget(this);
    resultsTabs->setDocumentMode(true);
    resultsTabs->setUsesScrollButtons(true);
    auto *endpointCard = makeListCard(tr("Bulunan Endpoint'ler"),
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
    resultsTabs->addTab(makeListCard(tr("Parametreler"), QString(), &m_parameterList), tr("Girdi"));
    resultsTabs->addTab(makeListCard(tr("Asset ve Scriptler"), QString(), &m_assetList), tr("Asset"));
    resultsTabs->addTab(makeListCard(tr("Kritik Yuzey"), QString(), &m_highValueList), tr("Kritik"));
    resultsTabs->addTab(makeListCard(tr("Segmentler"), QString(), &m_segmentList), tr("Segmentler"));
    resultsTabs->addTab(makeListCard(tr("Benchmark"), QString(), &m_benchmarkHistoryList), tr("Benchmark"));
    resultsTabs->addTab(makeListCard(tr("Timeline"), QString(), &m_timelineList), tr("Timeline"));
    m_hostPanel = new SpiderHostHealthPanel(this);
    resultsTabs->addTab(m_hostPanel, tr("Host"));
    resultsTabs->addTab(makeListCard(tr("Ozellikler"), QString(), &m_featureList), tr("Ozellikler"));

    m_workTabs = new QTabWidget(this);
    m_workTabs->setDocumentMode(true);
    m_workTabs->setUsesScrollButtons(true);
    m_workTabs->addTab(new QWidget(this), tr("Kurulum"));
    m_workTabs->addTab(liveTab, tr("Canli"));
    m_workTabs->addTab(resultsTabs, tr("Sonuclar"));

    root->addWidget(m_workTabs);
}

void SpiderResultsPanel::setSetupTab(QWidget *setupTab)
{
    if (!m_workTabs || !setupTab) {
        return;
    }
    QWidget *old = m_workTabs->widget(0);
    m_workTabs->removeTab(0);
    if (old) {
        old->deleteLater();
    }
    m_workTabs->insertTab(0, setupTab, tr("Kurulum"));
    m_workTabs->setCurrentIndex(0);
}
