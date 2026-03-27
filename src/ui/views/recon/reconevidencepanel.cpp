#include "ui/views/recon/reconevidencepanel.h"

#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>

QFrame *ReconEvidencePanel::makeListCard(const QString &title, const QString &description, QListWidget **list)
{
    auto *card = new QFrame(this);
    card->setObjectName(QStringLiteral("summaryCard"));
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(8);
    auto *titleLabel = new QLabel(title, card);
    titleLabel->setObjectName(QStringLiteral("cardTitle"));
    layout->addWidget(titleLabel);
    if (!description.isEmpty()) {
        auto *descriptionLabel = new QLabel(description, card);
        descriptionLabel->setObjectName(QStringLiteral("mutedText"));
        descriptionLabel->setWordWrap(true);
        layout->addWidget(descriptionLabel);
    }
    *list = new QListWidget(card);
    layout->addWidget(*list, 1);
    return card;
}

ReconEvidencePanel::ReconEvidencePanel(QWidget *parent)
    : QFrame(parent)
{
    setObjectName(QStringLiteral("cardPanel"));
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(12);

    auto *title = new QLabel(tr("Teknik Kanitlar"), this);
    title->setObjectName(QStringLiteral("sectionTitle"));
    auto *info = new QLabel(tr("Kucuk kucuk ayri paneller yerine kanitlar burada sekmeli yapida toplanir."), this);
    info->setObjectName(QStringLiteral("mutedText"));
    info->setWordWrap(true);

    m_evidenceSearchEdit = new QLineEdit(this);
    m_evidenceSearchEdit->setPlaceholderText(tr("Tum kanitlarda ara"));

    auto *tabs = new QTabWidget(this);
    tabs->setDocumentMode(true);
    tabs->setUsesScrollButtons(true);

    auto *dnsCard = makeListCard(tr("DNS Kayitlari"), QString(), &m_dnsList);
    auto *surfaceCard = makeListCard(tr("Yuzey Gozlemleri"), QString(), &m_surfaceList);
    auto *osintCard = makeListCard(tr("OSINT"), QString(), &m_osintList);
    auto *subdomainCard = makeListCard(tr("Subdomain"), QString(), &m_subdomainList);
    auto *archiveCard = makeListCard(tr("Wayback"), QString(), &m_archiveList);
    auto *jsCard = makeListCard(tr("JS"), QString(), &m_jsFindingList);
    auto *cveCard = makeListCard(tr("CVE"), QString(), &m_cveList);
    auto *spiderEndpointCard = makeListCard(tr("Spider Yuzey"), QString(), &m_spiderEndpointList);
    auto *spiderParameterCard = makeListCard(tr("Spider Girdi"), QString(), &m_spiderParameterList);
    auto *spiderAssetCard = makeListCard(tr("Spider Asset"), QString(), &m_spiderAssetList);
    auto *spiderHighValueCard = makeListCard(tr("Spider Kritik"), QString(), &m_spiderHighValueList);
    auto *spiderTimelineCard = makeListCard(tr("Spider Timeline"), QString(), &m_spiderTimelineList);
    auto *spiderTimelineLayout = qobject_cast<QVBoxLayout *>(spiderTimelineCard->layout());
    m_spiderCoverageLabel = new QLabel(tr("Spider coverage bekleniyor."), spiderTimelineCard);
    m_spiderCoverageLabel->setObjectName(QStringLiteral("mutedText"));
    m_spiderCoverageLabel->setWordWrap(true);
    spiderTimelineLayout->insertWidget(2, m_spiderCoverageLabel);

    auto *whoisCard = new QFrame(tabs);
    whoisCard->setObjectName(QStringLiteral("summaryCard"));
    auto *whoisLayout = new QVBoxLayout(whoisCard);
    whoisLayout->setContentsMargins(16, 14, 16, 14);
    whoisLayout->setSpacing(8);
    m_whoisSummaryView = new QTextEdit(whoisCard);
    m_whoisSummaryView->setReadOnly(true);
    whoisLayout->addWidget(m_whoisSummaryView);

    auto *relationshipCard = new QFrame(tabs);
    relationshipCard->setObjectName(QStringLiteral("summaryCard"));
    auto *relationshipLayout = new QVBoxLayout(relationshipCard);
    relationshipLayout->setContentsMargins(16, 14, 16, 14);
    relationshipLayout->setSpacing(8);
    m_relationshipView = new QTextEdit(relationshipCard);
    m_relationshipView->setReadOnly(true);
    relationshipLayout->addWidget(m_relationshipView);

    auto *analysisTimelineCard = new QFrame(tabs);
    analysisTimelineCard->setObjectName(QStringLiteral("summaryCard"));
    auto *analysisTimelineLayout = new QVBoxLayout(analysisTimelineCard);
    analysisTimelineLayout->setContentsMargins(16, 14, 16, 14);
    analysisTimelineLayout->setSpacing(8);
    m_analysisTimelineList = new QListWidget(analysisTimelineCard);
    analysisTimelineLayout->addWidget(m_analysisTimelineList);

    tabs->addTab(dnsCard, tr("DNS"));
    tabs->addTab(surfaceCard, tr("Yuzey"));
    tabs->addTab(osintCard, tr("OSINT"));
    tabs->addTab(subdomainCard, tr("Subdomain"));
    tabs->addTab(archiveCard, tr("Wayback"));
    tabs->addTab(jsCard, tr("JS"));
    tabs->addTab(cveCard, tr("CVE"));
    tabs->addTab(whoisCard, tr("Whois"));
    tabs->addTab(relationshipCard, tr("Iliski"));
    tabs->addTab(analysisTimelineCard, tr("Timeline"));
    tabs->addTab(spiderEndpointCard, tr("Spider Yuzey"));
    tabs->addTab(spiderParameterCard, tr("Spider Girdi"));
    tabs->addTab(spiderAssetCard, tr("Spider Asset"));
    tabs->addTab(spiderHighValueCard, tr("Spider Kritik"));
    tabs->addTab(spiderTimelineCard, tr("Spider Timeline"));

    layout->addWidget(title);
    layout->addWidget(info);
    layout->addWidget(m_evidenceSearchEdit);
    layout->addWidget(tabs, 1);
}
