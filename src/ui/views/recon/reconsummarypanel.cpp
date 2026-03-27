#include "ui/views/recon/reconsummarypanel.h"

#include "ui/layout/flowlayout.h"

#include <QLabel>
#include <QVBoxLayout>

namespace {

QWidget *makeInfoBlock(QWidget *parent, const QString &title, QLabel **valueLabel)
{
    auto *card = new QFrame(parent);
    card->setObjectName("summaryCard");
    card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(6);
    auto *titleLabel = new QLabel(title, card);
    titleLabel->setObjectName("mutedText");
    *valueLabel = new QLabel(QStringLiteral("0"), card);
    (*valueLabel)->setObjectName("statValue");
    (*valueLabel)->setWordWrap(true);
    layout->addWidget(titleLabel);
    layout->addWidget(*valueLabel);
    return card;
}

}

ReconSummaryPanel::ReconSummaryPanel(QWidget *parent)
    : QFrame(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(12);

    auto *summaryHost = new QWidget(this);
    auto *summary = new FlowLayout(summaryHost, 0, 12, 12);
    auto *statusCard = makeInfoBlock(this, tr("Durum"), &m_statusValue);
    QLabel *targetValue = nullptr;
    auto *targetCard = makeInfoBlock(this, tr("Hedef"), &targetValue);
    auto *scoreCard = makeInfoBlock(this, tr("Guvenlik Puani"), &m_scoreValue);
    auto *findingsCountCard = makeInfoBlock(this, tr("Bulgu"), &m_findingsCountValue);
    auto *portsCountCard = makeInfoBlock(this, tr("Acik Port"), &m_portsCountValue);
    auto *subdomainCountCard = makeInfoBlock(this, tr("Subdomain"), &m_subdomainCountValue);
    auto *artifactCountCard = makeInfoBlock(this, tr("URL + JS"), &m_archiveCountValue);
    statusCard->setMinimumWidth(118);
    targetCard->setMinimumWidth(118);
    scoreCard->setMinimumWidth(118);
    findingsCountCard->setMinimumWidth(112);
    portsCountCard->setMinimumWidth(112);
    subdomainCountCard->setMinimumWidth(112);
    artifactCountCard->setMinimumWidth(112);
    targetValue->setText(tr("Canli"));
    m_scoreValue->setText(QStringLiteral("--"));
    summary->addWidget(statusCard);
    summary->addWidget(targetCard);
    summary->addWidget(scoreCard);
    summary->addWidget(findingsCountCard);
    summary->addWidget(portsCountCard);
    summary->addWidget(subdomainCountCard);
    summary->addWidget(artifactCountCard);
    summaryHost->setLayout(summary);

    auto *categoryHost = new QWidget(this);
    auto *categorySummary = new FlowLayout(categoryHost, 0, 12, 12);
    auto *dnsCountCard = makeInfoBlock(this, tr("DNS Kaydi"), &m_dnsCountValue);
    auto *surfaceCountCard = makeInfoBlock(this, tr("Yuzey"), &m_surfaceCountValue);
    auto *osintCountCard = makeInfoBlock(this, tr("OSINT"), &m_osintCountValue);
    auto *spiderCountCard = makeInfoBlock(this, tr("Spider"), &m_spiderCountValue);
    dnsCountCard->setMinimumWidth(112);
    surfaceCountCard->setMinimumWidth(112);
    osintCountCard->setMinimumWidth(112);
    spiderCountCard->setMinimumWidth(112);
    categorySummary->addWidget(dnsCountCard);
    categorySummary->addWidget(surfaceCountCard);
    categorySummary->addWidget(osintCountCard);
    categorySummary->addWidget(spiderCountCard);
    categoryHost->setLayout(categorySummary);

    layout->addWidget(summaryHost);
    layout->addWidget(categoryHost);
}
