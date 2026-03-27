#include "ui/views/spider/spiderhosthealthpanel.h"

#include "ui/layout/flowlayout.h"

#include <QComboBox>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

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
    *valueLabel = new QLabel(QStringLiteral("--"), card);
    (*valueLabel)->setObjectName("statValue");
    (*valueLabel)->setWordWrap(true);
    layout->addWidget(titleLabel);
    layout->addWidget(*valueLabel);
    return card;
}

}

SpiderHostHealthPanel::SpiderHostHealthPanel(QWidget *parent)
    : QFrame(parent)
{
    setObjectName("cardPanel");
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(12);

    auto *titleLabel = new QLabel(tr("Host Sagligi"), this);
    titleLabel->setObjectName("sectionTitle");
    auto *descLabel = new QLabel(tr("WAF, retry/backoff, baskilama ve scope disi davranislara gore host bazli ozet."), this);
    descLabel->setObjectName("mutedText");
    descLabel->setWordWrap(true);

    auto *hostSummaryHost = new QWidget(this);
    auto *hostSummaryFlow = new FlowLayout(hostSummaryHost, 0, 10, 10);
    auto *hostStableCard = makeSpiderInfoBlock(this, tr("Stable Host"), &m_hostStableValue);
    auto *hostGuardedCard = makeSpiderInfoBlock(this, tr("Guarded Host"), &m_hostGuardedValue);
    auto *hostWafCard = makeSpiderInfoBlock(this, tr("WAF Host"), &m_hostWafValue);
    auto *hostStressedCard = makeSpiderInfoBlock(this, tr("Stressed Host"), &m_hostStressedValue);
    hostStableCard->setMinimumWidth(116);
    hostGuardedCard->setMinimumWidth(116);
    hostWafCard->setMinimumWidth(116);
    hostStressedCard->setMinimumWidth(116);
    hostSummaryFlow->addWidget(hostStableCard);
    hostSummaryFlow->addWidget(hostGuardedCard);
    hostSummaryFlow->addWidget(hostWafCard);
    hostSummaryFlow->addWidget(hostStressedCard);
    hostSummaryHost->setLayout(hostSummaryFlow);

    auto *hostActionsHost = new QWidget(this);
    auto *hostActionsFlow = new FlowLayout(hostActionsHost, 0, 8, 8);
    m_hostFilterCombo = new QComboBox(hostActionsHost);
    m_hostFilterCombo->addItem(tr("Tum Host'lar"), QStringLiteral("all"));
    m_exportHostDiagnosticsButton = new QPushButton(tr("Host JSON"), hostActionsHost);
    hostActionsFlow->addWidget(m_hostFilterCombo);
    hostActionsFlow->addWidget(m_exportHostDiagnosticsButton);
    hostActionsHost->setLayout(hostActionsFlow);

    m_hostReplayDiffLabel = new QLabel(tr("Replay farki hazir degil."), this);
    m_hostReplayDiffLabel->setObjectName("mutedText");
    m_hostReplayDiffLabel->setWordWrap(true);
    m_hostPressureTrendLabel = new QLabel(tr("Pressure trend hazir degil."), this);
    m_hostPressureTrendLabel->setObjectName("mutedText");
    m_hostPressureTrendLabel->setWordWrap(true);

    auto *hostTimelineTitle = new QLabel(tr("Son Host Olaylari"), this);
    hostTimelineTitle->setObjectName("sectionTitle");

    m_hostHealthList = new QListWidget(this);
    m_hostHealthList->setAlternatingRowColors(true);
    m_hostTimelineList = new QListWidget(this);
    m_hostTimelineList->setAlternatingRowColors(true);
    m_hostTimelineList->setMinimumHeight(120);

    layout->addWidget(titleLabel);
    layout->addWidget(descLabel);
    layout->addWidget(hostSummaryHost);
    layout->addWidget(hostActionsHost);
    layout->addWidget(m_hostReplayDiffLabel);
    layout->addWidget(m_hostPressureTrendLabel);
    layout->addWidget(m_hostHealthList);
    layout->addWidget(hostTimelineTitle);
    layout->addWidget(m_hostTimelineList);
}
