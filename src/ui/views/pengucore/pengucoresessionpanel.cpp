#include "ui/views/pengucore/pengucoresessionpanel.h"

#include "ui/layout/flowlayout.h"

#include <QLabel>
#include <QVBoxLayout>

namespace {

QFrame *makeSummaryCard(QWidget *parent, const QString &labelText, QLabel **valueLabel, const QString &defaultValue, const QString &valueObjectName, int minWidth)
{
    auto *card = new QFrame(parent);
    card->setObjectName("summaryCard");
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(12, 10, 12, 10);
    layout->setSpacing(4);
    auto *label = new QLabel(labelText, card);
    label->setObjectName("summaryKicker");
    *valueLabel = new QLabel(defaultValue, card);
    (*valueLabel)->setObjectName(valueObjectName);
    (*valueLabel)->setWordWrap(true);
    layout->addWidget(label);
    layout->addWidget(*valueLabel);
    card->setMinimumWidth(minWidth);
    return card;
}

}

PenguCoreSessionPanel::PenguCoreSessionPanel(QWidget *parent)
    : QFrame(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(10);

    auto *statsHost = new QWidget(this);
    auto *statsRow = new FlowLayout(statsHost, 0, 10, 10);
    statsRow->addWidget(makeSummaryCard(this, tr("Toplam Packet"), &m_totalPacketsValue, QStringLiteral("0"), QStringLiteral("statValue"), 112));
    statsRow->addWidget(makeSummaryCard(this, tr("Gorunen Packet"), &m_visiblePacketsValue, QStringLiteral("0"), QStringLiteral("statValue"), 112));
    statsRow->addWidget(makeSummaryCard(this, tr("Toplam Flow"), &m_totalFlowsValue, QStringLiteral("0"), QStringLiteral("statValue"), 112));
    statsRow->addWidget(makeSummaryCard(this, tr("Gorunen Flow"), &m_visibleFlowsValue, QStringLiteral("0"), QStringLiteral("statValue"), 112));
    statsHost->setLayout(statsRow);

    auto *sessionHost = new QWidget(this);
    auto *sessionRow = new FlowLayout(sessionHost, 0, 10, 10);
    sessionRow->addWidget(makeSummaryCard(this, tr("Dosya"), &m_sessionFileCardValue, QStringLiteral("--"), QStringLiteral("mutedText"), 124));
    sessionRow->addWidget(makeSummaryCard(this, tr("Format"), &m_sessionFormatCardValue, QStringLiteral("--"), QStringLiteral("mutedText"), 124));
    sessionRow->addWidget(makeSummaryCard(this, tr("Toplam Byte"), &m_sessionBytesCardValue, QStringLiteral("--"), QStringLiteral("mutedText"), 124));
    sessionRow->addWidget(makeSummaryCard(this, tr("Yuklendi"), &m_sessionOpenedCardValue, QStringLiteral("--"), QStringLiteral("mutedText"), 124));
    sessionRow->addWidget(makeSummaryCard(this, tr("Ilk Packet"), &m_sessionFirstSeenCardValue, QStringLiteral("--"), QStringLiteral("mutedText"), 124));
    sessionRow->addWidget(makeSummaryCard(this, tr("Son Packet"), &m_sessionLastSeenCardValue, QStringLiteral("--"), QStringLiteral("mutedText"), 124));
    sessionRow->addWidget(makeSummaryCard(this, tr("Live Save"), &m_sessionLiveSaveCardValue, QStringLiteral("--"), QStringLiteral("mutedText"), 124));
    sessionHost->setLayout(sessionRow);

    auto *timelineCard = new QFrame(this);
    timelineCard->setObjectName("cardPanel");
    auto *timelineLayout = new QVBoxLayout(timelineCard);
    timelineLayout->setContentsMargins(14, 12, 14, 12);
    timelineLayout->setSpacing(6);
    auto *timelineTitle = new QLabel(tr("Session Timeline"), timelineCard);
    timelineTitle->setObjectName("sectionTitle");
    m_timelineValue = new QLabel(tr("Henuz zaman ekseni olusmadi"), timelineCard);
    m_timelineValue->setObjectName("mutedText");
    m_timelineValue->setWordWrap(true);
    timelineLayout->addWidget(timelineTitle);
    timelineLayout->addWidget(m_timelineValue);

    layout->addWidget(statsHost);
    layout->addWidget(sessionHost);
    layout->addWidget(timelineCard);
}
