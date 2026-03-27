#include "ui/views/pengucore/pengucoreinspectorpanel.h"

#include "ui/layout/flowlayout.h"

#include <QFrame>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

PenguCoreInspectorPanel::PenguCoreInspectorPanel(QWidget *parent)
    : QFrame(parent)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(12);

    m_selectionCard = new QFrame(this);
    m_selectionCard->setObjectName(QStringLiteral("cardPanel"));
    auto *selectionLayout = new QVBoxLayout(m_selectionCard);
    selectionLayout->setContentsMargins(16, 16, 16, 16);
    selectionLayout->setSpacing(8);
    auto *selectionTitle = new QLabel(tr("Inspector"), m_selectionCard);
    selectionTitle->setObjectName(QStringLiteral("sectionTitle"));
    auto *selectionLead = new QLabel(tr("Derin inceleme alani. Yalniz secili kayda odaklanir."), m_selectionCard);
    selectionLead->setObjectName(QStringLiteral("mutedText"));
    selectionLead->setWordWrap(true);
    selectionLayout->addWidget(selectionTitle);
    selectionLayout->addWidget(selectionLead);

    m_detailCard = new QFrame(this);
    m_detailCard->setObjectName(QStringLiteral("cardPanel"));
    auto *detailLayout = new QVBoxLayout(m_detailCard);
    detailLayout->setContentsMargins(16, 16, 16, 16);
    detailLayout->setSpacing(10);
    auto *detailTitle = new QLabel(tr("Packet Detail"), m_detailCard);
    detailTitle->setObjectName(QStringLiteral("sectionTitle"));
    auto *detailSearchHost = new QWidget(m_detailCard);
    auto *detailSearchRow = new FlowLayout(detailSearchHost, 0, 8, 8);
    m_detailSearchEdit = new QLineEdit(m_detailCard);
    m_detailSearchEdit->setPlaceholderText(tr("Detay, hex veya stream icinde ara"));
    m_findDetailButton = new QPushButton(tr("Detayda Bul"), m_detailCard);
    m_findHexButton = new QPushButton(tr("Hex'te Bul"), m_detailCard);
    m_findFlowStreamButton = new QPushButton(tr("Flow'da Bul"), m_detailCard);
    m_findFlowStreamPrevButton = new QPushButton(tr("Flow Onceki"), m_detailCard);
    m_findFlowStreamNextButton = new QPushButton(tr("Flow Sonraki"), m_detailCard);
    detailSearchRow->addWidget(m_detailSearchEdit);
    detailSearchRow->addWidget(m_findDetailButton);
    detailSearchRow->addWidget(m_findHexButton);
    detailSearchRow->addWidget(m_findFlowStreamButton);
    detailSearchRow->addWidget(m_findFlowStreamPrevButton);
    detailSearchRow->addWidget(m_findFlowStreamNextButton);
    detailSearchHost->setLayout(detailSearchRow);

    m_detailView = new QPlainTextEdit(m_detailCard);
    m_detailView->setReadOnly(true);
    auto *hexTitle = new QLabel(tr("Hex / Raw"), m_detailCard);
    hexTitle->setObjectName(QStringLiteral("cardTitle"));
    m_hexView = new QPlainTextEdit(m_detailCard);
    m_hexView->setReadOnly(true);

    detailLayout->addWidget(detailTitle);
    detailLayout->addWidget(detailSearchHost);
    detailLayout->addWidget(m_detailView, 1);
    detailLayout->addWidget(hexTitle);
    detailLayout->addWidget(m_hexView, 1);

    layout->addWidget(m_selectionCard);
    layout->addWidget(m_detailCard, 1);
}
