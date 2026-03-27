#include "ui/views/pengucore/pengucorebrowserpanel.h"

#include "ui/layout/flowlayout.h"

#include <QLabel>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QVBoxLayout>

PenguCoreBrowserPanel::PenguCoreBrowserPanel(QWidget *parent)
    : QFrame(parent)
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    auto *splitter = new QSplitter(Qt::Vertical, this);
    splitter->setChildrenCollapsible(false);
    splitter->setHandleWidth(10);
    splitter->setOpaqueResize(false);

    auto *packetCard = new QFrame(splitter);
    packetCard->setObjectName("cardPanel");
    auto *packetLayout = new QVBoxLayout(packetCard);
    packetLayout->setContentsMargins(18, 18, 18, 18);
    packetLayout->setSpacing(10);
    auto *packetTitle = new QLabel(tr("Packet Browser"), packetCard);
    packetTitle->setObjectName("sectionTitle");
    auto *packetLead = new QLabel(tr("Ana izleme alani. Filtreden gecen packet'lar burada listelenir."), packetCard);
    packetLead->setObjectName("mutedText");
    packetLead->setWordWrap(true);
    auto *packetActionRow = new QHBoxLayout();
    packetActionRow->setSpacing(8);
    m_packetApplyFilterButton = new QPushButton(tr("Packet Filtresi"), packetCard);
    m_packetCopySourceButton = new QPushButton(tr("Kaynagi Kopyala"), packetCard);
    m_packetCopyDestinationButton = new QPushButton(tr("Hedefi Kopyala"), packetCard);
    m_packetSaveRawButton = new QPushButton(tr("Raw Kaydet"), packetCard);
    m_packetSaveRangeButton = new QPushButton(tr("Aralik Kaydet"), packetCard);
    m_packetExportJsonButton = new QPushButton(tr("Packet JSON"), packetCard);
    m_packetCopyFieldButton = new QPushButton(tr("Alani Kopyala"), packetCard);
    m_packetExportFieldButton = new QPushButton(tr("Alani Kaydet"), packetCard);
    packetActionRow->addWidget(m_packetApplyFilterButton);
    packetActionRow->addWidget(m_packetCopySourceButton);
    packetActionRow->addWidget(m_packetCopyDestinationButton);
    packetActionRow->addWidget(m_packetSaveRawButton);
    packetActionRow->addWidget(m_packetSaveRangeButton);
    packetActionRow->addWidget(m_packetExportJsonButton);
    packetActionRow->addWidget(m_packetCopyFieldButton);
    packetActionRow->addWidget(m_packetExportFieldButton);
    packetActionRow->addStretch();
    m_packetList = new QListWidget(packetCard);
    m_packetList->setAlternatingRowColors(true);
    m_packetList->setContextMenuPolicy(Qt::CustomContextMenu);
    packetLayout->addWidget(packetTitle);
    packetLayout->addWidget(packetLead);
    packetLayout->addLayout(packetActionRow);
    packetLayout->addWidget(m_packetList, 1);

    auto *flowCard = new QFrame(splitter);
    flowCard->setObjectName("cardPanel");
    auto *flowLayout = new QVBoxLayout(flowCard);
    flowLayout->setContentsMargins(18, 18, 18, 18);
    flowLayout->setSpacing(10);
    auto *flowTitle = new QLabel(tr("Flow Intelligence"), flowCard);
    flowTitle->setObjectName("sectionTitle");
    auto *flowLead = new QLabel(tr("Ikincil analiz alani. Secili akisa gore baglam verir."), flowCard);
    flowLead->setObjectName("mutedText");
    flowLead->setWordWrap(true);
    auto *flowActionHost = new QWidget(flowCard);
    auto *flowActionRow = new FlowLayout(flowActionHost, 0, 8, 8);
    m_flowApplyFilterButton = new QPushButton(tr("Flow Filtresi"), flowCard);
    m_flowIsolateButton = new QPushButton(tr("Flow'u Izole Et"), flowCard);
    m_clearFlowIsolationButton = new QPushButton(tr("Izolasyonu Temizle"), flowCard);
    m_exportFlowsButton = new QPushButton(tr("Flow JSON"), flowCard);
    m_exportFlowStreamButton = new QPushButton(tr("Stream Kaydet"), flowCard);
    m_exportFlowHexButton = new QPushButton(tr("Hex Kaydet"), flowCard);
    m_exportFlowPacketsButton = new QPushButton(tr("Flow CSV"), flowCard);
    flowActionRow->addWidget(m_flowApplyFilterButton);
    flowActionRow->addWidget(m_flowIsolateButton);
    flowActionRow->addWidget(m_clearFlowIsolationButton);
    flowActionRow->addWidget(m_exportFlowsButton);
    flowActionRow->addWidget(m_exportFlowStreamButton);
    flowActionRow->addWidget(m_exportFlowHexButton);
    flowActionRow->addWidget(m_exportFlowPacketsButton);
    flowActionHost->setLayout(flowActionRow);
    m_flowList = new QListWidget(flowCard);
    m_flowList->setAlternatingRowColors(true);
    m_flowList->setContextMenuPolicy(Qt::CustomContextMenu);
    m_flowDetailView = new QPlainTextEdit(flowCard);
    m_flowDetailView->setReadOnly(true);
    flowLayout->addWidget(flowTitle);
    flowLayout->addWidget(flowLead);
    flowLayout->addWidget(flowActionHost);
    flowLayout->addWidget(m_flowList, 1);
    flowLayout->addWidget(m_flowDetailView, 1);

    splitter->setSizes({560, 280});
    root->addWidget(splitter, 1);
}
