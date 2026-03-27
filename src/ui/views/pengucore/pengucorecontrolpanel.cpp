#include "pengucorecontrolpanel.h"

#include "ui/layout/flowlayout.h"

#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>

PenguCoreControlPanel::PenguCoreControlPanel(bool viewerOnly, QWidget *parent)
    : QFrame(parent)
{
    auto *actionRow = new FlowLayout(this, 0, 10, 10);
    m_clearButton = new QPushButton(tr("Oturumu Temizle"), this);
    m_exportButton = new QPushButton(tr("JSON Disa Aktar"), this);
    m_exportLiveReportButton = new QPushButton(tr("Live Rapor"), this);
    m_openLiveFolderButton = new QPushButton(tr("Live Klasorunu Ac"), this);
    m_refreshAdaptersButton = new QPushButton(tr("Adapterleri Yenile"), this);
    m_liveAdapterCombo = new QComboBox(this);
    m_liveFilterEdit = new QLineEdit(this);
    m_liveFilterEdit->setPlaceholderText(tr("Capture filter (ornek: tcp port 80)"));
    m_liveSaveFormatCombo = new QComboBox(this);
    m_liveSaveFormatCombo->addItem(QStringLiteral("PCAP"), QStringLiteral("pcap"));
    m_liveSaveFormatCombo->addItem(QStringLiteral("PCAPNG"), QStringLiteral("pcapng"));
    m_startLiveButton = new QPushButton(tr("Canli Baslat"), this);
    m_stopLiveButton = new QPushButton(tr("Canli Durdur"), this);
    m_liveAdapterCombo->setMinimumWidth(180);
    m_liveFilterEdit->setMinimumWidth(200);

    actionRow->addWidget(m_clearButton);
    actionRow->addWidget(m_exportButton);
    actionRow->addWidget(m_exportLiveReportButton);
    actionRow->addWidget(m_openLiveFolderButton);
    actionRow->addWidget(m_refreshAdaptersButton);
    actionRow->addWidget(m_liveAdapterCombo);
    actionRow->addWidget(m_liveFilterEdit);
    actionRow->addWidget(m_liveSaveFormatCombo);
    actionRow->addWidget(m_startLiveButton);
    actionRow->addWidget(m_stopLiveButton);
    setLayout(actionRow);

    if (viewerOnly) {
        m_refreshAdaptersButton->hide();
        m_liveAdapterCombo->hide();
        m_liveFilterEdit->hide();
        m_liveSaveFormatCombo->hide();
        m_startLiveButton->hide();
        m_stopLiveButton->hide();
        m_openLiveFolderButton->hide();
        m_exportLiveReportButton->hide();
        m_clearButton->setText(tr("Gorunumu Temizle"));
    }
}
