#include "pengucorefilterpanel.h"

#include "ui/layout/flowlayout.h"

#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

PenguCoreFilterPanel::PenguCoreFilterPanel(QWidget *parent)
    : QFrame(parent)
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(12);

    m_filterCard = new QFrame(this);
    m_filterCard->setObjectName("cardPanel");
    auto *filterLayout = new QVBoxLayout(m_filterCard);
    filterLayout->setContentsMargins(18, 18, 18, 18);
    filterLayout->setSpacing(10);
    auto *filterTitle = new QLabel(tr("Filtreler"), m_filterCard);
    filterTitle->setObjectName("sectionTitle");
    auto *filterHost = new QWidget(m_filterCard);
    auto *filterRow = new FlowLayout(filterHost, 0, 10, 10);
    m_searchEdit = new QLineEdit(m_filterCard);
    m_searchEdit->setPlaceholderText(tr("Serbest metin ara"));
    m_sourceFilterEdit = new QLineEdit(m_filterCard);
    m_sourceFilterEdit->setPlaceholderText(tr("Kaynak"));
    m_destinationFilterEdit = new QLineEdit(m_filterCard);
    m_destinationFilterEdit->setPlaceholderText(tr("Hedef"));
    m_protocolFilter = new QComboBox(m_filterCard);
    m_filterPresetCombo = new QComboBox(m_filterCard);
    m_protocolFilter->addItems({tr("Tum Protokoller"), QStringLiteral("ARP"), QStringLiteral("IPv4"), QStringLiteral("TCP"), QStringLiteral("UDP"), QStringLiteral("ICMP"), QStringLiteral("DNS"), QStringLiteral("HTTP")});
    m_filterPresetCombo->addItem(tr("Hazir Preset"), QString());
    m_filterPresetCombo->addItem(tr("Web Trafiği"), QStringLiteral("tcp port 80 or tcp port 443 or tcp port 8080"));
    m_filterPresetCombo->addItem(tr("DNS Trafiği"), QStringLiteral("udp port 53"));
    m_filterPresetCombo->addItem(tr("ICMP / Ping"), QStringLiteral("icmp"));
    m_filterPresetCombo->addItem(tr("Localhost Hariç"), QStringLiteral("not host 127.0.0.1"));
    m_filterPresetCombo->addItem(tr("Yalnız TCP"), QStringLiteral("tcp"));
    m_filterPresetCombo->addItem(tr("Yalnız UDP"), QStringLiteral("udp"));
    m_searchEdit->setMinimumWidth(180);
    m_sourceFilterEdit->setMinimumWidth(120);
    m_destinationFilterEdit->setMinimumWidth(120);
    m_protocolFilter->setMinimumWidth(112);
    m_filterPresetCombo->setMinimumWidth(124);
    filterRow->addWidget(m_searchEdit);
    filterRow->addWidget(m_sourceFilterEdit);
    filterRow->addWidget(m_destinationFilterEdit);
    filterRow->addWidget(m_protocolFilter);
    filterRow->addWidget(m_filterPresetCombo);
    filterHost->setLayout(filterRow);
    filterLayout->addWidget(filterTitle);
    filterLayout->addWidget(filterHost);

    m_quickActionCard = new QFrame(this);
    m_quickActionCard->setObjectName("cardPanel");
    auto *quickActionLayout = new QVBoxLayout(m_quickActionCard);
    quickActionLayout->setContentsMargins(18, 14, 18, 14);
    quickActionLayout->setSpacing(10);
    auto *quickActionTitle = new QLabel(tr("Quick Actions"), m_quickActionCard);
    quickActionTitle->setObjectName("sectionTitle");
    auto *quickActionHost = new QWidget(m_quickActionCard);
    auto *quickActionRow = new FlowLayout(quickActionHost, 0, 8, 8);
    m_toggleInspectorButton = new QPushButton(tr("Inspector"), m_quickActionCard);
    m_toggleHexButton = new QPushButton(tr("Hex Panel"), m_quickActionCard);
    m_toggleFlowDetailButton = new QPushButton(tr("Flow Detail"), m_quickActionCard);
    m_pauseLiveUiButton = new QPushButton(tr("UI Pause"), m_quickActionCard);
    m_autoScrollButton = new QPushButton(tr("Auto Scroll"), m_quickActionCard);
    m_onlyWarningsButton = new QPushButton(tr("Only Warnings"), m_quickActionCard);
    m_dnsFocusButton = new QPushButton(tr("Only DNS"), m_quickActionCard);
    m_httpFocusButton = new QPushButton(tr("Only HTTP"), m_quickActionCard);
    quickActionRow->addWidget(m_toggleInspectorButton);
    quickActionRow->addWidget(m_toggleHexButton);
    quickActionRow->addWidget(m_toggleFlowDetailButton);
    quickActionRow->addWidget(m_pauseLiveUiButton);
    quickActionRow->addWidget(m_autoScrollButton);
    quickActionRow->addWidget(m_onlyWarningsButton);
    quickActionRow->addWidget(m_dnsFocusButton);
    quickActionRow->addWidget(m_httpFocusButton);
    quickActionHost->setLayout(quickActionRow);
    quickActionLayout->addWidget(quickActionTitle);
    quickActionLayout->addWidget(quickActionHost);

    root->addWidget(m_filterCard);
    root->addWidget(m_quickActionCard);
}
