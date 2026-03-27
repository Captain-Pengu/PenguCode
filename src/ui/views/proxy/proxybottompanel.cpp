#include "ui/views/proxy/proxybottompanel.h"

#include "ui/views/proxy/proxywidget.h"

#include <QAbstractItemView>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

ProxyBottomPanel::ProxyBottomPanel(QWidget *parent)
    : QFrame(parent)
{
    setObjectName(QStringLiteral("cardPanel"));
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(12);

    m_tabs = new QTabWidget(this);
    m_tabs->setDocumentMode(true);
    m_tabs->setUsesScrollButtons(true);

    auto *feedTab = new QWidget(m_tabs);
    auto *feedLayout = new QVBoxLayout(feedTab);
    feedLayout->setContentsMargins(6, 8, 6, 6);
    feedLayout->setSpacing(10);
    auto *feedTitle = new QLabel(tr("Tactical Feed"), feedTab);
    feedTitle->setObjectName(QStringLiteral("sectionTitle"));
    auto *feedInfo = new QLabel(tr("Proxy oturumu boyunca servis olaylari, kontrol degisimleri ve kullanici aksiyonlari burada akar."), feedTab);
    feedInfo->setObjectName(QStringLiteral("mutedText"));
    feedInfo->setWordWrap(true);
    m_eventFeed = new QListWidget(feedTab);
    m_eventFeed->setAlternatingRowColors(true);
    m_eventFeed->setSelectionMode(QAbstractItemView::NoSelection);
    m_eventFeed->setMinimumHeight(180);
    feedLayout->addWidget(feedTitle);
    feedLayout->addWidget(feedInfo);
    feedLayout->addWidget(m_eventFeed);

    auto *waterfallTab = new QWidget(m_tabs);
    auto *waterfallLayout = new QVBoxLayout(waterfallTab);
    waterfallLayout->setContentsMargins(6, 8, 6, 6);
    waterfallLayout->setSpacing(12);
    auto *waterfallTitle = new QLabel(tr("Traffic Waterfall"), waterfallTab);
    waterfallTitle->setObjectName(QStringLiteral("sectionTitle"));
    auto *waterfallInfo = new QLabel(tr("Anlik trafik yogunlugu zaman ekseninde akar. Dusuk akista soguk tonlar, spike aninda sicak tonlar gorunur."), waterfallTab);
    waterfallInfo->setObjectName(QStringLiteral("mutedText"));
    waterfallInfo->setWordWrap(true);
    m_waterfallDetailWidget = new TrafficWaterfallWidget(waterfallTab);
    m_waterfallDetailWidget->setMinimumHeight(240);
    auto *legendRow = new QHBoxLayout();
    legendRow->setSpacing(10);
    auto addLegend = [waterfallTab, legendRow](const QString &labelText, const QColor &color) {
        auto *chip = new QLabel(labelText, waterfallTab);
        chip->setStyleSheet(QString("QLabel { background:%1; color:#f8fafc; border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:4px 10px; }")
                                .arg(color.name()));
        legendRow->addWidget(chip);
    };
    addLegend(tr("Dusuk"), QColor("#18687a"));
    addLegend(tr("Orta"), QColor("#2ab06c"));
    addLegend(tr("Yuksek"), QColor("#ecb32f"));
    addLegend(tr("Spike"), QColor("#dc2840"));
    legendRow->addStretch();
    waterfallLayout->addWidget(waterfallTitle);
    waterfallLayout->addWidget(waterfallInfo);
    waterfallLayout->addWidget(m_waterfallDetailWidget, 1);
    waterfallLayout->addLayout(legendRow);

    m_tabs->addTab(feedTab, tr("Feed"));
    m_tabs->addTab(waterfallTab, tr("Waterfall"));
    layout->addWidget(m_tabs);
}
