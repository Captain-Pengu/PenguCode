#pragma once

#include <QFrame>

class QListWidget;
class QTabWidget;
class TrafficWaterfallWidget;

class ProxyBottomPanel : public QFrame
{
    Q_OBJECT

public:
    explicit ProxyBottomPanel(QWidget *parent = nullptr);

    QListWidget *eventFeed() const { return m_eventFeed; }
    TrafficWaterfallWidget *waterfallDetailWidget() const { return m_waterfallDetailWidget; }
    QTabWidget *tabs() const { return m_tabs; }

private:
    QTabWidget *m_tabs = nullptr;
    QListWidget *m_eventFeed = nullptr;
    TrafficWaterfallWidget *m_waterfallDetailWidget = nullptr;
};
