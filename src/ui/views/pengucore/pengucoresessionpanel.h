#pragma once

#include <QFrame>

class QLabel;

class PenguCoreSessionPanel : public QFrame
{
    Q_OBJECT

public:
    explicit PenguCoreSessionPanel(QWidget *parent = nullptr);

    QLabel *totalPacketsValue() const { return m_totalPacketsValue; }
    QLabel *visiblePacketsValue() const { return m_visiblePacketsValue; }
    QLabel *totalFlowsValue() const { return m_totalFlowsValue; }
    QLabel *visibleFlowsValue() const { return m_visibleFlowsValue; }
    QLabel *sessionFileCardValue() const { return m_sessionFileCardValue; }
    QLabel *sessionFormatCardValue() const { return m_sessionFormatCardValue; }
    QLabel *sessionBytesCardValue() const { return m_sessionBytesCardValue; }
    QLabel *sessionOpenedCardValue() const { return m_sessionOpenedCardValue; }
    QLabel *sessionFirstSeenCardValue() const { return m_sessionFirstSeenCardValue; }
    QLabel *sessionLastSeenCardValue() const { return m_sessionLastSeenCardValue; }
    QLabel *sessionLiveSaveCardValue() const { return m_sessionLiveSaveCardValue; }
    QLabel *timelineValue() const { return m_timelineValue; }

private:
    QLabel *m_totalPacketsValue = nullptr;
    QLabel *m_visiblePacketsValue = nullptr;
    QLabel *m_totalFlowsValue = nullptr;
    QLabel *m_visibleFlowsValue = nullptr;
    QLabel *m_sessionFileCardValue = nullptr;
    QLabel *m_sessionFormatCardValue = nullptr;
    QLabel *m_sessionBytesCardValue = nullptr;
    QLabel *m_sessionOpenedCardValue = nullptr;
    QLabel *m_sessionFirstSeenCardValue = nullptr;
    QLabel *m_sessionLastSeenCardValue = nullptr;
    QLabel *m_sessionLiveSaveCardValue = nullptr;
    QLabel *m_timelineValue = nullptr;
};
