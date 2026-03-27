#pragma once

#include <QFrame>

class QLabel;
class QListWidget;
class QComboBox;
class QPushButton;

class SpiderHostHealthPanel : public QFrame
{
    Q_OBJECT

public:
    explicit SpiderHostHealthPanel(QWidget *parent = nullptr);

    QListWidget *hostHealthList() const { return m_hostHealthList; }
    QListWidget *hostTimelineList() const { return m_hostTimelineList; }
    QComboBox *hostFilterCombo() const { return m_hostFilterCombo; }
    QPushButton *exportHostDiagnosticsButton() const { return m_exportHostDiagnosticsButton; }
    QLabel *hostStableValue() const { return m_hostStableValue; }
    QLabel *hostGuardedValue() const { return m_hostGuardedValue; }
    QLabel *hostWafValue() const { return m_hostWafValue; }
    QLabel *hostStressedValue() const { return m_hostStressedValue; }
    QLabel *hostReplayDiffLabel() const { return m_hostReplayDiffLabel; }
    QLabel *hostPressureTrendLabel() const { return m_hostPressureTrendLabel; }

private:
    QListWidget *m_hostHealthList = nullptr;
    QListWidget *m_hostTimelineList = nullptr;
    QComboBox *m_hostFilterCombo = nullptr;
    QPushButton *m_exportHostDiagnosticsButton = nullptr;
    QLabel *m_hostStableValue = nullptr;
    QLabel *m_hostGuardedValue = nullptr;
    QLabel *m_hostWafValue = nullptr;
    QLabel *m_hostStressedValue = nullptr;
    QLabel *m_hostReplayDiffLabel = nullptr;
    QLabel *m_hostPressureTrendLabel = nullptr;
};
