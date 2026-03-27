#pragma once

#include <QFrame>

class QLabel;
class QPlainTextEdit;
class QProgressBar;
class QWidget;

class ReconLivePanel : public QFrame
{
    Q_OBJECT

public:
    explicit ReconLivePanel(QWidget *parent = nullptr);

    QWidget *pulseWidget() const { return m_pulseWidget; }
    QPlainTextEdit *feedConsole() const { return m_feedConsole; }
    QLabel *activityValue() const { return m_activityValue; }
    QProgressBar *progressBar() const { return m_progressBar; }
    QLabel *phaseSummaryValue() const { return m_phaseSummaryValue; }

private:
    QWidget *m_pulseWidget = nullptr;
    QPlainTextEdit *m_feedConsole = nullptr;
    QLabel *m_activityValue = nullptr;
    QProgressBar *m_progressBar = nullptr;
    QLabel *m_phaseSummaryValue = nullptr;
};
