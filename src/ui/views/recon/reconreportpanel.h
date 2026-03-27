#pragma once

#include <QFrame>

class QComboBox;
class QLabel;
class QPushButton;
class QTextEdit;

class ReconReportPanel : public QFrame
{
    Q_OBJECT

public:
    explicit ReconReportPanel(QWidget *parent = nullptr);

    QPushButton *exportJsonButton() const { return m_exportJsonButton; }
    QPushButton *exportCsvButton() const { return m_exportCsvButton; }
    QPushButton *saveSessionButton() const { return m_saveSessionButton; }
    QPushButton *openSessionButton() const { return m_openSessionButton; }
    QComboBox *recentSessionCombo() const { return m_recentSessionCombo; }
    QLabel *diffSummaryValue() const { return m_diffSummaryValue; }
    QTextEdit *analystNotesEdit() const { return m_analystNotesEdit; }

private:
    QPushButton *m_exportJsonButton = nullptr;
    QPushButton *m_exportCsvButton = nullptr;
    QPushButton *m_saveSessionButton = nullptr;
    QPushButton *m_openSessionButton = nullptr;
    QComboBox *m_recentSessionCombo = nullptr;
    QLabel *m_diffSummaryValue = nullptr;
    QTextEdit *m_analystNotesEdit = nullptr;
};
