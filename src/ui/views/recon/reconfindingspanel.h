#pragma once

#include <QFrame>

class QComboBox;
class QLineEdit;
class QListWidget;
class QTextEdit;
class QPushButton;

class ReconFindingsPanel : public QFrame
{
    Q_OBJECT

public:
    explicit ReconFindingsPanel(QWidget *parent = nullptr);

    QComboBox *severityFilter() const { return m_findingsSeverityFilter; }
    QLineEdit *searchEdit() const { return m_findingsSearchEdit; }
    QPushButton *addManualFindingButton() const { return m_addManualFindingButton; }
    QListWidget *findingsList() const { return m_findingsList; }
    QPushButton *copyDetailButton() const { return m_copyDetailButton; }
    QTextEdit *findingDetailView() const { return m_findingDetailView; }
    QTextEdit *findingNoteEdit() const { return m_findingNoteEdit; }
    QPushButton *saveFindingNoteButton() const { return m_saveFindingNoteButton; }

private:
    QComboBox *m_findingsSeverityFilter = nullptr;
    QLineEdit *m_findingsSearchEdit = nullptr;
    QPushButton *m_addManualFindingButton = nullptr;
    QListWidget *m_findingsList = nullptr;
    QPushButton *m_copyDetailButton = nullptr;
    QTextEdit *m_findingDetailView = nullptr;
    QTextEdit *m_findingNoteEdit = nullptr;
    QPushButton *m_saveFindingNoteButton = nullptr;
};
