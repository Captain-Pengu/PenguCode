#pragma once

#include <QFrame>

class QComboBox;
class QLineEdit;
class QPushButton;

class PenguCoreControlPanel : public QFrame
{
    Q_OBJECT

public:
    explicit PenguCoreControlPanel(bool viewerOnly, QWidget *parent = nullptr);

    QPushButton *clearButton() const { return m_clearButton; }
    QPushButton *exportButton() const { return m_exportButton; }
    QPushButton *exportLiveReportButton() const { return m_exportLiveReportButton; }
    QPushButton *openLiveFolderButton() const { return m_openLiveFolderButton; }
    QPushButton *refreshAdaptersButton() const { return m_refreshAdaptersButton; }
    QComboBox *liveAdapterCombo() const { return m_liveAdapterCombo; }
    QLineEdit *liveFilterEdit() const { return m_liveFilterEdit; }
    QComboBox *liveSaveFormatCombo() const { return m_liveSaveFormatCombo; }
    QPushButton *startLiveButton() const { return m_startLiveButton; }
    QPushButton *stopLiveButton() const { return m_stopLiveButton; }

private:
    QPushButton *m_clearButton = nullptr;
    QPushButton *m_exportButton = nullptr;
    QPushButton *m_exportLiveReportButton = nullptr;
    QPushButton *m_openLiveFolderButton = nullptr;
    QPushButton *m_refreshAdaptersButton = nullptr;
    QComboBox *m_liveAdapterCombo = nullptr;
    QLineEdit *m_liveFilterEdit = nullptr;
    QComboBox *m_liveSaveFormatCombo = nullptr;
    QPushButton *m_startLiveButton = nullptr;
    QPushButton *m_stopLiveButton = nullptr;
};
