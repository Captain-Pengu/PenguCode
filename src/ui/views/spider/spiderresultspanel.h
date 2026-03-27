#pragma once

#include <QFrame>

class QComboBox;
class QListWidget;
class QPlainTextEdit;
class QTextEdit;
class QTabWidget;
class QWidget;

class SpiderResultsPanel : public QFrame
{
    Q_OBJECT

public:
    explicit SpiderResultsPanel(QWidget *parent = nullptr);

    QPlainTextEdit *console() const { return m_console; }
    QComboBox *assetFilterCombo() const { return m_assetFilterCombo; }
    QListWidget *evidenceList() const { return m_evidenceList; }
    QTextEdit *evidenceDetailView() const { return m_evidenceDetailView; }
    QComboBox *endpointFilterCombo() const { return m_endpointFilterCombo; }
    QListWidget *endpointList() const { return m_endpointList; }
    QListWidget *parameterList() const { return m_parameterList; }
    QListWidget *assetList() const { return m_assetList; }
    QListWidget *highValueList() const { return m_highValueList; }
    QListWidget *segmentList() const { return m_segmentList; }
    QListWidget *benchmarkHistoryList() const { return m_benchmarkHistoryList; }
    QListWidget *timelineList() const { return m_timelineList; }
    QListWidget *featureList() const { return m_featureList; }
    QWidget *hostPanel() const { return m_hostPanel; }
    QTabWidget *workTabs() const { return m_workTabs; }
    void setSetupTab(QWidget *setupTab);

private:
    QFrame *makeListCard(const QString &title, const QString &description, QListWidget **list);

    QPlainTextEdit *m_console = nullptr;
    QComboBox *m_assetFilterCombo = nullptr;
    QListWidget *m_evidenceList = nullptr;
    QTextEdit *m_evidenceDetailView = nullptr;
    QComboBox *m_endpointFilterCombo = nullptr;
    QListWidget *m_endpointList = nullptr;
    QListWidget *m_parameterList = nullptr;
    QListWidget *m_assetList = nullptr;
    QListWidget *m_highValueList = nullptr;
    QListWidget *m_segmentList = nullptr;
    QListWidget *m_benchmarkHistoryList = nullptr;
    QListWidget *m_timelineList = nullptr;
    QListWidget *m_featureList = nullptr;
    QWidget *m_hostPanel = nullptr;
    QTabWidget *m_workTabs = nullptr;
};
