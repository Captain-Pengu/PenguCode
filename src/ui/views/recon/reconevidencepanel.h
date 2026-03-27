#pragma once

#include <QFrame>

class QLineEdit;
class QListWidget;
class QLabel;
class QTextEdit;

class ReconEvidencePanel : public QFrame
{
    Q_OBJECT

public:
    explicit ReconEvidencePanel(QWidget *parent = nullptr);

    QLineEdit *evidenceSearchEdit() const { return m_evidenceSearchEdit; }
    QListWidget *dnsList() const { return m_dnsList; }
    QListWidget *surfaceList() const { return m_surfaceList; }
    QListWidget *osintList() const { return m_osintList; }
    QListWidget *subdomainList() const { return m_subdomainList; }
    QListWidget *archiveList() const { return m_archiveList; }
    QListWidget *jsFindingList() const { return m_jsFindingList; }
    QListWidget *cveList() const { return m_cveList; }
    QTextEdit *whoisSummaryView() const { return m_whoisSummaryView; }
    QTextEdit *relationshipView() const { return m_relationshipView; }
    QListWidget *analysisTimelineList() const { return m_analysisTimelineList; }
    QListWidget *spiderEndpointList() const { return m_spiderEndpointList; }
    QListWidget *spiderParameterList() const { return m_spiderParameterList; }
    QListWidget *spiderAssetList() const { return m_spiderAssetList; }
    QListWidget *spiderHighValueList() const { return m_spiderHighValueList; }
    QListWidget *spiderTimelineList() const { return m_spiderTimelineList; }
    QLabel *spiderCoverageLabel() const { return m_spiderCoverageLabel; }

private:
    QFrame *makeListCard(const QString &title, const QString &description, QListWidget **list);

    QLineEdit *m_evidenceSearchEdit = nullptr;
    QListWidget *m_dnsList = nullptr;
    QListWidget *m_surfaceList = nullptr;
    QListWidget *m_osintList = nullptr;
    QListWidget *m_subdomainList = nullptr;
    QListWidget *m_archiveList = nullptr;
    QListWidget *m_jsFindingList = nullptr;
    QListWidget *m_cveList = nullptr;
    QListWidget *m_spiderEndpointList = nullptr;
    QListWidget *m_spiderParameterList = nullptr;
    QListWidget *m_spiderAssetList = nullptr;
    QListWidget *m_spiderHighValueList = nullptr;
    QListWidget *m_spiderTimelineList = nullptr;
    QLabel *m_spiderCoverageLabel = nullptr;
    QTextEdit *m_whoisSummaryView = nullptr;
    QTextEdit *m_relationshipView = nullptr;
    QListWidget *m_analysisTimelineList = nullptr;
};
