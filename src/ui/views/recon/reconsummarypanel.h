#pragma once

#include <QFrame>

class QLabel;

class ReconSummaryPanel : public QFrame
{
    Q_OBJECT

public:
    explicit ReconSummaryPanel(QWidget *parent = nullptr);

    QLabel *statusValue() const { return m_statusValue; }
    QLabel *scoreValue() const { return m_scoreValue; }
    QLabel *findingsCountValue() const { return m_findingsCountValue; }
    QLabel *portsCountValue() const { return m_portsCountValue; }
    QLabel *subdomainCountValue() const { return m_subdomainCountValue; }
    QLabel *archiveCountValue() const { return m_archiveCountValue; }
    QLabel *dnsCountValue() const { return m_dnsCountValue; }
    QLabel *surfaceCountValue() const { return m_surfaceCountValue; }
    QLabel *osintCountValue() const { return m_osintCountValue; }
    QLabel *spiderCountValue() const { return m_spiderCountValue; }

private:
    QLabel *m_statusValue = nullptr;
    QLabel *m_scoreValue = nullptr;
    QLabel *m_findingsCountValue = nullptr;
    QLabel *m_portsCountValue = nullptr;
    QLabel *m_subdomainCountValue = nullptr;
    QLabel *m_archiveCountValue = nullptr;
    QLabel *m_dnsCountValue = nullptr;
    QLabel *m_surfaceCountValue = nullptr;
    QLabel *m_osintCountValue = nullptr;
    QLabel *m_spiderCountValue = nullptr;
};
