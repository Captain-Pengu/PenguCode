#include "reconreportpanel.h"

#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"

#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>

ReconReportPanel::ReconReportPanel(QWidget *parent)
    : QFrame(parent)
{
    setObjectName("cardPanel");
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(20, 20, 20, 20);
    root->setSpacing(12);

    auto *reportTitle = new QLabel(tr("Resmi Pentest Raporu"), this);
    reportTitle->setObjectName("sectionTitle");

    auto *reportInfo = new QLabel(tr("PDF onizleme hizli erisim icin ust sagdadir. Buradaki alanlar rapor kapagi ve yonetici ozeti icin kullanilir."), this);
    reportInfo->setObjectName("mutedText");
    reportInfo->setWordWrap(true);

    auto *reportActionsHost = new QWidget(this);
    auto *reportActions = new FlowLayout(reportActionsHost, 0, 10, 10);
    m_exportJsonButton = new QPushButton(tr("JSON Disa Aktar"), this);
    m_exportCsvButton = new QPushButton(tr("CSV Disa Aktar"), this);
    m_saveSessionButton = new QPushButton(tr("Oturumu Kaydet"), this);
    m_openSessionButton = new QPushButton(tr("Oturum Ac"), this);
    m_exportJsonButton->setEnabled(false);
    m_exportCsvButton->setEnabled(false);
    m_saveSessionButton->setEnabled(false);
    reportActions->addWidget(m_exportJsonButton);
    reportActions->addWidget(m_exportCsvButton);
    reportActions->addWidget(m_saveSessionButton);
    reportActions->addWidget(m_openSessionButton);
    reportActionsHost->setLayout(reportActions);

    auto *sessionArchiveHost = new QWidget(this);
    auto *sessionArchiveLayout = new FlowLayout(sessionArchiveHost, 0, 10, 10);
    m_recentSessionCombo = new QComboBox(this);
    sessionArchiveLayout->addWidget(m_recentSessionCombo);
    sessionArchiveHost->setLayout(sessionArchiveLayout);

    auto *diffCard = new QFrame(this);
    diffCard->setObjectName("cardPanel");
    auto *diffLayout = new QVBoxLayout(diffCard);
    diffLayout->setContentsMargins(16, 16, 16, 16);
    diffLayout->setSpacing(8);
    auto *diffTitle = new QLabel(tr("Oturum Karsilastirma"), diffCard);
    diffTitle->setObjectName("sectionTitle");
    m_diffSummaryValue = new QLabel(tr("Karsilastirma icin once bir oturum yukle veya yeni bir baseline olustur."), diffCard);
    m_diffSummaryValue->setObjectName("mutedText");
    m_diffSummaryValue->setWordWrap(true);
    diffLayout->addWidget(diffTitle);
    diffLayout->addWidget(m_diffSummaryValue);

    auto *notesCard = new QFrame(this);
    notesCard->setObjectName("cardPanel");
    auto *notesLayout = new QVBoxLayout(notesCard);
    notesLayout->setContentsMargins(16, 16, 16, 16);
    notesLayout->setSpacing(8);
    auto *notesTitle = new QLabel(tr("Analist Notlari"), notesCard);
    notesTitle->setObjectName("sectionTitle");
    m_analystNotesEdit = new QTextEdit(notesCard);
    m_analystNotesEdit->setPlaceholderText(tr("Buraya manuel gozlem, dogrulama notu veya sonraki aksiyonlarini yazabilirsin."));
    notesLayout->addWidget(notesTitle);
    notesLayout->addWidget(m_analystNotesEdit, 1);

    root->addWidget(reportTitle);
    root->addWidget(reportInfo);
    root->addWidget(reportActionsHost);
    root->addWidget(sessionArchiveHost);
    root->addWidget(diffCard);
    root->addWidget(notesCard);
}
