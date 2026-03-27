#include "ui/views/recon/reconfindingspanel.h"

#include "ui/layout/flowlayout.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

ReconFindingsPanel::ReconFindingsPanel(QWidget *parent)
    : QFrame(parent)
{
    setObjectName("cardPanel");
    auto *findingsLayout = new QHBoxLayout(this);
    findingsLayout->setContentsMargins(20, 20, 20, 20);
    findingsLayout->setSpacing(16);

    auto *findingsColumn = new QVBoxLayout();
    findingsColumn->setSpacing(12);
    auto *findingsTitle = new QLabel(tr("Oncelikli Bulgular"), this);
    findingsTitle->setObjectName("sectionTitle");
    auto *findingsInfo = new QLabel(tr("Tum aciklar tek listede yuksek riskten dusuge siralanir. Bir bulguya tikladiginda neden var oldugunu, etkisini ve onerilen aksiyonu sag panelde gorursun."), this);
    findingsInfo->setObjectName("mutedText");
    findingsInfo->setWordWrap(true);
    auto *findingsFilterHost = new QWidget(this);
    auto *findingsFilterLayout = new FlowLayout(findingsFilterHost, 0, 10, 10);
    m_findingsSeverityFilter = new QComboBox(this);
    m_findingsSeverityFilter->addItems({tr("Tum seviyeler"), tr("Yuksek"), tr("Orta"), tr("Dusuk"), tr("Bilgi")});
    m_findingsSearchEdit = new QLineEdit(this);
    m_findingsSearchEdit->setPlaceholderText(tr("Bulgu ara"));
    m_addManualFindingButton = new QPushButton(tr("Manuel Bulgu Ekle"), this);
    findingsFilterLayout->addWidget(m_findingsSeverityFilter);
    findingsFilterLayout->addWidget(m_findingsSearchEdit);
    findingsFilterLayout->addWidget(m_addManualFindingButton);
    findingsFilterHost->setLayout(findingsFilterLayout);
    m_findingsList = new QListWidget(this);
    m_findingsList->setMinimumWidth(180);
    m_findingsList->setMinimumHeight(200);
    findingsColumn->addWidget(findingsTitle);
    findingsColumn->addWidget(findingsInfo);
    findingsColumn->addWidget(findingsFilterHost);
    findingsColumn->addWidget(m_findingsList, 1);

    auto *detailColumn = new QVBoxLayout();
    detailColumn->setSpacing(12);
    auto *detailTitle = new QLabel(tr("Bulgu Detayi"), this);
    detailTitle->setObjectName("sectionTitle");
    m_copyDetailButton = new QPushButton(tr("Detayi Kopyala"), this);
    auto *detailHeader = new QHBoxLayout();
    detailHeader->addWidget(detailTitle);
    detailHeader->addStretch();
    detailHeader->addWidget(m_copyDetailButton);
    m_findingDetailView = new QTextEdit(this);
    m_findingDetailView->setReadOnly(true);
    m_findingDetailView->setMinimumHeight(200);
    m_findingDetailView->setHtml(tr("<h3>Bir bulgu sec</h3><p>Listeden bir risk secildiginde burada neden var oldugu, neye yol acabilecegi ve nasil kapatilacagi gorunur.</p>"));
    auto *noteTitle = new QLabel(tr("Bulguya Bagli Analist Notu"), this);
    noteTitle->setObjectName("sectionTitle");
    m_findingNoteEdit = new QTextEdit(this);
    m_findingNoteEdit->setPlaceholderText(tr("Secili bulgu icin manuel not, dogrulama veya aksiyon yaz."));
    m_findingNoteEdit->setMaximumHeight(120);
    m_saveFindingNoteButton = new QPushButton(tr("Bulgu Notunu Kaydet"), this);
    detailColumn->addLayout(detailHeader);
    detailColumn->addWidget(m_findingDetailView, 1);
    detailColumn->addWidget(noteTitle);
    detailColumn->addWidget(m_findingNoteEdit);
    detailColumn->addWidget(m_saveFindingNoteButton, 0, Qt::AlignRight);

    findingsLayout->addLayout(findingsColumn, 3);
    findingsLayout->addLayout(detailColumn, 4);
}
