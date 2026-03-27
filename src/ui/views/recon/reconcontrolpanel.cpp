#include "reconcontrolpanel.h"

#include "ui/layout/flowlayout.h"

#include <QComboBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

QWidget *ReconControlPanel::createInfoLabel(const QString &title, const QString &tooltip) const
{
    auto *host = new QWidget();
    auto *row = new QHBoxLayout(host);
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(6);
    auto *label = new QLabel(title, host);
    label->setObjectName("mutedText");
    auto *hint = new QLabel(QStringLiteral("i"), host);
    hint->setObjectName("mutedText");
    hint->setToolTip(tooltip);
    row->addWidget(label);
    row->addWidget(hint);
    row->addStretch();
    return host;
}

ReconControlPanel::ReconControlPanel(QWidget *parent)
    : QFrame(parent)
{
    setObjectName("cardPanel");
    auto *setupOuterLayout = new QHBoxLayout(this);
    setupOuterLayout->setContentsMargins(20, 20, 20, 20);
    setupOuterLayout->setSpacing(0);
    auto *setupFormHost = new QWidget(this);
    setupFormHost->setMinimumWidth(0);
    setupFormHost->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    auto *setupLayout = new QGridLayout(setupFormHost);
    setupLayout->setContentsMargins(0, 0, 0, 0);
    setupLayout->setHorizontalSpacing(12);
    setupLayout->setVerticalSpacing(10);
    setupLayout->setColumnMinimumWidth(0, 72);
    setupLayout->setColumnMinimumWidth(1, 120);
    setupLayout->setColumnMinimumWidth(2, 72);
    setupLayout->setColumnMinimumWidth(3, 120);
    setupLayout->setColumnStretch(0, 1);
    setupLayout->setColumnStretch(1, 3);
    setupLayout->setColumnStretch(2, 1);
    setupLayout->setColumnStretch(3, 3);

    m_targetEdit = new QLineEdit(this);
    m_endpointEdit = new QLineEdit(this);
    m_targetPresetCombo = new QComboBox(this);
    m_recentTargetCombo = new QComboBox(this);
    m_scanProfileCombo = new QComboBox(this);
    m_companyEdit = new QLineEdit(this);
    m_clientEdit = new QLineEdit(this);
    m_testerEdit = new QLineEdit(this);
    m_classificationEdit = new QLineEdit(this);
    m_scopeEdit = new QLineEdit(this);
    m_endpointEdit->setPlaceholderText("https://ornek-osint-ucnokta/api/search");
    const QList<QLineEdit *> edits = {m_targetEdit, m_endpointEdit, m_companyEdit, m_clientEdit, m_testerEdit, m_classificationEdit, m_scopeEdit};
    for (QLineEdit *edit : edits) {
        edit->setMinimumWidth(132);
        edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }
    m_targetPresetCombo->addItem(tr("Hazir hedefler"));
    m_targetPresetCombo->addItem(QStringLiteral("scanme.nmap.org"));
    m_targetPresetCombo->addItem(QStringLiteral("example.com"));
    m_targetPresetCombo->addItem(QStringLiteral("testphp.vulnweb.com"));
    m_targetPresetCombo->addItem(QStringLiteral("demo.testfire.net"));
    m_targetPresetCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_recentTargetCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_scanProfileCombo->addItems({tr("Tam Kesif"), tr("Alan Adi Istihbarati"), tr("Web Yuzeyi"), tr("Hizli Bakis")});
    m_scanProfileCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    setupLayout->addWidget(createInfoLabel(tr("Hedef"), tr("Alan adi, IP veya tam URL girebilirsin. Sistem uygun formata cevirip tek tusla tarar.")), 0, 0);
    setupLayout->addWidget(m_targetEdit, 0, 1);
    setupLayout->addWidget(createInfoLabel(tr("OSINT API"), tr("Istege bagli tehdit istihbarati veya sizinti servisi ucnoktasi. Bos birakirsan sadece yerel kontroller calisir.")), 0, 2);
    setupLayout->addWidget(m_endpointEdit, 0, 3);
    setupLayout->addWidget(createInfoLabel(tr("Hazirlayan Kurum"), tr("PDF kapak ve yonetici ozeti icin kullanilir.")), 1, 0);
    setupLayout->addWidget(m_companyEdit, 1, 1);
    setupLayout->addWidget(createInfoLabel(tr("Musteri"), tr("Raporun teslim edilecegi kurum veya birim adi.")), 1, 2);
    setupLayout->addWidget(m_clientEdit, 1, 3);
    setupLayout->addWidget(createInfoLabel(tr("Test Uzmani"), tr("Raporu hazirlayan uzman veya ekip.")), 2, 0);
    setupLayout->addWidget(m_testerEdit, 2, 1);
    setupLayout->addWidget(createInfoLabel(tr("Siniflandirma"), tr("Ornek: Kurum Ici, Gizli, Kisitli Dagitim.")), 2, 2);
    setupLayout->addWidget(m_classificationEdit, 2, 3);
    setupLayout->addWidget(createInfoLabel(tr("Kapsam Ozeti"), tr("PDF raporunda metodoloji ve kapsam basligi altinda gosterilir.")), 3, 0);
    setupLayout->addWidget(m_scopeEdit, 3, 1, 1, 3);
    setupLayout->addWidget(createInfoLabel(tr("Hazir Hedef"), tr("Demo veya test ortamlari icin hizli hedef secimi.")), 4, 0);
    setupLayout->addWidget(m_targetPresetCombo, 4, 1);
    setupLayout->addWidget(createInfoLabel(tr("Tarama Profili"), tr("Hazir profil secimi kapsam ozetini hizla doldurur.")), 4, 2);
    setupLayout->addWidget(m_scanProfileCombo, 4, 3);
    setupLayout->addWidget(createInfoLabel(tr("Son Hedefler"), tr("En son kullandigin hedefleri tek tikla geri cagirir.")), 5, 0);
    setupLayout->addWidget(m_recentTargetCombo, 5, 1, 1, 3);

    auto *buttonsHost = new QWidget(this);
    auto *buttons = new FlowLayout(buttonsHost, 0, 10, 10);
    m_startButton = new QPushButton(tr("Kesifi Baslat"), this);
    m_startButton->setObjectName("accentButton");
    m_stopButton = new QPushButton(tr("Durdur"), this);
    buttons->addWidget(m_startButton);
    buttons->addWidget(m_stopButton);
    buttonsHost->setLayout(buttons);
    setupLayout->addWidget(buttonsHost, 6, 0, 1, 4);

    setupOuterLayout->addStretch();
    setupOuterLayout->addWidget(setupFormHost);
    setupOuterLayout->addStretch();
}
