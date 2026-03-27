#include "ui/widgets/reportpreviewdialog.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

ReportPreviewDialog::ReportPreviewDialog(const QString &titleText,
                                         const QString &infoText,
                                         const QString &pdfButtonText,
                                         const QString &htmlButtonText,
                                         QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(titleText);
    resize(980, 780);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    auto *title = new QLabel(titleText, this);
    title->setObjectName("sectionTitle");
    auto *info = new QLabel(infoText, this);
    info->setObjectName("mutedText");
    info->setWordWrap(true);
    layout->addWidget(title);
    layout->addWidget(info);

    m_view = new QTextEdit(this);
    m_view->setReadOnly(true);
    m_view->setStyleSheet("QTextEdit { background: #ffffff; color: #171a20; border: 1px solid #c7cdd8; border-radius: 10px; padding: 20px; }");
    layout->addWidget(m_view, 1);

    auto *buttons = new QHBoxLayout();
    m_savePdfButton = new QPushButton(pdfButtonText, this);
    m_saveHtmlButton = new QPushButton(htmlButtonText, this);
    auto *closeButton = new QPushButton(tr("Kapat"), this);
    buttons->addStretch();
    buttons->addWidget(m_savePdfButton);
    buttons->addWidget(m_saveHtmlButton);
    buttons->addWidget(closeButton);
    layout->addLayout(buttons);

    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

QTextEdit *ReportPreviewDialog::view() const
{
    return m_view;
}

QPushButton *ReportPreviewDialog::savePdfButton() const
{
    return m_savePdfButton;
}

QPushButton *ReportPreviewDialog::saveHtmlButton() const
{
    return m_saveHtmlButton;
}
