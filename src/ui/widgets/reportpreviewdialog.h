#pragma once

#include <QDialog>

class QPushButton;
class QTextEdit;

class ReportPreviewDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ReportPreviewDialog(const QString &titleText,
                                 const QString &infoText,
                                 const QString &pdfButtonText,
                                 const QString &htmlButtonText,
                                 QWidget *parent = nullptr);

    QTextEdit *view() const;
    QPushButton *savePdfButton() const;
    QPushButton *saveHtmlButton() const;

private:
    QTextEdit *m_view = nullptr;
    QPushButton *m_savePdfButton = nullptr;
    QPushButton *m_saveHtmlButton = nullptr;
};
