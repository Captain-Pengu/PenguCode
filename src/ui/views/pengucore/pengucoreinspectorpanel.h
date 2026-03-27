#pragma once

#include <QFrame>

class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QWidget;

class PenguCoreInspectorPanel : public QFrame
{
    Q_OBJECT

public:
    explicit PenguCoreInspectorPanel(QWidget *parent = nullptr);

    QWidget *selectionCard() const { return m_selectionCard; }
    QWidget *detailCard() const { return m_detailCard; }
    QLineEdit *detailSearchEdit() const { return m_detailSearchEdit; }
    QPushButton *findDetailButton() const { return m_findDetailButton; }
    QPushButton *findHexButton() const { return m_findHexButton; }
    QPushButton *findFlowStreamButton() const { return m_findFlowStreamButton; }
    QPushButton *findFlowStreamPrevButton() const { return m_findFlowStreamPrevButton; }
    QPushButton *findFlowStreamNextButton() const { return m_findFlowStreamNextButton; }
    QPlainTextEdit *detailView() const { return m_detailView; }
    QPlainTextEdit *hexView() const { return m_hexView; }

private:
    QFrame *m_selectionCard = nullptr;
    QFrame *m_detailCard = nullptr;
    QLineEdit *m_detailSearchEdit = nullptr;
    QPushButton *m_findDetailButton = nullptr;
    QPushButton *m_findHexButton = nullptr;
    QPushButton *m_findFlowStreamButton = nullptr;
    QPushButton *m_findFlowStreamPrevButton = nullptr;
    QPushButton *m_findFlowStreamNextButton = nullptr;
    QPlainTextEdit *m_detailView = nullptr;
    QPlainTextEdit *m_hexView = nullptr;
};
