#pragma once

#include <QFrame>

class QComboBox;
class QLineEdit;
class QPushButton;

class PenguCoreFilterPanel : public QFrame
{
    Q_OBJECT

public:
    explicit PenguCoreFilterPanel(QWidget *parent = nullptr);

    QFrame *filterCard() const { return m_filterCard; }
    QFrame *quickActionCard() const { return m_quickActionCard; }
    QLineEdit *searchEdit() const { return m_searchEdit; }
    QLineEdit *sourceFilterEdit() const { return m_sourceFilterEdit; }
    QLineEdit *destinationFilterEdit() const { return m_destinationFilterEdit; }
    QComboBox *protocolFilter() const { return m_protocolFilter; }
    QComboBox *filterPresetCombo() const { return m_filterPresetCombo; }
    QPushButton *toggleInspectorButton() const { return m_toggleInspectorButton; }
    QPushButton *toggleHexButton() const { return m_toggleHexButton; }
    QPushButton *toggleFlowDetailButton() const { return m_toggleFlowDetailButton; }
    QPushButton *pauseLiveUiButton() const { return m_pauseLiveUiButton; }
    QPushButton *autoScrollButton() const { return m_autoScrollButton; }
    QPushButton *onlyWarningsButton() const { return m_onlyWarningsButton; }
    QPushButton *dnsFocusButton() const { return m_dnsFocusButton; }
    QPushButton *httpFocusButton() const { return m_httpFocusButton; }

private:
    QFrame *m_filterCard = nullptr;
    QFrame *m_quickActionCard = nullptr;
    QLineEdit *m_searchEdit = nullptr;
    QLineEdit *m_sourceFilterEdit = nullptr;
    QLineEdit *m_destinationFilterEdit = nullptr;
    QComboBox *m_protocolFilter = nullptr;
    QComboBox *m_filterPresetCombo = nullptr;
    QPushButton *m_toggleInspectorButton = nullptr;
    QPushButton *m_toggleHexButton = nullptr;
    QPushButton *m_toggleFlowDetailButton = nullptr;
    QPushButton *m_pauseLiveUiButton = nullptr;
    QPushButton *m_autoScrollButton = nullptr;
    QPushButton *m_onlyWarningsButton = nullptr;
    QPushButton *m_dnsFocusButton = nullptr;
    QPushButton *m_httpFocusButton = nullptr;
};
