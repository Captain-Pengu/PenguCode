#pragma once

#include <QFrame>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;

class SpiderSetupPanel : public QFrame
{
    Q_OBJECT

public:
    explicit SpiderSetupPanel(QWidget *parent = nullptr);

    QLineEdit *targetEdit() const { return m_targetEdit; }
    QComboBox *stageCombo() const { return m_stageCombo; }
    QSpinBox *maxPagesSpin() const { return m_maxPagesSpin; }
    QSpinBox *maxDepthSpin() const { return m_maxDepthSpin; }
    QSpinBox *timeoutSpin() const { return m_timeoutSpin; }
    QComboBox *scopePresetCombo() const { return m_scopePresetCombo; }
    QCheckBox *allowSubdomainsCheck() const { return m_allowSubdomainsCheck; }
    QPlainTextEdit *includePatternsEdit() const { return m_includePatternsEdit; }
    QPlainTextEdit *excludePatternsEdit() const { return m_excludePatternsEdit; }
    QLineEdit *loginUrlEdit() const { return m_loginUrlEdit; }
    QLineEdit *authUsernameEdit() const { return m_authUsernameEdit; }
    QLineEdit *authPasswordEdit() const { return m_authPasswordEdit; }
    QLineEdit *usernameFieldEdit() const { return m_usernameFieldEdit; }
    QLineEdit *passwordFieldEdit() const { return m_passwordFieldEdit; }
    QLineEdit *csrfFieldEdit() const { return m_csrfFieldEdit; }
    QComboBox *authWorkflowPresetCombo() const { return m_authWorkflowPresetCombo; }
    QLabel *authWorkflowHintLabel() const { return m_authWorkflowHintLabel; }
    QLabel *workflowValidationLabel() const { return m_workflowValidationLabel; }
    QPushButton *applyWorkflowPresetButton() const { return m_applyWorkflowPresetButton; }
    QPlainTextEdit *authWorkflowEdit() const { return m_authWorkflowEdit; }
    QPushButton *startButton() const { return m_startButton; }
    QPushButton *stopButton() const { return m_stopButton; }
    QLabel *scopePresetInfoLabel() const { return m_scopePresetInfoLabel; }
    QFrame *scopeCard() const { return m_scopeCard; }
    QFrame *authCard() const { return m_authCard; }
    QFrame *advancedCard() const { return m_advancedCard; }

private:
    QWidget *createInfoLabel(const QString &title, const QString &tooltip) const;

    QLineEdit *m_targetEdit = nullptr;
    QComboBox *m_stageCombo = nullptr;
    QSpinBox *m_maxPagesSpin = nullptr;
    QSpinBox *m_maxDepthSpin = nullptr;
    QSpinBox *m_timeoutSpin = nullptr;
    QComboBox *m_scopePresetCombo = nullptr;
    QCheckBox *m_allowSubdomainsCheck = nullptr;
    QPlainTextEdit *m_includePatternsEdit = nullptr;
    QPlainTextEdit *m_excludePatternsEdit = nullptr;
    QLineEdit *m_loginUrlEdit = nullptr;
    QLineEdit *m_authUsernameEdit = nullptr;
    QLineEdit *m_authPasswordEdit = nullptr;
    QLineEdit *m_usernameFieldEdit = nullptr;
    QLineEdit *m_passwordFieldEdit = nullptr;
    QLineEdit *m_csrfFieldEdit = nullptr;
    QComboBox *m_authWorkflowPresetCombo = nullptr;
    QLabel *m_authWorkflowHintLabel = nullptr;
    QLabel *m_workflowValidationLabel = nullptr;
    QPushButton *m_applyWorkflowPresetButton = nullptr;
    QPlainTextEdit *m_authWorkflowEdit = nullptr;
    QPushButton *m_startButton = nullptr;
    QPushButton *m_stopButton = nullptr;
    QLabel *m_scopePresetInfoLabel = nullptr;
    QFrame *m_scopeCard = nullptr;
    QFrame *m_authCard = nullptr;
    QFrame *m_advancedCard = nullptr;
};
