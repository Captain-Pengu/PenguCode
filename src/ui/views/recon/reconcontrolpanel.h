#pragma once

#include <QFrame>

class QComboBox;
class QLineEdit;
class QPushButton;

class ReconControlPanel : public QFrame
{
    Q_OBJECT

public:
    explicit ReconControlPanel(QWidget *parent = nullptr);

    QLineEdit *targetEdit() const { return m_targetEdit; }
    QLineEdit *endpointEdit() const { return m_endpointEdit; }
    QLineEdit *companyEdit() const { return m_companyEdit; }
    QLineEdit *clientEdit() const { return m_clientEdit; }
    QLineEdit *testerEdit() const { return m_testerEdit; }
    QLineEdit *classificationEdit() const { return m_classificationEdit; }
    QLineEdit *scopeEdit() const { return m_scopeEdit; }
    QComboBox *targetPresetCombo() const { return m_targetPresetCombo; }
    QComboBox *recentTargetCombo() const { return m_recentTargetCombo; }
    QComboBox *scanProfileCombo() const { return m_scanProfileCombo; }
    QPushButton *startButton() const { return m_startButton; }
    QPushButton *stopButton() const { return m_stopButton; }

private:
    QWidget *createInfoLabel(const QString &title, const QString &tooltip) const;

    QLineEdit *m_targetEdit = nullptr;
    QLineEdit *m_endpointEdit = nullptr;
    QLineEdit *m_companyEdit = nullptr;
    QLineEdit *m_clientEdit = nullptr;
    QLineEdit *m_testerEdit = nullptr;
    QLineEdit *m_classificationEdit = nullptr;
    QLineEdit *m_scopeEdit = nullptr;
    QComboBox *m_targetPresetCombo = nullptr;
    QComboBox *m_recentTargetCombo = nullptr;
    QComboBox *m_scanProfileCombo = nullptr;
    QPushButton *m_startButton = nullptr;
    QPushButton *m_stopButton = nullptr;
};
