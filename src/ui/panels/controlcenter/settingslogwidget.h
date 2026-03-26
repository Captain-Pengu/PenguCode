#pragma once

#include <QWidget>

class AppController;
class LogModel;
class QCheckBox;
class QComboBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QLineEdit;

class SettingsLogWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SettingsLogWidget(AppController *controller, LogModel *logModel, QWidget *parent = nullptr);
    void reloadThemeInfo();
    void appendLogLine(const QString &line);
    void appendExistingLogs();

signals:
    void openSettingsRequested();
    void settingsApplied();

private:
    void buildUi();
    void loadFromSettings();
    void applyPreset();
    void applyAllSettings();
    QVariantMap presetPalette(const QString &theme, const QString &presetId) const;

    AppController *m_controller = nullptr;
    LogModel *m_logModel = nullptr;
    QLabel *m_themeModeValue = nullptr;
    QLabel *m_presetHintValue = nullptr;
    QLabel *m_logCountValue = nullptr;
    QPlainTextEdit *m_logConsole = nullptr;
    QPushButton *m_openSettingsButton = nullptr;
    QComboBox *m_themeModeCombo = nullptr;
    QComboBox *m_themePresetCombo = nullptr;
    QPushButton *m_applySettingsButton = nullptr;
    QLineEdit *m_portTargetEdit = nullptr;
    QLineEdit *m_portPortsEdit = nullptr;
    QComboBox *m_portScanTypeCombo = nullptr;
    QSpinBox *m_portThreadSpin = nullptr;
    QSpinBox *m_portTimeoutSpin = nullptr;
    QSpinBox *m_portRetrySpin = nullptr;
    QCheckBox *m_portServiceCheck = nullptr;
    QCheckBox *m_portOsCheck = nullptr;
    QLineEdit *m_proxyHostEdit = nullptr;
    QSpinBox *m_proxyPortSpin = nullptr;
    QLineEdit *m_proxyTargetHostEdit = nullptr;
    QSpinBox *m_proxyTargetPortSpin = nullptr;
    QSpinBox *m_proxyIdleTimeoutSpin = nullptr;
    QSpinBox *m_proxyWorkerSpin = nullptr;
    QCheckBox *m_proxyTlsCheck = nullptr;
    QLineEdit *m_reconTargetEdit = nullptr;
    QLineEdit *m_reconEndpointEdit = nullptr;
    QLineEdit *m_spiderTargetEdit = nullptr;
    QSpinBox *m_spiderMaxPagesSpin = nullptr;
    QSpinBox *m_spiderMaxDepthSpin = nullptr;
    QSpinBox *m_spiderTimeoutSpin = nullptr;
    QComboBox *m_spiderStageCombo = nullptr;
    QComboBox *m_spiderScopeCombo = nullptr;
    QCheckBox *m_spiderSubdomainsCheck = nullptr;
    QLineEdit *m_spiderLoginUrlEdit = nullptr;
    QLineEdit *m_spiderUserEdit = nullptr;
    QLineEdit *m_spiderPassEdit = nullptr;
    QLineEdit *m_spiderUserFieldEdit = nullptr;
    QLineEdit *m_spiderPassFieldEdit = nullptr;
    QLineEdit *m_spiderCsrfFieldEdit = nullptr;
    QPlainTextEdit *m_spiderIncludeEdit = nullptr;
    QPlainTextEdit *m_spiderExcludeEdit = nullptr;
    QPlainTextEdit *m_spiderWorkflowEdit = nullptr;
};
