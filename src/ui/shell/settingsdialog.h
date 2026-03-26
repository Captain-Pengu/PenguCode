#pragma once

#include <QDialog>
#include <QMap>

class AppController;
class ThemeEngine;
class QComboBox;
class QLineEdit;
class QPushButton;

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(AppController *controller, QWidget *parent = nullptr);

signals:
    void settingsApplied();

private slots:
    void chooseColor();
    void applyPreset();
    void applySettings();
    void refreshInputs();

private:
    QWidget *createInfoLabel(const QString &title, const QString &tooltip) const;
    QWidget *createColorPreview(const QString &key);
    QString currentThemeKey() const;
    QVariantMap presetPalette(const QString &theme, const QString &presetId) const;
    void refreshPresetOptions();

    AppController *m_controller = nullptr;
    ThemeEngine *m_themeEngine = nullptr;
    QComboBox *m_themeModeCombo = nullptr;
    QComboBox *m_presetCombo = nullptr;
    QPushButton *m_applyPresetButton = nullptr;
    QMap<QString, QLineEdit *> m_colorInputs;
    QMap<QString, QWidget *> m_colorPreviews;
};
