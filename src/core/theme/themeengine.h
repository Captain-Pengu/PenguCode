#pragma once

#include <QObject>
#include <QVariantMap>

class SettingsManager;

class ThemeEngine : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString currentTheme READ currentTheme WRITE setCurrentTheme NOTIFY currentThemeChanged)
    Q_PROPERTY(QVariantMap palette READ palette NOTIFY currentThemeChanged)

public:
    explicit ThemeEngine(QObject *parent = nullptr);

    QString currentTheme() const;
    QVariantMap palette() const;

    Q_INVOKABLE void toggleTheme();
    void loadSettings(SettingsManager *settings);
    void setPaletteValue(const QString &theme, const QString &key, const QString &value);

public slots:
    void setCurrentTheme(const QString &theme);

signals:
    void currentThemeChanged();

private:
    QVariantMap defaultPalette(const QString &theme) const;
    void persistThemeState();

    QString m_currentTheme;
    QVariantMap m_darkPalette;
    QVariantMap m_lightPalette;
    SettingsManager *m_settings = nullptr;
};
