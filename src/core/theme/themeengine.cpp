#include "themeengine.h"

#include "core/settings/settingsmanager.h"

ThemeEngine::ThemeEngine(QObject *parent)
    : QObject(parent)
    , m_currentTheme("dark")
    , m_darkPalette(defaultPalette("dark"))
    , m_lightPalette(defaultPalette("light"))
{
}

QString ThemeEngine::currentTheme() const
{
    return m_currentTheme;
}

QVariantMap ThemeEngine::palette() const
{
    return m_currentTheme == "light" ? m_lightPalette : m_darkPalette;
}

void ThemeEngine::toggleTheme()
{
    setCurrentTheme(m_currentTheme == "dark" ? "light" : "dark");
}

void ThemeEngine::setCurrentTheme(const QString &theme)
{
    if (theme == m_currentTheme) {
        return;
    }

    m_currentTheme = theme;
    persistThemeState();
    emit currentThemeChanged();
}

void ThemeEngine::loadSettings(SettingsManager *settings)
{
    if (!settings) {
        return;
    }

    m_settings = settings;

    const QStringList keys = {"window", "panel", "panelAlt", "border", "text", "mutedText", "accent", "accentSoft", "success", "warning", "danger"};
    for (const QString &key : keys) {
        m_darkPalette.insert(key, settings->typedValue("theme/dark", key, "string", m_darkPalette.value(key)).toString());
        m_lightPalette.insert(key, settings->typedValue("theme/light", key, "string", m_lightPalette.value(key)).toString());
    }

    const QString savedTheme = settings->typedValue("theme", "currentTheme", "string", m_currentTheme).toString();
    if (!savedTheme.isEmpty()) {
        m_currentTheme = savedTheme;
    }
}

void ThemeEngine::setPaletteValue(const QString &theme, const QString &key, const QString &value)
{
    if (theme == "light") {
        m_lightPalette.insert(key, value);
    } else {
        m_darkPalette.insert(key, value);
    }

    persistThemeState();

    if (theme == m_currentTheme) {
        emit currentThemeChanged();
    }
}

void ThemeEngine::persistThemeState()
{
    if (!m_settings) {
        return;
    }

    m_settings->setTypedValue(QStringLiteral("theme"), QStringLiteral("currentTheme"), QStringLiteral("string"), m_currentTheme);
    const QVariantMap darkPalette = m_darkPalette;
    const QVariantMap lightPalette = m_lightPalette;
    for (auto it = darkPalette.cbegin(); it != darkPalette.cend(); ++it) {
        m_settings->setTypedValue(QStringLiteral("theme/dark"), it.key(), QStringLiteral("string"), it.value());
    }
    for (auto it = lightPalette.cbegin(); it != lightPalette.cend(); ++it) {
        m_settings->setTypedValue(QStringLiteral("theme/light"), it.key(), QStringLiteral("string"), it.value());
    }
    m_settings->sync();
}

QVariantMap ThemeEngine::defaultPalette(const QString &theme) const
{
    if (theme == "light") {
        return {
            {"window", "#eceef1"},
            {"panel", "#ffffff"},
            {"panelAlt", "#f3f4f6"},
            {"border", "#ced4dd"},
            {"text", "#161a20"},
            {"mutedText", "#596273"},
            {"accent", "#a61b3f"},
            {"accentSoft", "#f4d9e1"},
            {"success", "#15803d"},
            {"warning", "#b45309"},
            {"danger", "#dc2626"}
        };
    }

    return {
        {"window", "#0a0d12"},
        {"panel", "#121720"},
        {"panelAlt", "#1a2230"},
        {"border", "#2f3846"},
        {"text", "#ece7e2"},
        {"mutedText", "#a5acb8"},
        {"accent", "#8f1732"},
        {"accentSoft", "#261018"},
        {"success", "#22c55e"},
        {"warning", "#f59e0b"},
        {"danger", "#ef4444"}
    };
}
