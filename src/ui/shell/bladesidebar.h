#pragma once

#include <QColor>
#include <QVariantList>
#include <QWidget>

class QQuickWidget;

class BladeSidebar : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(QVariantList allOrbs READ allOrbs NOTIFY allOrbsChanged)
    Q_PROPERTY(QVariantList visibleOrbs READ visibleOrbs NOTIFY visibleOrbsChanged)
    Q_PROPERTY(QVariantList previousVisibleOrbs READ previousVisibleOrbs NOTIFY previousVisibleOrbsChanged)
    Q_PROPERTY(bool canPageUp READ canPageUp NOTIFY orbWindowChanged)
    Q_PROPERTY(bool canPageDown READ canPageDown NOTIFY orbWindowChanged)
    Q_PROPERTY(int activeIndex READ activeIndex NOTIFY activeIndexChanged)
    Q_PROPERTY(QColor backgroundColor READ backgroundColor NOTIFY colorsChanged)
    Q_PROPERTY(QColor panelColor READ panelColor NOTIFY colorsChanged)
    Q_PROPERTY(QColor accentColor READ accentColor NOTIFY colorsChanged)
    Q_PROPERTY(QColor edgeGlowColor READ edgeGlowColor NOTIFY colorsChanged)
    Q_PROPERTY(QColor textMutedColor READ textMutedColor NOTIFY colorsChanged)
    Q_PROPERTY(int transitionDirection READ transitionDirection NOTIFY transitionChanged)
    Q_PROPERTY(int transitionSerial READ transitionSerial NOTIFY transitionChanged)

public:
    explicit BladeSidebar(QWidget *parent = nullptr);

    void clearModules();
    void addModule(const QString &name, const QString &description, int index);
    void addUtilityOrb(const QString &name, const QString &description, int index);
    void setActiveIndex(int index);
    void setColors(const QColor &background,
                   const QColor &panel,
                   const QColor &accent,
                   const QColor &edgeGlow,
                   const QColor &textMuted);

    QVariantList visibleOrbs() const;
    QVariantList previousVisibleOrbs() const;
    QVariantList allOrbs() const;
    bool canPageUp() const;
    bool canPageDown() const;
    int activeIndex() const;
    QColor backgroundColor() const;
    QColor panelColor() const;
    QColor accentColor() const;
    QColor edgeGlowColor() const;
    QColor textMutedColor() const;
    int transitionDirection() const;
    int transitionSerial() const;

    Q_INVOKABLE void selectOrb(int index);
    Q_INVOKABLE void pageUp();
    Q_INVOKABLE void pageDown();

signals:
    void moduleSelected(int index);
    void allOrbsChanged();
    void visibleOrbsChanged();
    void previousVisibleOrbsChanged();
    void orbWindowChanged();
    void activeIndexChanged();
    void colorsChanged();
    void transitionChanged();

private:
    static constexpr int kVisibleOrbCount = 3;

    struct OrbEntry {
        QString name;
        QString description;
        QString glyph;
        int index = -1;
        bool utility = false;
    };

    QString glyphForName(const QString &name) const;
    void refreshVisibleOrbs(bool animated, int direction = 0);
    void stepOrbWindow(int direction);
    void setupQuickScene();

    QQuickWidget *m_quickWidget = nullptr;
    QList<OrbEntry> m_entries;
    QVariantList m_allOrbs;
    QVariantList m_visibleOrbs;
    QVariantList m_previousVisibleOrbs;
    QColor m_backgroundColor;
    QColor m_panelColor;
    QColor m_accentColor;
    QColor m_edgeGlowColor;
    QColor m_textMutedColor;
    int m_activeIndex = -1;
    int m_orbWindowStart = 0;
    int m_transitionDirection = 0;
    int m_transitionSerial = 0;
};
