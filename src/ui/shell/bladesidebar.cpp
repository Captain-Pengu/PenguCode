#include "bladesidebar.h"

#include <QHBoxLayout>
#include <QQmlContext>
#include <QQuickWidget>
#include <QUrl>
#include <QtMath>

BladeSidebar::BladeSidebar(QWidget *parent)
    : QWidget(parent)
    , m_backgroundColor("#0a0d12")
    , m_panelColor("#121720")
    , m_accentColor("#8f1732")
    , m_edgeGlowColor("#f3f4f6")
    , m_textMutedColor("#a5acb8")
{
    setFixedWidth(400);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
    setAttribute(Qt::WA_StyledBackground, true);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    m_quickWidget = new QQuickWidget(this);
    m_quickWidget->setResizeMode(QQuickWidget::SizeRootObjectToView);
    m_quickWidget->setClearColor(Qt::transparent);
    m_quickWidget->setAttribute(Qt::WA_AlwaysStackOnTop, false);
    layout->addWidget(m_quickWidget, 1);

    setupQuickScene();
    refreshVisibleOrbs(false);
}

void BladeSidebar::clearModules()
{
    m_entries.clear();
    m_allOrbs.clear();
    m_visibleOrbs.clear();
    m_previousVisibleOrbs.clear();
    m_activeIndex = -1;
    m_orbWindowStart = 0;
    m_transitionDirection = 0;
    emit activeIndexChanged();
    emit allOrbsChanged();
    emit visibleOrbsChanged();
    emit previousVisibleOrbsChanged();
    emit orbWindowChanged();
    emit transitionChanged();
}

void BladeSidebar::addModule(const QString &name, const QString &description, int index)
{
    OrbEntry entry;
    entry.name = name;
    entry.description = description;
    entry.glyph = glyphForName(name);
    entry.index = index;
    entry.utility = false;
    m_entries.append(entry);
    refreshVisibleOrbs(false);
}

void BladeSidebar::addUtilityOrb(const QString &name, const QString &description, int index)
{
    OrbEntry entry;
    entry.name = name;
    entry.description = description;
    entry.glyph = glyphForName(name);
    entry.index = index;
    entry.utility = true;
    m_entries.append(entry);
    refreshVisibleOrbs(false);
}

void BladeSidebar::setActiveIndex(int index)
{
    if (m_activeIndex == index) {
        return;
    }

    m_activeIndex = index;
    if (!m_entries.isEmpty()) {
        const int count = m_entries.size();
        int row = -1;
        for (int i = 0; i < count; ++i) {
            if (m_entries[i].index == index) {
                row = i;
                break;
            }
        }
        if (row >= 0) {
            const int relative = (row - m_orbWindowStart + count) % count;
            if (relative >= kVisibleOrbCount) {
                m_orbWindowStart = (row / kVisibleOrbCount) * kVisibleOrbCount;
            }
        }
    }

    emit activeIndexChanged();
    refreshVisibleOrbs(false);
}

void BladeSidebar::setColors(const QColor &background,
                             const QColor &panel,
                             const QColor &accent,
                             const QColor &edgeGlow,
                             const QColor &textMuted)
{
    m_backgroundColor = background;
    m_panelColor = panel;
    m_accentColor = accent;
    m_edgeGlowColor = edgeGlow;
    m_textMutedColor = textMuted;
    emit colorsChanged();
}

QVariantList BladeSidebar::visibleOrbs() const
{
    return m_visibleOrbs;
}

QVariantList BladeSidebar::previousVisibleOrbs() const
{
    return m_previousVisibleOrbs;
}

QVariantList BladeSidebar::allOrbs() const
{
    return m_allOrbs;
}

bool BladeSidebar::canPageUp() const
{
    return m_entries.size() > kVisibleOrbCount;
}

bool BladeSidebar::canPageDown() const
{
    return m_entries.size() > kVisibleOrbCount;
}

int BladeSidebar::activeIndex() const
{
    return m_activeIndex;
}

QColor BladeSidebar::backgroundColor() const
{
    return m_backgroundColor;
}

QColor BladeSidebar::panelColor() const
{
    return m_panelColor;
}

QColor BladeSidebar::accentColor() const
{
    return m_accentColor;
}

QColor BladeSidebar::edgeGlowColor() const
{
    return m_edgeGlowColor;
}

QColor BladeSidebar::textMutedColor() const
{
    return m_textMutedColor;
}

int BladeSidebar::transitionDirection() const
{
    return m_transitionDirection;
}

int BladeSidebar::transitionSerial() const
{
    return m_transitionSerial;
}

void BladeSidebar::selectOrb(int index)
{
    emit moduleSelected(index);
}

void BladeSidebar::pageUp()
{
    stepOrbWindow(-1);
}

void BladeSidebar::pageDown()
{
    stepOrbWindow(1);
}

QString BladeSidebar::glyphForName(const QString &name) const
{
    if (name.contains("Proxy", Qt::CaseInsensitive)) return "P";
    if (name.contains("Port", Qt::CaseInsensitive)) return "S";
    if (name.contains("Recon", Qt::CaseInsensitive)) return "R";
    if (name.contains("Spider", Qt::CaseInsensitive)) return "W";
    if (name.contains("Waterfall", Qt::CaseInsensitive)) return "T";
    if (name.contains("PenguCore", Qt::CaseInsensitive)) return "P";
    if (name.contains("PCAP", Qt::CaseInsensitive)) return "P";
    if (name.contains("Ayar", Qt::CaseInsensitive) || name.contains("Gunluk", Qt::CaseInsensitive)) return "G";
    if (name.contains("Crawler", Qt::CaseInsensitive)) return "C";
    if (name.contains("Fuzzer", Qt::CaseInsensitive)) return "F";
    if (name.contains("SQL", Qt::CaseInsensitive)) return "Q";
    return "O";
}

void BladeSidebar::refreshVisibleOrbs(bool animated, int direction)
{
    if (m_entries.isEmpty()) {
        m_allOrbs.clear();
        m_visibleOrbs.clear();
        m_previousVisibleOrbs.clear();
        emit allOrbsChanged();
        emit visibleOrbsChanged();
        emit previousVisibleOrbsChanged();
        emit orbWindowChanged();
        return;
    }

    const int count = m_entries.size();
    m_orbWindowStart = ((m_orbWindowStart % count) + count) % count;

    if (animated) {
        m_previousVisibleOrbs = m_visibleOrbs;
    } else {
        m_previousVisibleOrbs.clear();
    }

    QVariantList newAll;
    QVariantList newVisible;
    for (int i = 0; i < count; ++i) {
        const auto &entry = m_entries[i];
        const int relative = (i - m_orbWindowStart + count) % count;
        const bool front = relative < kVisibleOrbCount;
        const int slot = front ? relative : -1;
        qreal angle = 0.0;

        if (count <= kVisibleOrbCount) {
            static const qreal frontAngles[3] = { -34.0, 0.0, 34.0 };
            angle = frontAngles[qBound(0, relative, 2)];
        } else if (front) {
            static const qreal frontAngles[3] = { -34.0, 0.0, 34.0 };
            angle = frontAngles[slot];
        } else {
            const int backCount = count - kVisibleOrbCount;
            const int backIndex = relative - kVisibleOrbCount;
            const qreal t = backCount > 0
                ? static_cast<qreal>(backIndex) / static_cast<qreal>(backCount)
                : 0.0;
            angle = 70.0 + (t * 240.0);
        }

        QVariantMap item;
        item.insert(QStringLiteral("slot"), slot);
        item.insert(QStringLiteral("index"), entry.index);
        item.insert(QStringLiteral("name"), entry.name);
        item.insert(QStringLiteral("description"), entry.description);
        item.insert(QStringLiteral("glyph"), entry.glyph);
        item.insert(QStringLiteral("utility"), entry.utility);
        item.insert(QStringLiteral("active"), entry.index == m_activeIndex);
        item.insert(QStringLiteral("front"), front);
        item.insert(QStringLiteral("relative"), relative);
        item.insert(QStringLiteral("angle"), angle);
        newAll.append(item);

        if (front) {
            newVisible.append(item);
        }
    }

    m_allOrbs = newAll;
    m_visibleOrbs = newVisible;
    if (animated) {
        m_transitionDirection = direction;
        ++m_transitionSerial;
        emit transitionChanged();
    } else if (m_transitionDirection != 0) {
        m_transitionDirection = 0;
        emit transitionChanged();
    }

    emit allOrbsChanged();
    emit visibleOrbsChanged();
    emit previousVisibleOrbsChanged();
    emit orbWindowChanged();
}

void BladeSidebar::stepOrbWindow(int direction)
{
    if (m_entries.size() <= kVisibleOrbCount) {
        return;
    }

    const int count = m_entries.size();
    const int newStart = (m_orbWindowStart + (direction * kVisibleOrbCount) + count) % count;
    if (newStart == m_orbWindowStart) {
        return;
    }

    m_orbWindowStart = newStart;
    refreshVisibleOrbs(true, direction);
}

void BladeSidebar::setupQuickScene()
{
    m_quickWidget->rootContext()->setContextProperty(QStringLiteral("bladeSidebarBridge"), this);
    m_quickWidget->setSource(QUrl(QStringLiteral("qrc:/src/ui/shell/qml/OrbitalSidebar3D.qml")));
}
