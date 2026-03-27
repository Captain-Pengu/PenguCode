#include "proxywidget.h"

#include "modules/proxy/proxymodule.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"
#include "ui/views/proxy/proxybottompanel.h"
#include "ui/views/proxy/proxyruntimepanel.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QRadialGradient>
#include <QImage>
#include <QPushButton>
#include <QEasingCurve>
#include <QResizeEvent>
#include <QStringBuilder>
#include <QSpinBox>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>

StatusLed::StatusLed(const QColor &baseColor, QWidget *parent)
    : QWidget(parent)
    , m_baseColor(baseColor)
    , m_timer(new QTimer(this))
{
    setFixedSize(18, 18);
    m_timer->setInterval(420);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        if (!m_blinking) {
            return;
        }
        m_phase = !m_phase;
        setIntensity(m_phase ? 1.0 : 0.35);
    });
}

qreal StatusLed::intensity() const
{
    return m_intensity;
}

void StatusLed::setIntensity(qreal value)
{
    m_intensity = value;
    update();
}

void StatusLed::setBlinking(bool value)
{
    m_blinking = value;
    if (value) {
        m_timer->start();
        setIntensity(1.0);
    } else {
        m_timer->stop();
        setIntensity(0.3);
    }
}

void StatusLed::setAnimationEnabled(bool value)
{
    if (value && m_blinking) {
        m_timer->start();
        setIntensity(1.0);
        return;
    }

    m_timer->stop();
    setIntensity(m_blinking ? 0.75 : 0.3);
}

void StatusLed::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    const QPointF c = rect().center();

    QColor glow = m_baseColor;
    glow.setAlphaF(0.18 + (m_intensity * 0.45));
    painter.setBrush(glow);
    painter.setPen(Qt::NoPen);
    painter.drawEllipse(c, 8.0, 8.0);

    QRadialGradient g(c, 6.0);
    g.setColorAt(0.0, QColor("#ffffff"));
    g.setColorAt(0.35, m_baseColor.lighter(180));
    g.setColorAt(1.0, m_baseColor.darker(180));
    painter.setBrush(g);
    painter.drawEllipse(c, 4.6, 4.6);
}

TacticalActionButton::TacticalActionButton(const QString &text, QWidget *parent)
    : QPushButton(text, parent)
    , m_neonColor(text.contains("Start") ? QColor("#22c55e") : QColor("#ef4444"))
    , m_animation(new QPropertyAnimation(this, "pressOffset", this))
    , m_glowAnimation(new QPropertyAnimation(this, "glowStrength", this))
{
    setCursor(Qt::PointingHandCursor);
    setMinimumHeight(46);
    m_animation->setEasingCurve(QEasingCurve::OutCubic);
    m_glowAnimation->setEasingCurve(QEasingCurve::OutCubic);
}

qreal TacticalActionButton::pressOffset() const
{
    return m_pressOffset;
}

void TacticalActionButton::setPressOffset(qreal value)
{
    m_pressOffset = value;
    update();
}

qreal TacticalActionButton::glowStrength() const
{
    return m_glowStrength;
}

void TacticalActionButton::setGlowStrength(qreal value)
{
    m_glowStrength = value;
    update();
}

void TacticalActionButton::enterEvent(QEnterEvent *event)
{
    m_hovered = true;
    m_glowAnimation->stop();
    m_glowAnimation->setDuration(140);
    m_glowAnimation->setStartValue(m_glowStrength);
    m_glowAnimation->setEndValue(1.0);
    m_glowAnimation->start();
    QPushButton::enterEvent(event);
}

void TacticalActionButton::leaveEvent(QEvent *event)
{
    m_hovered = false;
    animateTo(0.0, 120);
    m_glowAnimation->stop();
    m_glowAnimation->setDuration(160);
    m_glowAnimation->setStartValue(m_glowStrength);
    m_glowAnimation->setEndValue(0.0);
    m_glowAnimation->start();
    QPushButton::leaveEvent(event);
}

void TacticalActionButton::mousePressEvent(QMouseEvent *event)
{
    animateTo(3.0, 90);
    m_glowAnimation->stop();
    m_glowAnimation->setDuration(90);
    m_glowAnimation->setStartValue(m_glowStrength);
    m_glowAnimation->setEndValue(1.25);
    m_glowAnimation->start();
    QPushButton::mousePressEvent(event);
}

void TacticalActionButton::mouseReleaseEvent(QMouseEvent *event)
{
    animateTo(0.0, 140);
    m_glowAnimation->stop();
    m_glowAnimation->setDuration(180);
    m_glowAnimation->setStartValue(m_glowStrength);
    m_glowAnimation->setEndValue(m_hovered ? 1.0 : 0.0);
    m_glowAnimation->start();
    QPushButton::mouseReleaseEvent(event);
}

void TacticalActionButton::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    const QRectF r = rect().adjusted(1, 1 + m_pressOffset, -1, -1);

    QPainterPath path;
    path.addRoundedRect(r, 8, 8);

    if (m_glowStrength > 0.01) {
        QColor glow = m_neonColor;
        glow.setAlphaF(std::min(0.34, 0.12 + (m_glowStrength * 0.18)));
        painter.fillPath(path.translated(0, 1), glow);
    }

    QColor top = m_hovered ? m_neonColor.darker(150) : QColor("#283244");
    QColor bottom = QColor("#131923");
    if (text().contains("Stop")) {
        top = m_hovered ? QColor("#6a1f2f") : QColor("#37212a");
        bottom = QColor("#171217");
    }

    QLinearGradient g(r.topLeft(), r.bottomLeft());
    g.setColorAt(0.0, top);
    g.setColorAt(1.0, bottom);
    painter.fillPath(path, g);

    QColor border = m_hovered ? m_neonColor : QColor(255, 255, 255, 45);
    painter.setPen(QPen(border, m_hovered ? 1.6 : 1.0));
    painter.drawPath(path);

    painter.setPen(QColor("#f4f5f7"));
    QFont font = painter.font();
    font.setBold(true);
    painter.setFont(font);
    painter.drawText(r, Qt::AlignCenter, text());
}

void TacticalActionButton::animateTo(qreal value, int duration)
{
    m_animation->stop();
    m_animation->setDuration(duration);
    m_animation->setStartValue(m_pressOffset);
    m_animation->setEndValue(value);
    m_animation->start();
}

HoloScopeWidget::HoloScopeWidget(QWidget *parent)
    : QWidget(parent)
    , m_timer(new QTimer(this))
{
    setMinimumSize(180, 180);
    m_timer->setInterval(40);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        m_angle += 1.3;
        if (m_angle > 360.0) {
            m_angle -= 360.0;
        }
        update();
    });
    m_timer->start();
}

void HoloScopeWidget::setAnimationEnabled(bool enabled)
{
    if (enabled) {
        if (!m_timer->isActive()) {
            m_timer->start();
        }
    } else {
        m_timer->stop();
    }
}

void HoloScopeWidget::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    const QRectF r = rect().adjusted(8, 8, -8, -8);
    const QPointF c = r.center();

    painter.setPen(QPen(QColor(255, 255, 255, 28), 1.0));
    for (int i = 0; i < 4; ++i) {
        painter.drawEllipse(c, 22 + i * 18, 22 + i * 18);
    }

    painter.setPen(QPen(QColor(143, 23, 50, 180), 2.2));
    painter.save();
    painter.translate(c);
    painter.rotate(m_angle);
    painter.drawEllipse(QRectF(-54, -54, 108, 108));
    painter.drawLine(QPointF(-60, 0), QPointF(60, 0));
    painter.drawLine(QPointF(0, -60), QPointF(0, 60));
    painter.restore();

    painter.setPen(QPen(QColor(255, 255, 255, 80), 1.2, Qt::DashLine));
    painter.drawArc(r.adjusted(24, 24, -24, -24), 18 * 16, 130 * 16);
    painter.drawArc(r.adjusted(36, 36, -36, -36), -140 * 16, 110 * 16);
}

TrafficMeterWidget::TrafficMeterWidget(QWidget *parent)
    : QWidget(parent)
    , m_timer(new QTimer(this))
{
    setMinimumSize(240, 130);
    m_timer->setInterval(34);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        m_displayInbound += (m_targetInbound - m_displayInbound) * 0.22;
        m_displayOutbound += (m_targetOutbound - m_displayOutbound) * 0.22;
        update();
    });
    m_timer->start();
}

void TrafficMeterWidget::setTrafficLevels(qreal inboundLevel, qreal outboundLevel)
{
    m_targetInbound = std::clamp(inboundLevel, 0.0, 1.0);
    m_targetOutbound = std::clamp(outboundLevel, 0.0, 1.0);
}

void TrafficMeterWidget::setAnimationEnabled(bool enabled)
{
    if (enabled) {
        if (!m_timer->isActive()) {
            m_timer->start();
        }
    } else {
        m_timer->stop();
    }
}

void TrafficMeterWidget::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    const QRectF outer = rect().adjusted(8, 8, -8, -8);
    const QPointF center(outer.center().x(), outer.top() + outer.height() * 0.86);
    const qreal radius = std::min(outer.width() * 0.42, outer.height() * 0.72);

    painter.setPen(QPen(QColor(255, 255, 255, 30), 2.0));
    painter.drawArc(QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2), 25 * 16, 130 * 16);

    for (int i = 0; i <= 10; ++i) {
        const qreal t = static_cast<qreal>(i) / 10.0;
        const qreal angle = (205.0 - (130.0 * t)) * 3.14159265358979323846 / 180.0;
        const QPointF p1(center.x() + std::cos(angle) * (radius - 10.0),
                         center.y() - std::sin(angle) * (radius - 10.0));
        const QPointF p2(center.x() + std::cos(angle) * (radius + 2.0),
                         center.y() - std::sin(angle) * (radius + 2.0));
        painter.setPen(QPen(i > 6 ? QColor("#ef4444") : (i > 3 ? QColor("#f59e0b") : QColor("#22c55e")), 1.6));
        painter.drawLine(p1, p2);
    }

    auto drawNeedle = [&](qreal level, const QColor &color, qreal innerScale) {
        const qreal angle = (205.0 - (130.0 * level)) * 3.14159265358979323846 / 180.0;
        const QPointF tip(center.x() + std::cos(angle) * (radius * innerScale),
                          center.y() - std::sin(angle) * (radius * innerScale));
        painter.setPen(QPen(color, 2.4));
        painter.drawLine(center, tip);
    };

    drawNeedle(m_displayInbound, QColor("#22c55e"), 0.9);
    drawNeedle(m_displayOutbound, QColor("#60a5fa"), 0.78);

    painter.setBrush(QColor("#f3f4f6"));
    painter.setPen(Qt::NoPen);
    painter.drawEllipse(center, 6.0, 6.0);

    const QRectF barsRect = QRectF(outer.left() + 14, outer.bottom() - 32, outer.width() - 28, 16);
    const qreal gap = 4.0;
    const qreal totalSegments = 14.0;
    const qreal segmentWidth = (barsRect.width() - (gap * (totalSegments - 1.0))) / totalSegments;
    for (int i = 0; i < 14; ++i) {
        const qreal threshold = static_cast<qreal>(i + 1) / 14.0;
        QRectF seg(barsRect.left() + i * (segmentWidth + gap), barsRect.top(), segmentWidth, barsRect.height());
        QColor base = i > 10 ? QColor("#ef4444") : (i > 6 ? QColor("#f59e0b") : QColor("#22c55e"));
        QColor fill = (m_displayInbound >= threshold || m_displayOutbound >= threshold)
                          ? base
                          : QColor(base.red(), base.green(), base.blue(), 40);
        painter.setBrush(fill);
        painter.setPen(Qt::NoPen);
        painter.drawRoundedRect(seg, 3, 3);
    }
}

TrafficWaterfallWidget::TrafficWaterfallWidget(QWidget *parent)
    : QWidget(parent)
    , m_timer(new QTimer(this))
{
    setMinimumSize(280, 130);
    m_timer->setInterval(90);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        ensureImage();
        if (m_image.isNull()) {
            return;
        }

        m_image = m_image.copy();
        QPainter imagePainter(&m_image);
        imagePainter.drawImage(QPoint(0, 1), m_image.copy(0, 0, m_image.width(), std::max(0, m_image.height() - 1)));
        imagePainter.fillRect(QRect(0, 0, m_image.width(), 1), QColor("#081016"));
        imagePainter.end();
        QRgb *scan = reinterpret_cast<QRgb *>(m_image.scanLine(0));
        const int half = std::max(1, m_image.width() / 2);
        for (int x = 0; x < m_image.width(); ++x) {
            const qreal sideLevel = x < half ? m_pendingInbound : m_pendingOutbound;
            const qreal edge = x < half ? static_cast<qreal>(x) / half
                                        : static_cast<qreal>(x - half) / std::max(1, m_image.width() - half);
            const qreal shaped = std::clamp((sideLevel * 0.82) + (std::sin(edge * 6.28318) * 0.08) + 0.08, 0.0, 1.0);
            scan[x] = colorForLevel(shaped).rgba();
        }
        update();
    });
    m_timer->start();
}

void TrafficWaterfallWidget::pushSample(qreal inboundLevel, qreal outboundLevel)
{
    m_pendingInbound = std::clamp(inboundLevel, 0.0, 1.0);
    m_pendingOutbound = std::clamp(outboundLevel, 0.0, 1.0);
}

void TrafficWaterfallWidget::setAnimationEnabled(bool enabled)
{
    if (enabled) {
        if (!m_timer->isActive()) {
            m_timer->start();
        }
    } else {
        m_timer->stop();
    }
}

void TrafficWaterfallWidget::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    ensureImage();

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    const QRectF frame = rect().adjusted(1, 1, -1, -1);
    painter.fillRect(rect(), QColor("#081016"));
    if (!m_image.isNull()) {
        painter.drawImage(frame, m_image);
    }

    QLinearGradient fade(frame.topLeft(), frame.bottomLeft());
    fade.setColorAt(0.0, QColor(255, 255, 255, 10));
    fade.setColorAt(0.18, QColor(255, 255, 255, 0));
    fade.setColorAt(1.0, QColor(8, 16, 22, 190));
    painter.fillRect(frame, fade);

    painter.setPen(QPen(QColor(255, 255, 255, 26), 1.0));
    for (int y = 0; y < 5; ++y) {
        const qreal rowY = frame.top() + ((frame.height() / 4.0) * y);
        painter.drawLine(QPointF(frame.left(), rowY), QPointF(frame.right(), rowY));
    }
    painter.setPen(QPen(QColor(255, 255, 255, 34), 1.0));
    painter.drawLine(QPointF(frame.center().x(), frame.top()), QPointF(frame.center().x(), frame.bottom()));

    painter.setPen(QColor("#dbe7ff"));
    QFont labelFont = painter.font();
    labelFont.setPointSizeF(labelFont.pointSizeF() - 1.0);
    painter.setFont(labelFont);
    painter.drawText(QRectF(frame.left() + 10, frame.top() + 8, 80, 18), Qt::AlignLeft | Qt::AlignVCenter, tr("IN"));
    painter.drawText(QRectF(frame.center().x() + 10, frame.top() + 8, 80, 18), Qt::AlignLeft | Qt::AlignVCenter, tr("OUT"));
}

void TrafficWaterfallWidget::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    ensureImage();
}

void TrafficWaterfallWidget::ensureImage()
{
    const QSize targetSize = size() * devicePixelRatioF();
    if (targetSize.isEmpty()) {
        return;
    }
    if (m_image.size() == targetSize) {
        return;
    }
    m_image = QImage(targetSize, QImage::Format_ARGB32_Premultiplied);
    m_image.setDevicePixelRatio(devicePixelRatioF());
    m_image.fill(QColor("#081016"));
}

QColor TrafficWaterfallWidget::colorForLevel(qreal level) const
{
    if (level < 0.18) {
        return QColor(8, 22, 36, 230);
    }
    if (level < 0.35) {
        return QColor(24, 104, 122, 235);
    }
    if (level < 0.55) {
        return QColor(42, 176, 108, 240);
    }
    if (level < 0.75) {
        return QColor(236, 179, 47, 244);
    }
    if (level < 0.9) {
        return QColor(238, 102, 48, 248);
    }
    return QColor(220, 40, 64, 252);
}

namespace {

class ServerHandshakeWidget : public QWidget
{
public:
    explicit ServerHandshakeWidget(QWidget *parent = nullptr)
        : QWidget(parent)
    {
        setMinimumSize(150, 110);
    }

protected:
    void paintEvent(QPaintEvent *event) override
    {
        Q_UNUSED(event);
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);

        const QRectF leftNode(16, 26, 42, 42);
        const QRectF rightNode(width() - 58, 26, 42, 42);
        painter.setBrush(QColor(20, 26, 36, 220));
        painter.setPen(QPen(QColor(255, 255, 255, 40), 1.2));
        painter.drawRoundedRect(leftNode, 8, 8);
        painter.drawRoundedRect(rightNode, 8, 8);

        painter.setPen(QPen(QColor(143, 23, 50, 180), 2.0));
        painter.drawLine(leftNode.center() + QPointF(10, 0), rightNode.center() - QPointF(10, 0));
        painter.drawLine(leftNode.center() + QPointF(12, -8), rightNode.center() - QPointF(12, -8));

        painter.setBrush(QColor(243, 244, 246, 170));
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(QPointF(width() / 2.0 - 8, height() / 2.0 + 10), 10, 10);
        painter.drawEllipse(QPointF(width() / 2.0 + 8, height() / 2.0 + 10), 10, 10);
    }
};

}

ProxyWidget::ProxyWidget(ProxyModule *module, QWidget *parent)
    : QWidget(parent)
    , m_module(module)
{
    auto *layout = pengufoce::ui::layout::createPageRoot(this, 18);

    auto *topRow = new QHBoxLayout();
    topRow->setSpacing(18);

    auto *focusCard = pengufoce::ui::layout::createHeroCard(this, QMargins(24, 24, 24, 24), 18);
    focusCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    auto *focusLayout = new QHBoxLayout(focusCard);
    focusLayout->setContentsMargins(0, 0, 0, 0);
    focusLayout->setSpacing(18);

    auto *focusTextCol = new QVBoxLayout();
    auto *focusTitle = new QLabel(tr("Focus"), focusCard);
    focusTitle->setObjectName("sectionTitle");
    m_focusValue = new QLabel(tr("Proxy"), focusCard);
    m_focusValue->setObjectName("heroTitle");
    auto *focusText = new QLabel(tr("Intercept, replay ve traffic inspection akisini daha taktik bir kontrol masasi mantigiyla yonet."), focusCard);
    focusText->setObjectName("mutedText");
    focusText->setWordWrap(true);
    m_statusLabel = new QLabel(tr("Durum: Hazir"), focusCard);
    m_statusLabel->setObjectName("cardTitle");
    focusTextCol->addWidget(focusTitle);
    focusTextCol->addWidget(m_focusValue);
    focusTextCol->addWidget(focusText);
    focusTextCol->addWidget(m_statusLabel);
    focusTextCol->addStretch();

    m_holoWidget = new HoloScopeWidget(focusCard);
    focusLayout->addLayout(focusTextCol, 2);
    focusLayout->addWidget(m_holoWidget, 1);

    auto *proxyCard = new ProxyRuntimePanel(this);
    proxyCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    m_flowValue = proxyCard->flowValue();
    m_healthValue = proxyCard->healthValue();
    m_sessionsValue = proxyCard->sessionsValue();
    m_throughputValue = proxyCard->throughputValue();
    m_targetValue = proxyCard->targetValue();
    m_tlsValue = proxyCard->tlsValue();
    m_listenHostEdit = proxyCard->listenHostEdit();
    m_listenPortSpin = proxyCard->listenPortSpin();
    m_targetHostEdit = proxyCard->targetHostEdit();
    m_targetPortSpin = proxyCard->targetPortSpin();
    m_idleTimeoutSpin = proxyCard->idleTimeoutSpin();
    m_workerSpin = proxyCard->workerSpin();
    m_sharedSecretEdit = proxyCard->sharedSecretEdit();
    m_requireHandshakeCheck = proxyCard->requireHandshakeCheck();
    m_startLed = proxyCard->startLed();
    m_stopLed = proxyCard->stopLed();
    m_meterWidget = proxyCard->meterWidget();
    m_waterfallWidget = proxyCard->waterfallWidget();
    QPushButton *startButton = proxyCard->startButton();
    QPushButton *stopButton = proxyCard->stopButton();
    QPushButton *applySettingsButton = proxyCard->applySettingsButton();

    topRow->addWidget(focusCard, 3);
    topRow->addWidget(proxyCard, 4);

    auto *bottomTabsCard = new ProxyBottomPanel(this);
    m_eventFeed = bottomTabsCard->eventFeed();
    m_waterfallDetailWidget = bottomTabsCard->waterfallDetailWidget();

    layout->addLayout(topRow);
    layout->addWidget(bottomTabsCard);
    layout->addStretch();

    m_startLed->setBlinking(false);
    m_stopLed->setBlinking(true);
    appendEvent(tr("Proxy workspace online."));

    connect(m_module, &ProxyModule::statusChanged, this, &ProxyWidget::applyStatus);
    connect(m_module, &ProxyModule::telemetryUpdated, this, &ProxyWidget::applyTelemetry);
    connect(m_module, &ProxyModule::eventAppended, this, &ProxyWidget::applyEvent);
    connect(m_module, &ProxyModule::runningChanged, this, [this](bool running) {
        m_startLed->setBlinking(running);
        m_stopLed->setBlinking(!running);
    });

    connect(startButton, &QPushButton::clicked, this, &ProxyWidget::startProxy);
    connect(stopButton, &QPushButton::clicked, this, &ProxyWidget::stopProxy);
    connect(applySettingsButton, &QPushButton::clicked, this, &ProxyWidget::applyQuickSettings);

#ifndef PENGUFOCE_WITH_BOOST_PROXY
    startButton->setEnabled(false);
    stopButton->setEnabled(false);
    m_statusLabel->setText(tr("Durum: Boost.Asio bekleniyor"));
    m_flowValue->setText(tr("Destek yok"));
    m_healthValue->setText(tr("Boost kurulu degil"));
    appendEvent(tr("Boost.Asio/Boost.System bulunamadi. Proxy motoru bu build icinde pasif."));
#endif

    reloadSettings();
    setActiveView(false);
}

void ProxyWidget::reloadSettings()
{
    if (!m_module) {
        return;
    }

    m_module->reloadSettings();
    m_targetValue->setText(QString("%1:%2 -> %3:%4")
                               .arg(m_module->listenHost())
                               .arg(m_module->listenPort())
                               .arg(m_module->targetHost())
                               .arg(m_module->targetPort()));
    m_listenHostEdit->setText(m_module->listenHost());
    m_listenPortSpin->setValue(m_module->listenPort());
    m_targetHostEdit->setText(m_module->targetHost());
    m_targetPortSpin->setValue(m_module->targetPort());
    m_idleTimeoutSpin->setValue(m_module->idleTimeoutSeconds());
    m_workerSpin->setValue(m_module->workerThreads());
    m_sharedSecretEdit->setText(m_module->sharedSecret());
    m_requireHandshakeCheck->setChecked(m_module->requireHandshake());
    m_tlsValue->setText(m_module->interceptTls() ? tr("TLS Metadata Hazir") : tr("Yerel Arastirma Modu"));
    m_statusLabel->setText(m_module->running() ? tr("Durum: Yerel kopru aktif") : tr("Durum: Hazir"));
    refreshSummary(m_module->latestSnapshot());
}

void ProxyWidget::setActiveView(bool active)
{
    m_viewActive = active;
    if (m_holoWidget) {
        m_holoWidget->setAnimationEnabled(active);
    }
    if (m_meterWidget) {
        m_meterWidget->setAnimationEnabled(active);
    }
    if (m_waterfallWidget) {
        m_waterfallWidget->setAnimationEnabled(active);
    }
    if (m_waterfallDetailWidget) {
        m_waterfallDetailWidget->setAnimationEnabled(active);
    }
    if (m_startLed) {
        m_startLed->setAnimationEnabled(active);
    }
    if (m_stopLed) {
        m_stopLed->setAnimationEnabled(active);
    }
}

void ProxyWidget::startProxy()
{
    if (!m_module) {
        return;
    }

    m_module->start();
    reloadSettings();
}

void ProxyWidget::stopProxy()
{
    if (!m_module) {
        return;
    }

    m_module->stop();
    reloadSettings();
}

void ProxyWidget::applyQuickSettings()
{
    if (!m_module) {
        return;
    }

    m_module->applyRuntimeSettings(m_listenHostEdit->text(),
                                   m_listenPortSpin->value(),
                                   m_targetHostEdit->text(),
                                   m_targetPortSpin->value(),
                                   m_idleTimeoutSpin->value(),
                                   m_workerSpin->value(),
                                   m_sharedSecretEdit->text(),
                                   m_requireHandshakeCheck->isChecked());
    reloadSettings();
}

void ProxyWidget::appendEvent(const QString &message)
{
    auto *item = new QListWidgetItem(message);
    const QString lowered = message.toLower();
    if (lowered.contains("hata") || lowered.contains("failed") || lowered.contains("timeout") || lowered.contains("redd")) {
        item->setForeground(QColor("#ffd6d6"));
        item->setBackground(QColor(128, 28, 40, 120));
    } else if (lowered.contains("aktif") || lowered.contains("accepted") || lowered.contains("ok") || lowered.contains("guncellendi")) {
        item->setForeground(QColor("#dcffe9"));
        item->setBackground(QColor(24, 92, 48, 110));
    } else if (lowered.contains("uyari") || lowered.contains("hazir") || lowered.contains("bekle")) {
        item->setForeground(QColor("#fff2cc"));
        item->setBackground(QColor(122, 88, 20, 92));
    } else {
        item->setForeground(QColor("#e8edf7"));
        item->setBackground(QColor(255, 255, 255, 18));
    }
    m_eventFeed->insertItem(0, item);
    while (m_eventFeed->count() > 10) {
        delete m_eventFeed->takeItem(m_eventFeed->count() - 1);
    }
}

void ProxyWidget::applyStatus(const QString &status)
{
    m_statusLabel->setText(tr("Durum: %1").arg(status));
}

void ProxyWidget::applyTelemetry(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot)
{
    m_lastSnapshot = snapshot;
    refreshSummary(snapshot);
}

void ProxyWidget::applyEvent(const QString &message)
{
    appendEvent(message);
}

void ProxyWidget::refreshSummary(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot)
{
    const double bytesPerSecond = snapshot.bytesPerSecond;
    QString throughputText;
    if (bytesPerSecond >= 1024.0 * 1024.0) {
        throughputText = QString::number(bytesPerSecond / (1024.0 * 1024.0), 'f', 2) % tr(" MB/sn");
    } else if (bytesPerSecond >= 1024.0) {
        throughputText = QString::number(bytesPerSecond / 1024.0, 'f', 1) % tr(" KB/sn");
    } else {
        throughputText = QString::number(bytesPerSecond, 'f', 0) % tr(" B/sn");
    }

    m_flowValue->setText(snapshot.totalAccepted > 0 ? tr("Akis var") : tr("Idle"));
    m_healthValue->setText(snapshot.timeoutClosures > 0
                               ? tr("%1 timeout").arg(snapshot.timeoutClosures)
                               : tr("Stabil"));
    m_sessionsValue->setText(QString::number(snapshot.activeSessions));
    m_throughputValue->setText(throughputText);
    if (m_meterWidget) {
        const std::size_t inboundDelta = snapshot.bytesClientToTarget >= m_lastClientBytes
                                             ? snapshot.bytesClientToTarget - m_lastClientBytes
                                             : snapshot.bytesClientToTarget;
        const std::size_t outboundDelta = snapshot.bytesTargetToClient >= m_lastTargetBytes
                                              ? snapshot.bytesTargetToClient - m_lastTargetBytes
                                              : snapshot.bytesTargetToClient;
        const qreal inboundLevel = std::clamp(static_cast<qreal>(inboundDelta) / 32768.0, 0.0, 1.0);
        const qreal outboundLevel = std::clamp(static_cast<qreal>(outboundDelta) / 32768.0, 0.0, 1.0);
        m_meterWidget->setTrafficLevels(inboundLevel, outboundLevel);
        if (m_waterfallWidget) {
            m_waterfallWidget->pushSample(inboundLevel, outboundLevel);
        }
        if (m_waterfallDetailWidget) {
            m_waterfallDetailWidget->pushSample(inboundLevel, outboundLevel);
        }
        m_lastClientBytes = snapshot.bytesClientToTarget;
        m_lastTargetBytes = snapshot.bytesTargetToClient;
    }
}

ProxyWaterfallPage::ProxyWaterfallPage(ProxyModule *module, QWidget *parent)
    : QWidget(parent)
    , m_module(module)
{
    auto *layout = pengufoce::ui::layout::createPageRoot(this, 18);

    auto *heroCard = pengufoce::ui::layout::createHeroCard(this, QMargins(24, 24, 24, 24), 12);
    auto *heroLayout = qobject_cast<QVBoxLayout *>(heroCard->layout());

    auto *title = new QLabel(tr("Traffic Waterfall"), heroCard);
    title->setObjectName("heroTitle");
    auto *lead = new QLabel(tr("Akan spektrum gorunumu anlik trafik yogunlugunu zaman ekseninde izler. Spike aninda panel isinir, akis sakinse tonlar sogur."), heroCard);
    lead->setObjectName("mutedText");
    lead->setWordWrap(true);
    m_statusLabel = new QLabel(tr("Durum: Hazir"), heroCard);
    m_statusLabel->setObjectName("cardTitle");

    auto *summaryHost = new QWidget(heroCard);
    auto *summaryRow = new FlowLayout(summaryHost, 0, 12, 12);
    auto makeCard = [heroCard](const QString &kicker, QLabel **valueOut) {
        auto *card = new QFrame(heroCard);
        card->setObjectName("summaryCard");
        auto *cardLayout = new QVBoxLayout(card);
        cardLayout->setContentsMargins(14, 14, 14, 14);
        auto *label = new QLabel(kicker, card);
        label->setObjectName("mutedText");
        auto *value = new QLabel("--", card);
        value->setObjectName("statValue");
        cardLayout->addWidget(label);
        cardLayout->addWidget(value);
        *valueOut = value;
        return card;
    };
    auto *flowCard = makeCard(tr("Flow"), &m_flowLabel);
    auto *sessionCard = makeCard(tr("Sessions"), &m_sessionsLabel);
    auto *throughputCard = makeCard(tr("Throughput"), &m_throughputLabel);
    auto *targetCard = makeCard(tr("Target"), &m_targetLabel);
    flowCard->setMinimumWidth(145);
    sessionCard->setMinimumWidth(145);
    throughputCard->setMinimumWidth(145);
    targetCard->setMinimumWidth(160);
    summaryRow->addWidget(flowCard);
    summaryRow->addWidget(sessionCard);
    summaryRow->addWidget(throughputCard);
    summaryRow->addWidget(targetCard);
    summaryHost->setLayout(summaryRow);

    heroLayout->addWidget(title);
    heroLayout->addWidget(lead);
    heroLayout->addWidget(m_statusLabel);
    heroLayout->addWidget(summaryHost);

    auto *vizCard = pengufoce::ui::layout::createCard(this, QStringLiteral("cardPanel"), QMargins(20, 20, 20, 20), 14);
    auto *vizLayout = qobject_cast<QVBoxLayout *>(vizCard->layout());

    auto *vizTitle = new QLabel(tr("Canli Spektrum"), vizCard);
    vizTitle->setObjectName("sectionTitle");
    auto *vizInfo = new QLabel(tr("Sol yarida inbound, sag yarida outbound akis izlenir. Renk paleti trafik yogunluguna gore degisir."), vizCard);
    vizInfo->setObjectName("mutedText");
    vizInfo->setWordWrap(true);
    m_meterWidget = new TrafficMeterWidget(vizCard);
    m_meterWidget->setMinimumHeight(130);
    m_waterfallWidget = new TrafficWaterfallWidget(vizCard);
    m_waterfallWidget->setMinimumHeight(300);

    auto *legendHost = new QWidget(vizCard);
    auto *legendRow = new FlowLayout(legendHost, 0, 10, 8);
    auto addLegend = [vizCard, legendRow](const QString &text, const QColor &color) {
        auto *chip = new QLabel(text, vizCard);
        chip->setStyleSheet(QString("QLabel { background:%1; color:#f8fafc; border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:4px 10px; }")
                                .arg(color.name()));
        legendRow->addWidget(chip);
    };
    addLegend(tr("Dusuk"), QColor("#18687a"));
    addLegend(tr("Orta"), QColor("#2ab06c"));
    addLegend(tr("Yuksek"), QColor("#ecb32f"));
    addLegend(tr("Spike"), QColor("#dc2840"));
    legendHost->setLayout(legendRow);

    vizLayout->addWidget(vizTitle);
    vizLayout->addWidget(vizInfo);
    vizLayout->addWidget(m_meterWidget);
    vizLayout->addWidget(m_waterfallWidget, 1);
    vizLayout->addWidget(legendHost);

    layout->addWidget(heroCard);
    layout->addWidget(vizCard, 1);

    if (m_module) {
        connect(m_module, &ProxyModule::statusChanged, this, &ProxyWaterfallPage::applyStatus);
        connect(m_module, &ProxyModule::telemetryUpdated, this, &ProxyWaterfallPage::applyTelemetry);
    }

    reloadSettings();
    setActiveView(false);
}

void ProxyWaterfallPage::reloadSettings()
{
    if (!m_module) {
        return;
    }
    m_targetLabel->setText(QString("%1:%2 -> %3:%4")
                               .arg(m_module->listenHost())
                               .arg(m_module->listenPort())
                               .arg(m_module->targetHost())
                               .arg(m_module->targetPort()));
    m_statusLabel->setText(m_module->running() ? tr("Durum: Waterfall aktif akis izliyor") : tr("Durum: Hazir"));
    refreshSummary(m_module->latestSnapshot());
}

void ProxyWaterfallPage::setActiveView(bool active)
{
    if (m_meterWidget) {
        m_meterWidget->setAnimationEnabled(active);
    }
    if (m_waterfallWidget) {
        m_waterfallWidget->setAnimationEnabled(active);
    }
}

void ProxyWaterfallPage::applyStatus(const QString &status)
{
    m_statusLabel->setText(tr("Durum: %1").arg(status));
}

void ProxyWaterfallPage::applyTelemetry(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot)
{
    m_lastSnapshot = snapshot;
    refreshSummary(snapshot);
}

void ProxyWaterfallPage::refreshSummary(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot)
{
    const double bytesPerSecond = snapshot.bytesPerSecond;
    QString throughputText;
    if (bytesPerSecond >= 1024.0 * 1024.0) {
        throughputText = QString::number(bytesPerSecond / (1024.0 * 1024.0), 'f', 2) % tr(" MB/sn");
    } else if (bytesPerSecond >= 1024.0) {
        throughputText = QString::number(bytesPerSecond / 1024.0, 'f', 1) % tr(" KB/sn");
    } else {
        throughputText = QString::number(bytesPerSecond, 'f', 0) % tr(" B/sn");
    }

    m_flowLabel->setText(snapshot.totalAccepted > 0 ? tr("Akis var") : tr("Idle"));
    m_sessionsLabel->setText(QString::number(snapshot.activeSessions));
    m_throughputLabel->setText(throughputText);

    const std::size_t inboundDelta = snapshot.bytesClientToTarget >= m_lastClientBytes
                                         ? snapshot.bytesClientToTarget - m_lastClientBytes
                                         : snapshot.bytesClientToTarget;
    const std::size_t outboundDelta = snapshot.bytesTargetToClient >= m_lastTargetBytes
                                          ? snapshot.bytesTargetToClient - m_lastTargetBytes
                                          : snapshot.bytesTargetToClient;
    const qreal inboundLevel = std::clamp(static_cast<qreal>(inboundDelta) / 32768.0, 0.0, 1.0);
    const qreal outboundLevel = std::clamp(static_cast<qreal>(outboundDelta) / 32768.0, 0.0, 1.0);
    if (m_meterWidget) {
        m_meterWidget->setTrafficLevels(inboundLevel, outboundLevel);
    }
    if (m_waterfallWidget) {
        m_waterfallWidget->pushSample(inboundLevel, outboundLevel);
    }
    m_lastClientBytes = snapshot.bytesClientToTarget;
    m_lastTargetBytes = snapshot.bytesTargetToClient;
}
