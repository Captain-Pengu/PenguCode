#pragma once

#include "modules/proxy/engine/localresearchcore.h"

#include <QColor>
#include <QPushButton>
#include <QWidget>

class ProxyModule;
class QLabel;
class QListWidget;
class QTimer;
class QPropertyAnimation;
class QLineEdit;
class QSpinBox;
class QCheckBox;
class QGraphicsOpacityEffect;
class QTabWidget;

class StatusLed : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(qreal intensity READ intensity WRITE setIntensity)

public:
    explicit StatusLed(const QColor &baseColor, QWidget *parent = nullptr);

    qreal intensity() const;
    void setIntensity(qreal value);
    void setBlinking(bool value);
    void setAnimationEnabled(bool value);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QColor m_baseColor;
    qreal m_intensity = 0.45;
    QTimer *m_timer = nullptr;
    bool m_blinking = false;
    bool m_phase = false;
};

class TacticalActionButton : public QPushButton
{
    Q_OBJECT
    Q_PROPERTY(qreal pressOffset READ pressOffset WRITE setPressOffset)
    Q_PROPERTY(qreal glowStrength READ glowStrength WRITE setGlowStrength)

public:
    explicit TacticalActionButton(const QString &text, QWidget *parent = nullptr);

    qreal pressOffset() const;
    void setPressOffset(qreal value);
    qreal glowStrength() const;
    void setGlowStrength(qreal value);

protected:
    void enterEvent(QEnterEvent *event) override;
    void leaveEvent(QEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void paintEvent(QPaintEvent *event) override;

private:
    void animateTo(qreal value, int duration);

    qreal m_pressOffset = 0.0;
    qreal m_glowStrength = 0.0;
    bool m_hovered = false;
    QColor m_neonColor;
    QPropertyAnimation *m_animation = nullptr;
    QPropertyAnimation *m_glowAnimation = nullptr;
};

class HoloScopeWidget : public QWidget
{
    Q_OBJECT

public:
    explicit HoloScopeWidget(QWidget *parent = nullptr);
    void setAnimationEnabled(bool enabled);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QTimer *m_timer = nullptr;
    qreal m_angle = 0.0;
};

class TrafficMeterWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TrafficMeterWidget(QWidget *parent = nullptr);
    void setTrafficLevels(qreal inboundLevel, qreal outboundLevel);
    void setAnimationEnabled(bool enabled);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    qreal m_targetInbound = 0.0;
    qreal m_targetOutbound = 0.0;
    qreal m_displayInbound = 0.0;
    qreal m_displayOutbound = 0.0;
    QTimer *m_timer = nullptr;
};

class TrafficWaterfallWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TrafficWaterfallWidget(QWidget *parent = nullptr);
    void pushSample(qreal inboundLevel, qreal outboundLevel);
    void setAnimationEnabled(bool enabled);

protected:
    void paintEvent(QPaintEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    void ensureImage();
    QColor colorForLevel(qreal level) const;

    QImage m_image;
    qreal m_pendingInbound = 0.0;
    qreal m_pendingOutbound = 0.0;
    QTimer *m_timer = nullptr;
};

class ProxyWidget : public QWidget
{
    Q_OBJECT

public:
    explicit ProxyWidget(ProxyModule *module, QWidget *parent = nullptr);
    void reloadSettings();
    void setActiveView(bool active);

private slots:
    void startProxy();
    void stopProxy();
    void applyQuickSettings();
    void applyStatus(const QString &status);
    void applyTelemetry(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot);
    void applyEvent(const QString &message);

private:
    void appendEvent(const QString &message);
    void refreshSummary(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot);

    ProxyModule *m_module;
    QLabel *m_statusLabel = nullptr;
    QLabel *m_focusValue = nullptr;
    QLabel *m_flowValue = nullptr;
    QLabel *m_healthValue = nullptr;
    QLabel *m_targetValue = nullptr;
    QLabel *m_tlsValue = nullptr;
    QLabel *m_sessionsValue = nullptr;
    QLabel *m_throughputValue = nullptr;
    QLineEdit *m_listenHostEdit = nullptr;
    QSpinBox *m_listenPortSpin = nullptr;
    QLineEdit *m_targetHostEdit = nullptr;
    QSpinBox *m_targetPortSpin = nullptr;
    QSpinBox *m_idleTimeoutSpin = nullptr;
    QSpinBox *m_workerSpin = nullptr;
    QLineEdit *m_sharedSecretEdit = nullptr;
    QCheckBox *m_requireHandshakeCheck = nullptr;
    HoloScopeWidget *m_holoWidget = nullptr;
    TrafficMeterWidget *m_meterWidget = nullptr;
    TrafficWaterfallWidget *m_waterfallWidget = nullptr;
    TrafficWaterfallWidget *m_waterfallDetailWidget = nullptr;
    StatusLed *m_startLed = nullptr;
    StatusLed *m_stopLed = nullptr;
    QListWidget *m_eventFeed = nullptr;
    bool m_viewActive = true;
    pengufoce::proxy::localresearch::TransferSnapshot m_lastSnapshot;
    std::size_t m_lastClientBytes = 0;
    std::size_t m_lastTargetBytes = 0;
};

class ProxyWaterfallPage : public QWidget
{
    Q_OBJECT

public:
    explicit ProxyWaterfallPage(ProxyModule *module, QWidget *parent = nullptr);
    void reloadSettings();
    void setActiveView(bool active);

private slots:
    void applyStatus(const QString &status);
    void applyTelemetry(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot);

private:
    void refreshSummary(const pengufoce::proxy::localresearch::TransferSnapshot &snapshot);

    ProxyModule *m_module = nullptr;
    QLabel *m_statusLabel = nullptr;
    QLabel *m_targetLabel = nullptr;
    QLabel *m_sessionsLabel = nullptr;
    QLabel *m_throughputLabel = nullptr;
    QLabel *m_flowLabel = nullptr;
    TrafficMeterWidget *m_meterWidget = nullptr;
    TrafficWaterfallWidget *m_waterfallWidget = nullptr;
    pengufoce::proxy::localresearch::TransferSnapshot m_lastSnapshot;
    std::size_t m_lastClientBytes = 0;
    std::size_t m_lastTargetBytes = 0;
};
