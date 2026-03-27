#pragma once

#include <QFrame>

class QLabel;
class QLineEdit;
class QSpinBox;
class QCheckBox;
class QPushButton;
class StatusLed;
class TrafficMeterWidget;
class TrafficWaterfallWidget;

class ProxyRuntimePanel : public QFrame
{
    Q_OBJECT

public:
    explicit ProxyRuntimePanel(QWidget *parent = nullptr);

    QLabel *flowValue() const { return m_flowValue; }
    QLabel *healthValue() const { return m_healthValue; }
    QLabel *sessionsValue() const { return m_sessionsValue; }
    QLabel *throughputValue() const { return m_throughputValue; }
    QLabel *targetValue() const { return m_targetValue; }
    QLabel *tlsValue() const { return m_tlsValue; }
    QLineEdit *listenHostEdit() const { return m_listenHostEdit; }
    QSpinBox *listenPortSpin() const { return m_listenPortSpin; }
    QLineEdit *targetHostEdit() const { return m_targetHostEdit; }
    QSpinBox *targetPortSpin() const { return m_targetPortSpin; }
    QSpinBox *idleTimeoutSpin() const { return m_idleTimeoutSpin; }
    QSpinBox *workerSpin() const { return m_workerSpin; }
    QLineEdit *sharedSecretEdit() const { return m_sharedSecretEdit; }
    QCheckBox *requireHandshakeCheck() const { return m_requireHandshakeCheck; }
    QPushButton *applySettingsButton() const { return m_applySettingsButton; }
    QPushButton *startButton() const { return m_startButton; }
    QPushButton *stopButton() const { return m_stopButton; }
    StatusLed *startLed() const { return m_startLed; }
    StatusLed *stopLed() const { return m_stopLed; }
    TrafficMeterWidget *meterWidget() const { return m_meterWidget; }
    TrafficWaterfallWidget *waterfallWidget() const { return m_waterfallWidget; }

private:
    QLabel *m_flowValue = nullptr;
    QLabel *m_healthValue = nullptr;
    QLabel *m_sessionsValue = nullptr;
    QLabel *m_throughputValue = nullptr;
    QLabel *m_targetValue = nullptr;
    QLabel *m_tlsValue = nullptr;
    QLineEdit *m_listenHostEdit = nullptr;
    QSpinBox *m_listenPortSpin = nullptr;
    QLineEdit *m_targetHostEdit = nullptr;
    QSpinBox *m_targetPortSpin = nullptr;
    QSpinBox *m_idleTimeoutSpin = nullptr;
    QSpinBox *m_workerSpin = nullptr;
    QLineEdit *m_sharedSecretEdit = nullptr;
    QCheckBox *m_requireHandshakeCheck = nullptr;
    QPushButton *m_applySettingsButton = nullptr;
    QPushButton *m_startButton = nullptr;
    QPushButton *m_stopButton = nullptr;
    StatusLed *m_startLed = nullptr;
    StatusLed *m_stopLed = nullptr;
    TrafficMeterWidget *m_meterWidget = nullptr;
    TrafficWaterfallWidget *m_waterfallWidget = nullptr;
};
