#include "ui/views/proxy/proxyruntimepanel.h"

#include "ui/layout/flowlayout.h"
#include "ui/views/proxy/proxywidget.h"

#include <QCheckBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {

QFrame *makeStatCard(QWidget *parent, const QString &title, QLabel **valueLabel)
{
    auto *card = new QFrame(parent);
    card->setObjectName("summaryCard");
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(14, 14, 14, 14);
    auto *label = new QLabel(title, card);
    label->setObjectName("mutedText");
    *valueLabel = new QLabel(QStringLiteral("--"), card);
    (*valueLabel)->setObjectName("statValue");
    layout->addWidget(label);
    layout->addWidget(*valueLabel);
    return card;
}

}

ProxyRuntimePanel::ProxyRuntimePanel(QWidget *parent)
    : QFrame(parent)
{
    setObjectName("cardPanel");
    auto *proxyLayout = new QVBoxLayout(this);
    proxyLayout->setContentsMargins(22, 22, 22, 22);
    proxyLayout->setSpacing(16);

    auto *proxyTitle = new QLabel(tr("Proxy Gateway"), this);
    proxyTitle->setObjectName("sectionTitle");
    auto *proxyInfo = new QLabel(tr("Yerel arastirma koprusu, hedef endpoint ve canli trafik metrikleri."), this);
    proxyInfo->setObjectName("mutedText");
    proxyInfo->setWordWrap(true);

    auto *statHost = new QWidget(this);
    auto *statRow = new FlowLayout(statHost, 0, 12, 12);
    auto *flowCard = makeStatCard(this, tr("Traffic State"), &m_flowValue);
    auto *healthCard = makeStatCard(this, tr("Link Health"), &m_healthValue);
    auto *sessionsCard = makeStatCard(this, tr("Active Sessions"), &m_sessionsValue);
    auto *throughputCard = makeStatCard(this, tr("Throughput"), &m_throughputValue);
    flowCard->setMinimumWidth(145);
    healthCard->setMinimumWidth(145);
    sessionsCard->setMinimumWidth(145);
    throughputCard->setMinimumWidth(145);
    statRow->addWidget(flowCard);
    statRow->addWidget(healthCard);
    statRow->addWidget(sessionsCard);
    statRow->addWidget(throughputCard);
    statHost->setLayout(statRow);

    auto *detailsCard = new QFrame(this);
    detailsCard->setObjectName("summaryCard");
    auto *detailsLayout = new QGridLayout(detailsCard);
    detailsLayout->setContentsMargins(14, 14, 14, 14);
    detailsLayout->setHorizontalSpacing(12);
    detailsLayout->setVerticalSpacing(8);
    auto *targetLabel = new QLabel(tr("Target"), detailsCard);
    targetLabel->setObjectName("mutedText");
    m_targetValue = new QLabel(tr("127.0.0.1:8080 -> 127.0.0.1:18081"), detailsCard);
    m_targetValue->setObjectName("cardTitle");
    auto *tlsLabel = new QLabel(tr("TLS"), detailsCard);
    tlsLabel->setObjectName("mutedText");
    m_tlsValue = new QLabel(tr("Intercept Ready"), detailsCard);
    m_tlsValue->setObjectName("cardTitle");
    detailsLayout->addWidget(targetLabel, 0, 0);
    detailsLayout->addWidget(m_targetValue, 0, 1);
    detailsLayout->addWidget(tlsLabel, 1, 0);
    detailsLayout->addWidget(m_tlsValue, 1, 1);

    auto *quickCard = new QFrame(this);
    quickCard->setObjectName("summaryCard");
    auto *quickLayout = new QGridLayout(quickCard);
    quickLayout->setContentsMargins(14, 14, 14, 14);
    quickLayout->setHorizontalSpacing(10);
    quickLayout->setVerticalSpacing(8);

    auto addQuickField = [quickCard, quickLayout](int row, const QString &labelText, QWidget *field) {
        auto *label = new QLabel(labelText, quickCard);
        label->setObjectName("mutedText");
        quickLayout->addWidget(label, row, 0);
        quickLayout->addWidget(field, row, 1);
    };

    m_listenHostEdit = new QLineEdit(quickCard);
    m_listenPortSpin = new QSpinBox(quickCard);
    m_listenPortSpin->setRange(1, 65535);
    m_targetHostEdit = new QLineEdit(quickCard);
    m_targetPortSpin = new QSpinBox(quickCard);
    m_targetPortSpin->setRange(1, 65535);
    m_idleTimeoutSpin = new QSpinBox(quickCard);
    m_idleTimeoutSpin->setRange(5, 300);
    m_idleTimeoutSpin->setSuffix(tr(" sn"));
    m_workerSpin = new QSpinBox(quickCard);
    m_workerSpin->setRange(1, 16);
    m_sharedSecretEdit = new QLineEdit(quickCard);
    m_requireHandshakeCheck = new QCheckBox(tr("Handshake zorunlu"), quickCard);
    m_applySettingsButton = new QPushButton(tr("Ayar Uygula"), quickCard);
    m_applySettingsButton->setObjectName("bevelButton");

    addQuickField(0, tr("Dinleme host"), m_listenHostEdit);
    addQuickField(1, tr("Dinleme port"), m_listenPortSpin);
    addQuickField(2, tr("Hedef host"), m_targetHostEdit);
    addQuickField(3, tr("Hedef port"), m_targetPortSpin);
    addQuickField(4, tr("Idle timeout"), m_idleTimeoutSpin);
    addQuickField(5, tr("Worker"), m_workerSpin);
    addQuickField(6, tr("Secret"), m_sharedSecretEdit);
    quickLayout->addWidget(m_requireHandshakeCheck, 7, 1);
    quickLayout->addWidget(m_applySettingsButton, 8, 1);

    auto *buttonHost = new QWidget(this);
    auto *buttonRow = new FlowLayout(buttonHost, 0, 20, 12);
    auto buildButtonStack = [this](const QString &ledLabel, const QString &buttonText, const QColor &ledColor, StatusLed **ledOut, QPushButton **buttonOut) {
        auto *stack = new QVBoxLayout();
        stack->setSpacing(8);
        auto *top = new QHBoxLayout();
        *ledOut = new StatusLed(ledColor, this);
        auto *label = new QLabel(ledLabel, this);
        label->setObjectName("mutedText");
        top->addWidget(*ledOut);
        top->addWidget(label);
        top->addStretch();
        auto *button = new TacticalActionButton(buttonText, this);
        *buttonOut = button;
        stack->addLayout(top);
        stack->addWidget(button);
        return stack;
    };

    auto *startGroup = new QWidget(this);
    startGroup->setLayout(buildButtonStack(tr("Live"), tr("Start Proxy"), QColor("#22c55e"), &m_startLed, &m_startButton));
    auto *stopGroup = new QWidget(this);
    stopGroup->setLayout(buildButtonStack(tr("Halt"), tr("Stop Proxy"), QColor("#ef4444"), &m_stopLed, &m_stopButton));
    buttonRow->addWidget(startGroup);
    buttonRow->addWidget(stopGroup);
    buttonHost->setLayout(buttonRow);

    m_meterWidget = new TrafficMeterWidget(this);
    m_waterfallWidget = new TrafficWaterfallWidget(this);
    auto *handshake = new QFrame(this);
    handshake->setObjectName("summaryCard");
    auto *handshakeLayout = new QVBoxLayout(handshake);
    handshakeLayout->setContentsMargins(14, 14, 14, 14);
    auto *handshakeTitle = new QLabel(tr("Handshake"), handshake);
    handshakeTitle->setObjectName("sectionTitle");
    auto *handshakeBody = new QLabel(tr("Proxy oturumu acildiginda yerel kopru ve gizli anahtar durumu burada izlenir."), handshake);
    handshakeBody->setObjectName("mutedText");
    handshakeBody->setWordWrap(true);
    handshakeLayout->addWidget(handshakeTitle);
    handshakeLayout->addWidget(handshakeBody);
    auto *vizRow = new QHBoxLayout();
    vizRow->setSpacing(12);
    vizRow->addWidget(handshake, 0, Qt::AlignLeft);
    vizRow->addWidget(m_meterWidget, 1);
    vizRow->addWidget(m_waterfallWidget, 2);

    proxyLayout->addWidget(proxyTitle);
    proxyLayout->addWidget(proxyInfo);
    proxyLayout->addWidget(statHost);
    proxyLayout->addWidget(detailsCard);
    proxyLayout->addWidget(quickCard);
    proxyLayout->addWidget(buttonHost);
    proxyLayout->addLayout(vizRow);
}
