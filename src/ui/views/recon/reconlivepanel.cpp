#include "reconlivepanel.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QTimer>
#include <QVBoxLayout>

namespace {

class ReconPulseWidget : public QWidget
{
public:
    explicit ReconPulseWidget(QWidget *parent = nullptr)
        : QWidget(parent)
        , m_timer(new QTimer(this))
    {
        setMinimumSize(120, 120);
        m_timer->setInterval(42);
        connect(m_timer, &QTimer::timeout, this, [this]() {
            m_phase += 0.08;
            update();
        });
        m_timer->start();
    }

    void setPulseColor(const QColor &color)
    {
        m_color = color;
        update();
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.fillRect(rect(), Qt::transparent);
        const QPointF center = rect().center();
        const qreal base = qMin(width(), height()) * 0.16;
        for (int i = 3; i >= 0; --i) {
            const qreal factor = std::fmod(m_phase + (i * 0.25), 1.0);
            QColor ring = m_color;
            ring.setAlphaF(0.06 + ((1.0 - factor) * 0.10));
            painter.setPen(Qt::NoPen);
            painter.setBrush(ring);
            const qreal radius = base + (factor * qMin(width(), height()) * 0.34);
            painter.drawEllipse(center, radius, radius);
        }
        QRadialGradient glow(center, base * 2.2);
        glow.setColorAt(0.0, QColor("#fff7fb"));
        glow.setColorAt(0.35, m_color.lighter(155));
        glow.setColorAt(1.0, QColor(32, 16, 24, 0));
        painter.setBrush(glow);
        painter.drawEllipse(center, base * 1.8, base * 1.8);
    }

private:
    QColor m_color = QColor("#f05c86");
    qreal m_phase = 0.0;
    QTimer *m_timer = nullptr;
};

}

ReconLivePanel::ReconLivePanel(QWidget *parent)
    : QFrame(parent)
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(18);

    auto *feedCard = new QFrame(this);
    feedCard->setObjectName("cardPanel");
    auto *feedLayout = new QVBoxLayout(feedCard);
    feedLayout->setContentsMargins(20, 20, 20, 20);
    feedLayout->setSpacing(12);
    auto *feedHeader = new QHBoxLayout();
    auto *feedTitle = new QLabel(tr("Canli Islem Konsolu"), feedCard);
    feedTitle->setObjectName("sectionTitle");
    auto *feedInfo = new QLabel(tr("Tarayicinin attigi her adim burada terminal akisi gibi gorunur. Her kayit zaman damgasi ve gecen sure ile yazilir."), feedCard);
    feedInfo->setObjectName("mutedText");
    feedInfo->setWordWrap(true);
    m_pulseWidget = new ReconPulseWidget(feedCard);
    m_feedConsole = new QPlainTextEdit(feedCard);
    m_feedConsole->setReadOnly(true);
    m_feedConsole->setMinimumHeight(148);
    m_feedConsole->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_feedConsole->setPlaceholderText(tr("[hazir] Tarama baslatildiginda canli adimlar burada gorunecek."));
    feedHeader->addWidget(feedTitle);
    feedHeader->addStretch();
    feedHeader->addWidget(m_pulseWidget);
    feedLayout->addLayout(feedHeader);
    feedLayout->addWidget(feedInfo);
    feedLayout->addWidget(m_feedConsole);

    auto *opsCard = new QFrame(this);
    opsCard->setObjectName("cardPanel");
    auto *opsLayout = new QHBoxLayout(opsCard);
    opsLayout->setContentsMargins(20, 20, 20, 20);
    opsLayout->setSpacing(18);
    auto *opsTextLayout = new QVBoxLayout();
    opsTextLayout->setSpacing(10);
    auto *opsTitle = new QLabel(tr("Canli Tarama Durumu"), opsCard);
    opsTitle->setObjectName("sectionTitle");
    m_activityValue = new QLabel(tr("Hazir. Baslattiginda DNS, web guvenligi, port ve OSINT adimlari burada canli gorunur."), opsCard);
    m_activityValue->setObjectName("mutedText");
    m_activityValue->setWordWrap(true);
    m_progressBar = new QProgressBar(opsCard);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(false);
    m_phaseSummaryValue = new QLabel(tr("Hazir"), opsCard);
    m_phaseSummaryValue->setObjectName("mutedText");
    m_phaseSummaryValue->setWordWrap(true);
    opsTextLayout->addWidget(opsTitle);
    opsTextLayout->addWidget(m_activityValue);
    opsTextLayout->addWidget(m_progressBar);
    opsTextLayout->addWidget(m_phaseSummaryValue);
    opsTextLayout->addStretch();
    opsLayout->addLayout(opsTextLayout, 1);

    root->addWidget(feedCard);
    root->addWidget(opsCard);
}
