#include "pengucorewidget.h"

#include "pengucore/api/pengucoresessionreportservice.h"
#include "modules/pengucore/pengucoremodule.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"
#include "ui/views/pengucore/pengucorebrowserpanel.h"
#include "ui/views/pengucore/pengucorecontrolpanel.h"
#include "ui/views/pengucore/pengucorefilterpanel.h"
#include "ui/views/pengucore/pengucoreinspectorpanel.h"
#include "ui/views/pengucore/pengucoresessionpanel.h"

#include <QClipboard>
#include <QComboBox>
#include <QDialog>
#include <QDesktopServices>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QFrame>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMap>
#include <QMenu>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTabBar>
#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextEdit>
#include <QTextStream>
#include <QUrl>
#include <QVBoxLayout>
#include <QtEndian>

#include <algorithm>

using pengufoce::pengucore::FlowStats;
using pengufoce::pengucore::PacketRecord;
using pengufoce::pengucore::ProtocolLayer;

namespace {

quint16 readBig16Safe(const QByteArray &bytes, int offset)
{
    return qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(bytes.constData() + offset));
}

QByteArray extractPacketPayload(const PacketRecord &packet)
{
    const QByteArray &bytes = packet.rawFrame.bytes;
    if (bytes.size() < 34 || packet.networkLayer != pengufoce::pengucore::NetworkLayerType::IPv4) {
        return {};
    }

    const int ipOffset = 14;
    const quint8 versionIhl = static_cast<quint8>(bytes[ipOffset]);
    const int ipHeaderLength = static_cast<int>((versionIhl & 0x0F) * 4);
    const int transportOffset = ipOffset + ipHeaderLength;
    if (transportOffset >= bytes.size()) {
        return {};
    }

    if (packet.transportLayer == pengufoce::pengucore::TransportLayerType::Tcp) {
        if (bytes.size() < transportOffset + 20) {
            return {};
        }
        const int tcpHeaderLength = static_cast<int>((static_cast<quint8>(bytes[transportOffset + 12]) >> 4) * 4);
        const int payloadOffset = transportOffset + tcpHeaderLength;
        return payloadOffset < bytes.size() ? bytes.mid(payloadOffset) : QByteArray{};
    }

    if (packet.transportLayer == pengufoce::pengucore::TransportLayerType::Udp) {
        const int payloadOffset = transportOffset + 8;
        return payloadOffset < bytes.size() ? bytes.mid(payloadOffset) : QByteArray{};
    }

    return {};
}

quint32 extractTcpSequenceNumber(const PacketRecord &packet)
{
    const QByteArray &bytes = packet.rawFrame.bytes;
    if (bytes.size() < 38 || packet.networkLayer != pengufoce::pengucore::NetworkLayerType::IPv4
        || packet.transportLayer != pengufoce::pengucore::TransportLayerType::Tcp) {
        return 0;
    }

    const int ipOffset = 14;
    const quint8 versionIhl = static_cast<quint8>(bytes[ipOffset]);
    const int ipHeaderLength = static_cast<int>((versionIhl & 0x0F) * 4);
    const int transportOffset = ipOffset + ipHeaderLength;
    if (bytes.size() < transportOffset + 8) {
        return 0;
    }

    return qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(bytes.constData() + transportOffset + 4));
}

QString payloadPreview(const QByteArray &payload)
{
    if (payload.isEmpty()) {
        return QStringLiteral("[no payload]");
    }

    QString text = QString::fromLatin1(payload);
    for (QChar &ch : text) {
        if (!ch.isPrint() && !ch.isSpace()) {
            ch = QLatin1Char('.');
        }
    }
    text.replace(QStringLiteral("\r"), QString());
    text.replace(QLatin1Char('\n'), QStringLiteral(" "));
    return text.left(180).trimmed();
}

struct ReassembledStreamResult
{
    QByteArray payload;
    int segmentCount = 0;
    int gapCount = 0;
    int overlapCount = 0;
    bool tcpSequenceAware = false;
};

ReassembledStreamResult reassemblePackets(const QList<const PacketRecord *> &packets)
{
    ReassembledStreamResult result;
    if (packets.isEmpty()) {
        return result;
    }

    result.segmentCount = packets.size();
    QList<const PacketRecord *> sortedPackets = packets;
    std::sort(sortedPackets.begin(), sortedPackets.end(), [](const PacketRecord *left, const PacketRecord *right) {
        if (left == nullptr || right == nullptr) {
            return left < right;
        }
        const quint32 leftSeq = extractTcpSequenceNumber(*left);
        const quint32 rightSeq = extractTcpSequenceNumber(*right);
        if (leftSeq == rightSeq) {
            return left->rawFrame.frameNumber < right->rawFrame.frameNumber;
        }
        return leftSeq < rightSeq;
    });

    quint32 currentSeq = 0;
    bool hasCurrentSeq = false;
    for (const PacketRecord *packet : sortedPackets) {
        if (!packet) {
            continue;
        }
        const QByteArray payload = extractPacketPayload(*packet);
        if (payload.isEmpty()) {
            continue;
        }

        if (packet->transportLayer == pengufoce::pengucore::TransportLayerType::Tcp) {
            result.tcpSequenceAware = true;
            const quint32 seq = extractTcpSequenceNumber(*packet);
            if (!hasCurrentSeq) {
                result.payload.append(payload);
                currentSeq = seq + static_cast<quint32>(payload.size());
                hasCurrentSeq = true;
            } else if (seq > currentSeq) {
                ++result.gapCount;
                result.payload.append(QByteArray("[GAP]"));
                result.payload.append(payload);
                currentSeq = seq + static_cast<quint32>(payload.size());
            } else {
                const qint64 overlapBytes = static_cast<qint64>(currentSeq) - static_cast<qint64>(seq);
                if (overlapBytes > 0) {
                    ++result.overlapCount;
                    if (overlapBytes < payload.size()) {
                        result.payload.append(payload.mid(static_cast<int>(overlapBytes)));
                    }
                    currentSeq = std::max(currentSeq, seq + static_cast<quint32>(payload.size()));
                } else {
                    result.payload.append(payload);
                    currentSeq = seq + static_cast<quint32>(payload.size());
                }
            }
        } else {
            result.payload.append(payload);
        }

        if (result.payload.size() >= 4096) {
            result.payload = result.payload.left(4096);
            break;
        }
    }

    return result;
}

QString reassembledPayloadPreview(const QList<const PacketRecord *> &packets)
{
    const ReassembledStreamResult result = reassemblePackets(packets);
    if (result.payload.isEmpty()) {
        return QStringLiteral("[no payload]");
    }
    return payloadPreview(result.payload);
}

QString reassemblySummaryText(const QList<const PacketRecord *> &packets)
{
    const ReassembledStreamResult result = reassemblePackets(packets);
    if (result.segmentCount == 0) {
        return QStringLiteral("segments=0");
    }

    QStringList parts;
    parts << QStringLiteral("segments=%1").arg(result.segmentCount);
    if (result.tcpSequenceAware) {
        parts << QStringLiteral("tcp-seq=on");
    }
    parts << QStringLiteral("gaps=%1").arg(result.gapCount);
    parts << QStringLiteral("overlaps=%1").arg(result.overlapCount);
    parts << QStringLiteral("bytes=%1").arg(result.payload.size());
    return parts.join(QStringLiteral(" | "));
}

QString packetDirectionText(const PacketRecord &packet, const FlowStats &flow)
{
    const bool forward = packet.sourceEndpoint.startsWith(flow.key.sourceAddress)
                         && packet.destinationEndpoint.startsWith(flow.key.destinationAddress);
    return forward ? QStringLiteral("CLIENT -> SERVER") : QStringLiteral("SERVER -> CLIENT");
}

QString sequenceLabelForPacket(const PacketRecord &packet)
{
    if (packet.transportLayer != pengufoce::pengucore::TransportLayerType::Tcp) {
        return {};
    }
    return QStringLiteral("  TCP Sequence: %1").arg(extractTcpSequenceNumber(packet));
}

QString payloadLabelForPacket(const PacketRecord &packet)
{
    return QStringLiteral("  Payload: %1").arg(payloadPreview(extractPacketPayload(packet)));
}

QString streamHeadingText(const QString &direction, const QList<const PacketRecord *> &packets)
{
    return QStringLiteral("[%1]  %2").arg(direction, reassemblySummaryText(packets));
}

QString buildFlowDirectionSection(const QString &direction, const QList<const PacketRecord *> &packets)
{
    if (packets.isEmpty()) {
        return {};
    }

    QStringList lines;
    lines << streamHeadingText(direction, packets);
    for (const PacketRecord *packet : packets) {
        if (!packet) {
            continue;
        }
        lines << QStringLiteral("#%1  %2").arg(packet->rawFrame.frameNumber).arg(packet->summary);
        lines << QStringLiteral("  %1 -> %2").arg(packet->sourceEndpoint, packet->destinationEndpoint);
        const QString seqLabel = sequenceLabelForPacket(*packet);
        if (!seqLabel.isEmpty()) {
            lines << seqLabel;
        }
        lines << payloadLabelForPacket(*packet);
        lines << QString();
    }
    lines << QStringLiteral("  Reassembled Preview: %1").arg(reassembledPayloadPreview(packets));
    return lines.join('\n');
}

QString buildDirectionalReassemblySummary(const QList<const PacketRecord *> &forwardPackets,
                                          const QList<const PacketRecord *> &reversePackets)
{
    QStringList lines;
    lines << QStringLiteral("[Reassembled Preview]");
    lines << QStringLiteral("CLIENT -> SERVER: %1").arg(reassembledPayloadPreview(forwardPackets));
    lines << QStringLiteral("  %1").arg(reassemblySummaryText(forwardPackets));
    lines << QStringLiteral("SERVER -> CLIENT: %1").arg(reassembledPayloadPreview(reversePackets));
    lines << QStringLiteral("  %1").arg(reassemblySummaryText(reversePackets));
    return lines.join('\n');
}

QString buildStreamSectionsForFlow(const QVector<PacketRecord> &packets, const FlowStats &flow)
{
    QStringList lines;
    QList<const PacketRecord *> forwardPackets;
    QList<const PacketRecord *> reversePackets;
    for (const PacketRecord &packet : packets) {
        const QString direction = packetDirectionText(packet, flow);
        if (direction == QStringLiteral("CLIENT -> SERVER")) {
            forwardPackets.push_back(&packet);
        } else {
            reversePackets.push_back(&packet);
        }
    }

    const QString forwardSection = buildFlowDirectionSection(QStringLiteral("CLIENT -> SERVER"), forwardPackets);
    if (!forwardSection.isEmpty()) {
        lines << forwardSection << QString();
    }
    const QString reverseSection = buildFlowDirectionSection(QStringLiteral("SERVER -> CLIENT"), reversePackets);
    if (!reverseSection.isEmpty()) {
        lines << reverseSection << QString();
    }
    lines << buildDirectionalReassemblySummary(forwardPackets, reversePackets);
    return lines.join('\n');
}

int countOccurrences(const QString &haystack, const QString &needle)
{
    if (needle.isEmpty()) {
        return 0;
    }
    int count = 0;
    int position = 0;
    while ((position = haystack.indexOf(needle, position, Qt::CaseInsensitive)) >= 0) {
        ++count;
        position += needle.size();
    }
    return count;
}

struct SessionPacketStats
{
    qint64 totalBytes = 0;
    qint64 totalCapturedBytes = 0;
    QDateTime firstPacketUtc;
    QDateTime lastPacketUtc;
    QMap<QString, int> protocolCounts;
};

SessionPacketStats collectSessionPacketStats(const QVector<PacketRecord> &packets)
{
    SessionPacketStats stats;
    for (const PacketRecord &packet : packets) {
        stats.totalBytes += packet.rawFrame.originalLength;
        stats.totalCapturedBytes += packet.rawFrame.capturedLength;
        if (!stats.firstPacketUtc.isValid() || packet.rawFrame.timestampUtc < stats.firstPacketUtc) {
            stats.firstPacketUtc = packet.rawFrame.timestampUtc;
        }
        if (!stats.lastPacketUtc.isValid() || packet.rawFrame.timestampUtc > stats.lastPacketUtc) {
            stats.lastPacketUtc = packet.rawFrame.timestampUtc;
        }

        QString protocol = QStringLiteral("OTHER");
        for (auto it = packet.layers.crbegin(); it != packet.layers.crend(); ++it) {
            const QString layerName = it->name.trimmed();
            if (!layerName.isEmpty() && layerName != QStringLiteral("Raw Frame")) {
                protocol = layerName.toUpper();
                break;
            }
        }
        ++stats.protocolCounts[protocol];
    }
    return stats;
}

} // namespace

PenguCoreWidget::PenguCoreWidget(PenguCoreModule *module, QWidget *parent, bool viewerOnly)
    : QWidget(parent)
    , m_module(module)
    , m_viewerOnly(viewerOnly)
{
    buildUi();
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setSingleShot(true);
    m_refreshTimer->setInterval(350);
    connect(m_refreshTimer, &QTimer::timeout, this, &PenguCoreWidget::refreshState);

    if (m_module && m_module->engine()) {
        connect(m_module, &PenguCoreModule::statusChanged, this, [this](const QString &) {
            scheduleRefresh();
        });
        connect(m_module->engine(), &pengufoce::pengucore::PenguCoreEngine::sessionUpdated, this, &PenguCoreWidget::scheduleRefresh);
        connect(m_module->engine(), &pengufoce::pengucore::PenguCoreEngine::sessionReset, this, &PenguCoreWidget::refreshState);
        connect(m_module->engine(), &pengufoce::pengucore::PenguCoreEngine::liveAdaptersChanged, this, &PenguCoreWidget::refreshLiveCaptureUi);
        connect(m_module->engine(), &pengufoce::pengucore::PenguCoreEngine::liveCaptureStateChanged, this, [this](bool, const QString &) {
            refreshLiveCaptureUi();
            scheduleRefresh();
        });
    }

    refreshState();
    if (!m_viewerOnly) {
        refreshLiveCaptureUi();
    }
}

void PenguCoreWidget::openCaptureDialog()
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    const QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("Capture dosyasi ac"),
        QString(),
        tr("Capture Files (*.pcap *.pcapng);;All Files (*.*)"));
    if (!filePath.isEmpty()) {
        m_module->engine()->openCaptureFile(filePath);
    }
}

void PenguCoreWidget::openLastLiveCaptureWindow()
{
    if (m_module && m_module->engine()) {
        openCaptureInSeparateWindow(m_module->engine()->lastLiveCaptureSavePath());
    }
}

void PenguCoreWidget::scheduleRefresh()
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    if (m_contextMenuOpen) {
        m_refreshDeferredWhileMenuOpen = true;
        return;
    }

    if (m_liveUiPaused) {
        m_refreshDeferredWhileMenuOpen = true;
        return;
    }

    if (!m_viewerOnly && m_module->engine()->isLiveCaptureRunning()) {
        if (m_refreshTimer && !m_refreshTimer->isActive()) {
            m_refreshTimer->start();
        }
        return;
    }

    refreshState();
}

void PenguCoreWidget::buildUi()
{
    auto *root = pengufoce::ui::layout::createPageRoot(this, 12);

    m_workbenchTabs = new QTabBar(this);
    m_workbenchTabs->addTab(tr("Live Monitor"));
    m_workbenchTabs->addTab(tr("Capture Review"));
    m_workbenchTabs->addTab(tr("Flow Analysis"));
    m_workbenchTabs->addTab(tr("Protocol Drilldown"));
    m_workbenchTabs->setExpanding(false);
    m_workbenchTabs->setDrawBase(false);
    if (m_viewerOnly) {
        m_workbenchTabs->setCurrentIndex(1);
    }
    root->addWidget(m_workbenchTabs);

    m_heroPanel = pengufoce::ui::layout::createHeroCard(this, QMargins(24, 24, 24, 24), 10);
    auto *heroLayout = qobject_cast<QVBoxLayout *>(m_heroPanel->layout());

    auto *title = new QLabel(tr("PenguCore"), m_heroPanel);
    title->setObjectName("heroTitle");
    auto *lead = new QLabel(tr("Kendi capture reader, parser pipeline ve flow cekirdegimizi ayni ekranda gelistiriyoruz. Bu alan dosya, oturum ve hizli aksiyonlar icin merkez panel gorevi gorur."), m_heroPanel);
    lead->setObjectName("mutedText");
    lead->setWordWrap(true);

    m_statusValue = new QLabel(m_heroPanel);
    m_statusValue->setObjectName("cardTitle");
    m_statusValue->setWordWrap(true);
    m_workbenchGuideValue = new QLabel(tr("Bu mod packet akisini hizli izlemek icin optimize edildi."), m_heroPanel);
    m_workbenchGuideValue->setObjectName("mutedText");
    m_workbenchGuideValue->setWordWrap(true);
    m_fileValue = new QLabel(tr("Dosya: secilmedi"), m_heroPanel);
    m_fileValue->setObjectName("mutedText");
    m_fileValue->setWordWrap(true);
    m_sessionInfoValue = new QLabel(tr("Oturum bilgisi: henuz capture yuklenmedi"), m_heroPanel);
    m_sessionInfoValue->setObjectName("mutedText");
    m_sessionInfoValue->setWordWrap(true);

    auto *actionHost = new PenguCoreControlPanel(m_viewerOnly, m_heroPanel);
    m_clearButton = actionHost->clearButton();
    m_exportButton = actionHost->exportButton();
    m_exportLiveReportButton = actionHost->exportLiveReportButton();
    m_openLiveFolderButton = actionHost->openLiveFolderButton();
    m_refreshAdaptersButton = actionHost->refreshAdaptersButton();
    m_liveAdapterCombo = actionHost->liveAdapterCombo();
    m_liveFilterEdit = actionHost->liveFilterEdit();
    m_liveSaveFormatCombo = actionHost->liveSaveFormatCombo();
    m_startLiveButton = actionHost->startLiveButton();
    m_stopLiveButton = actionHost->stopLiveButton();

    connect(m_clearButton, &QPushButton::clicked, this, [this]() {
        if (m_module && m_module->engine()) {
            m_module->engine()->clearSession();
        }
    });
    connect(m_exportButton, &QPushButton::clicked, this, &PenguCoreWidget::exportVisibleAnalysis);
    connect(m_exportLiveReportButton, &QPushButton::clicked, this, &PenguCoreWidget::exportLiveSessionReport);
    connect(m_openLiveFolderButton, &QPushButton::clicked, this, &PenguCoreWidget::openLiveCaptureFolder);
    connect(m_refreshAdaptersButton, &QPushButton::clicked, this, [this]() {
        if (m_module && m_module->engine()) {
            m_module->engine()->refreshLiveAdapters();
        }
    });
    connect(m_startLiveButton, &QPushButton::clicked, this, [this]() {
        if (!m_module || !m_module->engine() || !m_liveAdapterCombo) {
            return;
        }
        const QString adapterName = m_liveAdapterCombo->currentData().toString();
        if (!adapterName.isEmpty()) {
            if (m_liveFilterEdit) {
                m_module->engine()->setLiveCaptureFilter(m_liveFilterEdit->text());
            }
            if (m_liveSaveFormatCombo) {
                m_module->engine()->setLiveSaveFormat(m_liveSaveFormatCombo->currentData().toString());
            }
            m_module->engine()->startLiveCapture(adapterName);
        }
    });
    connect(m_stopLiveButton, &QPushButton::clicked, this, [this]() {
        if (m_module && m_module->engine()) {
            m_module->engine()->stopLiveCapture();
        }
    });

    heroLayout->addWidget(title);
    heroLayout->addWidget(lead);
    heroLayout->addWidget(m_statusValue);
    heroLayout->addWidget(m_workbenchGuideValue);
    heroLayout->addWidget(m_fileValue);
    heroLayout->addWidget(m_sessionInfoValue);
    heroLayout->addWidget(actionHost);

    auto *sessionPanel = new PenguCoreSessionPanel(m_heroPanel);
    m_totalPacketsValue = sessionPanel->totalPacketsValue();
    m_visiblePacketsValue = sessionPanel->visiblePacketsValue();
    m_totalFlowsValue = sessionPanel->totalFlowsValue();
    m_visibleFlowsValue = sessionPanel->visibleFlowsValue();
    m_sessionFileCardValue = sessionPanel->sessionFileCardValue();
    m_sessionFormatCardValue = sessionPanel->sessionFormatCardValue();
    m_sessionBytesCardValue = sessionPanel->sessionBytesCardValue();
    m_sessionOpenedCardValue = sessionPanel->sessionOpenedCardValue();
    m_sessionFirstSeenCardValue = sessionPanel->sessionFirstSeenCardValue();
    m_sessionLastSeenCardValue = sessionPanel->sessionLastSeenCardValue();
    m_sessionLiveSaveCardValue = sessionPanel->sessionLiveSaveCardValue();
    m_timelineValue = sessionPanel->timelineValue();
    m_timelineCard = sessionPanel;
    heroLayout->addWidget(sessionPanel);

    auto *filterPanel = new PenguCoreFilterPanel(this);
    m_filterCard = filterPanel->filterCard();
    m_quickActionCard = filterPanel->quickActionCard();
    m_searchEdit = filterPanel->searchEdit();
    m_sourceFilterEdit = filterPanel->sourceFilterEdit();
    m_destinationFilterEdit = filterPanel->destinationFilterEdit();
    m_protocolFilter = filterPanel->protocolFilter();
    m_filterPresetCombo = filterPanel->filterPresetCombo();
    m_toggleInspectorButton = filterPanel->toggleInspectorButton();
    m_toggleHexButton = filterPanel->toggleHexButton();
    m_toggleFlowDetailButton = filterPanel->toggleFlowDetailButton();
    m_pauseLiveUiButton = filterPanel->pauseLiveUiButton();
    m_autoScrollButton = filterPanel->autoScrollButton();
    m_onlyWarningsButton = filterPanel->onlyWarningsButton();
    m_dnsFocusButton = filterPanel->dnsFocusButton();
    m_httpFocusButton = filterPanel->httpFocusButton();

    m_emptyStateCard = new QFrame(this);
    m_emptyStateCard->setObjectName("cardPanel");
    auto *emptyLayout = new QVBoxLayout(m_emptyStateCard);
    emptyLayout->setContentsMargins(22, 20, 22, 20);
    emptyLayout->setSpacing(8);
    m_emptyStateTitle = new QLabel(tr("Analiz oturumu bekleniyor"), m_emptyStateCard);
    m_emptyStateTitle->setObjectName("sectionTitle");
    m_emptyStateBody = new QLabel(
        m_viewerOnly
            ? tr("Ust menuden Dosya > Capture Dosyasi Ac diyerek kayit yukleyebilirsin.")
            : tr("Ust menuden PenguCore > Capture Dosyasi Ac ile kayit ac veya canli akisi baslat."),
        m_emptyStateCard);
    m_emptyStateBody->setObjectName("mutedText");
    m_emptyStateBody->setWordWrap(true);
    emptyLayout->addWidget(m_emptyStateTitle);
    emptyLayout->addWidget(m_emptyStateBody);

    m_workspaceSplitter = new QSplitter(Qt::Horizontal, this);
    m_workspaceSplitter->setChildrenCollapsible(false);
    m_workspaceSplitter->setHandleWidth(10);
    m_workspaceSplitter->setOpaqueResize(false);

    auto *leftWorkspace = new QFrame(m_workspaceSplitter);
    auto *leftWorkspaceLayout = new QVBoxLayout(leftWorkspace);
    leftWorkspaceLayout->setContentsMargins(0, 0, 0, 0);
    leftWorkspaceLayout->setSpacing(0);
    auto *browserPanel = new PenguCoreBrowserPanel(leftWorkspace);
    m_packetList = browserPanel->packetList();
    m_flowList = browserPanel->flowList();
    m_flowDetailView = browserPanel->flowDetailView();
    m_packetApplyFilterButton = browserPanel->packetApplyFilterButton();
    m_packetCopySourceButton = browserPanel->packetCopySourceButton();
    m_packetCopyDestinationButton = browserPanel->packetCopyDestinationButton();
    m_packetSaveRawButton = browserPanel->packetSaveRawButton();
    m_packetSaveRangeButton = browserPanel->packetSaveRangeButton();
    m_packetExportJsonButton = browserPanel->packetExportJsonButton();
    m_packetCopyFieldButton = browserPanel->packetCopyFieldButton();
    m_packetExportFieldButton = browserPanel->packetExportFieldButton();
    m_flowApplyFilterButton = browserPanel->flowApplyFilterButton();
    m_flowIsolateButton = browserPanel->flowIsolateButton();
    m_clearFlowIsolationButton = browserPanel->clearFlowIsolationButton();
    m_exportFlowsButton = browserPanel->exportFlowsButton();
    m_exportFlowStreamButton = browserPanel->exportFlowStreamButton();
    m_exportFlowHexButton = browserPanel->exportFlowHexButton();
    m_exportFlowPacketsButton = browserPanel->exportFlowPacketsButton();
    leftWorkspaceLayout->addWidget(browserPanel, 1);

    m_rightWorkspace = new QFrame(m_workspaceSplitter);
    auto *rightWorkspaceLayout = new QVBoxLayout(m_rightWorkspace);
    rightWorkspaceLayout->setContentsMargins(0, 0, 0, 0);
    rightWorkspaceLayout->setSpacing(16);
    auto *inspectorPanel = new PenguCoreInspectorPanel(m_rightWorkspace);
    m_selectionCard = qobject_cast<QFrame *>(inspectorPanel->selectionCard());
    m_detailCard = qobject_cast<QFrame *>(inspectorPanel->detailCard());
    m_detailSearchEdit = inspectorPanel->detailSearchEdit();
    m_findDetailButton = inspectorPanel->findDetailButton();
    m_findHexButton = inspectorPanel->findHexButton();
    m_findFlowStreamButton = inspectorPanel->findFlowStreamButton();
    m_findFlowStreamPrevButton = inspectorPanel->findFlowStreamPrevButton();
    m_findFlowStreamNextButton = inspectorPanel->findFlowStreamNextButton();
    m_detailView = inspectorPanel->detailView();
    m_hexView = inspectorPanel->hexView();
    rightWorkspaceLayout->addWidget(inspectorPanel, 1);

    m_workspaceSplitter->addWidget(leftWorkspace);
    m_workspaceSplitter->addWidget(m_rightWorkspace);
    m_workspaceSplitter->setStretchFactor(0, 11);
    m_workspaceSplitter->setStretchFactor(1, 10);
    m_workspaceSplitter->setSizes({900, 420});

    if (m_rightWorkspace) {
        m_rightWorkspace->hide();
    }
    if (m_flowDetailView) {
        m_flowDetailView->hide();
    }

    if (!m_viewerOnly && m_heroPanel) {
        root->addWidget(m_heroPanel);
    }
    root->addWidget(filterPanel);
    root->addWidget(m_emptyStateCard);
    root->addWidget(m_workspaceSplitter, 1);

    auto *statusRail = new QFrame(this);
    statusRail->setObjectName("cardPanel");
    auto *statusRailLayout = new QHBoxLayout(statusRail);
    statusRailLayout->setContentsMargins(16, 10, 16, 10);
    statusRailLayout->setSpacing(12);
    m_statusRailValue = new QLabel(tr("Hazir"), statusRail);
    m_statusRailValue->setObjectName("mutedText");
    m_statusRailSelection = new QLabel(tr("Secim: yok"), statusRail);
    m_statusRailSelection->setObjectName("mutedText");
    statusRailLayout->addWidget(m_statusRailValue, 2);
    statusRailLayout->addWidget(m_statusRailSelection, 1);
    root->addWidget(statusRail);

    connect(m_packetList, &QListWidget::currentRowChanged, this, [this](int row) {
        m_selectedPacketIndex = row;
        refreshPacketDetails();
        refreshStatusRail();
    });
    connect(m_packetList, &QListWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        if (!m_packetList) {
            return;
        }

        if (auto *item = m_packetList->itemAt(pos)) {
            m_packetList->setCurrentItem(item);
        }
        const PacketRecord *packet = selectedPacket();
        if (!packet) {
            return;
        }
        const PacketRecord packetSnapshot = *packet;

        QMenu menu(this);
        auto *detailAction = menu.addAction(tr("Detayi Ayri Pencerede Ac"));
        auto *hexAction = menu.addAction(tr("Hex / Raw Ayri Pencerede Ac"));
        m_contextMenuOpen = true;
        auto *selectedAction = menu.exec(m_packetList->viewport()->mapToGlobal(pos));
        m_contextMenuOpen = false;
        if (selectedAction == detailAction) {
            openPacketDetailWindow(packetSnapshot);
        } else if (selectedAction == hexAction) {
            openPacketHexWindow(packetSnapshot);
        }
        if (m_refreshDeferredWhileMenuOpen) {
            m_refreshDeferredWhileMenuOpen = false;
            refreshState();
        }
    });
    connect(m_flowList, &QListWidget::currentRowChanged, this, [this](int row) {
        m_selectedFlowIndex = row;
        refreshFlowDetails();
        refreshStatusRail();
    });
    connect(m_flowList, &QListWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        if (!m_flowList) {
            return;
        }

        if (auto *item = m_flowList->itemAt(pos)) {
            m_flowList->setCurrentItem(item);
        }
        const FlowStats *flow = selectedFlow();
        if (!flow) {
            return;
        }
        const FlowStats flowSnapshot = *flow;

        QMenu menu(this);
        auto *detailAction = menu.addAction(tr("Flow Detayini Ayri Pencerede Ac"));
        auto *streamAction = menu.addAction(tr("Flow Akisini Ayri Pencerede Ac"));
        auto *hexAction = menu.addAction(tr("Flow Hex / Raw Ayri Pencerede Ac"));
        m_contextMenuOpen = true;
        auto *selectedAction = menu.exec(m_flowList->viewport()->mapToGlobal(pos));
        m_contextMenuOpen = false;
        if (selectedAction == detailAction) {
            openFlowDetailWindow(flowSnapshot);
        } else if (selectedAction == streamAction) {
            openFlowStreamWindow(flowSnapshot);
        } else if (selectedAction == hexAction) {
            openFlowHexWindow(flowSnapshot);
        }
        if (m_refreshDeferredWhileMenuOpen) {
            m_refreshDeferredWhileMenuOpen = false;
            refreshState();
        }
    });
    connect(m_searchEdit, &QLineEdit::textChanged, this, [this](const QString &) {
        applyFilters();
    });
    connect(m_sourceFilterEdit, &QLineEdit::textChanged, this, [this](const QString &) {
        applyFilters();
    });
    connect(m_destinationFilterEdit, &QLineEdit::textChanged, this, [this](const QString &) {
        applyFilters();
    });
    connect(m_protocolFilter, &QComboBox::currentTextChanged, this, [this](const QString &) {
        applyFilters();
    });
    connect(m_filterPresetCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        if (!m_filterPresetCombo || !m_liveFilterEdit || index <= 0) {
            return;
        }
        m_liveFilterEdit->setText(m_filterPresetCombo->currentData().toString());
    });
    connect(m_packetApplyFilterButton, &QPushButton::clicked, this, &PenguCoreWidget::applySelectedPacketEndpointsToFilters);
    connect(m_packetCopySourceButton, &QPushButton::clicked, this, [this]() {
        const PacketRecord *packet = selectedPacket();
        if (packet) {
            copyTextToClipboard(packet->sourceEndpoint);
        }
    });
    connect(m_packetCopyDestinationButton, &QPushButton::clicked, this, [this]() {
        const PacketRecord *packet = selectedPacket();
        if (packet) {
            copyTextToClipboard(packet->destinationEndpoint);
        }
    });
    connect(m_packetSaveRawButton, &QPushButton::clicked, this, &PenguCoreWidget::saveSelectedPacketRaw);
    connect(m_packetSaveRangeButton, &QPushButton::clicked, this, &PenguCoreWidget::saveSelectedPacketRange);
    connect(m_packetExportJsonButton, &QPushButton::clicked, this, &PenguCoreWidget::exportSelectedPacketJson);
    connect(m_packetCopyFieldButton, &QPushButton::clicked, this, &PenguCoreWidget::copySelectedDetailField);
    connect(m_packetExportFieldButton, &QPushButton::clicked, this, &PenguCoreWidget::exportSelectedDetailField);
    connect(m_flowApplyFilterButton, &QPushButton::clicked, this, &PenguCoreWidget::applySelectedFlowEndpointsToFilters);
    connect(m_flowIsolateButton, &QPushButton::clicked, this, &PenguCoreWidget::isolateSelectedFlow);
    connect(m_clearFlowIsolationButton, &QPushButton::clicked, this, &PenguCoreWidget::clearFlowIsolation);
    connect(m_exportFlowStreamButton, &QPushButton::clicked, this, &PenguCoreWidget::exportSelectedFlowStream);
    connect(m_exportFlowHexButton, &QPushButton::clicked, this, &PenguCoreWidget::exportSelectedFlowHex);
    connect(m_exportFlowPacketsButton, &QPushButton::clicked, this, &PenguCoreWidget::exportSelectedFlowPacketsCsv);
    connect(m_exportFlowsButton, &QPushButton::clicked, this, [this]() {
        if (!m_module || !m_module->engine()) {
            return;
        }
        const QString filePath = QFileDialog::getSaveFileName(
            this,
            tr("Flow analizini disa aktar"),
            QStringLiteral("pengucore_flows.json"),
            tr("JSON Files (*.json);;CSV Files (*.csv)"));
        if (filePath.isEmpty()) {
            return;
        }
        const bool exportCsv = filePath.endsWith(QStringLiteral(".csv"), Qt::CaseInsensitive);
        const auto &flows = m_module->engine()->flows();
        if (exportCsv) {
            QFile file(filePath);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
                return;
            }
            QTextStream stream(&file);
            stream << "source_address,source_port,destination_address,destination_port,transport,packet_count,byte_count,first_seen_utc,last_seen_utc\n";
            for (int index : std::as_const(m_visibleFlowIndices)) {
                if (index < 0 || index >= flows.size()) {
                    continue;
                }
                const FlowStats &flow = flows[index];
                stream << '"' << flow.key.sourceAddress << '"' << ','
                       << flow.key.sourcePort << ','
                       << '"' << flow.key.destinationAddress << '"' << ','
                       << flow.key.destinationPort << ','
                       << '"' << flow.key.transport << '"' << ','
                       << flow.packetCount << ','
                       << flow.byteCount << ','
                       << '"' << flow.firstSeenUtc.toString(Qt::ISODateWithMs) << '"' << ','
                       << '"' << flow.lastSeenUtc.toString(Qt::ISODateWithMs) << '"' << '\n';
            }
            file.close();
            return;
        }
        QJsonArray flowsArray;
        for (int index : std::as_const(m_visibleFlowIndices)) {
            if (index < 0 || index >= flows.size()) {
                continue;
            }
            const FlowStats &flow = flows[index];
            QJsonObject flowObject;
            flowObject.insert(QStringLiteral("source_address"), flow.key.sourceAddress);
            flowObject.insert(QStringLiteral("source_port"), static_cast<int>(flow.key.sourcePort));
            flowObject.insert(QStringLiteral("destination_address"), flow.key.destinationAddress);
            flowObject.insert(QStringLiteral("destination_port"), static_cast<int>(flow.key.destinationPort));
            flowObject.insert(QStringLiteral("transport"), flow.key.transport);
            flowObject.insert(QStringLiteral("packet_count"), flow.packetCount);
            flowObject.insert(QStringLiteral("byte_count"), QString::number(flow.byteCount));
            flowObject.insert(QStringLiteral("first_seen_utc"), flow.firstSeenUtc.toString(Qt::ISODateWithMs));
            flowObject.insert(QStringLiteral("last_seen_utc"), flow.lastSeenUtc.toString(Qt::ISODateWithMs));
            flowsArray.append(flowObject);
        }
        QFile file(filePath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            return;
        }
        file.write(QJsonDocument(flowsArray).toJson(QJsonDocument::Indented));
        file.close();
    });
    connect(m_workbenchTabs, &QTabBar::currentChanged, this, [this](int) {
        refreshWorkbenchLayout();
    });
    connect(m_toggleInspectorButton, &QPushButton::clicked, this, [this]() {
        m_inspectorVisible = !m_inspectorVisible;
        updateInspectorVisibility();
        refreshWorkbenchLayout();
    });
    connect(m_toggleHexButton, &QPushButton::clicked, this, [this]() {
        m_inspectorVisible = true;
        updateInspectorVisibility();
        if (m_detailView) {
            m_detailView->setFocus();
        }
        refreshWorkbenchLayout();
    });
    connect(m_toggleFlowDetailButton, &QPushButton::clicked, this, [this]() {
        m_flowDetailVisible = !m_flowDetailVisible;
        updateInspectorVisibility();
    });
    connect(m_pauseLiveUiButton, &QPushButton::clicked, this, [this]() {
        m_liveUiPaused = !m_liveUiPaused;
        if (!m_liveUiPaused && m_refreshDeferredWhileMenuOpen) {
            m_refreshDeferredWhileMenuOpen = false;
            refreshState();
        }
        refreshStatusRail();
    });
    connect(m_autoScrollButton, &QPushButton::clicked, this, [this]() {
        m_autoScrollEnabled = !m_autoScrollEnabled;
        refreshStatusRail();
    });
    connect(m_onlyWarningsButton, &QPushButton::clicked, this, [this]() {
        m_onlyWarnings = !m_onlyWarnings;
        applyFilters();
        refreshStatusRail();
    });
    connect(m_dnsFocusButton, &QPushButton::clicked, this, &PenguCoreWidget::focusOnDns);
    connect(m_httpFocusButton, &QPushButton::clicked, this, &PenguCoreWidget::focusOnHttp);
    connect(m_findDetailButton, &QPushButton::clicked, this, &PenguCoreWidget::findInDetailView);
    connect(m_findHexButton, &QPushButton::clicked, this, &PenguCoreWidget::findInHexView);
    connect(m_findFlowStreamButton, &QPushButton::clicked, this, &PenguCoreWidget::findInSelectedFlowStream);
    connect(m_findFlowStreamPrevButton, &QPushButton::clicked, this, &PenguCoreWidget::findInSelectedFlowStream);
    connect(m_findFlowStreamNextButton, &QPushButton::clicked, this, &PenguCoreWidget::findInSelectedFlowStream);
    connect(m_detailSearchEdit, &QLineEdit::returnPressed, this, &PenguCoreWidget::findInDetailView);
    connect(m_detailView, &QPlainTextEdit::cursorPositionChanged, this, [this]() {
        if (!m_detailView) {
            return;
        }
        const QString lineText = m_detailView->textCursor().block().text();
        const int markerIndex = lineText.indexOf(QStringLiteral("@0x"));
        if (markerIndex < 0) {
            return;
        }
        const QString offsetHex = lineText.mid(markerIndex + 3, 4);
        const int lenIndex = lineText.indexOf(QStringLiteral("len="), markerIndex);
        bool offsetOk = false;
        bool lengthOk = false;
        const int offset = offsetHex.toInt(&offsetOk, 16);
        const int length = lenIndex >= 0 ? lineText.mid(lenIndex + 4).toInt(&lengthOk) : 0;
        if (offsetOk) {
            focusHexOffset(offset, lengthOk ? length : 0);
        }
    });

    updateInspectorVisibility();
    refreshWorkbenchLayout();
}

void PenguCoreWidget::refreshState()
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    if (m_contextMenuOpen) {
        m_refreshDeferredWhileMenuOpen = true;
        return;
    }

    const auto *engine = m_module->engine();
    if (m_statusValue) {
        m_statusValue->setText(engine->statusText());
    }
    if (m_fileValue) {
        m_fileValue->setText(engine->lastOpenedFile().isEmpty()
                                 ? tr("Dosya: secilmedi")
                                 : tr("Dosya: %1").arg(engine->lastOpenedFile()));
    }
    refreshSessionInfo();
    if (m_sessionFileCardValue || m_sessionFormatCardValue || m_sessionBytesCardValue
        || m_sessionOpenedCardValue || m_sessionFirstSeenCardValue || m_sessionLastSeenCardValue
        || m_sessionLiveSaveCardValue || m_timelineValue) {
        const auto &packets = engine->packets();
        const SessionPacketStats stats = collectSessionPacketStats(packets);

        const QString fileName = QFileInfo(engine->lastOpenedFile()).fileName();
        const QString formatText = engine->lastOpenedFormat().isEmpty() ? QStringLiteral("--") : engine->lastOpenedFormat();
        const QString loadedText = engine->lastSessionOpenedUtc().isValid()
                                       ? engine->lastSessionOpenedUtc().toString(Qt::ISODateWithMs)
                                       : QStringLiteral("--");
        const QString firstSeenText = stats.firstPacketUtc.isValid() ? stats.firstPacketUtc.toString(Qt::ISODateWithMs) : QStringLiteral("--");
        const QString lastSeenText = stats.lastPacketUtc.isValid() ? stats.lastPacketUtc.toString(Qt::ISODateWithMs) : QStringLiteral("--");
        const QString liveSaveText = engine->lastLiveCaptureSavePath().isEmpty()
                                         ? QStringLiteral("--")
                                         : QFileInfo(engine->lastLiveCaptureSavePath()).fileName();

        if (m_sessionFileCardValue) {
            m_sessionFileCardValue->setText(fileName.isEmpty() ? QStringLiteral("--") : fileName);
        }
        if (m_sessionFormatCardValue) {
            m_sessionFormatCardValue->setText(formatText);
        }
        if (m_sessionBytesCardValue) {
            m_sessionBytesCardValue->setText(packets.isEmpty() ? QStringLiteral("--") : QString::number(stats.totalBytes));
        }
        if (m_sessionOpenedCardValue) {
            m_sessionOpenedCardValue->setText(loadedText);
        }
        if (m_sessionFirstSeenCardValue) {
            m_sessionFirstSeenCardValue->setText(firstSeenText);
        }
        if (m_sessionLastSeenCardValue) {
            m_sessionLastSeenCardValue->setText(lastSeenText);
        }
        if (m_sessionLiveSaveCardValue) {
            m_sessionLiveSaveCardValue->setText(liveSaveText);
        }
        if (m_timelineValue) {
            m_timelineValue->setText(buildTimelineText());
        }
    }

    if (m_totalPacketsValue) {
        m_totalPacketsValue->setText(QString::number(engine->packets().size()));
    }
    if (m_totalFlowsValue) {
        m_totalFlowsValue->setText(QString::number(engine->flows().size()));
    }

    applyFilters();
    refreshPacketDetails();
    refreshFlowDetails();
    refreshLiveCaptureUi();
    refreshWorkbenchLayout();
    refreshStatusRail();
}

void PenguCoreWidget::refreshPacketDetails()
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    const PacketRecord *packet = selectedPacket();
    if (!packet) {
        if (m_detailView) {
            m_detailView->setPlainText(tr("Henüz packet seçilmedi.\n\nSoldaki Packet Browser alanından bir kayıt seçtiğinde protokol katmanları burada görünecek."));
        }
        if (m_hexView) {
            m_hexView->setPlainText(tr("Hex / raw görünümü için bir packet seç."));
        }
        return;
    }

    if (m_detailView) {
        m_detailView->setPlainText(buildPacketDetailText(*packet));
    }

    if (m_hexView) {
        m_hexView->setPlainText(formatHexView(*packet));
    }
}

QString PenguCoreWidget::buildPacketDetailText(const PacketRecord &packet) const
{
    QStringList lines;
    lines << QStringLiteral("Frame #%1").arg(packet.rawFrame.frameNumber);
    if (!packet.warnings.isEmpty()) {
        lines << QStringLiteral("State: MALFORMED / WARNING");
    }
    lines << QStringLiteral("Summary: %1").arg(packet.summary);
    lines << QStringLiteral("Endpoints: %1 -> %2").arg(packet.sourceEndpoint, packet.destinationEndpoint);
    lines << QString();

    for (const ProtocolLayer &layer : packet.layers) {
        lines << QStringLiteral("[%1]").arg(layer.name);
        for (const auto &field : layer.fields) {
            QString metadata;
            if (field.offset >= 0) {
                metadata = QStringLiteral("  @0x%1 len=%2")
                               .arg(field.offset, 4, 16, QLatin1Char('0'))
                               .arg(field.length);
            }
            lines << QStringLiteral("  %1: %2%3").arg(field.name, field.value, metadata);
        }
        lines << QString();
    }

    if (!packet.warnings.isEmpty()) {
        lines << QStringLiteral("[Warnings]");
        for (const QString &warning : packet.warnings) {
            lines << QStringLiteral("  %1").arg(warning);
        }
    }

    return lines.join('\n');
}

QString PenguCoreWidget::formatHexView(const PacketRecord &packet) const
{
    if (packet.rawFrame.bytes.isEmpty()) {
        return tr("Ham veri yok.");
    }

    QStringList lines;
    const QByteArray &bytes = packet.rawFrame.bytes;
    for (int offset = 0; offset < bytes.size(); offset += 16) {
        QString hex;
        QString ascii;
        const int end = std::min(offset + 16, static_cast<int>(bytes.size()));
        for (int i = offset; i < end; ++i) {
            const unsigned char byte = static_cast<unsigned char>(bytes[i]);
            hex += QStringLiteral("%1 ").arg(byte, 2, 16, QLatin1Char('0')).toUpper();
            ascii += (byte >= 32 && byte <= 126) ? QChar(byte) : QChar('.');
        }
        lines << QStringLiteral("%1  %2 %3")
                     .arg(offset, 4, 16, QLatin1Char('0'))
                     .arg(hex.leftJustified(16 * 3, QLatin1Char(' ')))
                     .arg(ascii);
    }

    return lines.join('\n');
}

void PenguCoreWidget::applyFilters()
{
    if (!m_module || !m_module->engine() || !m_packetList) {
        return;
    }

    const auto &packets = m_module->engine()->packets();
    const auto &flows = m_module->engine()->flows();
    const int previousVisibleSelection = m_selectedPacketIndex;
    const int previousFlowSelection = m_selectedFlowIndex;
    m_visiblePacketIndices.clear();
    m_visibleFlowIndices.clear();
    m_packetList->clear();
    if (m_flowList) {
        m_flowList->clear();
    }

    if (m_isolatedFlowEngineIndex >= flows.size()) {
        m_isolatedFlowEngineIndex = -1;
    }

    for (int i = 0; i < packets.size(); ++i) {
        const PacketRecord &packet = packets[i];
        if (!packetMatchesFilters(packet)) {
            continue;
        }
        if (m_isolatedFlowEngineIndex >= 0 && !packetMatchesFlow(packet, flows[m_isolatedFlowEngineIndex])) {
            continue;
        }

        m_visiblePacketIndices.push_back(i);
        auto *item = new QListWidgetItem(packetListLabel(packet));
        item->setForeground(protocolAccentColor(primaryProtocolLabel(packet), !packet.warnings.isEmpty()));
        m_packetList->addItem(item);
    }

    for (int i = 0; i < flows.size(); ++i) {
        const FlowStats &flow = flows[i];
        if (!flowMatchesVisiblePackets(flow)) {
            continue;
        }

        m_visibleFlowIndices.push_back(i);
        if (m_flowList) {
            QString label = QStringLiteral("%1:%2 -> %3:%4  %5  [%6 paket]")
                                .arg(flow.key.sourceAddress)
                                .arg(flow.key.sourcePort)
                                .arg(flow.key.destinationAddress)
                                .arg(flow.key.destinationPort)
                                .arg(flow.key.transport)
                                .arg(flow.packetCount);
            if (i == m_isolatedFlowEngineIndex) {
                label.prepend(QStringLiteral("[ISOLE] "));
            }
            auto *item = new QListWidgetItem(label);
            item->setForeground(protocolAccentColor(flow.key.transport, false));
            m_flowList->addItem(item);
        }
    }

    if (!m_visiblePacketIndices.isEmpty()) {
        m_selectedPacketIndex = qBound(0,
                                       previousVisibleSelection < 0 ? 0 : previousVisibleSelection,
                                       m_visiblePacketIndices.size() - 1);
        m_packetList->setCurrentRow(m_selectedPacketIndex);
    } else {
        m_selectedPacketIndex = -1;
        refreshPacketDetails();
    }

    if (!m_visibleFlowIndices.isEmpty() && m_flowList) {
        int nextFlowRow = 0;
        if (m_isolatedFlowEngineIndex >= 0) {
            const int isolatedVisibleRow = m_visibleFlowIndices.indexOf(m_isolatedFlowEngineIndex);
            nextFlowRow = isolatedVisibleRow >= 0 ? isolatedVisibleRow : 0;
        } else {
            nextFlowRow = qBound(0,
                                 previousFlowSelection < 0 ? 0 : previousFlowSelection,
                                 m_visibleFlowIndices.size() - 1);
        }
        m_selectedFlowIndex = nextFlowRow;
        m_flowList->setCurrentRow(m_selectedFlowIndex);
    } else {
        m_selectedFlowIndex = -1;
        refreshFlowDetails();
    }

    if (m_visiblePacketsValue) {
        m_visiblePacketsValue->setText(QString::number(m_visiblePacketIndices.size()));
    }
    if (m_visibleFlowsValue) {
        m_visibleFlowsValue->setText(QString::number(m_visibleFlowIndices.size()));
    }
    if (m_emptyStateCard) {
        m_emptyStateCard->setVisible(m_visiblePacketIndices.isEmpty());
    }
    if (m_autoScrollEnabled && !m_visiblePacketIndices.isEmpty() && m_packetList
        && m_module && m_module->engine() && m_module->engine()->isLiveCaptureRunning()) {
        m_selectedPacketIndex = m_visiblePacketIndices.size() - 1;
        m_packetList->setCurrentRow(m_selectedPacketIndex);
        m_packetList->scrollToBottom();
    }
    refreshStatusRail();
}

bool PenguCoreWidget::packetMatchesFilters(const PacketRecord &packet) const
{
    const QString searchText = m_searchEdit ? m_searchEdit->text().trimmed().toLower() : QString();
    const QString sourceText = m_sourceFilterEdit ? m_sourceFilterEdit->text().trimmed().toLower() : QString();
    const QString destinationText = m_destinationFilterEdit ? m_destinationFilterEdit->text().trimmed().toLower() : QString();
    const QString protocolText = m_protocolFilter ? m_protocolFilter->currentText().trimmed().toLower() : QString();

    if (!sourceText.isEmpty() && !packet.sourceEndpoint.toLower().contains(sourceText)) {
        return false;
    }
    if (!destinationText.isEmpty() && !packet.destinationEndpoint.toLower().contains(destinationText)) {
        return false;
    }
    if (m_onlyWarnings && packet.warnings.isEmpty()) {
        return false;
    }

    if (!protocolText.isEmpty() && protocolText != tr("Tum Protokoller").toLower()) {
        bool protocolMatched = false;
        for (const ProtocolLayer &layer : packet.layers) {
            if (layer.name.toLower() == protocolText) {
                protocolMatched = true;
                break;
            }
        }

        if (!protocolMatched) {
            if (protocolText == QStringLiteral("ipv4") && packet.networkLayer == pengufoce::pengucore::NetworkLayerType::IPv4) {
                protocolMatched = true;
            } else if (protocolText == QStringLiteral("arp") && packet.networkLayer == pengufoce::pengucore::NetworkLayerType::Arp) {
                protocolMatched = true;
            }
        }

        if (!protocolMatched) {
            return false;
        }
    }

    if (!searchText.isEmpty()) {
        QString haystack = QStringLiteral("%1 %2 %3")
                               .arg(packet.summary.toLower(),
                                    packet.sourceEndpoint.toLower(),
                                    packet.destinationEndpoint.toLower());
        for (const ProtocolLayer &layer : packet.layers) {
            haystack += QLatin1Char(' ');
            haystack += layer.name.toLower();
            for (const auto &field : layer.fields) {
                haystack += QLatin1Char(' ');
                haystack += field.name.toLower();
                haystack += QLatin1Char(' ');
                haystack += field.value.toLower();
            }
        }

        if (!haystack.contains(searchText)) {
            return false;
        }
    }

    return true;
}

bool PenguCoreWidget::flowMatchesVisiblePackets(const FlowStats &flow) const
{
    if (!m_module || !m_module->engine()) {
        return false;
    }

    const auto &packets = m_module->engine()->packets();
    for (int packetIndex : m_visiblePacketIndices) {
        if (packetIndex < 0 || packetIndex >= packets.size()) {
            continue;
        }

        if (packetMatchesFlow(packets[packetIndex], flow)) {
            return true;
        }
    }

    return false;
}

bool PenguCoreWidget::packetMatchesFlow(const PacketRecord &packet, const FlowStats &flow) const
{
    const QString sourceEndpoint = QStringLiteral("%1:%2").arg(flow.key.sourceAddress).arg(flow.key.sourcePort);
    const QString destinationEndpoint = QStringLiteral("%1:%2").arg(flow.key.destinationAddress).arg(flow.key.destinationPort);
    return packet.sourceEndpoint == sourceEndpoint
           && packet.destinationEndpoint == destinationEndpoint;
}

void PenguCoreWidget::refreshFlowDetails()
{
    if (!m_module || !m_module->engine() || !m_flowDetailView) {
        return;
    }

    const FlowStats *flow = selectedFlow();
    if (!flow) {
        m_flowDetailView->setPlainText(tr("Henüz flow seçilmedi.\n\nFlow Intelligence alanından bir akış seçtiğinde toplam bilgiler burada gösterilecek."));
        return;
    }

    m_flowDetailView->setPlainText(buildFlowDetailText(*flow));
}

QString PenguCoreWidget::buildFlowDetailText(const FlowStats &flow) const
{
    int flowIndex = -1;
    if (m_selectedFlowIndex >= 0 && m_selectedFlowIndex < m_visibleFlowIndices.size()) {
        flowIndex = m_visibleFlowIndices[m_selectedFlowIndex];
    }

    int forwardPackets = 0;
    int reversePackets = 0;
    quint64 forwardBytes = 0;
    quint64 reverseBytes = 0;
    QMap<QString, int> protocolCounts;
    QMap<QString, int> tcpFlagCounts;
    QMap<QString, int> applicationCounts;
    QMap<QString, int> forwardApplicationCounts;
    QMap<QString, int> reverseApplicationCounts;
    QMap<QString, int> forwardSemanticCounts;
    QMap<QString, int> reverseSemanticCounts;
    int httpRequestCount = 0;
    int httpResponseCount = 0;
    int dnsQueryCount = 0;
    int dnsResponseCount = 0;
    QStringList handshakeSummary;
    QStringList forwardHandshakeSummary;
    QStringList reverseHandshakeSummary;
    if (m_module && m_module->engine()) {
        for (const PacketRecord &packet : m_module->engine()->packets()) {
            if (!packetMatchesFlow(packet, flow)) {
                continue;
            }
            const bool forward = packet.sourceEndpoint.startsWith(flow.key.sourceAddress)
                                 && packet.destinationEndpoint.startsWith(flow.key.destinationAddress);
            protocolCounts[primaryProtocolLabel(packet)] += 1;
            for (const ProtocolLayer &layer : packet.layers) {
                if (layer.name == QStringLiteral("TCP")) {
                    for (const auto &field : layer.fields) {
                        if (field.name == QStringLiteral("Flags") && !field.value.isEmpty()) {
                            tcpFlagCounts[field.value] += 1;
                        }
                    }
                } else if (layer.name == QStringLiteral("TLS") || layer.name == QStringLiteral("HTTP") || layer.name == QStringLiteral("DNS")) {
                    applicationCounts[layer.name] += 1;
                    if (forward) {
                        forwardApplicationCounts[layer.name] += 1;
                    } else {
                        reverseApplicationCounts[layer.name] += 1;
                    }
                    if (layer.name == QStringLiteral("TLS")) {
                        QString handshakeType;
                        QString serverName;
                        QString cipherSuite;
                        QString alpn;
                        QString supportedGroup;
                        QString keyShareGroup;
                        for (const auto &field : layer.fields) {
                            if (field.name == QStringLiteral("Handshake Type")) {
                                handshakeType = field.value;
                            } else if (field.name == QStringLiteral("Server Name")) {
                                serverName = field.value;
                            } else if (field.name == QStringLiteral("Cipher Suite")) {
                                cipherSuite = field.value;
                            } else if (field.name == QStringLiteral("ALPN")) {
                                alpn = field.value;
                            } else if (field.name == QStringLiteral("Supported Group")) {
                                supportedGroup = field.value;
                            } else if (field.name == QStringLiteral("Key Share Group")) {
                                keyShareGroup = field.value;
                            }
                        }
                        QString summary = handshakeType;
                        if (!serverName.isEmpty()) {
                            summary += QStringLiteral(" sni=%1").arg(serverName);
                        }
                        if (!cipherSuite.isEmpty()) {
                            summary += QStringLiteral(" cipher=%1").arg(cipherSuite);
                        }
                        if (!alpn.isEmpty()) {
                            summary += QStringLiteral(" alpn=%1").arg(alpn);
                        }
                        if (!supportedGroup.isEmpty()) {
                            summary += QStringLiteral(" group=%1").arg(supportedGroup);
                        }
                        if (!keyShareGroup.isEmpty()) {
                            summary += QStringLiteral(" keyshare=%1").arg(keyShareGroup);
                        }
                        if (!summary.trimmed().isEmpty()) {
                            handshakeSummary << summary.trimmed();
                            if (forward) {
                                forwardHandshakeSummary << summary.trimmed();
                                if (!handshakeType.isEmpty()) {
                                    forwardSemanticCounts[QStringLiteral("TLS:%1").arg(handshakeType)] += 1;
                                }
                            } else {
                                reverseHandshakeSummary << summary.trimmed();
                                if (!handshakeType.isEmpty()) {
                                    reverseSemanticCounts[QStringLiteral("TLS:%1").arg(handshakeType)] += 1;
                                }
                            }
                        }
                    } else if (layer.name == QStringLiteral("HTTP")) {
                        QString httpType;
                        QString method;
                        QString statusCode;
                        for (const auto &field : layer.fields) {
                            if (field.name == QStringLiteral("Type")) {
                                httpType = field.value;
                            } else if (field.name == QStringLiteral("Method")) {
                                method = field.value;
                            } else if (field.name == QStringLiteral("Status Code")) {
                                statusCode = field.value;
                            }
                        }
                        const QString semantic = httpType == QStringLiteral("Request")
                                                     ? QStringLiteral("HTTP Request %1").arg(method)
                                                     : (httpType == QStringLiteral("Response")
                                                            ? QStringLiteral("HTTP Response %1").arg(statusCode)
                                                            : QStringLiteral("HTTP"));
                        if (httpType == QStringLiteral("Request")) {
                            ++httpRequestCount;
                        } else if (httpType == QStringLiteral("Response")) {
                            ++httpResponseCount;
                        }
                        if (forward) {
                            forwardSemanticCounts[semantic.trimmed()] += 1;
                        } else {
                            reverseSemanticCounts[semantic.trimmed()] += 1;
                        }
                    } else if (layer.name == QStringLiteral("DNS")) {
                        QString messageType;
                        for (const auto &field : layer.fields) {
                            if (field.name == QStringLiteral("Message Type")) {
                                messageType = field.value;
                                break;
                            }
                        }
                        const QString semantic = QStringLiteral("DNS %1").arg(messageType.isEmpty() ? QStringLiteral("Message") : messageType);
                        if (messageType == QStringLiteral("Query")) {
                            ++dnsQueryCount;
                        } else if (messageType == QStringLiteral("Response")) {
                            ++dnsResponseCount;
                        }
                        if (forward) {
                            forwardSemanticCounts[semantic] += 1;
                        } else {
                            reverseSemanticCounts[semantic] += 1;
                        }
                    }
                }
            }
            if (forward) {
                ++forwardPackets;
                forwardBytes += static_cast<quint64>(packet.rawFrame.capturedLength);
            } else {
                ++reversePackets;
                reverseBytes += static_cast<quint64>(packet.rawFrame.capturedLength);
            }
        }
    }
    const qint64 durationMs = flow.firstSeenUtc.isValid() && flow.lastSeenUtc.isValid()
        ? flow.firstSeenUtc.msecsTo(flow.lastSeenUtc)
        : 0;

    QStringList lines;
    lines << QStringLiteral("Selected Flow");
    lines << QString();
    lines << QStringLiteral("Flow: %1:%2 -> %3:%4")
                 .arg(flow.key.sourceAddress)
                 .arg(flow.key.sourcePort)
                 .arg(flow.key.destinationAddress)
                 .arg(flow.key.destinationPort);
    lines << QStringLiteral("Transport: %1").arg(flow.key.transport);
    lines << QStringLiteral("Packet Count: %1").arg(flow.packetCount);
    lines << QStringLiteral("Byte Count: %1").arg(flow.byteCount);
    lines << QStringLiteral("Duration Ms: %1").arg(durationMs);
    lines << QStringLiteral("Forward Packets / Bytes: %1 / %2").arg(forwardPackets).arg(forwardBytes);
    lines << QStringLiteral("Reverse Packets / Bytes: %1 / %2").arg(reversePackets).arg(reverseBytes);
    if (httpRequestCount > 0 || httpResponseCount > 0) {
        lines << QStringLiteral("HTTP Requests / Responses: %1 / %2").arg(httpRequestCount).arg(httpResponseCount);
    }
    if (dnsQueryCount > 0 || dnsResponseCount > 0) {
        lines << QStringLiteral("DNS Queries / Responses: %1 / %2").arg(dnsQueryCount).arg(dnsResponseCount);
    }
    lines << QStringLiteral("Isolation: %1").arg(flowIndex == m_isolatedFlowEngineIndex ? QStringLiteral("active") : QStringLiteral("off"));
    lines << QStringLiteral("First Seen UTC: %1").arg(flow.firstSeenUtc.isValid() ? flow.firstSeenUtc.toString(Qt::ISODateWithMs) : QStringLiteral("--"));
    lines << QStringLiteral("Last Seen UTC: %1").arg(flow.lastSeenUtc.isValid() ? flow.lastSeenUtc.toString(Qt::ISODateWithMs) : QStringLiteral("--"));
    if (!protocolCounts.isEmpty()) {
        QStringList protocolParts;
        for (auto it = protocolCounts.cbegin(); it != protocolCounts.cend(); ++it) {
            protocolParts << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
        }
        lines << QStringLiteral("Protocol Summary: %1").arg(protocolParts.join(QStringLiteral(", ")));
    }
    if (!tcpFlagCounts.isEmpty()) {
        QStringList flagParts;
        for (auto it = tcpFlagCounts.cbegin(); it != tcpFlagCounts.cend(); ++it) {
            flagParts << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
        }
        lines << QStringLiteral("TCP Flags: %1").arg(flagParts.join(QStringLiteral(", ")));
    }
    if (!applicationCounts.isEmpty()) {
        QStringList appParts;
        for (auto it = applicationCounts.cbegin(); it != applicationCounts.cend(); ++it) {
            appParts << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
        }
        lines << QStringLiteral("Application Summary: %1").arg(appParts.join(QStringLiteral(", ")));
    }
    if (!forwardApplicationCounts.isEmpty()) {
        QStringList appParts;
        for (auto it = forwardApplicationCounts.cbegin(); it != forwardApplicationCounts.cend(); ++it) {
            appParts << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
        }
        lines << QStringLiteral("Forward Apps: %1").arg(appParts.join(QStringLiteral(", ")));
    }
    if (!reverseApplicationCounts.isEmpty()) {
        QStringList appParts;
        for (auto it = reverseApplicationCounts.cbegin(); it != reverseApplicationCounts.cend(); ++it) {
            appParts << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
        }
        lines << QStringLiteral("Reverse Apps: %1").arg(appParts.join(QStringLiteral(", ")));
    }
    if (!handshakeSummary.isEmpty()) {
        handshakeSummary.removeDuplicates();
        lines << QStringLiteral("Handshake Summary: %1").arg(handshakeSummary.join(QStringLiteral(" | ")));
    }
    if (!forwardHandshakeSummary.isEmpty()) {
        forwardHandshakeSummary.removeDuplicates();
        lines << QStringLiteral("Forward Handshakes: %1").arg(forwardHandshakeSummary.join(QStringLiteral(" | ")));
    }
    if (!reverseHandshakeSummary.isEmpty()) {
        reverseHandshakeSummary.removeDuplicates();
        lines << QStringLiteral("Reverse Handshakes: %1").arg(reverseHandshakeSummary.join(QStringLiteral(" | ")));
    }
    if (!forwardSemanticCounts.isEmpty()) {
        QStringList parts;
        for (auto it = forwardSemanticCounts.cbegin(); it != forwardSemanticCounts.cend(); ++it) {
            parts << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
        }
        lines << QStringLiteral("Forward Summary: %1").arg(parts.join(QStringLiteral(", ")));
    }
    if (!reverseSemanticCounts.isEmpty()) {
        QStringList parts;
        for (auto it = reverseSemanticCounts.cbegin(); it != reverseSemanticCounts.cend(); ++it) {
            parts << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
        }
        lines << QStringLiteral("Reverse Summary: %1").arg(parts.join(QStringLiteral(", ")));
    }
    return lines.join('\n');
}

void PenguCoreWidget::refreshSessionInfo()
{
    if (!m_module || !m_module->engine() || !m_sessionInfoValue) {
        return;
    }

    const auto *engine = m_module->engine();
    const auto &packets = engine->packets();
    if (packets.isEmpty()) {
        m_sessionInfoValue->setText(tr("Oturum bilgisi: henüz capture yüklenmedi"));
        return;
    }

    qint64 totalBytes = 0;
    QDateTime firstPacketUtc;
    QDateTime lastPacketUtc;
    for (const PacketRecord &packet : packets) {
        totalBytes += packet.rawFrame.originalLength;
        if (!firstPacketUtc.isValid() || packet.rawFrame.timestampUtc < firstPacketUtc) {
            firstPacketUtc = packet.rawFrame.timestampUtc;
        }
        if (!lastPacketUtc.isValid() || packet.rawFrame.timestampUtc > lastPacketUtc) {
            lastPacketUtc = packet.rawFrame.timestampUtc;
        }
    }

    const QString fileName = QFileInfo(engine->lastOpenedFile()).fileName();
    m_sessionInfoValue->setText(
        tr("Oturum: %1 | Format: %2 | Toplam Byte: %3 | Yüklendi: %4 | İlk Packet: %5 | Son Packet: %6 | Live Save: %7")
            .arg(fileName.isEmpty() ? QStringLiteral("--") : fileName,
                 engine->lastOpenedFormat().isEmpty() ? QStringLiteral("--") : engine->lastOpenedFormat(),
                 QString::number(totalBytes),
                 engine->lastSessionOpenedUtc().isValid() ? engine->lastSessionOpenedUtc().toString(Qt::ISODateWithMs) : QStringLiteral("--"),
                 firstPacketUtc.isValid() ? firstPacketUtc.toString(Qt::ISODateWithMs) : QStringLiteral("--"),
                 lastPacketUtc.isValid() ? lastPacketUtc.toString(Qt::ISODateWithMs) : QStringLiteral("--"),
                 engine->lastLiveCaptureSavePath().isEmpty() ? QStringLiteral("--") : QFileInfo(engine->lastLiveCaptureSavePath()).fileName()));
}

void PenguCoreWidget::refreshLiveCaptureUi()
{
    if (m_viewerOnly) {
        return;
    }

    if (!m_module || !m_module->engine() || !m_liveAdapterCombo || !m_startLiveButton || !m_stopLiveButton) {
        return;
    }

    const auto adapters = m_module->engine()->liveAdapters();
    const QString previousSelection = m_liveAdapterCombo->currentData().toString();
    m_liveAdapterCombo->blockSignals(true);
    m_liveAdapterCombo->clear();
    for (const auto &adapter : adapters) {
        const QString label = adapter.description.isEmpty()
                                  ? adapter.name
                                  : QStringLiteral("%1 [%2]").arg(adapter.description, adapter.name);
        m_liveAdapterCombo->addItem(label, adapter.name);
        const int row = m_liveAdapterCombo->count() - 1;
        QString tooltip = QStringLiteral("Adapter: %1").arg(adapter.name);
        if (!adapter.description.isEmpty()) {
            tooltip += QStringLiteral("\nAciklama: %1").arg(adapter.description);
        }
        if (!adapter.addresses.isEmpty()) {
            tooltip += QStringLiteral("\nAdresler: %1").arg(adapter.addresses.join(QStringLiteral(", ")));
        }
        tooltip += QStringLiteral("\nLoopback: %1").arg(adapter.loopback ? QStringLiteral("evet") : QStringLiteral("hayir"));
        m_liveAdapterCombo->setItemData(row, tooltip, Qt::ToolTipRole);
    }
    const int previousIndex = m_liveAdapterCombo->findData(previousSelection);
    if (previousIndex >= 0) {
        m_liveAdapterCombo->setCurrentIndex(previousIndex);
    }
    m_liveAdapterCombo->blockSignals(false);

    const bool running = m_module->engine()->isLiveCaptureRunning();
    const bool hasAdapters = m_liveAdapterCombo->count() > 0;
    m_liveAdapterCombo->setEnabled(!running && hasAdapters);
    m_startLiveButton->setEnabled(!running && hasAdapters);
    m_stopLiveButton->setEnabled(running);
    if (m_liveFilterEdit) {
        if (m_liveFilterEdit->text().isEmpty()) {
            m_liveFilterEdit->setText(m_module->engine()->liveCaptureFilter());
        }
        m_liveFilterEdit->setEnabled(!running);
        m_liveFilterEdit->setToolTip(tr("Npcap/libpcap filtre ifadesi. Ornek: tcp port 443, udp port 53, host 8.8.8.8"));
    }
    if (m_liveSaveFormatCombo) {
        const int formatIndex = m_liveSaveFormatCombo->findData(m_module->engine()->liveSaveFormat());
        if (formatIndex >= 0) {
            m_liveSaveFormatCombo->setCurrentIndex(formatIndex);
        }
        m_liveSaveFormatCombo->setEnabled(!running);
        m_liveSaveFormatCombo->setToolTip(tr("Canli capture kaydinin yazilacagi format."));
    }
    if (m_openLiveFolderButton) {
        m_openLiveFolderButton->setEnabled(!m_module->engine()->lastLiveCaptureSavePath().isEmpty());
    }
    if (m_exportLiveReportButton) {
        m_exportLiveReportButton->setEnabled(!m_module->engine()->packets().isEmpty());
    }
    if (!hasAdapters) {
        m_liveAdapterCombo->setPlaceholderText(tr("Adapter bulunamadi"));
    }
}

void PenguCoreWidget::refreshWorkbenchLayout()
{
    if (!m_workspaceSplitter) {
        return;
    }

    const int tabIndex = m_workbenchTabs ? m_workbenchTabs->currentIndex() : 0;
    const bool liveMonitor = (tabIndex == 0);
    const bool captureReview = (tabIndex == 1);
    const bool flowAnalysis = (tabIndex == 2);
    const bool protocolDrilldown = (tabIndex == 3);

    if (m_heroPanel) {
        m_heroPanel->setVisible(!flowAnalysis);
    }
    if (m_workbenchGuideValue) {
        QString guideText;
        if (liveMonitor) {
            guideText = tr("Canli izleme modu: once packet akisina, sonra secili flow'a bak. Derin detaylar ikincil planda.");
        } else if (captureReview) {
            guideText = tr("Kayit inceleme modu: soldan packet sec, sagdan protocol ve hex detayini incele.");
        } else if (flowAnalysis) {
            guideText = tr("Flow analizi modu: once akis yogunluguna ve yonlerine bak, sonra gerekirse packet seviyesine in.");
        } else if (protocolDrilldown) {
            guideText = tr("Protocol drilldown modu: secili kaydin layer alanlari ve ham icerigi birincil odakta.");
        } else {
            guideText = tr("PenguCore hazir.");
        }
        m_workbenchGuideValue->setText(guideText);
    }
    if (m_timelineCard) {
        m_timelineCard->setVisible(captureReview || liveMonitor);
    }
    if (m_filterCard) {
        m_filterCard->setVisible(true);
    }
    if (m_quickActionCard) {
        m_quickActionCard->setVisible(!flowAnalysis);
    }
    if (m_packetCard) {
        m_packetCard->setVisible(true);
    }
    if (m_flowCard) {
        m_flowCard->setVisible(true);
    }
    if (m_selectionCard) {
        m_selectionCard->setVisible(protocolDrilldown || captureReview || m_inspectorVisible);
    }
    if (m_detailCard) {
        m_detailCard->setVisible(protocolDrilldown || captureReview || m_inspectorVisible);
    }

    switch (tabIndex) {
    case 0:
        m_inspectorVisible = false;
        m_flowDetailVisible = false;
        updateInspectorVisibility();
        if (m_workspaceSplitter) {
            m_workspaceSplitter->setSizes({980, 0});
        }
        if (m_leftWorkspaceSplitter) {
            m_leftWorkspaceSplitter->setSizes({520, 260});
        }
        break;
    case 1:
        m_inspectorVisible = true;
        updateInspectorVisibility();
        if (m_workspaceSplitter) {
            m_workspaceSplitter->setSizes({760, 420});
        }
        if (m_leftWorkspaceSplitter) {
            m_leftWorkspaceSplitter->setSizes({520, 260});
        }
        break;
    case 2:
        m_inspectorVisible = false;
        if (m_workspaceSplitter) {
            m_workspaceSplitter->setSizes({1040, 0});
        }
        if (m_leftWorkspaceSplitter) {
            m_leftWorkspaceSplitter->setSizes({260, 620});
        }
        m_flowDetailVisible = true;
        updateInspectorVisibility();
        break;
    case 3:
        m_inspectorVisible = true;
        m_flowDetailVisible = false;
        updateInspectorVisibility();
        if (m_workspaceSplitter) {
            m_workspaceSplitter->setSizes({620, 540});
        }
        if (m_leftWorkspaceSplitter) {
            m_leftWorkspaceSplitter->setSizes({560, 220});
        }
        break;
    default:
        break;
    }
}

void PenguCoreWidget::refreshStatusRail()
{
    if (!m_statusRailValue || !m_statusRailSelection || !m_module || !m_module->engine()) {
        return;
    }

    const SessionPacketStats stats = collectSessionPacketStats(m_module->engine()->packets());
    const QString durationText = (stats.firstPacketUtc.isValid() && stats.lastPacketUtc.isValid())
        ? QString::number(std::max<qint64>(0, stats.firstPacketUtc.msecsTo(stats.lastPacketUtc)) / 1000.0, 'f', 2) + QStringLiteral("s")
        : QStringLiteral("--");
    const QString liveState = m_module->engine()->isLiveCaptureRunning() ? QStringLiteral("LIVE") : QStringLiteral("IDLE");
    const QString liveHealth = m_module->engine()->liveHealthStatus();
    const QString pauseState = m_liveUiPaused
        ? (m_module->engine()->isLiveCaptureRunning() ? QStringLiteral("PAUSED+BUFFER") : QStringLiteral("PAUSED"))
        : QStringLiteral("FLOW");
    m_statusRailValue->setText(
        QStringLiteral("State: %1 | Health: %2 | UI: %3 | AutoScroll: %4 | Warning Filter: %5 | Rate: %6 pkt/s | Throughput: %7 KB/s | Captured: %8 | Analyzed: %9 | Window: %10 | Bytes: %11 | Duration: %12 | Drop: %13 | Trim: %14 | %15")
            .arg(liveState,
                 liveHealth,
                 pauseState,
                 m_autoScrollEnabled ? QStringLiteral("on") : QStringLiteral("off"),
                 m_onlyWarnings ? QStringLiteral("on") : QStringLiteral("off"),
                 QString::number(m_module->engine()->livePacketsPerSecond(), 'f', 1),
                 QString::number(m_module->engine()->liveBytesPerSecond() / 1024.0, 'f', 1),
                 QString::number(m_module->engine()->liveCapturedFrameCount()),
                 QString::number(m_module->engine()->liveAnalyzedFrameCount()),
                 QString::number(m_module->engine()->packets().size()),
                 QString::number(stats.totalBytes),
                 durationText,
                 QString::number(m_module->engine()->liveDroppedFrameCount()),
                 QString::number(m_module->engine()->liveTrimmedFrameCount()),
                 m_module->engine()->statusText()));

    const PacketRecord *packet = selectedPacket();
    const FlowStats *flow = selectedFlow();
    QString selection = QStringLiteral("Secim: yok");
    if (packet) {
        selection = QStringLiteral("Packet #%1 [%2] %3 -> %4")
                        .arg(packet->rawFrame.frameNumber)
                        .arg(primaryProtocolLabel(*packet), packet->sourceEndpoint, packet->destinationEndpoint);
    } else if (flow) {
        selection = QStringLiteral("Flow %1:%2 -> %3:%4 [%5]")
                        .arg(flow->key.sourceAddress)
                        .arg(flow->key.sourcePort)
                        .arg(flow->key.destinationAddress)
                        .arg(flow->key.destinationPort)
                        .arg(flow->key.transport);
    }
    m_statusRailSelection->setText(selection);

    if (m_pauseLiveUiButton) {
        m_pauseLiveUiButton->setText(m_liveUiPaused ? tr("UI Resume") : tr("UI Pause"));
    }
    if (m_autoScrollButton) {
        m_autoScrollButton->setText(m_autoScrollEnabled ? tr("Auto Scroll") : tr("Manual Scroll"));
    }
    if (m_onlyWarningsButton) {
        m_onlyWarningsButton->setText(m_onlyWarnings ? tr("Warnings Active") : tr("Only Warnings"));
    }
    if (m_exportLiveReportButton) {
        m_exportLiveReportButton->setEnabled(!m_module->engine()->packets().isEmpty());
    }
}

QString PenguCoreWidget::buildTimelineText() const
{
    if (!m_module || !m_module->engine()) {
        return tr("Henuz zaman ekseni olusmadi");
    }

    const auto &packets = m_module->engine()->packets();
    if (packets.isEmpty()) {
        return tr("Henuz zaman ekseni olusmadi");
    }

    constexpr int bucketCount = 24;
    QVector<int> buckets(bucketCount, 0);
    QDateTime first = packets.first().rawFrame.timestampUtc;
    QDateTime last = packets.last().rawFrame.timestampUtc;
    for (const PacketRecord &packet : packets) {
        if (!first.isValid() || packet.rawFrame.timestampUtc < first) {
            first = packet.rawFrame.timestampUtc;
        }
        if (!last.isValid() || packet.rawFrame.timestampUtc > last) {
            last = packet.rawFrame.timestampUtc;
        }
    }

    const qint64 spanMs = std::max<qint64>(1, first.msecsTo(last));
    for (const PacketRecord &packet : packets) {
        const qint64 offsetMs = first.msecsTo(packet.rawFrame.timestampUtc);
        int bucket = static_cast<int>((offsetMs * bucketCount) / spanMs);
        bucket = qBound(0, bucket, bucketCount - 1);
        buckets[bucket] += 1;
    }

    int maxBucket = 1;
    for (int value : buckets) {
        maxBucket = std::max(maxBucket, value);
    }

    QString graph;
    for (int value : buckets) {
        const double ratio = static_cast<double>(value) / static_cast<double>(maxBucket);
        if (ratio <= 0.0) {
            graph += QLatin1Char('.');
        } else if (ratio < 0.2) {
            graph += QLatin1Char(':');
        } else if (ratio < 0.45) {
            graph += QLatin1Char('*');
        } else if (ratio < 0.75) {
            graph += QLatin1Char('O');
        } else {
            graph += QLatin1Char('#');
        }
    }

    return tr("Timeline %1  [%2 -> %3]")
        .arg(graph,
             first.isValid() ? first.toString(Qt::ISODateWithMs) : QStringLiteral("--"),
             last.isValid() ? last.toString(Qt::ISODateWithMs) : QStringLiteral("--"));
}

QColor PenguCoreWidget::protocolAccentColor(const QString &protocol, bool warning) const
{
    if (warning) {
        return QColor(QStringLiteral("#ffb347"));
    }
    const QString normalized = protocol.toUpper();
    if (normalized == QStringLiteral("DNS")) {
        return QColor(QStringLiteral("#63c174"));
    }
    if (normalized == QStringLiteral("HTTP")) {
        return QColor(QStringLiteral("#e16b5b"));
    }
    if (normalized == QStringLiteral("TCP")) {
        return QColor(QStringLiteral("#68a9ff"));
    }
    if (normalized == QStringLiteral("UDP")) {
        return QColor(QStringLiteral("#f5a742"));
    }
    if (normalized == QStringLiteral("ICMP")) {
        return QColor(QStringLiteral("#caa6ff"));
    }
    if (normalized == QStringLiteral("ARP")) {
        return QColor(QStringLiteral("#9ec6cf"));
    }
    return QColor(QStringLiteral("#d7dee9"));
}

void PenguCoreWidget::updateInspectorVisibility()
{
    if (m_rightWorkspace) {
        m_rightWorkspace->setVisible(m_inspectorVisible);
    }
    if (m_flowDetailView) {
        m_flowDetailView->setVisible(m_flowDetailVisible);
    }
}

void PenguCoreWidget::focusOnDns()
{
    if (m_protocolFilter) {
        m_protocolFilter->setCurrentText(QStringLiteral("DNS"));
    }
}

void PenguCoreWidget::focusOnHttp()
{
    if (m_protocolFilter) {
        m_protocolFilter->setCurrentText(QStringLiteral("HTTP"));
    }
}

QJsonObject PenguCoreWidget::buildSessionReportObject(bool visibleOnly) const
{
    if (!m_module || !m_module->engine()) {
        return {};
    }
    return pengufoce::pengucore::buildSessionReportObject(*m_module->engine(),
                                                          m_visiblePacketIndices,
                                                          m_visibleFlowIndices,
                                                          visibleOnly,
                                                          [this](const PacketRecord &packet) { return primaryProtocolLabel(packet); },
                                                          [this](const FlowStats &flow) { return buildFlowDetailText(flow); });
}

void PenguCoreWidget::exportVisibleAnalysis()
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Gorunen analizi disa aktar"),
        QStringLiteral("pengucore_analysis.json"),
        tr("JSON Files (*.json);;CSV Files (*.csv)"));
    if (filePath.isEmpty()) {
        return;
    }

    const bool exportCsv = filePath.endsWith(QStringLiteral(".csv"), Qt::CaseInsensitive);

    const auto &packets = m_module->engine()->packets();
    if (exportCsv) {
        QFile file(filePath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
            return;
        }
        QTextStream stream(&file);
        stream << "frame,timestamp_utc,source,destination,protocol,warning_count,summary\n";
        for (int index : std::as_const(m_visiblePacketIndices)) {
            if (index < 0 || index >= packets.size()) {
                continue;
            }
            const PacketRecord &packet = packets[index];
            QString csvSummary = packet.summary;
            csvSummary.replace('"', QStringLiteral("'"));
            stream << packet.rawFrame.frameNumber << ','
                   << '"' << packet.rawFrame.timestampUtc.toString(Qt::ISODateWithMs) << '"' << ','
                   << '"' << packet.sourceEndpoint << '"' << ','
                   << '"' << packet.destinationEndpoint << '"' << ','
                   << '"' << primaryProtocolLabel(packet) << '"' << ','
                   << packet.warnings.size() << ','
                   << '"' << csvSummary << '"' << '\n';
        }
        file.close();
        return;
    }

    const QJsonObject rootObject = buildSessionReportObject(true);

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }

    file.write(QJsonDocument(rootObject).toJson(QJsonDocument::Indented));
    file.close();
}

void PenguCoreWidget::exportLiveSessionReport()
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Canli oturum raporunu disa aktar"),
        QStringLiteral("pengucore_live_report.json"),
        tr("JSON Files (*.json);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }
    file.write(QJsonDocument(buildSessionReportObject(false)).toJson(QJsonDocument::Indented));
    file.close();
}

void PenguCoreWidget::openLiveCaptureFolder()
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    const QString livePath = m_module->engine()->lastLiveCaptureSavePath();
    if (livePath.isEmpty()) {
        return;
    }

    const QFileInfo info(livePath);
    QDesktopServices::openUrl(QUrl::fromLocalFile(info.absolutePath()));
}

void PenguCoreWidget::saveSelectedPacketRaw()
{
    const PacketRecord *packet = selectedPacket();
    if (!packet) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Packet raw verisini kaydet"),
        QStringLiteral("frame_%1.bin").arg(packet->rawFrame.frameNumber),
        tr("Binary Files (*.bin);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }
    file.write(packet->rawFrame.bytes);
    file.close();
}

void PenguCoreWidget::saveSelectedPacketRange()
{
    const PacketRecord *packet = selectedPacket();
    if (!packet || !m_detailView) {
        return;
    }

    const QString lineText = m_detailView->textCursor().block().text();
    const int markerIndex = lineText.indexOf(QStringLiteral("@0x"));
    if (markerIndex < 0) {
        return;
    }

    const QString offsetHex = lineText.mid(markerIndex + 3, 4);
    const int lenIndex = lineText.indexOf(QStringLiteral("len="), markerIndex);
    bool offsetOk = false;
    bool lenOk = false;
    const int offset = offsetHex.toInt(&offsetOk, 16);
    const int length = lenIndex >= 0 ? lineText.mid(lenIndex + 4).toInt(&lenOk) : 0;
    if (!offsetOk || !lenOk || length <= 0 || offset < 0 || offset + length > packet->rawFrame.bytes.size()) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Secili alan byte araligini kaydet"),
        QStringLiteral("frame_%1_offset_%2.bin").arg(packet->rawFrame.frameNumber).arg(offset, 4, 16, QLatin1Char('0')),
        tr("Binary Files (*.bin);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }
    file.write(packet->rawFrame.bytes.mid(offset, length));
    file.close();
}

void PenguCoreWidget::exportSelectedPacketJson()
{
    const PacketRecord *packet = selectedPacket();
    if (!packet) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Secili packet'i JSON olarak kaydet"),
        QStringLiteral("frame_%1.json").arg(packet->rawFrame.frameNumber),
        tr("JSON Files (*.json);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }
    file.write(QJsonDocument(pengufoce::pengucore::buildPacketJsonObject(*packet)).toJson(QJsonDocument::Indented));
    file.close();
}

void PenguCoreWidget::copySelectedDetailField()
{
    if (!m_detailView) {
        return;
    }
    const QString lineText = m_detailView->textCursor().block().text().trimmed();
    if (lineText.isEmpty() || !lineText.contains(QStringLiteral(": "))) {
        return;
    }
    QString valueText = lineText.section(QStringLiteral(": "), 1);
    const int metaMarker = valueText.indexOf(QStringLiteral("  @0x"));
    if (metaMarker >= 0) {
        valueText = valueText.left(metaMarker);
    }
    copyTextToClipboard(valueText.trimmed());
}

void PenguCoreWidget::exportSelectedDetailField()
{
    if (!m_detailView) {
        return;
    }
    const QString lineText = m_detailView->textCursor().block().text().trimmed();
    if (lineText.isEmpty() || !lineText.contains(QStringLiteral(": "))) {
        return;
    }
    const QString fieldName = lineText.section(QStringLiteral(": "), 0, 0).trimmed();
    QString valueText = lineText.section(QStringLiteral(": "), 1);
    int offset = -1;
    int length = 0;
    const int metaMarker = valueText.indexOf(QStringLiteral("  @0x"));
    if (metaMarker >= 0) {
        const QString metadataText = valueText.mid(metaMarker + 2);
        const QString offsetHex = metadataText.mid(3, 4);
        bool offsetOk = false;
        offset = offsetHex.toInt(&offsetOk, 16);
        const int lenIndex = metadataText.indexOf(QStringLiteral("len="));
        bool lenOk = false;
        if (lenIndex >= 0) {
            length = metadataText.mid(lenIndex + 4).toInt(&lenOk);
        }
        if (!offsetOk) {
            offset = -1;
        }
        if (!lenOk) {
            length = 0;
        }
        valueText = valueText.left(metaMarker);
    }
    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Secili detail alanini kaydet"),
        QStringLiteral("detail_field.json"),
        tr("JSON Files (*.json);;Text Files (*.txt);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return;
    }
    QFile file(filePath);
    const bool exportJson = filePath.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive);
    if (!file.open(exportJson
                       ? (QIODevice::WriteOnly | QIODevice::Truncate)
                       : (QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))) {
        return;
    }
    if (exportJson) {
        QJsonObject object;
        object.insert(QStringLiteral("field_name"), fieldName);
        object.insert(QStringLiteral("value"), valueText.trimmed());
        object.insert(QStringLiteral("offset"), offset);
        object.insert(QStringLiteral("length"), length);
        file.write(QJsonDocument(object).toJson(QJsonDocument::Indented));
    } else {
        QTextStream stream(&file);
        stream << valueText.trimmed();
    }
    file.close();
}

void PenguCoreWidget::exportSelectedFlowStream()
{
    const FlowStats *flow = selectedFlow();
    if (!flow) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Flow stream metnini kaydet"),
        QStringLiteral("flow_stream_%1_%2.txt").arg(flow->key.sourcePort).arg(flow->key.destinationPort),
        tr("Text Files (*.txt);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        return;
    }
    QTextStream stream(&file);
    stream << buildFlowStreamText(*flow);
    file.close();
}

void PenguCoreWidget::exportSelectedFlowHex()
{
    const FlowStats *flow = selectedFlow();
    if (!flow) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Flow hex gorunumunu kaydet"),
        QStringLiteral("flow_hex_%1_%2.txt").arg(flow->key.sourcePort).arg(flow->key.destinationPort),
        tr("Text Files (*.txt);;All Files (*.*)"));
    if (filePath.isEmpty()) {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        return;
    }
    QTextStream stream(&file);
    stream << buildFlowHexText(*flow);
    file.close();
}

void PenguCoreWidget::exportSelectedFlowPacketsCsv()
{
    const FlowStats *flow = selectedFlow();
    if (!flow || !m_module || !m_module->engine()) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Flow packet listesini CSV olarak kaydet"),
        QStringLiteral("flow_packets_%1_%2.csv").arg(flow->key.sourcePort).arg(flow->key.destinationPort),
        tr("CSV Files (*.csv)"));
    if (filePath.isEmpty()) {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        return;
    }

    QTextStream stream(&file);
    stream << "frame,timestamp_utc,source,destination,protocol,captured_length,summary\n";
    for (const PacketRecord &packet : m_module->engine()->packets()) {
        if (!packetMatchesFlow(packet, *flow)) {
            continue;
        }
        QString summary = packet.summary;
        summary.replace('"', QStringLiteral("'"));
        stream << packet.rawFrame.frameNumber << ','
               << '"' << packet.rawFrame.timestampUtc.toString(Qt::ISODateWithMs) << '"' << ','
               << '"' << packet.sourceEndpoint << '"' << ','
               << '"' << packet.destinationEndpoint << '"' << ','
               << '"' << primaryProtocolLabel(packet) << '"' << ','
               << packet.rawFrame.capturedLength << ','
               << '"' << summary << '"' << '\n';
    }
    file.close();
}

void PenguCoreWidget::findInDetailView()
{
    if (!m_detailView || !m_detailSearchEdit) {
        return;
    }
    const QString term = m_detailSearchEdit->text().trimmed();
    if (term.isEmpty()) {
        return;
    }
    if (!m_detailView->find(term)) {
        auto cursor = m_detailView->textCursor();
        cursor.movePosition(QTextCursor::Start);
        m_detailView->setTextCursor(cursor);
        m_detailView->find(term);
    }
}

void PenguCoreWidget::findInHexView()
{
    if (!m_hexView || !m_detailSearchEdit) {
        return;
    }
    const QString term = m_detailSearchEdit->text().trimmed();
    if (term.isEmpty()) {
        return;
    }
    if (!m_hexView->find(term)) {
        auto cursor = m_hexView->textCursor();
        cursor.movePosition(QTextCursor::Start);
        m_hexView->setTextCursor(cursor);
        m_hexView->find(term);
    }
}

void PenguCoreWidget::findInSelectedFlowStream()
{
    const FlowStats *flow = selectedFlow();
    if (!flow || !m_detailSearchEdit) {
        return;
    }

    auto *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose, true);
    dialog->setWindowTitle(tr("Flow Arama - %1:%2 -> %3:%4")
                               .arg(flow->key.sourceAddress)
                               .arg(flow->key.sourcePort)
                               .arg(flow->key.destinationAddress)
                               .arg(flow->key.destinationPort));
    dialog->resize(1040, 760);

    auto *layout = new QVBoxLayout(dialog);
    auto *toolbar = new QWidget(dialog);
    auto *toolbarLayout = new QHBoxLayout(toolbar);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(8);
    auto *resultLabel = new QLabel(toolbar);
    auto *prevButton = new QPushButton(tr("Onceki"), toolbar);
    auto *nextButton = new QPushButton(tr("Sonraki"), toolbar);
    toolbarLayout->addWidget(resultLabel);
    toolbarLayout->addWidget(prevButton);
    toolbarLayout->addWidget(nextButton);
    toolbarLayout->addStretch(1);
    auto *matchesList = new QListWidget(dialog);
    matchesList->setMaximumHeight(140);
    auto *view = new QPlainTextEdit(dialog);
    view->setReadOnly(true);
    view->setPlainText(buildFlowStreamText(*flow));
    layout->addWidget(toolbar);
    layout->addWidget(matchesList);
    layout->addWidget(view);

    const QString term = m_detailSearchEdit->text().trimmed();
    const QString streamText = view->toPlainText();
    const int totalMatches = countOccurrences(streamText, term);
    QVector<int> matchPositions;
    if (!term.isEmpty()) {
        int position = 0;
        while ((position = streamText.indexOf(term, position, Qt::CaseInsensitive)) >= 0) {
            matchPositions.push_back(position);
            const int previewStart = qMax(0, position - 24);
            const int previewLength = qMin(term.size() + 48, streamText.size() - previewStart);
            QString preview = streamText.mid(previewStart, previewLength).simplified();
            matchesList->addItem(QStringLiteral("%1. %2").arg(matchPositions.size()).arg(preview));
            position += qMax(1, term.size());
        }
    }
    auto updateResultLabel = [view, resultLabel, term, totalMatches]() {
        if (!resultLabel) {
            return;
        }
        if (term.isEmpty()) {
            resultLabel->setText(QObject::tr("Arama yok"));
            return;
        }
        if (totalMatches <= 0) {
            resultLabel->setText(QObject::tr("Eslesme yok"));
            return;
        }
        const int position = view->textCursor().selectionStart();
        const int currentIndex = qMax(1, countOccurrences(view->toPlainText().left(position + term.size()), term));
        resultLabel->setText(QObject::tr("Eslesme %1 / %2").arg(qMin(currentIndex, totalMatches)).arg(totalMatches));
    };
    if (!term.isEmpty()) {
        view->find(term);
    }
    updateResultLabel();
    connect(matchesList, &QListWidget::currentRowChanged, dialog, [view, matchesList, matchPositions, term]() {
        const int row = matchesList ? matchesList->currentRow() : -1;
        if (row < 0 || row >= matchPositions.size() || term.isEmpty()) {
            return;
        }
        QTextCursor cursor = view->textCursor();
        cursor.setPosition(matchPositions[row]);
        cursor.setPosition(matchPositions[row] + term.size(), QTextCursor::KeepAnchor);
        view->setTextCursor(cursor);
        view->centerCursor();
    });
    connect(nextButton, &QPushButton::clicked, dialog, [view, term]() {
        if (term.isEmpty()) {
            return;
        }
        if (!view->find(term)) {
            QTextCursor cursor = view->textCursor();
            cursor.movePosition(QTextCursor::Start);
            view->setTextCursor(cursor);
            view->find(term);
        }
    });
    connect(prevButton, &QPushButton::clicked, dialog, [view, term]() {
        if (term.isEmpty()) {
            return;
        }
        if (!view->find(term, QTextDocument::FindBackward)) {
            QTextCursor cursor = view->textCursor();
            cursor.movePosition(QTextCursor::End);
            view->setTextCursor(cursor);
            view->find(term, QTextDocument::FindBackward);
        }
    });
    connect(nextButton, &QPushButton::clicked, dialog, updateResultLabel);
    connect(prevButton, &QPushButton::clicked, dialog, updateResultLabel);
    connect(nextButton, &QPushButton::clicked, dialog, [view, matchesList, matchPositions]() {
        if (!matchesList) {
            return;
        }
        const int cursorPos = view->textCursor().selectionStart();
        for (int i = 0; i < matchPositions.size(); ++i) {
            if (matchPositions[i] == cursorPos) {
                matchesList->setCurrentRow(i);
                break;
            }
        }
    });
    connect(prevButton, &QPushButton::clicked, dialog, [view, matchesList, matchPositions]() {
        if (!matchesList) {
            return;
        }
        const int cursorPos = view->textCursor().selectionStart();
        for (int i = 0; i < matchPositions.size(); ++i) {
            if (matchPositions[i] == cursorPos) {
                matchesList->setCurrentRow(i);
                break;
            }
        }
    });
    if (matchesList->count() > 0) {
        matchesList->setCurrentRow(0);
    }
    dialog->show();
}

void PenguCoreWidget::focusHexOffset(int offset, int length)
{
    if (!m_hexView || offset < 0) {
        return;
    }

    const int lineOffset = (offset / 16) * 16;
    const QString needle = QStringLiteral("%1  ").arg(lineOffset, 4, 16, QLatin1Char('0')).toUpper();
    auto cursor = m_hexView->document()->find(needle);
    if (cursor.isNull()) {
        return;
    }
    m_hexView->setTextCursor(cursor);
    m_hexView->centerCursor();
    QList<QTextEdit::ExtraSelection> selections;
    QTextEdit::ExtraSelection selection;
    selection.cursor = cursor;
    selection.cursor.select(QTextCursor::LineUnderCursor);
    selection.format.setBackground(QColor(180, 90, 110, 70));
    selections.push_back(selection);
    if (length > 0) {
        QTextEdit::ExtraSelection infoSelection;
        infoSelection.cursor = cursor;
        infoSelection.format.setForeground(QColor(255, 240, 245));
        infoSelection.format.setFontWeight(QFont::Bold);
        selections.push_back(infoSelection);
    }
    m_hexView->setExtraSelections(selections);
    m_inspectorVisible = true;
    updateInspectorVisibility();
}

void PenguCoreWidget::openCaptureInSeparateWindow(const QString &filePath)
{
    if (filePath.trimmed().isEmpty()) {
        return;
    }

    auto *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose, true);
    dialog->setWindowTitle(tr("PenguCore Kayit Inceleme - %1").arg(QFileInfo(filePath).fileName()));
    dialog->resize(1680, 980);

    auto *layout = new QVBoxLayout(dialog);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    auto *menuBar = new QMenuBar(dialog);
    auto *fileMenu = menuBar->addMenu(tr("Dosya"));

    auto *viewerModule = new PenguCoreModule(dialog);
    auto *viewerWidget = new PenguCoreWidget(viewerModule, dialog, true);
    fileMenu->addAction(tr("Capture Dosyasi Ac"), viewerWidget, &PenguCoreWidget::openCaptureDialog);
    fileMenu->addSeparator();
    fileMenu->addAction(tr("Pencereyi Kapat"), dialog, &QDialog::close);

    layout->setMenuBar(menuBar);
    layout->addWidget(viewerWidget, 1);

    viewerModule->engine()->openCaptureFile(filePath);
    dialog->show();
}

void PenguCoreWidget::openPacketDetailWindow(const PacketRecord &packet)
{
    auto *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose, true);
    dialog->setWindowTitle(tr("Packet Detayi - Frame #%1").arg(packet.rawFrame.frameNumber));
    dialog->resize(980, 760);

    auto *layout = new QVBoxLayout(dialog);
    auto *view = new QPlainTextEdit(dialog);
    view->setReadOnly(true);

    view->setPlainText(buildPacketDetailText(packet));
    layout->addWidget(view);
    dialog->show();
}

void PenguCoreWidget::openPacketHexWindow(const PacketRecord &packet)
{
    auto *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose, true);
    dialog->setWindowTitle(tr("Hex / Raw - Frame #%1").arg(packet.rawFrame.frameNumber));
    dialog->resize(980, 760);

    auto *layout = new QVBoxLayout(dialog);
    auto *view = new QPlainTextEdit(dialog);
    view->setReadOnly(true);
    view->setPlainText(formatHexView(packet));
    layout->addWidget(view);
    dialog->show();
}

void PenguCoreWidget::openFlowDetailWindow(const FlowStats &flow)
{
    auto *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose, true);
    dialog->setWindowTitle(tr("Flow Detayi - %1:%2 -> %3:%4")
                               .arg(flow.key.sourceAddress)
                               .arg(flow.key.sourcePort)
                               .arg(flow.key.destinationAddress)
                               .arg(flow.key.destinationPort));
    dialog->resize(760, 520);

    auto *layout = new QVBoxLayout(dialog);
    auto *view = new QPlainTextEdit(dialog);
    view->setReadOnly(true);

    view->setPlainText(buildFlowDetailText(flow));

    layout->addWidget(view);
    dialog->show();
}

void PenguCoreWidget::openFlowStreamWindow(const FlowStats &flow)
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    auto *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose, true);
    dialog->setWindowTitle(tr("Flow Akisi - %1:%2 -> %3:%4")
                               .arg(flow.key.sourceAddress)
                               .arg(flow.key.sourcePort)
                               .arg(flow.key.destinationAddress)
                               .arg(flow.key.destinationPort));
    dialog->resize(1040, 760);

    auto *layout = new QVBoxLayout(dialog);
    auto *view = new QPlainTextEdit(dialog);
    view->setReadOnly(true);

    view->setPlainText(buildFlowStreamText(flow));
    layout->addWidget(view);
    dialog->show();
}

void PenguCoreWidget::openFlowHexWindow(const FlowStats &flow)
{
    if (!m_module || !m_module->engine()) {
        return;
    }

    auto *dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose, true);
    dialog->setWindowTitle(tr("Flow Hex / Raw - %1:%2 -> %3:%4")
                               .arg(flow.key.sourceAddress)
                               .arg(flow.key.sourcePort)
                               .arg(flow.key.destinationAddress)
                               .arg(flow.key.destinationPort));
    dialog->resize(1120, 820);

    auto *layout = new QVBoxLayout(dialog);
    auto *view = new QPlainTextEdit(dialog);
    view->setReadOnly(true);

    view->setPlainText(buildFlowHexText(flow));
    layout->addWidget(view);
    dialog->show();
}

QString PenguCoreWidget::buildFlowStreamText(const FlowStats &flow) const
{
    if (!m_module || !m_module->engine()) {
        return tr("Bu flow icin packet bulunamadi.");
    }

    QStringList lines;
    lines << QStringLiteral("Stream Summary");
    lines << QStringLiteral("Flow: %1:%2 -> %3:%4 [%5]")
                 .arg(flow.key.sourceAddress)
                 .arg(flow.key.sourcePort)
                 .arg(flow.key.destinationAddress)
                 .arg(flow.key.destinationPort)
                 .arg(flow.key.transport);
    lines << QStringLiteral("Packets: %1 | Bytes: %2").arg(flow.packetCount).arg(flow.byteCount);
    lines << QString();
    const auto &packets = m_module->engine()->packets();
    QList<const PacketRecord *> forwardPackets;
    QList<const PacketRecord *> reversePackets;
    for (const PacketRecord &packet : packets) {
        if (!packetMatchesFlow(packet, flow)) {
            continue;
        }
        if (packetDirectionText(packet, flow) == QStringLiteral("CLIENT -> SERVER")) {
            forwardPackets.push_back(&packet);
        } else {
            reversePackets.push_back(&packet);
        }
    }
    if (forwardPackets.isEmpty() && reversePackets.isEmpty()) {
        return tr("Bu flow icin packet bulunamadi.");
    }
    lines << buildFlowDirectionSection(QStringLiteral("CLIENT -> SERVER"), forwardPackets);
    lines << QString();
    lines << buildFlowDirectionSection(QStringLiteral("SERVER -> CLIENT"), reversePackets);
    lines << QString();
    lines << buildDirectionalReassemblySummary(forwardPackets, reversePackets);
    return lines.join('\n').trimmed();
}

QString PenguCoreWidget::buildFlowHexText(const FlowStats &flow) const
{
    if (!m_module || !m_module->engine()) {
        return tr("Bu flow icin hex veri bulunamadi.");
    }

    QStringList lines;
    const auto &packets = m_module->engine()->packets();
    for (const PacketRecord &packet : packets) {
        if (!packetMatchesFlow(packet, flow)) {
            continue;
        }
        lines << QStringLiteral("Frame #%1").arg(packet.rawFrame.frameNumber);
        lines << formatHexView(packet);
        lines << QString();
    }

    return lines.isEmpty() ? tr("Bu flow icin hex veri bulunamadi.") : lines.join('\n');
}

QString PenguCoreWidget::primaryProtocolLabel(const PacketRecord &packet) const
{
    for (auto it = packet.layers.crbegin(); it != packet.layers.crend(); ++it) {
        if (it->name == QStringLiteral("HTTP")
            || it->name == QStringLiteral("DNS")
            || it->name == QStringLiteral("TCP")
            || it->name == QStringLiteral("UDP")
            || it->name == QStringLiteral("ICMP")
            || it->name == QStringLiteral("ARP")
            || it->name == QStringLiteral("IPv4")) {
            return it->name;
        }
    }
    return QStringLiteral("RAW");
}

QString PenguCoreWidget::packetListLabel(const PacketRecord &packet) const
{
    const QString protocol = primaryProtocolLabel(packet);
    const QString warningPrefix = packet.warnings.isEmpty() ? QStringLiteral("   ") : QStringLiteral(" M ");
    return QStringLiteral("%1 [%2]  #%3  %4 -> %5  %6")
        .arg(warningPrefix,
             protocol.leftJustified(5, QLatin1Char(' ')),
             QString::number(packet.rawFrame.frameNumber),
             packet.sourceEndpoint,
             packet.destinationEndpoint,
             packet.summary);
}

void PenguCoreWidget::copyTextToClipboard(const QString &text) const
{
    if (auto *clipboard = QGuiApplication::clipboard()) {
        clipboard->setText(text);
    }
}

void PenguCoreWidget::applySelectedPacketEndpointsToFilters()
{
    const PacketRecord *packet = selectedPacket();
    if (!packet) {
        return;
    }
    if (m_sourceFilterEdit) {
        m_sourceFilterEdit->setText(packet->sourceEndpoint);
    }
    if (m_destinationFilterEdit) {
        m_destinationFilterEdit->setText(packet->destinationEndpoint);
    }
}

void PenguCoreWidget::applySelectedFlowEndpointsToFilters()
{
    const FlowStats *flow = selectedFlow();
    if (!flow) {
        return;
    }
    if (m_sourceFilterEdit) {
        m_sourceFilterEdit->setText(QStringLiteral("%1:%2").arg(flow->key.sourceAddress).arg(flow->key.sourcePort));
    }
    if (m_destinationFilterEdit) {
        m_destinationFilterEdit->setText(QStringLiteral("%1:%2").arg(flow->key.destinationAddress).arg(flow->key.destinationPort));
    }
}

void PenguCoreWidget::isolateSelectedFlow()
{
    if (m_selectedFlowIndex < 0 || m_selectedFlowIndex >= m_visibleFlowIndices.size()) {
        return;
    }
    m_isolatedFlowEngineIndex = m_visibleFlowIndices[m_selectedFlowIndex];
    applyFilters();
}

void PenguCoreWidget::clearFlowIsolation()
{
    if (m_isolatedFlowEngineIndex < 0) {
        return;
    }
    m_isolatedFlowEngineIndex = -1;
    applyFilters();
}

const PacketRecord *PenguCoreWidget::selectedPacket() const
{
    if (!m_module || !m_module->engine()) {
        return nullptr;
    }
    if (m_selectedPacketIndex < 0 || m_selectedPacketIndex >= m_visiblePacketIndices.size()) {
        return nullptr;
    }

    const int packetIndex = m_visiblePacketIndices[m_selectedPacketIndex];
    const auto &packets = m_module->engine()->packets();
    if (packetIndex < 0 || packetIndex >= packets.size()) {
        return nullptr;
    }

    return &packets[packetIndex];
}

const FlowStats *PenguCoreWidget::selectedFlow() const
{
    if (!m_module || !m_module->engine()) {
        return nullptr;
    }
    if (m_selectedFlowIndex < 0 || m_selectedFlowIndex >= m_visibleFlowIndices.size()) {
        return nullptr;
    }

    const int flowIndex = m_visibleFlowIndices[m_selectedFlowIndex];
    const auto &flows = m_module->engine()->flows();
    if (flowIndex < 0 || flowIndex >= flows.size()) {
        return nullptr;
    }

    return &flows[flowIndex];
}

