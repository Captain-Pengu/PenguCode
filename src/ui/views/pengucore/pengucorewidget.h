#pragma once

#include "pengucore/model/packettypes.h"

#include <QColor>
#include <QTimer>
#include <QWidget>

class QLabel;
class QListWidget;
class QListWidgetItem;
class QPushButton;
class QPlainTextEdit;
class QLineEdit;
class QComboBox;
class QFrame;
class QJsonObject;
class QSplitter;
class QTabBar;
class PenguCoreModule;

class PenguCoreWidget : public QWidget
{
    Q_OBJECT

public:
    explicit PenguCoreWidget(PenguCoreModule *module, QWidget *parent = nullptr, bool viewerOnly = false);
    void openCaptureDialog();
    void openLastLiveCaptureWindow();

private:
    void buildUi();
    void refreshState();
    void scheduleRefresh();
    void refreshPacketDetails();
    void refreshFlowDetails();
    void refreshSessionInfo();
    void refreshLiveCaptureUi();
    void refreshWorkbenchLayout();
    void refreshStatusRail();
    void openCaptureInSeparateWindow(const QString &filePath);
    void openPacketDetailWindow(const pengufoce::pengucore::PacketRecord &packet);
    void openPacketHexWindow(const pengufoce::pengucore::PacketRecord &packet);
    void openFlowDetailWindow(const pengufoce::pengucore::FlowStats &flow);
    void openFlowStreamWindow(const pengufoce::pengucore::FlowStats &flow);
    void openFlowHexWindow(const pengufoce::pengucore::FlowStats &flow);
    QString buildPacketDetailText(const pengufoce::pengucore::PacketRecord &packet) const;
    QString buildFlowDetailText(const pengufoce::pengucore::FlowStats &flow) const;
    QString buildFlowStreamText(const pengufoce::pengucore::FlowStats &flow) const;
    QString buildFlowHexText(const pengufoce::pengucore::FlowStats &flow) const;
    QJsonObject buildSessionReportObject(bool visibleOnly) const;
    QString formatHexView(const pengufoce::pengucore::PacketRecord &packet) const;
    void applyFilters();
    bool packetMatchesFilters(const pengufoce::pengucore::PacketRecord &packet) const;
    bool flowMatchesVisiblePackets(const pengufoce::pengucore::FlowStats &flow) const;
    bool packetMatchesFlow(const pengufoce::pengucore::PacketRecord &packet,
                          const pengufoce::pengucore::FlowStats &flow) const;
    QString packetListLabel(const pengufoce::pengucore::PacketRecord &packet) const;
    QString primaryProtocolLabel(const pengufoce::pengucore::PacketRecord &packet) const;
    QString buildTimelineText() const;
    QColor protocolAccentColor(const QString &protocol, bool warning) const;
    void updateInspectorVisibility();
    void copyTextToClipboard(const QString &text) const;
    void applySelectedPacketEndpointsToFilters();
    void applySelectedFlowEndpointsToFilters();
    void isolateSelectedFlow();
    void clearFlowIsolation();
    void focusOnDns();
    void focusOnHttp();
    void exportVisibleAnalysis();
    void exportLiveSessionReport();
    void openLiveCaptureFolder();
    void saveSelectedPacketRaw();
    void saveSelectedPacketRange();
    void exportSelectedPacketJson();
    void copySelectedDetailField();
    void exportSelectedDetailField();
    void exportSelectedFlowStream();
    void exportSelectedFlowHex();
    void exportSelectedFlowPacketsCsv();
    void findInDetailView();
    void findInHexView();
    void findInSelectedFlowStream();
    void focusHexOffset(int offset, int length = 0);
    const pengufoce::pengucore::PacketRecord *selectedPacket() const;
    const pengufoce::pengucore::FlowStats *selectedFlow() const;

    PenguCoreModule *m_module = nullptr;
    QTabBar *m_workbenchTabs = nullptr;
    QLabel *m_statusValue = nullptr;
    QLabel *m_workbenchGuideValue = nullptr;
    QLabel *m_fileValue = nullptr;
    QLabel *m_sessionInfoValue = nullptr;
    QLabel *m_timelineValue = nullptr;
    QLabel *m_emptyStateTitle = nullptr;
    QLabel *m_emptyStateBody = nullptr;
    QLabel *m_statusRailValue = nullptr;
    QLabel *m_statusRailSelection = nullptr;
    QLabel *m_sessionFileCardValue = nullptr;
    QLabel *m_sessionFormatCardValue = nullptr;
    QLabel *m_sessionBytesCardValue = nullptr;
    QLabel *m_sessionOpenedCardValue = nullptr;
    QLabel *m_sessionFirstSeenCardValue = nullptr;
    QLabel *m_sessionLastSeenCardValue = nullptr;
    QLabel *m_sessionLiveSaveCardValue = nullptr;
    QLabel *m_totalPacketsValue = nullptr;
    QLabel *m_visiblePacketsValue = nullptr;
    QLabel *m_totalFlowsValue = nullptr;
    QLabel *m_visibleFlowsValue = nullptr;
    QLineEdit *m_searchEdit = nullptr;
    QLineEdit *m_sourceFilterEdit = nullptr;
    QLineEdit *m_destinationFilterEdit = nullptr;
    QLineEdit *m_liveFilterEdit = nullptr;
    QLineEdit *m_detailSearchEdit = nullptr;
    QComboBox *m_protocolFilter = nullptr;
    QComboBox *m_filterPresetCombo = nullptr;
    QComboBox *m_liveAdapterCombo = nullptr;
    QComboBox *m_liveSaveFormatCombo = nullptr;
    QListWidget *m_packetList = nullptr;
    QListWidget *m_flowList = nullptr;
    QPlainTextEdit *m_detailView = nullptr;
    QPlainTextEdit *m_hexView = nullptr;
    QPlainTextEdit *m_flowDetailView = nullptr;
    QPushButton *m_toggleInspectorButton = nullptr;
    QPushButton *m_toggleHexButton = nullptr;
    QPushButton *m_toggleFlowDetailButton = nullptr;
    QPushButton *m_pauseLiveUiButton = nullptr;
    QPushButton *m_autoScrollButton = nullptr;
    QPushButton *m_onlyWarningsButton = nullptr;
    QPushButton *m_dnsFocusButton = nullptr;
    QPushButton *m_httpFocusButton = nullptr;
    QPushButton *m_packetApplyFilterButton = nullptr;
    QPushButton *m_packetCopySourceButton = nullptr;
    QPushButton *m_packetCopyDestinationButton = nullptr;
    QPushButton *m_packetSaveRawButton = nullptr;
    QPushButton *m_packetSaveRangeButton = nullptr;
    QPushButton *m_packetExportJsonButton = nullptr;
    QPushButton *m_packetCopyFieldButton = nullptr;
    QPushButton *m_packetExportFieldButton = nullptr;
    QPushButton *m_flowApplyFilterButton = nullptr;
    QPushButton *m_flowIsolateButton = nullptr;
    QPushButton *m_clearFlowIsolationButton = nullptr;
    QPushButton *m_refreshAdaptersButton = nullptr;
    QPushButton *m_startLiveButton = nullptr;
    QPushButton *m_stopLiveButton = nullptr;
    QPushButton *m_openLiveFolderButton = nullptr;
    QPushButton *m_exportButton = nullptr;
    QPushButton *m_exportLiveReportButton = nullptr;
    QPushButton *m_exportFlowsButton = nullptr;
    QPushButton *m_exportFlowStreamButton = nullptr;
    QPushButton *m_exportFlowHexButton = nullptr;
    QPushButton *m_exportFlowPacketsButton = nullptr;
    QPushButton *m_clearButton = nullptr;
    QPushButton *m_findDetailButton = nullptr;
    QPushButton *m_findHexButton = nullptr;
    QPushButton *m_findFlowStreamButton = nullptr;
    QPushButton *m_findFlowStreamPrevButton = nullptr;
    QPushButton *m_findFlowStreamNextButton = nullptr;
    QTimer *m_refreshTimer = nullptr;
    QWidget *m_rightWorkspace = nullptr;
    QFrame *m_heroPanel = nullptr;
    QFrame *m_timelineCard = nullptr;
    QFrame *m_filterCard = nullptr;
    QFrame *m_quickActionCard = nullptr;
    QFrame *m_packetCard = nullptr;
    QFrame *m_flowCard = nullptr;
    QFrame *m_selectionCard = nullptr;
    QFrame *m_detailCard = nullptr;
    QFrame *m_emptyStateCard = nullptr;
    QSplitter *m_workspaceSplitter = nullptr;
    QSplitter *m_leftWorkspaceSplitter = nullptr;
    bool m_viewerOnly = false;
    bool m_contextMenuOpen = false;
    bool m_refreshDeferredWhileMenuOpen = false;
    bool m_liveUiPaused = false;
    bool m_autoScrollEnabled = true;
    bool m_onlyWarnings = false;
    bool m_inspectorVisible = false;
    bool m_flowDetailVisible = false;
    int m_selectedPacketIndex = -1;
    int m_selectedFlowIndex = -1;
    int m_isolatedFlowEngineIndex = -1;
    QVector<int> m_visiblePacketIndices;
    QVector<int> m_visibleFlowIndices;
};
