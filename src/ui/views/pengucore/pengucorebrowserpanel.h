#pragma once

#include <QFrame>

class QListWidget;
class QPlainTextEdit;
class QPushButton;

class PenguCoreBrowserPanel : public QFrame
{
    Q_OBJECT

public:
    explicit PenguCoreBrowserPanel(QWidget *parent = nullptr);

    QListWidget *packetList() const { return m_packetList; }
    QListWidget *flowList() const { return m_flowList; }
    QPlainTextEdit *flowDetailView() const { return m_flowDetailView; }
    QPushButton *packetApplyFilterButton() const { return m_packetApplyFilterButton; }
    QPushButton *packetCopySourceButton() const { return m_packetCopySourceButton; }
    QPushButton *packetCopyDestinationButton() const { return m_packetCopyDestinationButton; }
    QPushButton *packetSaveRawButton() const { return m_packetSaveRawButton; }
    QPushButton *packetSaveRangeButton() const { return m_packetSaveRangeButton; }
    QPushButton *packetExportJsonButton() const { return m_packetExportJsonButton; }
    QPushButton *packetCopyFieldButton() const { return m_packetCopyFieldButton; }
    QPushButton *packetExportFieldButton() const { return m_packetExportFieldButton; }
    QPushButton *flowApplyFilterButton() const { return m_flowApplyFilterButton; }
    QPushButton *flowIsolateButton() const { return m_flowIsolateButton; }
    QPushButton *clearFlowIsolationButton() const { return m_clearFlowIsolationButton; }
    QPushButton *exportFlowsButton() const { return m_exportFlowsButton; }
    QPushButton *exportFlowStreamButton() const { return m_exportFlowStreamButton; }
    QPushButton *exportFlowHexButton() const { return m_exportFlowHexButton; }
    QPushButton *exportFlowPacketsButton() const { return m_exportFlowPacketsButton; }

private:
    QListWidget *m_packetList = nullptr;
    QListWidget *m_flowList = nullptr;
    QPlainTextEdit *m_flowDetailView = nullptr;
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
    QPushButton *m_exportFlowsButton = nullptr;
    QPushButton *m_exportFlowStreamButton = nullptr;
    QPushButton *m_exportFlowHexButton = nullptr;
    QPushButton *m_exportFlowPacketsButton = nullptr;
};
