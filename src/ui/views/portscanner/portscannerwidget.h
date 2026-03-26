#pragma once

#include <QVariantMap>
#include <QWidget>

class PortScannerModule;
class QCheckBox;
class QComboBox;
class QListWidget;
class QLabel;
class QLineEdit;
class QPushButton;
class QProgressBar;
class QSpinBox;
class QTableWidget;

class PortScannerWidget : public QWidget
{
    Q_OBJECT

public:
    explicit PortScannerWidget(PortScannerModule *module, QWidget *parent = nullptr);
    void reloadSettings();

private slots:
    void applyFormToModule();
    void refreshFromModule();
    void refreshResults();
    void startScan();
    void stopScan();
    void exportResults();
    void copySelectedRow();
    void appendEvent(const QString &message);
    void handlePortFound(const QVariantMap &row);
    void handleServiceDetected(const QString &ip, int port, const QString &serviceName, const QString &banner);
    void handleScanFinished();

private:
    void buildUi();
    QVariantMap selectedRow() const;
    QWidget *createMetricCard(const QString &title, QLabel **valueLabel, const QString &helperText = {});
    QWidget *createInfoLabel(const QString &title, const QString &tooltip) const;

    PortScannerModule *m_module;
    QLineEdit *m_targetEdit = nullptr;
    QLineEdit *m_portsEdit = nullptr;
    QComboBox *m_scanTypeCombo = nullptr;
    QSpinBox *m_threadsSpin = nullptr;
    QSpinBox *m_timeoutSpin = nullptr;
    QSpinBox *m_retrySpin = nullptr;
    QCheckBox *m_serviceCheck = nullptr;
    QCheckBox *m_osCheck = nullptr;
    QLabel *m_statusValue = nullptr;
    QLabel *m_progressValue = nullptr;
    QLabel *m_rateValue = nullptr;
    QLabel *m_etaValue = nullptr;
    QLabel *m_elapsedValue = nullptr;
    QLabel *m_openPortsValue = nullptr;
    QLabel *m_targetsSummaryValue = nullptr;
    QLabel *m_scanModeSummaryValue = nullptr;
    QLabel *m_resultsSummaryValue = nullptr;
    QLabel *m_liveHintLabel = nullptr;
    QPushButton *m_startButton = nullptr;
    QPushButton *m_stopButton = nullptr;
    QProgressBar *m_progressBar = nullptr;
    QTableWidget *m_resultsTable = nullptr;
    QListWidget *m_eventFeed = nullptr;
};
