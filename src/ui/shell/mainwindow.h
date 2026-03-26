#pragma once

#include <QMainWindow>
class AppController;
class LogModel;
class ModuleManager;
class PortScannerWidget;
class ProxyWidget;
class ProxyWaterfallPage;
class ReconWidget;
class SpiderWidget;
class PenguCoreWidget;
class BladeSidebar;
class SettingsDialog;
class SettingsLogWidget;
class QFrame;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QGraphicsOpacityEffect;
class QPropertyAnimation;
class QScrollArea;
class QStackedWidget;
class QWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(AppController *controller, QWidget *parent = nullptr);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void handleModuleSelectionChanged(int row);
    void handleLogRowsInserted();
    void syncTheme();
    void openSettings();
    void saveSession();
    void loadSession();

private:
    void buildUi();
    void populateModules();
    void appendExistingLogs();
    QString buildStyleSheet() const;
    void setActiveModuleIndex(int row);
    void animateCurrentPage();

    AppController *m_controller;
    ModuleManager *m_moduleManager;
    LogModel *m_logModel;
    QWidget *m_mainContentWidget = nullptr;
    QStackedWidget *m_contentStack = nullptr;
    QPlainTextEdit *m_logConsole = nullptr;
    QLabel *m_headerTitle = nullptr;
    QLabel *m_headerDescription = nullptr;
    QLabel *m_moduleCountValue = nullptr;
    QLabel *m_activeModuleValue = nullptr;
    QLabel *m_statusHint = nullptr;
    QPushButton *m_settingsButton = nullptr;
    QGraphicsOpacityEffect *m_pageOpacityEffect = nullptr;
    QPropertyAnimation *m_pageFadeAnimation = nullptr;
    BladeSidebar *m_sidebar = nullptr;
    SettingsLogWidget *m_settingsLogWidget = nullptr;
    PortScannerWidget *m_portScannerWidget = nullptr;
    ProxyWidget *m_proxyWidget = nullptr;
    ProxyWaterfallPage *m_proxyWaterfallPage = nullptr;
    ReconWidget *m_reconWidget = nullptr;
    SpiderWidget *m_spiderWidget = nullptr;
    PenguCoreWidget *m_penguCoreWidget = nullptr;
    SettingsDialog *m_settingsDialog = nullptr;
};
