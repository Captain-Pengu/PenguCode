#pragma once

#include "scantypes.h"

#include <QNetworkRequest>
#include <QObject>
#include <QUrl>

class QNetworkAccessManager;
class QNetworkReply;

class OsintAndLeakModule : public QObject
{
    Q_OBJECT

public:
    explicit OsintAndLeakModule(QObject *parent = nullptr);

public slots:
    void queryPublicLeaks(const QString &target, const QUrl &endpoint, const QString &apiKey = QString());

signals:
    void leakDetected(const QString &severity, const QString &details);
    void leakFindingReady(const LeakFinding &finding);
    void queryFinished();
    void statusMessage(const QString &message);

private:
    void ensureNetworkManager();
    void handleReply(QNetworkReply *reply, const QString &target);

    QNetworkAccessManager *m_networkAccessManager = nullptr;
};
