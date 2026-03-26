#include "osintandleakmodule.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QUrlQuery>

OsintAndLeakModule::OsintAndLeakModule(QObject *parent)
    : QObject(parent)
{
}

void OsintAndLeakModule::queryPublicLeaks(const QString &target, const QUrl &endpoint, const QString &apiKey)
{
    if (!endpoint.isValid() || endpoint.isEmpty()) {
        emit statusMessage("OSINT query skipped: invalid endpoint");
        emit queryFinished();
        return;
    }

    ensureNetworkManager();

    QUrl queryUrl(endpoint);
    QUrlQuery query(queryUrl);
    query.addQueryItem("target", target);
    queryUrl.setQuery(query);

    QNetworkRequest request(queryUrl);
    request.setHeader(QNetworkRequest::UserAgentHeader, "PenguFoce/0.1");
    request.setRawHeader("Accept", "application/json");
    if (!apiKey.isEmpty()) {
        request.setRawHeader("hibp-api-key", apiKey.toUtf8());
        request.setRawHeader("api-key", apiKey.toUtf8());
    }

    emit statusMessage(QString("OSINT query dispatched: %1").arg(queryUrl.toString()));
    QNetworkReply *reply = m_networkAccessManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, target]() {
        handleReply(reply, target);
    });
}

void OsintAndLeakModule::ensureNetworkManager()
{
    if (!m_networkAccessManager) {
        m_networkAccessManager = new QNetworkAccessManager(this);
    }
}

void OsintAndLeakModule::handleReply(QNetworkReply *reply, const QString &target)
{
    std::unique_ptr<QNetworkReply, void (*)(QNetworkReply *)> guard(reply, [](QNetworkReply *r) { r->deleteLater(); });

    if (reply->error() != QNetworkReply::NoError) {
        emit statusMessage(QString("OSINT query failed for %1: %2").arg(target, reply->errorString()));
        emit queryFinished();
        return;
    }

    const QByteArray body = reply->readAll();
    const QJsonDocument json = QJsonDocument::fromJson(body);
    bool findingEmitted = false;

    if (json.isArray()) {
        const QJsonArray breaches = json.array();
        if (!breaches.isEmpty()) {
            const QString details = QString("%1 public breach records matched").arg(breaches.size());
            emit leakDetected("high", details);
            emit leakFindingReady({"high", details, reply->url().host()});
            findingEmitted = true;
        }
    } else if (json.isObject()) {
        const QJsonObject object = json.object();
        const int count = object.value("count").toInt(object.value("breaches").toArray().size());
        const bool found = object.value("found").toBool(count > 0);
        if (found || count > 0) {
            const QString details = object.value("details").toString(
                QString("%1 breach indicators returned for %2").arg(qMax(1, count)).arg(target));
            const QString severity = object.value("severity").toString("high");
            emit leakDetected(severity, details);
            emit leakFindingReady({severity, details, reply->url().host()});
            findingEmitted = true;
        }
    }

    if (!findingEmitted) {
        emit statusMessage(QString("OSINT query returned no public leaks for %1").arg(target));
    }

    emit queryFinished();
}
