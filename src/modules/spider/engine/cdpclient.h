#pragma once

#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QVariantList>

class CdpClient
{
public:
    struct StatefulResult
    {
        QString stepLabel;
        QString pageTitle;
        QString currentUrl;
        QStringList urls;
        QStringList formActions;
    };

    ~CdpClient();
    bool connectToPage(const QString &wsUrl, int timeoutMs, QString *errorMessage = nullptr);
    void disconnect();
    bool isConnected() const;

    QJsonObject sendCommand(const QString &method,
                            const QJsonObject &params = {},
                            int timeoutMs = 2000,
                            QString *errorMessage = nullptr);

    QString evaluateExpression(const QString &expression,
                               int timeoutMs = 2000,
                               QString *errorMessage = nullptr);

    QVariantList collectInteractiveSnapshot(int timeoutMs, QString *errorMessage = nullptr);
    QList<StatefulResult> runSafeStatefulExploration(int timeoutMs, QString *errorMessage = nullptr);

private:
    bool performHandshake(const QString &host, quint16 port, const QString &path, int timeoutMs, QString *errorMessage);
    bool writeTextFrame(const QByteArray &payload, int timeoutMs, QString *errorMessage);
    QByteArray readFrame(int timeoutMs, bool *isTextFrame, QString *errorMessage);
    QByteArray readHttpHeaders(int timeoutMs, QString *errorMessage);

    class Impl;
    Impl *m_impl = nullptr;
};
