#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QNetworkCookie>
#include <QPair>
#include <QSsl>
#include <QString>
#include <QUrl>
#include <QVariantMap>

struct ReconFindingCandidate
{
    QString severity;
    QString title;
    QString description;
    QString category;
    int penalty = 0;
};

struct ReconCveCandidate
{
    QString product;
    QString version;
};

struct ReconWebResponseInput
{
    QUrl url;
    QList<QPair<QByteArray, QByteArray>> rawHeaders;
    QList<QNetworkCookie> cookies;
    QByteArray bodyPreview;
    int statusCode = 0;
};

struct ReconWebAnalysis
{
    QList<ReconFindingCandidate> findings;
    QList<ReconCveCandidate> cveCandidates;
    QVariantMap observation;
};

struct ReconTlsInput
{
    bool hasCertificate = false;
    QDateTime expiryDateUtc;
    QSsl::SslProtocol protocol = QSsl::UnknownProtocol;
    QStringList cipherNames;
    QString commonName;
    QString issuerOrganization;
};

struct ReconTlsAnalysis
{
    QList<ReconFindingCandidate> findings;
    QVariantMap observation;
};

ReconWebAnalysis reconAnalyzeWebResponse(const ReconWebResponseInput &input);
ReconTlsAnalysis reconAnalyzeTlsState(const ReconTlsInput &input);
