#pragma once

#include "scantypes.h"

#include <QObject>
#include <QPointer>

class QDnsLookup;

class DnsReconModule : public QObject
{
    Q_OBJECT

public:
    explicit DnsReconModule(QObject *parent = nullptr);

public slots:
    void startLookup(const QString &domain);

signals:
    void dnsRecordFound(const QString &type, const QString &value);
    void dnsRecordBatchFound(const DnsRecordResult &record);
    void misconfigurationFound(const QString &severity, const QString &details);
    void lookupFinished();
    void statusMessage(const QString &message);

private:
    void dispatchLookup(int recordType, const QString &label, const QString &domain);
    void handleTxtRecords(const QList<QString> &values);

    int m_pendingLookups = 0;
    QString m_domain;
};
