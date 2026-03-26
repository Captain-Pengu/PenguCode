#include "dnsreconmodule.h"

#include <QDnsDomainNameRecord>
#include <QDnsHostAddressRecord>
#include <QDnsLookup>
#include <QDnsMailExchangeRecord>
#include <QDnsTextRecord>
#include <QHostAddress>

DnsReconModule::DnsReconModule(QObject *parent)
    : QObject(parent)
{
}

void DnsReconModule::startLookup(const QString &domain)
{
    m_domain = domain.trimmed();
    m_pendingLookups = 0;

    if (m_domain.isEmpty()) {
        emit statusMessage("DNS lookup skipped: empty domain");
        emit lookupFinished();
        return;
    }

    emit statusMessage(QString("DNS enumeration started for %1").arg(m_domain));
    dispatchLookup(QDnsLookup::A, "A", m_domain);
    dispatchLookup(QDnsLookup::AAAA, "AAAA", m_domain);
    dispatchLookup(QDnsLookup::NS, "NS", m_domain);
    dispatchLookup(QDnsLookup::MX, "MX", m_domain);
    dispatchLookup(QDnsLookup::TXT, "TXT", m_domain);
}

void DnsReconModule::dispatchLookup(int recordType, const QString &label, const QString &domain)
{
    auto *lookup = new QDnsLookup(static_cast<QDnsLookup::Type>(recordType), domain, this);
    ++m_pendingLookups;

    connect(lookup, &QDnsLookup::finished, this, [this, lookup, label]() {
        if (lookup->error() != QDnsLookup::NoError) {
            emit statusMessage(QString("DNS %1 lookup error: %2").arg(label, lookup->errorString()));
        } else if (label == "A" || label == "AAAA") {
            for (const QDnsHostAddressRecord &record : lookup->hostAddressRecords()) {
                const QString value = record.value().toString();
                emit dnsRecordFound(label, value);
                emit dnsRecordBatchFound(DnsRecordResult{label, value});
            }
        } else if (label == "NS") {
            for (const QDnsDomainNameRecord &record : lookup->nameServerRecords()) {
                emit dnsRecordFound(label, record.value());
                emit dnsRecordBatchFound(DnsRecordResult{label, record.value()});
            }
        } else if (label == "MX") {
            for (const QDnsMailExchangeRecord &record : lookup->mailExchangeRecords()) {
                const QString value = QString("%1 (pref=%2)").arg(record.exchange()).arg(record.preference());
                emit dnsRecordFound(label, value);
                emit dnsRecordBatchFound(DnsRecordResult{label, value});
            }
        } else if (label == "TXT") {
            QList<QString> txtValues;
            for (const QDnsTextRecord &record : lookup->textRecords()) {
                const QString value = record.values().join(' ');
                txtValues << value;
                emit dnsRecordFound(label, value);
                emit dnsRecordBatchFound(DnsRecordResult{label, value});
            }
            handleTxtRecords(txtValues);
        }

        lookup->deleteLater();
        --m_pendingLookups;
        if (m_pendingLookups == 0) {
            emit statusMessage(QString("DNS enumeration completed for %1").arg(m_domain));
            emit lookupFinished();
        }
    });

    lookup->lookup();
}

void DnsReconModule::handleTxtRecords(const QList<QString> &values)
{
    bool spfFound = false;
    bool dmarcFound = false;

    for (const QString &value : values) {
        const QString lower = value.toLower();
        if (lower.startsWith("v=spf1")) {
            spfFound = true;
            if (!lower.contains("-all") && !lower.contains("~all")) {
                emit misconfigurationFound("medium", "SPF policy does not define a strict all qualifier");
            }
        }
        if (lower.contains("v=dmarc1")) {
            dmarcFound = true;
            if (!lower.contains("p=reject") && !lower.contains("p=quarantine")) {
                emit misconfigurationFound("medium", "DMARC policy is present but not enforcing quarantine/reject");
            }
        }
    }

    if (!spfFound) {
        emit misconfigurationFound("high", "No SPF TXT record detected");
    }
    if (!dmarcFound) {
        emit misconfigurationFound("medium", "No DMARC TXT policy detected");
    }
}
