#pragma once

#include <QMetaType>
#include <QString>
#include <QVariantMap>

struct ServiceFingerprint
{
    QString host;
    int port = 0;
    QString protocol;
    QString service;
    QString banner;
    QString version;
    qint64 responseTimeMs = -1;

    QVariantMap toVariantMap() const
    {
        return {
            {"host", host},
            {"port", port},
            {"protocol", protocol},
            {"service", service},
            {"banner", banner},
            {"version", version},
            {"responseTimeMs", responseTimeMs}
        };
    }
};

struct DnsRecordResult
{
    QString type;
    QString value;

    QVariantMap toVariantMap() const
    {
        return {
            {"type", type},
            {"value", value}
        };
    }
};

struct LeakFinding
{
    QString severity;
    QString details;
    QString source;

    QVariantMap toVariantMap() const
    {
        return {
            {"severity", severity},
            {"details", details},
            {"source", source}
        };
    }
};

struct VulnerabilityMatch
{
    QString host;
    int port = 0;
    QString service;
    QString version;
    QString cveId;
    QString summary;
    QString severity;

    QVariantMap toVariantMap() const
    {
        return {
            {"host", host},
            {"port", port},
            {"service", service},
            {"version", version},
            {"cveId", cveId},
            {"summary", summary},
            {"severity", severity}
        };
    }
};

Q_DECLARE_METATYPE(ServiceFingerprint)
Q_DECLARE_METATYPE(DnsRecordResult)
Q_DECLARE_METATYPE(LeakFinding)
Q_DECLARE_METATYPE(VulnerabilityMatch)
