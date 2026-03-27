#include "spiderhostinsights.h"

#include <QMap>
#include <QRegularExpression>
#include <QUrl>

namespace {

QString hostFromAsset(const QVariantMap &asset)
{
    const QString source = asset.value(QStringLiteral("source")).toString().trimmed();
    if (!source.isEmpty()) {
        const QUrl sourceUrl(source);
        const QString host = sourceUrl.host().trimmed().toLower();
        if (!host.isEmpty()) {
            return host;
        }
    }

    const QString value = asset.value(QStringLiteral("value")).toString();
    const QRegularExpression hostRegex(QStringLiteral("host=([^|\\s]+)"));
    const auto match = hostRegex.match(value);
    if (match.hasMatch()) {
        return match.captured(1).trimmed().toLower();
    }

    return QStringLiteral("(bilinmiyor)");
}

QString pressureStateOrFallback(const SpiderHostInsightRow &row)
{
    if (!row.pressureState.isEmpty()) {
        return row.pressureState;
    }
    if (row.pressureScore >= 8) {
        return QStringLiteral("STRESSED");
    }
    if (row.wafHits > 0 || row.pressureScore >= 5) {
        return QStringLiteral("WAF");
    }
    if (row.scopeOutliers > 0) {
        return QStringLiteral("SCOPE");
    }
    if (row.suppressedHits > 0 || row.pressureScore > 0) {
        return QStringLiteral("GUARDED");
    }
    return QStringLiteral("STABLE");
}

}

SpiderHostInsightsSummary buildSpiderHostInsights(const QVariantList &endpoints, const QVariantList &assets)
{
    SpiderHostInsightsSummary summary;
    QMap<QString, SpiderHostInsightRow> rows;

    for (const QVariant &value : endpoints) {
        const QVariantMap row = value.toMap();
        const QUrl url(row.value(QStringLiteral("url")).toString());
        const QString host = url.host().trimmed().isEmpty() ? QStringLiteral("(bilinmiyor)") : url.host().trimmed().toLower();
        rows[host].host = host;
        rows[host].endpoints += 1;
    }

    for (const QVariant &value : assets) {
        const QVariantMap row = value.toMap();
        const QString kind = row.value(QStringLiteral("kind")).toString();
        const QString host = hostFromAsset(row);
        auto &hostRow = rows[host];
        hostRow.host = host;

        if (kind.startsWith(QStringLiteral("workflow-")) || kind.startsWith(QStringLiteral("auth-step-"))) {
            hostRow.workflowHits += 1;
            if (kind.endsWith(QStringLiteral("-result"))) {
                hostRow.workflowResultHits += 1;
            }
        } else if (kind == QLatin1String("waf-vendor") || kind == QLatin1String("waf-challenge")) {
            hostRow.wafHits += 1;
            if (kind == QLatin1String("waf-vendor")) {
                hostRow.vendorHint = row.value(QStringLiteral("value")).toString().trimmed();
            }
        } else if (kind == QLatin1String("host-pressure")) {
            const QString valueText = row.value(QStringLiteral("value")).toString();
            const QRegularExpression scoreRegex(QStringLiteral("score=(\\d+)"));
            const QRegularExpression stateRegex(QStringLiteral("state=([^|]+)"));
            const QRegularExpression reasonRegex(QStringLiteral("reason=([^|]+)"));
            const auto scoreMatch = scoreRegex.match(valueText);
            const auto stateMatch = stateRegex.match(valueText);
            const auto reasonMatch = reasonRegex.match(valueText);
            if (scoreMatch.hasMatch()) {
                hostRow.pressureScore = qMax(hostRow.pressureScore, scoreMatch.captured(1).toInt());
            }
            if (stateMatch.hasMatch()) {
                hostRow.pressureState = stateMatch.captured(1).trimmed();
            }
            if (reasonMatch.hasMatch()) {
                hostRow.pressureReason = reasonMatch.captured(1).trimmed();
            }
        } else if (kind == QLatin1String("retry-after")) {
            hostRow.retryAfterCount += 1;
            const QRegularExpression delayRegex(QStringLiteral("delay=(\\d+\\s*ms)"));
            const auto delayMatch = delayRegex.match(row.value(QStringLiteral("value")).toString());
            if (delayMatch.hasMatch()) {
                hostRow.retryDelay = delayMatch.captured(1).trimmed();
            }
        } else if (kind == QLatin1String("retry-scheduled")) {
            hostRow.retryScheduledCount += 1;
        } else if (kind == QLatin1String("crawl-suppressed")) {
            hostRow.suppressedHits += 1;
        } else if (kind == QLatin1String("scope-outlier") || kind == QLatin1String("scope-excluded")) {
            hostRow.scopeOutliers += 1;
        }

        if (kind == QLatin1String("host-pressure")
            || kind == QLatin1String("retry-after")
            || kind == QLatin1String("retry-scheduled")
            || kind == QLatin1String("workflow-submit-result")
            || kind == QLatin1String("workflow-action-result")
            || kind == QLatin1String("waf-vendor")
            || kind == QLatin1String("waf-challenge"))
        {
            const QString entry = QStringLiteral("[%1] %2 -> %3")
                                      .arg(host, kind, row.value(QStringLiteral("value")).toString());
            hostRow.timelineEntries.prepend(entry);
            while (hostRow.timelineEntries.size() > 12) {
                hostRow.timelineEntries.removeLast();
            }
            summary.timelineEntries.prepend(entry);
            while (summary.timelineEntries.size() > 18) {
                summary.timelineEntries.removeLast();
            }
        }
    }

    for (auto it = rows.cbegin(); it != rows.cend(); ++it) {
        const QString state = pressureStateOrFallback(it.value());
        if (state == QLatin1String("STRESSED")) {
            ++summary.stressedHosts;
        } else if (state == QLatin1String("WAF")) {
            ++summary.wafHosts;
        } else if (state == QLatin1String("GUARDED") || state == QLatin1String("SCOPE")) {
            ++summary.guardedHosts;
        } else {
            ++summary.stableHosts;
        }
        summary.rows.push_back(it.value());
    }

    return summary;
}
