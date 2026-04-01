#include "modules/recon/engine/reconcoreutils.h"

#include <QUrl>

ReconParsedTarget reconParseTarget(const QString &target)
{
    ReconParsedTarget parsed;
    parsed.original = target.trimmed();

    const QUrl candidate = QUrl::fromUserInput(parsed.original);
    parsed.url = candidate.isValid() ? candidate : QUrl(QStringLiteral("https://%1").arg(parsed.original));
    if (parsed.url.scheme().isEmpty()) {
        parsed.url.setScheme(QStringLiteral("https"));
    }

    parsed.host = parsed.url.host().trimmed();
    if (parsed.host.isEmpty()) {
        parsed.host = parsed.original;
    }

    parsed.scheme = parsed.url.scheme().isEmpty() ? QStringLiteral("https") : parsed.url.scheme().toLower();
    parsed.sanitized = parsed.url.toString(QUrl::RemoveUserInfo | QUrl::NormalizePathSegments);
    return parsed;
}

int reconClampedSecurityScore(int score)
{
    return qBound(0, score, 100);
}

QString reconSeverityForPenalty(int penalty)
{
    if (penalty >= 25) {
        return QStringLiteral("high");
    }
    if (penalty >= 10) {
        return QStringLiteral("medium");
    }
    return QStringLiteral("low");
}

int reconProgressPercent(int totalStages, int pendingStages)
{
    if (totalStages <= 0) {
        return 0;
    }

    const int completed = totalStages - pendingStages;
    return static_cast<int>((static_cast<double>(completed) / static_cast<double>(totalStages)) * 100.0);
}
