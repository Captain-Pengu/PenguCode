#pragma once

#include <QUrl>

struct ReconParsedTarget
{
    QString original;
    QString sanitized;
    QString host;
    QString scheme;
    QUrl url;
};

ReconParsedTarget reconParseTarget(const QString &target);
int reconClampedSecurityScore(int score);
QString reconSeverityForPenalty(int penalty);
int reconProgressPercent(int totalStages, int pendingStages);
