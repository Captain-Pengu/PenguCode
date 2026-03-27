#pragma once

#include <QVariantList>

#include <QString>
#include <QStringList>
#include <QVector>

struct SpiderHostInsightRow
{
    QString host;
    int endpoints = 0;
    int workflowHits = 0;
    int workflowResultHits = 0;
    int wafHits = 0;
    int suppressedHits = 0;
    int scopeOutliers = 0;
    int pressureScore = 0;
    QString pressureState;
    QString pressureReason;
    int retryAfterCount = 0;
    int retryScheduledCount = 0;
    QString retryDelay;
    QString vendorHint;
    QStringList timelineEntries;
};

struct SpiderHostInsightsSummary
{
    QVector<SpiderHostInsightRow> rows;
    QStringList timelineEntries;
    int stableHosts = 0;
    int guardedHosts = 0;
    int wafHosts = 0;
    int stressedHosts = 0;
};

SpiderHostInsightsSummary buildSpiderHostInsights(const QVariantList &endpoints, const QVariantList &assets);
