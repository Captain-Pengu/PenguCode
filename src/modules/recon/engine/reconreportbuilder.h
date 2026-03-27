#pragma once

#include "modules/recon/engine/pengufoce_masterscanner.h"

#include <QVariantMap>

struct ReconReportContext
{
    QString companyName;
    QString clientName;
    QString testerName;
    QString classification;
    QString scopeSummary;
    QVariantMap spiderSnapshot;
    QVariantMap findingNotes;
};

ScanReport reconScanReportFromVariantMap(const QVariantMap &map);
QString reconCorporateReportFileName(const QString &company, const QString &target, const QString &extension);
QVariantMap reconDeveloperGuidanceForFinding(const QString &title, const QString &description);
QString buildReconFindingDetailHtml(const QString &severity,
                                    const QString &title,
                                    const QString &description,
                                    const QString &analystNote);
int reconSeverityRank(const QString &severity);
QString buildReconDiffSummary(const QVariantMap &currentReport, const QVariantMap &baselineReport);
QString buildReconReportHtml(const ReconReportContext &context, const ScanReport &report, int securityScore);
