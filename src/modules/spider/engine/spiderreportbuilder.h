#pragma once

#include <QString>

class SpiderModule;

QString spiderReportFileName(const QString &target, const QString &extension);
QString spiderReportDefaultPath(const QString &target, const QString &extension);
bool saveSpiderPdfReport(const QString &path, const QString &html, QString *errorMessage);
QString buildSpiderReportHtml(const SpiderModule &module, const QStringList &featureItems);
