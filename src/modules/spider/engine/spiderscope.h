#pragma once

#include <QString>
#include <QStringList>

QStringList spiderScopePresetPatterns(const QString &preset);
QString mergeSpiderExcludePatterns(const QString &manualPatterns, const QString &preset);
bool spiderAssetShouldBeSuppressed(const QString &kind, const QString &value, const QString &preset);
