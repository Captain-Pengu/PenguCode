#pragma once

#include "spidercore.h"

#include <QStringList>
#include <QUrl>

#include <vector>

struct SpiderWorkflowValidationResult
{
    int validSteps = 0;
    QStringList issues;

    bool valid() const
    {
        return issues.isEmpty();
    }
};

std::vector<SpiderAuthProfile::Step> parseSpiderWorkflowSteps(const QString &workflowText);
SpiderWorkflowValidationResult validateSpiderWorkflowText(const QString &workflowText);
bool spiderLooksLikeSuppressedSafetyTarget(const QUrl &url);
