#include "spiderworkflow.h"

namespace {

QVariantMap parseWorkflowFieldMap(const QStringList &fieldParts)
{
    QVariantMap fields;
    for (const QString &part : fieldParts) {
        const QString trimmed = part.trimmed();
        if (trimmed.isEmpty()) {
            continue;
        }
        const int eq = trimmed.indexOf('=');
        if (eq <= 0) {
            continue;
        }
        fields.insert(trimmed.left(eq).trimmed(), trimmed.mid(eq + 1).trimmed());
    }
    return fields;
}

bool looksLikeWorkflowToken(const QString &token)
{
    return token.compare(QStringLiteral("optional"), Qt::CaseInsensitive) == 0
        || token.startsWith(QStringLiteral("label="), Qt::CaseInsensitive)
        || token.startsWith(QStringLiteral("delay="), Qt::CaseInsensitive)
        || token.startsWith(QStringLiteral("expect="), Qt::CaseInsensitive)
        || token.startsWith(QStringLiteral("header:"), Qt::CaseInsensitive)
        || token.contains('=');
}

} // namespace

std::vector<SpiderAuthProfile::Step> parseSpiderWorkflowSteps(const QString &workflowText)
{
    std::vector<SpiderAuthProfile::Step> steps;
    const QStringList lines = workflowText.split('\n', Qt::SkipEmptyParts);
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith('#')) {
            continue;
        }

        const QStringList parts = trimmed.split('|');
        if (parts.isEmpty()) {
            continue;
        }

        SpiderAuthProfile::Step step;
        const QString rawUrl = parts.value(0).trimmed();
        if (rawUrl.isEmpty()) {
            continue;
        }
        if (rawUrl != QLatin1String("@current")) {
            step.url = QUrl::fromUserInput(rawUrl);
            if (!step.url.isValid() && !rawUrl.startsWith('/')) {
                continue;
            }
            if (!step.url.isValid() && rawUrl.startsWith('/')) {
                step.url = QUrl(rawUrl);
            }
        }
        step.method = parts.value(1, QStringLiteral("POST")).trimmed().toUpper();
        const QString mode = parts.value(2, QStringLiteral("form")).trimmed().toLower();
        step.fetchFormFirst = (mode != QLatin1String("direct"));
        QStringList fieldParts;
        for (int i = 3; i < parts.size(); ++i) {
            const QString token = parts.at(i).trimmed();
            if (token.compare(QStringLiteral("optional"), Qt::CaseInsensitive) == 0) {
                step.optional = true;
                continue;
            }
            if (token.startsWith(QStringLiteral("label="), Qt::CaseInsensitive)) {
                step.label = token.mid(6).trimmed();
                continue;
            }
            if (token.startsWith(QStringLiteral("delay="), Qt::CaseInsensitive)) {
                step.pauseAfterMs = qMax(0, token.mid(6).trimmed().toInt());
                continue;
            }
            if (token.startsWith(QStringLiteral("expect="), Qt::CaseInsensitive)) {
                const QString rule = token.mid(7).trimmed();
                if (rule.startsWith(QStringLiteral("status:"), Qt::CaseInsensitive)) {
                    step.expectedStatusCode = rule.mid(7).toInt();
                } else if (rule.startsWith(QStringLiteral("url:"), Qt::CaseInsensitive)) {
                    step.expectedUrlContains = rule.mid(4).trimmed();
                } else if (rule.startsWith(QStringLiteral("!redirect:"), Qt::CaseInsensitive)) {
                    step.expectedRedirectNotContains = rule.mid(10).trimmed();
                } else if (rule.startsWith(QStringLiteral("redirect:"), Qt::CaseInsensitive)) {
                    step.expectedRedirectContains = rule.mid(9).trimmed();
                } else if (rule.startsWith(QStringLiteral("body:"), Qt::CaseInsensitive)) {
                    step.expectedBodyContains = rule.mid(5).trimmed();
                } else if (rule.startsWith(QStringLiteral("header:"), Qt::CaseInsensitive)) {
                    step.expectedHeaderContains = rule.mid(7).trimmed();
                } else if (rule.startsWith(QStringLiteral("cookie:"), Qt::CaseInsensitive)) {
                    step.expectedCookieName = rule.mid(7).trimmed();
                } else if (rule.compare(QStringLiteral("!login"), Qt::CaseInsensitive) == 0) {
                    step.expectNotLogin = true;
                }
            } else if (token.startsWith(QStringLiteral("header:"), Qt::CaseInsensitive)) {
                const QString headerPart = token.mid(7).trimmed();
                const int eq = headerPart.indexOf('=');
                if (eq > 0) {
                    step.headers.insert(headerPart.left(eq).trimmed(), headerPart.mid(eq + 1).trimmed());
                }
            } else {
                fieldParts << token;
            }
        }
        step.fields = parseWorkflowFieldMap(fieldParts);
        steps.push_back(std::move(step));
    }
    return steps;
}

SpiderWorkflowValidationResult validateSpiderWorkflowText(const QString &workflowText)
{
    SpiderWorkflowValidationResult result;
    const QString trimmedText = workflowText.trimmed();
    if (trimmedText.isEmpty()) {
        return result;
    }

    const QStringList lines = trimmedText.split('\n', Qt::SkipEmptyParts);
    for (int i = 0; i < lines.size(); ++i) {
        const QString trimmed = lines.at(i).trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith('#')) {
            continue;
        }

        bool lineValid = true;
        const QStringList parts = trimmed.split('|');
        if (parts.size() < 3) {
            result.issues << QObject::tr("Satir %1: en az url|METHOD|mode bekleniyor").arg(i + 1);
            continue;
        }

        const QString rawUrl = parts.value(0).trimmed();
        const QString method = parts.value(1).trimmed().toUpper();
        const QString mode = parts.value(2).trimmed().toLower();
        if (!(rawUrl == QLatin1String("@current") || rawUrl.startsWith('/') || QUrl::fromUserInput(rawUrl).isValid())) {
            result.issues << QObject::tr("Satir %1: URL gecersiz").arg(i + 1);
            lineValid = false;
        }
        if (method != QLatin1String("GET") && method != QLatin1String("POST")) {
            result.issues << QObject::tr("Satir %1: yalnizca GET veya POST desteklenir").arg(i + 1);
            lineValid = false;
        }
        if (mode != QLatin1String("form") && mode != QLatin1String("direct")) {
            result.issues << QObject::tr("Satir %1: mode form veya direct olmali").arg(i + 1);
            lineValid = false;
        }

        for (int partIndex = 3; partIndex < parts.size(); ++partIndex) {
            const QString token = parts.at(partIndex).trimmed();
            if (token.isEmpty()) {
                continue;
            }
            if (token.startsWith(QStringLiteral("delay="), Qt::CaseInsensitive)) {
                bool ok = false;
                token.mid(6).trimmed().toInt(&ok);
                if (!ok) {
                    result.issues << QObject::tr("Satir %1: delay sayisal olmali").arg(i + 1);
                    lineValid = false;
                }
                continue;
            }
            if (token.startsWith(QStringLiteral("header:"), Qt::CaseInsensitive)) {
                const QString headerPart = token.mid(7).trimmed();
                if (!headerPart.contains('=')) {
                    result.issues << QObject::tr("Satir %1: header anahtar=deger olmali").arg(i + 1);
                    lineValid = false;
                }
                continue;
            }
            if (token.startsWith(QStringLiteral("expect="), Qt::CaseInsensitive)) {
                const QString rule = token.mid(7).trimmed();
                const bool knownExpectation =
                    rule.startsWith(QStringLiteral("status:"), Qt::CaseInsensitive)
                    || rule.startsWith(QStringLiteral("url:"), Qt::CaseInsensitive)
                    || rule.startsWith(QStringLiteral("!redirect:"), Qt::CaseInsensitive)
                    || rule.startsWith(QStringLiteral("redirect:"), Qt::CaseInsensitive)
                    || rule.startsWith(QStringLiteral("body:"), Qt::CaseInsensitive)
                    || rule.startsWith(QStringLiteral("header:"), Qt::CaseInsensitive)
                    || rule.startsWith(QStringLiteral("cookie:"), Qt::CaseInsensitive)
                    || rule.compare(QStringLiteral("!login"), Qt::CaseInsensitive) == 0;
                if (!knownExpectation) {
                    result.issues << QObject::tr("Satir %1: expect kurali bilinmiyor").arg(i + 1);
                    lineValid = false;
                }
                continue;
            }
            if (!looksLikeWorkflowToken(token)) {
                result.issues << QObject::tr("Satir %1: token anlasilmadi (%2)").arg(i + 1).arg(token);
                lineValid = false;
            }
        }

        if (lineValid) {
            ++result.validSteps;
        }
    }
    return result;
}

bool spiderLooksLikeSuppressedSafetyTarget(const QUrl &url)
{
    const QString candidate = (url.path() + QStringLiteral(" ") + url.query()).toLower();
    return candidate.contains(QStringLiteral("logout"))
        || candidate.contains(QStringLiteral("signout"))
        || candidate.contains(QStringLiteral("sign-out"))
        || candidate.contains(QStringLiteral("logoff"))
        || candidate.contains(QStringLiteral("destroy"))
        || candidate.contains(QStringLiteral("terminate"))
        || candidate.contains(QStringLiteral("revoke"))
        || candidate.contains(QStringLiteral("deleteaccount"))
        || candidate.contains(QStringLiteral("delete-account"));
}
