#include "spiderscope.h"

#include <QRegularExpression>
#include <QUrl>

QStringList spiderScopePresetPatterns(const QString &preset)
{
    const QString normalized = preset.trimmed().toLower();
    if (normalized == QStringLiteral("guvenli")) {
        return {
            QStringLiteral("(^|\\.)fonts\\.googleapis\\.com"),
            QStringLiteral("(^|\\.)fonts\\.gstatic\\.com"),
            QStringLiteral("(^|\\.)ajax\\.googleapis\\.com"),
            QStringLiteral("(^|\\.)googletagmanager\\.com"),
            QStringLiteral("(^|\\.)google-analytics\\.com"),
            QStringLiteral("(^|\\.)doubleclick\\.net"),
            QStringLiteral("(^|\\.)youtube\\.com"),
            QStringLiteral("(^|\\.)ytimg\\.com"),
            QStringLiteral("(^|\\.)facebook\\.com"),
            QStringLiteral("(^|\\.)fbcdn\\.net"),
            QStringLiteral("(^|\\.)twitter\\.com"),
            QStringLiteral("(^|\\.)x\\.com"),
            QStringLiteral("(^|\\.)linkedin\\.com"),
            QStringLiteral("(^|\\.)cloudflareinsights\\.com"),
            QStringLiteral("(^|\\.)hotjar\\.com"),
            QStringLiteral("(^|\\.)intercomcdn\\.com")
        };
    }
    if (normalized == QStringLiteral("agresif")) {
        return {
            QStringLiteral("(^|\\.)fonts\\.googleapis\\.com"),
            QStringLiteral("(^|\\.)fonts\\.gstatic\\.com")
        };
    }
    return {
        QStringLiteral("(^|\\.)fonts\\.googleapis\\.com"),
        QStringLiteral("(^|\\.)fonts\\.gstatic\\.com"),
        QStringLiteral("(^|\\.)ajax\\.googleapis\\.com"),
        QStringLiteral("(^|\\.)googletagmanager\\.com"),
        QStringLiteral("(^|\\.)google-analytics\\.com"),
        QStringLiteral("(^|\\.)doubleclick\\.net"),
        QStringLiteral("(^|\\.)cloudflareinsights\\.com")
    };
}

QString mergeSpiderExcludePatterns(const QString &manualPatterns, const QString &preset)
{
    QStringList merged = manualPatterns.split('\n', Qt::SkipEmptyParts);
    const QStringList presetPatterns = spiderScopePresetPatterns(preset);
    for (const QString &pattern : presetPatterns) {
        if (!merged.contains(pattern)) {
            merged << pattern;
        }
    }
    return merged.join('\n');
}

bool spiderAssetShouldBeSuppressed(const QString &kind, const QString &value, const QString &preset)
{
    if (kind.startsWith(QStringLiteral("auth-")) || kind == QStringLiteral("redirect-chain") || kind == QStringLiteral("response-signature")) {
        return false;
    }

    const QUrl url = QUrl::fromUserInput(value);
    if (!url.isValid() || url.host().trimmed().isEmpty()) {
        return false;
    }

    const QString candidate = url.host();
    for (const QString &pattern : spiderScopePresetPatterns(preset)) {
        if (QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption).match(candidate).hasMatch()) {
            return true;
        }
    }
    return false;
}
