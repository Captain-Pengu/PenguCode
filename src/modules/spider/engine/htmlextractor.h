#pragma once

#include <QRegularExpression>
#include <QStringList>
#include <QUrl>

#include <memory>
#include <vector>

struct SpiderHtmlFormField
{
    QString name;
    QString type;
    QString role;
    QString value;
};

struct SpiderHtmlForm
{
    QUrl actionUrl;
    QString method;
    QString sourceSummary;
    QStringList fieldNames;
    std::vector<SpiderHtmlFormField> fields;
    bool loginLike = false;
};

struct SpiderHtmlAction
{
    QString kind;
    QString label;
    QUrl targetUrl;
    QString method;
    QString selectorHint;
    QString triggerKind;
};

enum class SpiderHtmlExtractorBackend
{
    Regex,
    FastTokenizer,
    DomLite
};

class ISpiderHtmlExtractor
{
public:
    virtual ~ISpiderHtmlExtractor() = default;

    virtual QString backendName() const = 0;
    virtual QString extractPageTitle(const QString &html) const = 0;
    virtual QStringList extractHeadingHints(const QString &html) const = 0;
    virtual std::vector<QUrl> extractLinks(const QString &html, const QUrl &baseUrl) const = 0;
    virtual std::vector<SpiderHtmlForm> extractForms(const QString &html, const QUrl &baseUrl) const = 0;
    virtual std::vector<SpiderHtmlAction> extractInteractionActions(const QString &html, const QUrl &baseUrl) const = 0;
    virtual QStringList extractInterestingLiterals(const QString &body) const = 0;
    virtual QStringList extractJsRoutes(const QString &body) const = 0;
};

class RegexSpiderHtmlExtractor final : public ISpiderHtmlExtractor
{
public:
    QString backendName() const override;
    QString extractPageTitle(const QString &html) const override;
    QStringList extractHeadingHints(const QString &html) const override;
    std::vector<QUrl> extractLinks(const QString &html, const QUrl &baseUrl) const override;
    std::vector<SpiderHtmlForm> extractForms(const QString &html, const QUrl &baseUrl) const override;
    std::vector<SpiderHtmlAction> extractInteractionActions(const QString &html, const QUrl &baseUrl) const override;
    QStringList extractInterestingLiterals(const QString &body) const override;
    QStringList extractJsRoutes(const QString &body) const override;

    static QString normalizedFieldType(QString tagName, QString typeValue);
    static QString classifyFieldRole(const QString &fieldName, const QString &fieldType, const QString &autoComplete);
};

class FastSpiderHtmlExtractor final : public ISpiderHtmlExtractor
{
public:
    QString backendName() const override;
    QString extractPageTitle(const QString &html) const override;
    QStringList extractHeadingHints(const QString &html) const override;
    std::vector<QUrl> extractLinks(const QString &html, const QUrl &baseUrl) const override;
    std::vector<SpiderHtmlForm> extractForms(const QString &html, const QUrl &baseUrl) const override;
    std::vector<SpiderHtmlAction> extractInteractionActions(const QString &html, const QUrl &baseUrl) const override;
    QStringList extractInterestingLiterals(const QString &body) const override;
    QStringList extractJsRoutes(const QString &body) const override;
};

class DomSpiderHtmlExtractor final : public ISpiderHtmlExtractor
{
public:
    QString backendName() const override;
    QString extractPageTitle(const QString &html) const override;
    QStringList extractHeadingHints(const QString &html) const override;
    std::vector<QUrl> extractLinks(const QString &html, const QUrl &baseUrl) const override;
    std::vector<SpiderHtmlForm> extractForms(const QString &html, const QUrl &baseUrl) const override;
    std::vector<SpiderHtmlAction> extractInteractionActions(const QString &html, const QUrl &baseUrl) const override;
    QStringList extractInterestingLiterals(const QString &body) const override;
    QStringList extractJsRoutes(const QString &body) const override;
};

class Html5SpiderHtmlExtractor final : public ISpiderHtmlExtractor
{
public:
    QString backendName() const override;
    QString extractPageTitle(const QString &html) const override;
    QStringList extractHeadingHints(const QString &html) const override;
    std::vector<QUrl> extractLinks(const QString &html, const QUrl &baseUrl) const override;
    std::vector<SpiderHtmlForm> extractForms(const QString &html, const QUrl &baseUrl) const override;
    std::vector<SpiderHtmlAction> extractInteractionActions(const QString &html, const QUrl &baseUrl) const override;
    QStringList extractInterestingLiterals(const QString &body) const override;
    QStringList extractJsRoutes(const QString &body) const override;
};

std::unique_ptr<ISpiderHtmlExtractor> createBestSpiderHtmlExtractor();
std::unique_ptr<ISpiderHtmlExtractor> createSpiderHtmlExtractor(SpiderHtmlExtractorBackend backend);
