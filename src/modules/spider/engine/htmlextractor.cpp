#include "htmlextractor.h"

#include <QProcessEnvironment>
#include <QVector>

#ifdef PENGUFOCE_WITH_GUMBO
#include <gumbo.h>
#endif

namespace {

struct ParsedHtmlTag
{
    QString name;
    QVariantMap attrs;
    bool closing = false;
    bool selfClosing = false;
    int start = 0;
    int end = 0;
};

const QRegularExpression kTagStripper(QStringLiteral("<[^>]+>"));

QString stripHtml(QString text)
{
    return text.remove(kTagStripper).simplified();
}

QString extractAttributeValue(QStringView attrs, QStringView name)
{
    const QString lowerAttrs = attrs.toString().toLower();
    const QString lowerName = name.toString().toLower();
    const QString token = lowerName + "=";
    int pos = lowerAttrs.indexOf(token);
    if (pos < 0) {
        return {};
    }

    pos += token.size();
    while (pos < attrs.size() && attrs.at(pos).isSpace()) {
        ++pos;
    }
    if (pos >= attrs.size()) {
        return {};
    }

    const QChar quote = attrs.at(pos);
    if (quote == '\'' || quote == '"') {
        const int end = attrs.indexOf(quote, pos + 1);
        return end > pos ? attrs.mid(pos + 1, end - pos - 1).toString().trimmed() : QString();
    }

    int end = pos;
    while (end < attrs.size() && !attrs.at(end).isSpace() && attrs.at(end) != '>') {
        ++end;
    }
    return attrs.mid(pos, end - pos).toString().trimmed();
}

QString tagInnerText(const QString &html, QStringView openTag, QStringView closeTag, int from = 0)
{
    const QString lowerHtml = html.toLower();
    const QString open = openTag.toString().toLower();
    const QString close = closeTag.toString().toLower();
    const int start = lowerHtml.indexOf(open, from);
    if (start < 0) {
        return {};
    }
    const int contentStart = lowerHtml.indexOf('>', start);
    if (contentStart < 0) {
        return {};
    }
    const int end = lowerHtml.indexOf(close, contentStart + 1);
    if (end < 0) {
        return {};
    }
    return stripHtml(html.mid(contentStart + 1, end - contentStart - 1));
}

bool isInterestingUrl(QStringView raw)
{
    if (raw.isEmpty()) {
        return false;
    }
    return !raw.startsWith('#')
        && !raw.startsWith(QStringLiteral("javascript:"), Qt::CaseInsensitive)
        && !raw.startsWith(QStringLiteral("mailto:"), Qt::CaseInsensitive)
        && !raw.startsWith(QStringLiteral("tel:"), Qt::CaseInsensitive);
}

QVariantMap extractAllAttributes(QStringView attrs)
{
    QVariantMap map;
    int pos = 0;
    while (pos < attrs.size()) {
        while (pos < attrs.size() && attrs.at(pos).isSpace()) {
            ++pos;
        }
        const int nameStart = pos;
        while (pos < attrs.size() && !attrs.at(pos).isSpace() && attrs.at(pos) != '=' && attrs.at(pos) != '/' && attrs.at(pos) != '>') {
            ++pos;
        }
        const QString key = attrs.mid(nameStart, pos - nameStart).toString().trimmed().toLower();
        while (pos < attrs.size() && attrs.at(pos).isSpace()) {
            ++pos;
        }
        QString value;
        if (pos < attrs.size() && attrs.at(pos) == '=') {
            ++pos;
            while (pos < attrs.size() && attrs.at(pos).isSpace()) {
                ++pos;
            }
            if (pos < attrs.size() && (attrs.at(pos) == '"' || attrs.at(pos) == '\'')) {
                const QChar quote = attrs.at(pos++);
                const int end = attrs.indexOf(quote, pos);
                value = (end >= pos ? attrs.mid(pos, end - pos) : attrs.mid(pos)).toString();
                pos = end >= 0 ? end + 1 : attrs.size();
            } else {
                const int valueStart = pos;
                while (pos < attrs.size() && !attrs.at(pos).isSpace() && attrs.at(pos) != '>' && attrs.at(pos) != '/') {
                    ++pos;
                }
                value = attrs.mid(valueStart, pos - valueStart).toString();
            }
        }
        if (!key.isEmpty()) {
            map.insert(key, value.trimmed());
        }
    }
    return map;
}

std::vector<ParsedHtmlTag> tokenizeHtml(const QString &html)
{
    std::vector<ParsedHtmlTag> tags;
    int pos = 0;
    while ((pos = html.indexOf('<', pos)) >= 0) {
        const int end = html.indexOf('>', pos + 1);
        if (end < 0) {
            break;
        }
        QStringView raw = QStringView(html).mid(pos + 1, end - pos - 1).trimmed();
        if (raw.isEmpty() || raw.startsWith('!') || raw.startsWith('?')) {
            pos = end + 1;
            continue;
        }
        ParsedHtmlTag tag;
        tag.start = pos;
        tag.end = end;
        if (raw.startsWith('/')) {
            tag.closing = true;
            raw = raw.mid(1).trimmed();
        }
        if (raw.endsWith('/')) {
            tag.selfClosing = true;
            raw = raw.left(raw.size() - 1).trimmed();
        }
        int split = 0;
        while (split < raw.size() && !raw.at(split).isSpace()) {
            ++split;
        }
        tag.name = raw.left(split).toString().trimmed().toLower();
        if (!tag.closing && split < raw.size()) {
            tag.attrs = extractAllAttributes(raw.mid(split));
        }
        if (!tag.name.isEmpty()) {
            tags.push_back(std::move(tag));
        }
        pos = end + 1;
    }
    return tags;
}

QString innerTextBetween(const QString &html, const ParsedHtmlTag &openTag, const QString &closingName)
{
    const QString closeToken = QStringLiteral("</%1").arg(closingName);
    const QString lowerHtml = html.toLower();
    const int closeStart = lowerHtml.indexOf(closeToken, openTag.end + 1);
    if (closeStart < 0) {
        return {};
    }
    return stripHtml(html.mid(openTag.end + 1, closeStart - openTag.end - 1));
}

QString routeLikeValue(const QString &value)
{
    const QString trimmed = value.trimmed();
    if (trimmed.startsWith('/')) {
        return trimmed;
    }
    const QRegularExpression regex(QStringLiteral(R"((/(?:api|admin|auth|dashboard|panel|graphql|internal|test|v1|v2|manifest|sw|service-worker|worker|rest|rpc|gateway|service)[^"'\s)]*))"),
                                   QRegularExpression::CaseInsensitiveOption);
    const auto match = regex.match(trimmed);
    return match.hasMatch() ? match.captured(1).trimmed() : QString();
}

void appendResolvedUrlIfValid(std::vector<QUrl> &result, const QUrl &baseUrl, const QString &raw)
{
    if (!isInterestingUrl(raw)) {
        return;
    }
    const QUrl resolved = baseUrl.resolved(QUrl(raw.trimmed()));
    if (resolved.isValid()) {
        result.push_back(resolved);
    }
}

void appendSrcsetUrls(std::vector<QUrl> &result, const QUrl &baseUrl, const QString &srcset)
{
    const QStringList candidates = srcset.split(',', Qt::SkipEmptyParts);
    for (const QString &candidate : candidates) {
        const QString raw = candidate.trimmed().section(' ', 0, 0).trimmed();
        appendResolvedUrlIfValid(result, baseUrl, raw);
    }
}

QString metaRefreshTarget(const QString &content)
{
    static const QRegularExpression refreshRegex(QStringLiteral(R"(url\s*=\s*([^;]+)$)"),
                                                 QRegularExpression::CaseInsensitiveOption);
    const auto match = refreshRegex.match(content.trimmed());
    return match.hasMatch() ? match.captured(1).trimmed().remove('\'').remove('"') : QString();
}

QString tagLabelHint(const QString &html, const ParsedHtmlTag &tag)
{
    const QString text = innerTextBetween(html, tag, tag.name).trimmed();
    if (!text.isEmpty()) {
        return text.left(80);
    }
    return tag.attrs.value(QStringLiteral("aria-label")).toString().left(80);
}

QString selectorHintForTag(const ParsedHtmlTag &tag)
{
    const QString id = tag.attrs.value(QStringLiteral("id")).toString().trimmed();
    if (!id.isEmpty()) {
        return QStringLiteral("#%1").arg(id);
    }
    const QString dataTestId = tag.attrs.value(QStringLiteral("data-testid")).toString().trimmed();
    if (!dataTestId.isEmpty()) {
        return QStringLiteral("[data-testid=\"%1\"]").arg(dataTestId);
    }
    const QString name = tag.attrs.value(QStringLiteral("name")).toString().trimmed();
    if (!name.isEmpty()) {
        return QStringLiteral("%1[name=\"%2\"]").arg(tag.name, name);
    }
    const QString className = tag.attrs.value(QStringLiteral("class")).toString().split(' ', Qt::SkipEmptyParts).value(0);
    if (!className.trimmed().isEmpty()) {
        return QStringLiteral("%1.%2").arg(tag.name, className.trimmed());
    }
    return tag.name;
}

#ifdef PENGUFOCE_WITH_GUMBO

QString gumboNodeText(const GumboNode *node)
{
    if (!node) {
        return {};
    }
    if (node->type == GUMBO_NODE_TEXT || node->type == GUMBO_NODE_WHITESPACE || node->type == GUMBO_NODE_CDATA) {
        return QString::fromUtf8(node->v.text.text);
    }
    if (node->type != GUMBO_NODE_ELEMENT && node->type != GUMBO_NODE_TEMPLATE) {
        return {};
    }

    QString text;
    const GumboVector *children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        text += gumboNodeText(static_cast<GumboNode *>(children->data[i]));
        text += QLatin1Char(' ');
    }
    return text.simplified();
}

QString gumboAttr(const GumboNode *node, const char *name)
{
    if (!node || node->type != GUMBO_NODE_ELEMENT) {
        return {};
    }
    if (GumboAttribute *attr = gumbo_get_attribute(&node->v.element.attributes, name)) {
        return QString::fromUtf8(attr->value).trimmed();
    }
    return {};
}

void collectGumboElements(const GumboNode *node, GumboTag tag, QVector<const GumboNode *> &out)
{
    if (!node || node->type != GUMBO_NODE_ELEMENT) {
        return;
    }
    if (node->v.element.tag == tag) {
        out.push_back(node);
    }
    const GumboVector *children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        collectGumboElements(static_cast<GumboNode *>(children->data[i]), tag, out);
    }
}

void collectGumboInterestingNodes(const GumboNode *node, QVector<const GumboNode *> &out)
{
    if (!node || node->type != GUMBO_NODE_ELEMENT) {
        return;
    }
    const GumboTag tag = node->v.element.tag;
    if (tag == GUMBO_TAG_A
        || tag == GUMBO_TAG_FORM
        || tag == GUMBO_TAG_INPUT
        || tag == GUMBO_TAG_TEXTAREA
        || tag == GUMBO_TAG_SELECT
        || tag == GUMBO_TAG_BUTTON) {
        out.push_back(node);
    }
    const GumboVector *children = &node->v.element.children;
    for (unsigned int i = 0; i < children->length; ++i) {
        collectGumboInterestingNodes(static_cast<GumboNode *>(children->data[i]), out);
    }
}

#endif

}

QString RegexSpiderHtmlExtractor::backendName() const
{
    return QStringLiteral("regex");
}

QString RegexSpiderHtmlExtractor::extractPageTitle(const QString &html) const
{
    static const QRegularExpression titleRegex(QStringLiteral(R"(<title[^>]*>(.*?)</title>)"),
                                               QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
    const auto match = titleRegex.match(html);
    return match.hasMatch() ? match.captured(1).remove(kTagStripper).simplified().left(120) : QString();
}

QStringList RegexSpiderHtmlExtractor::extractHeadingHints(const QString &html) const
{
    QStringList headings;
    static const QRegularExpression headingRegex(QStringLiteral(R"(<h[1-3][^>]*>(.*?)</h[1-3]>)"),
                                                 QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
    auto it = headingRegex.globalMatch(html);
    while (it.hasNext()) {
        const QString value = stripHtml(it.next().captured(1));
        if (!value.isEmpty()) {
            headings << value.left(80);
        }
    }
    headings.removeDuplicates();
    return headings.mid(0, 4);
}

std::vector<QUrl> RegexSpiderHtmlExtractor::extractLinks(const QString &html, const QUrl &baseUrl) const
{
    std::vector<QUrl> result;
    static const QRegularExpression regex(QStringLiteral(R"((?:href|src|action|data-href|data-url|data-src|formaction|poster|ng-href|ng-src)\s*=\s*["']([^"'#]+)["'])"),
                                          QRegularExpression::CaseInsensitiveOption);
    auto it = regex.globalMatch(html);
    while (it.hasNext()) {
        const QString raw = it.next().captured(1).trimmed();
        appendResolvedUrlIfValid(result, baseUrl, raw);
    }

    static const QRegularExpression srcsetRegex(QStringLiteral(R"(srcset\s*=\s*["']([^"']+)["'])"),
                                                QRegularExpression::CaseInsensitiveOption);
    auto srcsetIt = srcsetRegex.globalMatch(html);
    while (srcsetIt.hasNext()) {
        appendSrcsetUrls(result, baseUrl, srcsetIt.next().captured(1));
    }

    static const QRegularExpression refreshRegex(QStringLiteral(R"(<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']([^"']+)["'][^>]*>)"),
                                                 QRegularExpression::CaseInsensitiveOption);
    auto refreshIt = refreshRegex.globalMatch(html);
    while (refreshIt.hasNext()) {
        appendResolvedUrlIfValid(result, baseUrl, metaRefreshTarget(refreshIt.next().captured(1)));
    }

    static const QRegularExpression metaUrlRegex(
        QStringLiteral(R"(<meta[^>]*(?:property|name)\s*=\s*["'](?:og:url|twitter:url)["'][^>]*content\s*=\s*["']([^"']+)["'][^>]*>)"),
        QRegularExpression::CaseInsensitiveOption);
    auto metaIt = metaUrlRegex.globalMatch(html);
    while (metaIt.hasNext()) {
        appendResolvedUrlIfValid(result, baseUrl, metaIt.next().captured(1));
    }
    return result;
}

QString RegexSpiderHtmlExtractor::normalizedFieldType(QString tagName, QString typeValue)
{
    tagName = tagName.trimmed().toLower();
    typeValue = typeValue.trimmed().toLower();
    if (!typeValue.isEmpty()) {
        return typeValue;
    }
    if (tagName == "textarea") {
        return QStringLiteral("textarea");
    }
    if (tagName == "select") {
        return QStringLiteral("select");
    }
    return QStringLiteral("text");
}

QString RegexSpiderHtmlExtractor::classifyFieldRole(const QString &fieldName, const QString &fieldType, const QString &autoComplete)
{
    const QString loweredName = fieldName.toLower();
    const QString loweredType = fieldType.toLower();
    const QString loweredAutocomplete = autoComplete.toLower();

    if (loweredName.contains("csrf") || loweredName.contains("_token") || loweredName.contains("xsrf")) {
        return QStringLiteral("csrf");
    }
    if (loweredType == "hidden" || loweredName.contains("token")) {
        return QStringLiteral("gizli-alan");
    }
    if (loweredType == "file" || loweredName.contains("upload") || loweredName.contains("attachment")) {
        return QStringLiteral("dosya-yukleme");
    }
    if (loweredType == "search" || loweredName.contains("search") || loweredName.contains("query") || loweredName == "q") {
        return QStringLiteral("arama");
    }
    if (loweredType == "password") {
        return QStringLiteral("parola");
    }
    if (loweredType == "email"
        || loweredAutocomplete.contains("username")
        || loweredName.contains("user")
        || loweredName.contains("mail")
        || loweredName.contains("login")
        || loweredName.contains("account")) {
        return QStringLiteral("kullanici-adi");
    }
    if (loweredType == "textarea"
        || loweredName.contains("comment")
        || loweredName.contains("message")
        || loweredName.contains("feedback")
        || loweredName.contains("description")) {
        return QStringLiteral("yorum");
    }
    if (loweredName.contains("role")
        || loweredName.contains("permission")
        || loweredName.contains("status")
        || loweredName.contains("admin")
        || loweredName.contains("filter")) {
        return QStringLiteral("admin-filtresi");
    }
    if (loweredType == "tel" || loweredType == "number" || loweredName.contains("phone")) {
        return QStringLiteral("iletisim-veya-sayisal");
    }
    if (loweredType == "text") {
        return QStringLiteral("genel-girdi");
    }
    return QStringLiteral("diger");
}

std::vector<SpiderHtmlForm> RegexSpiderHtmlExtractor::extractForms(const QString &html, const QUrl &baseUrl) const
{
    std::vector<SpiderHtmlForm> forms;

    static const QRegularExpression formBlockRegex(
        QStringLiteral(R"(<form\b([^>]*)>(.*?)</form>)"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
    static const QRegularExpression attrRegex(
        QStringLiteral(R"((action|method)\s*=\s*["']([^"']*)["'])"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression fieldRegex(
        QStringLiteral(R"(<(input|select|textarea)\b([^>]*)>)"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression fieldAttrRegex(
        QStringLiteral(R"((name|type|autocomplete|value)\s*=\s*["']([^"']*)["'])"),
        QRegularExpression::CaseInsensitiveOption);

    auto formIt = formBlockRegex.globalMatch(html);
    while (formIt.hasNext()) {
        const auto formMatch = formIt.next();
        SpiderHtmlForm form;
        const QString formAttrs = formMatch.captured(1);
        const QString formBody = formMatch.captured(2);

        auto attrIt = attrRegex.globalMatch(formAttrs);
        while (attrIt.hasNext()) {
            const auto attr = attrIt.next();
            const QString key = attr.captured(1).trimmed().toLower();
            const QString value = attr.captured(2).trimmed();
            if (key == "action") {
                form.actionUrl = baseUrl.resolved(QUrl(value));
            } else if (key == "method") {
                form.method = value.toUpper();
            }
        }
        if (!form.actionUrl.isValid()) {
            form.actionUrl = baseUrl;
        }
        if (form.method.isEmpty()) {
            form.method = QStringLiteral("GET");
        }

        bool hasPassword = false;
        bool hasIdentity = false;
        auto fieldIt = fieldRegex.globalMatch(formBody);
        while (fieldIt.hasNext()) {
            const auto fieldMatch = fieldIt.next();
            const QString tagName = fieldMatch.captured(1).trimmed();
            const QString attrs = fieldMatch.captured(2);
            QString fieldName;
            QString fieldType;
            QString autoComplete;
            QString fieldValue;

            auto fieldAttrIt = fieldAttrRegex.globalMatch(attrs);
            while (fieldAttrIt.hasNext()) {
                const auto attr = fieldAttrIt.next();
                const QString key = attr.captured(1).trimmed().toLower();
                const QString value = attr.captured(2).trimmed();
                if (key == "name") {
                    fieldName = value;
                } else if (key == "type") {
                    fieldType = value;
                } else if (key == "autocomplete") {
                    autoComplete = value.toLower();
                } else if (key == "value") {
                    fieldValue = value;
                }
            }

            const QString normalizedType = normalizedFieldType(tagName, fieldType);
            if (!fieldName.isEmpty()) {
                form.fieldNames << fieldName;
                form.fields.push_back({fieldName, normalizedType, classifyFieldRole(fieldName, normalizedType, autoComplete), fieldValue});
            }

            const QString loweredName = fieldName.toLower();
            if (normalizedType == "password" || loweredName.contains("password") || autoComplete.contains("current-password")) {
                hasPassword = true;
            }
            if (normalizedType == "email"
                || loweredName.contains("user")
                || loweredName.contains("mail")
                || loweredName.contains("login")
                || loweredName.contains("account")
                || autoComplete.contains("username")) {
                hasIdentity = true;
            }
        }

        form.loginLike = hasPassword && hasIdentity;
        const QStringList summaryPieces = {
            form.method,
            form.loginLike ? QStringLiteral("login-form") : QStringLiteral("form"),
            QStringLiteral("%1 alan").arg(form.fieldNames.size())
        };
        form.sourceSummary = summaryPieces.join(' ');
        forms.push_back(std::move(form));
    }

    return forms;
}

std::vector<SpiderHtmlAction> RegexSpiderHtmlExtractor::extractInteractionActions(const QString &html, const QUrl &baseUrl) const
{
    std::vector<SpiderHtmlAction> actions;
    static const QRegularExpression actionRegex(
        QStringLiteral(R"(<(button|a|div|span)[^>]*(?:onclick|data-url|data-href|href)\s*=\s*["']([^"']+)["'][^>]*>(.*?)</\1>)"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
    auto it = actionRegex.globalMatch(html);
    while (it.hasNext()) {
        const auto match = it.next();
        QString raw = match.captured(2).trimmed();
        raw = routeLikeValue(raw).isEmpty() ? raw : routeLikeValue(raw);
        if (!isInterestingUrl(raw)) {
            continue;
        }
        const QUrl resolved = baseUrl.resolved(QUrl(raw));
        if (!resolved.isValid()) {
            continue;
        }
        actions.push_back({QStringLiteral("interactive"),
                           stripHtml(match.captured(3)).left(80),
                           resolved,
                           QStringLiteral("GET"),
                           QStringLiteral("regex-candidate"),
                           QStringLiteral("inline")});
    }
    return actions;
}

QStringList RegexSpiderHtmlExtractor::extractInterestingLiterals(const QString &body) const
{
    QStringList findings;

    static const QRegularExpression emailRegex(QStringLiteral(R"(([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}))"),
                                               QRegularExpression::CaseInsensitiveOption);
    auto emailIt = emailRegex.globalMatch(body);
    while (emailIt.hasNext()) {
        findings << QStringLiteral("email:%1").arg(emailIt.next().captured(1));
    }

    static const QRegularExpression commentRegex(QStringLiteral(R"(<!--(.*?)-->)"),
                                                 QRegularExpression::DotMatchesEverythingOption);
    auto commentIt = commentRegex.globalMatch(body);
    while (commentIt.hasNext()) {
        const QString comment = commentIt.next().captured(1).simplified();
        if (!comment.isEmpty() && comment.size() <= 180) {
            findings << QStringLiteral("comment:%1").arg(comment);
        }
    }

    static const QRegularExpression secretRegex(QStringLiteral(R"((api[_-]?key|access[_-]?token|secret|bearer)[\"'\s:=]+([A-Za-z0-9_\-]{8,}))"),
                                                QRegularExpression::CaseInsensitiveOption);
    auto secretIt = secretRegex.globalMatch(body);
    while (secretIt.hasNext()) {
        const auto match = secretIt.next();
        findings << QStringLiteral("secret:%1=%2...").arg(match.captured(1), match.captured(2).left(6));
    }

    static const QRegularExpression jwtRegex(QStringLiteral(R"(([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+))"));
    auto jwtIt = jwtRegex.globalMatch(body);
    while (jwtIt.hasNext()) {
        findings << QStringLiteral("jwt:%1...").arg(jwtIt.next().captured(1).left(18));
    }

    static const QRegularExpression awsRegex(QStringLiteral(R"((AKIA[0-9A-Z]{16}))"));
    auto awsIt = awsRegex.globalMatch(body);
    while (awsIt.hasNext()) {
        findings << QStringLiteral("aws-key:%1").arg(awsIt.next().captured(1));
    }

    findings.removeDuplicates();
    return findings;
}

QStringList RegexSpiderHtmlExtractor::extractJsRoutes(const QString &body) const
{
    QStringList routes;
    static const QRegularExpression routeRegex(QStringLiteral(R"((/[\w\-/\.]*(?:api|admin|auth|v1|v2)[\w\-/\.]*))"),
                                               QRegularExpression::CaseInsensitiveOption);
    auto it = routeRegex.globalMatch(body);
    while (it.hasNext()) {
        routes << it.next().captured(1).trimmed();
    }
    routes.removeDuplicates();

    static const QRegularExpression quotedPathRegex(QStringLiteral(R"(["'](/(?:api|admin|debug|internal|test|graphql|auth|dashboard|panel|manifest|sw|service-worker|worker|rest|rpc|gateway|service)[^"']*)["'])"),
                                                    QRegularExpression::CaseInsensitiveOption);
    auto pathIt = quotedPathRegex.globalMatch(body);
    while (pathIt.hasNext()) {
        routes << pathIt.next().captured(1).trimmed();
    }

    static const QRegularExpression fetchRegex(QStringLiteral(R"((?:fetch|axios\.(?:get|post|put|delete|patch)|open)\s*\(\s*["']([^"']+)["'])"),
                                               QRegularExpression::CaseInsensitiveOption);
    auto fetchIt = fetchRegex.globalMatch(body);
    while (fetchIt.hasNext()) {
        const QString route = routeLikeValue(fetchIt.next().captured(1).trimmed());
        if (!route.isEmpty()) {
            routes << route;
        }
    }

    static const QRegularExpression assignRegex(QStringLiteral(R"((?:location(?:\.href)?|window\.open|document\.location)\s*=\s*["']([^"']+)["'])"),
                                                QRegularExpression::CaseInsensitiveOption);
    auto assignIt = assignRegex.globalMatch(body);
    while (assignIt.hasNext()) {
        const QString route = routeLikeValue(assignIt.next().captured(1).trimmed());
        if (!route.isEmpty()) {
            routes << route;
        }
    }

    static const QRegularExpression spaNavigationRegex(
        QStringLiteral(R"((?:history\.(?:pushState|replaceState)|router\.(?:push|replace|navigate)|navigateTo|redirectTo|window\.location(?:\.assign|\.replace)?)\s*\([^)]*["'](/[^"']+)["'][^)]*\))"),
        QRegularExpression::CaseInsensitiveOption);
    auto navigationIt = spaNavigationRegex.globalMatch(body);
    while (navigationIt.hasNext()) {
        const QString route = routeLikeValue(navigationIt.next().captured(1).trimmed());
        if (!route.isEmpty()) {
            routes << route;
        }
    }

    static const QRegularExpression endpointRegex(
        QStringLiteral(R"(["']((?:/(?:api|admin|debug|internal|test|graphql|auth|dashboard|panel|rest|rpc|gateway|service|manifest|sw|service-worker|worker)[^"'\\s)]*)|(?:https?://[^"']+/(?:api|graphql|rest|rpc|manifest|service-worker)[^"']*))["'])"),
        QRegularExpression::CaseInsensitiveOption);
    auto endpointIt = endpointRegex.globalMatch(body);
    while (endpointIt.hasNext()) {
        const QString route = routeLikeValue(endpointIt.next().captured(1).trimmed());
        if (!route.isEmpty()) {
            routes << route;
        }
    }

    static const QRegularExpression basePathRegex(
        QStringLiteral(R"((?:baseURL|apiBase|api_root|endpoint|graphqlEndpoint)\s*[:=]\s*["']([^"']+)["'])"),
        QRegularExpression::CaseInsensitiveOption);
    auto basePathIt = basePathRegex.globalMatch(body);
    while (basePathIt.hasNext()) {
        const QString route = routeLikeValue(basePathIt.next().captured(1).trimmed());
        if (!route.isEmpty()) {
            routes << route;
        }
    }

    static const QRegularExpression serviceWorkerRegex(
        QStringLiteral(R"(serviceWorker\.register\s*\(\s*["']([^"']+)["'])"),
        QRegularExpression::CaseInsensitiveOption);
    auto serviceWorkerIt = serviceWorkerRegex.globalMatch(body);
    while (serviceWorkerIt.hasNext()) {
        const QString route = routeLikeValue(serviceWorkerIt.next().captured(1).trimmed());
        if (!route.isEmpty()) {
            routes << route;
        }
    }

    routes.removeDuplicates();
    return routes;
}

QString FastSpiderHtmlExtractor::backendName() const
{
    return QStringLiteral("fast-tokenizer");
}

QString FastSpiderHtmlExtractor::extractPageTitle(const QString &html) const
{
    return tagInnerText(html, QStringLiteral("<title"), QStringLiteral("</title>")).left(120);
}

QStringList FastSpiderHtmlExtractor::extractHeadingHints(const QString &html) const
{
    QStringList headings;
    const QString lowerHtml = html.toLower();
    int from = 0;
    while (headings.size() < 4) {
        int nextTagPos = -1;
        QString closingTag;
        for (const QString &tag : {QStringLiteral("<h1"), QStringLiteral("<h2"), QStringLiteral("<h3")}) {
            const int pos = lowerHtml.indexOf(tag, from);
            if (pos >= 0 && (nextTagPos < 0 || pos < nextTagPos)) {
                nextTagPos = pos;
                closingTag = QStringLiteral("</") + tag.mid(1, 2) + QStringLiteral(">");
            }
        }
        if (nextTagPos < 0) {
            break;
        }
        const int start = lowerHtml.indexOf('>', nextTagPos);
        const int end = lowerHtml.indexOf(closingTag, start + 1);
        if (start < 0 || end < 0) {
            break;
        }
        const QString heading = stripHtml(html.mid(start + 1, end - start - 1)).left(80);
        if (!heading.isEmpty() && !headings.contains(heading)) {
            headings << heading;
        }
        from = end + closingTag.size();
    }
    return headings;
}

std::vector<QUrl> FastSpiderHtmlExtractor::extractLinks(const QString &html, const QUrl &baseUrl) const
{
    std::vector<QUrl> result;
    const QString lowerHtml = html.toLower();
    int pos = 0;
    while ((pos = lowerHtml.indexOf('<', pos)) >= 0) {
        const int tagEnd = lowerHtml.indexOf('>', pos + 1);
        if (tagEnd < 0) {
            break;
        }
        const QStringView tag = QStringView(html).mid(pos + 1, tagEnd - pos - 1);
        const QStringView lowerTag = QStringView(lowerHtml).mid(pos + 1, tagEnd - pos - 1);
        QString attr;
        if (lowerTag.startsWith(QStringLiteral("a ")) || lowerTag == QStringLiteral("a")) {
            attr = extractAttributeValue(tag, QStringLiteral("href"));
        } else if (lowerTag.startsWith(QStringLiteral("script ")) || lowerTag.startsWith(QStringLiteral("img ")) || lowerTag.startsWith(QStringLiteral("iframe ")) || lowerTag.startsWith(QStringLiteral("audio ")) || lowerTag.startsWith(QStringLiteral("video ")) || lowerTag.startsWith(QStringLiteral("source "))) {
            attr = extractAttributeValue(tag, QStringLiteral("src"));
            if (attr.isEmpty()) {
                attr = extractAttributeValue(tag, QStringLiteral("data-src"));
            }
        } else if (lowerTag.startsWith(QStringLiteral("form ")) || lowerTag == QStringLiteral("form")) {
            attr = extractAttributeValue(tag, QStringLiteral("action"));
        } else if (lowerTag.startsWith(QStringLiteral("link ")) || lowerTag == QStringLiteral("link")) {
            attr = extractAttributeValue(tag, QStringLiteral("href"));
        } else if (lowerTag.startsWith(QStringLiteral("meta ")) || lowerTag == QStringLiteral("meta")) {
            const QString equiv = extractAttributeValue(tag, QStringLiteral("http-equiv")).toLower();
            if (equiv == QLatin1String("refresh")) {
                attr = metaRefreshTarget(extractAttributeValue(tag, QStringLiteral("content")));
            } else {
                attr = extractAttributeValue(tag, QStringLiteral("content"));
            }
        }

        appendResolvedUrlIfValid(result, baseUrl, attr);

        const QString srcset = extractAttributeValue(tag, QStringLiteral("srcset"));
        if (!srcset.isEmpty()) {
            appendSrcsetUrls(result, baseUrl, srcset);
        }
        pos = tagEnd + 1;
    }
    return result;
}

std::vector<SpiderHtmlForm> FastSpiderHtmlExtractor::extractForms(const QString &html, const QUrl &baseUrl) const
{
    std::vector<SpiderHtmlForm> forms;
    const QString lowerHtml = html.toLower();
    int formStart = 0;
    while ((formStart = lowerHtml.indexOf(QStringLiteral("<form"), formStart)) >= 0) {
        const int attrsEnd = lowerHtml.indexOf('>', formStart);
        const int formEnd = lowerHtml.indexOf(QStringLiteral("</form>"), attrsEnd + 1);
        if (attrsEnd < 0 || formEnd < 0) {
            break;
        }

        SpiderHtmlForm form;
        const QStringView formAttrs = QStringView(html).mid(formStart + 5, attrsEnd - formStart - 5);
        const QString body = html.mid(attrsEnd + 1, formEnd - attrsEnd - 1);
        form.actionUrl = baseUrl.resolved(QUrl(extractAttributeValue(formAttrs, QStringLiteral("action"))));
        form.method = extractAttributeValue(formAttrs, QStringLiteral("method")).toUpper();
        if (!form.actionUrl.isValid()) {
            form.actionUrl = baseUrl;
        }
        if (form.method.isEmpty()) {
            form.method = QStringLiteral("GET");
        }

        bool hasPassword = false;
        bool hasIdentity = false;
        const QString lowerBody = body.toLower();
        int fieldPos = 0;
        while ((fieldPos = lowerBody.indexOf('<', fieldPos)) >= 0) {
            const int fieldEnd = lowerBody.indexOf('>', fieldPos + 1);
            if (fieldEnd < 0) {
                break;
            }
            const QStringView fieldTag = QStringView(body).mid(fieldPos + 1, fieldEnd - fieldPos - 1);
            const QStringView lowerFieldTag = QStringView(lowerBody).mid(fieldPos + 1, fieldEnd - fieldPos - 1);
            QString tagName;
            if (lowerFieldTag.startsWith(QStringLiteral("input"))) {
                tagName = QStringLiteral("input");
            } else if (lowerFieldTag.startsWith(QStringLiteral("select"))) {
                tagName = QStringLiteral("select");
            } else if (lowerFieldTag.startsWith(QStringLiteral("textarea"))) {
                tagName = QStringLiteral("textarea");
            } else {
                fieldPos = fieldEnd + 1;
                continue;
            }

            const QString fieldName = extractAttributeValue(fieldTag, QStringLiteral("name"));
            const QString fieldType = RegexSpiderHtmlExtractor::normalizedFieldType(tagName, extractAttributeValue(fieldTag, QStringLiteral("type")));
            const QString autoComplete = extractAttributeValue(fieldTag, QStringLiteral("autocomplete")).toLower();
            const QString fieldValue = extractAttributeValue(fieldTag, QStringLiteral("value"));
            if (!fieldName.isEmpty()) {
                const QString role = RegexSpiderHtmlExtractor::classifyFieldRole(fieldName, fieldType, autoComplete);
                form.fieldNames << fieldName;
                form.fields.push_back({fieldName, fieldType, role, fieldValue});
                const QString loweredName = fieldName.toLower();
                if (fieldType == QLatin1String("password") || loweredName.contains(QStringLiteral("password")) || autoComplete.contains(QStringLiteral("current-password"))) {
                    hasPassword = true;
                }
                if (fieldType == QLatin1String("email")
                    || loweredName.contains(QStringLiteral("user"))
                    || loweredName.contains(QStringLiteral("mail"))
                    || loweredName.contains(QStringLiteral("login"))
                    || loweredName.contains(QStringLiteral("account"))
                    || autoComplete.contains(QStringLiteral("username"))) {
                    hasIdentity = true;
                }
            }
            fieldPos = fieldEnd + 1;
        }

        form.loginLike = hasPassword && hasIdentity;
        form.sourceSummary = QStringList{
            form.method,
            form.loginLike ? QStringLiteral("login-form") : QStringLiteral("form"),
            QStringLiteral("%1 alan").arg(form.fieldNames.size())
        }.join(' ');
        forms.push_back(std::move(form));
        formStart = formEnd + 7;
    }
    return forms;
}

std::vector<SpiderHtmlAction> FastSpiderHtmlExtractor::extractInteractionActions(const QString &html, const QUrl &baseUrl) const
{
    return RegexSpiderHtmlExtractor().extractInteractionActions(html, baseUrl);
}

QStringList FastSpiderHtmlExtractor::extractInterestingLiterals(const QString &body) const
{
    return RegexSpiderHtmlExtractor().extractInterestingLiterals(body);
}

QStringList FastSpiderHtmlExtractor::extractJsRoutes(const QString &body) const
{
    return RegexSpiderHtmlExtractor().extractJsRoutes(body);
}

QString DomSpiderHtmlExtractor::backendName() const
{
    return QStringLiteral("dom-lite");
}

QString DomSpiderHtmlExtractor::extractPageTitle(const QString &html) const
{
    const auto tags = tokenizeHtml(html);
    for (const auto &tag : tags) {
        if (!tag.closing && tag.name == QLatin1String("title")) {
            return innerTextBetween(html, tag, tag.name).left(120);
        }
    }
    return {};
}

QStringList DomSpiderHtmlExtractor::extractHeadingHints(const QString &html) const
{
    QStringList headings;
    const auto tags = tokenizeHtml(html);
    for (const auto &tag : tags) {
        if (!tag.closing && (tag.name == QLatin1String("h1") || tag.name == QLatin1String("h2") || tag.name == QLatin1String("h3"))) {
            const QString text = innerTextBetween(html, tag, tag.name).left(80);
            if (!text.isEmpty() && !headings.contains(text)) {
                headings << text;
            }
            if (headings.size() >= 4) {
                break;
            }
        }
    }
    return headings;
}

std::vector<QUrl> DomSpiderHtmlExtractor::extractLinks(const QString &html, const QUrl &baseUrl) const
{
    std::vector<QUrl> result;
    const auto tags = tokenizeHtml(html);
    for (const auto &tag : tags) {
        if (tag.closing) {
            continue;
        }
        const QStringList attrOrder = {
            QStringLiteral("href"),
            QStringLiteral("src"),
            QStringLiteral("action"),
            QStringLiteral("formaction"),
            QStringLiteral("data-href"),
            QStringLiteral("data-url"),
            QStringLiteral("data-src"),
            QStringLiteral("ng-href"),
            QStringLiteral("ng-src"),
            QStringLiteral("routerlink"),
            QStringLiteral("xlink:href"),
            QStringLiteral("poster"),
            QStringLiteral("onclick")
        };
        for (const QString &attr : attrOrder) {
            QString raw = tag.attrs.value(attr).toString();
            if (attr == QLatin1String("onclick")) {
                raw = routeLikeValue(raw);
            }
            appendResolvedUrlIfValid(result, baseUrl, raw);
        }

        appendSrcsetUrls(result, baseUrl, tag.attrs.value(QStringLiteral("srcset")).toString());
        appendSrcsetUrls(result, baseUrl, tag.attrs.value(QStringLiteral("data-srcset")).toString());

        if (tag.name == QLatin1String("meta")) {
            const QString equiv = tag.attrs.value(QStringLiteral("http-equiv")).toString().trimmed().toLower();
            if (equiv == QLatin1String("refresh")) {
                appendResolvedUrlIfValid(result, baseUrl, metaRefreshTarget(tag.attrs.value(QStringLiteral("content")).toString()));
            } else {
                const QString property = tag.attrs.value(QStringLiteral("property")).toString().trimmed().toLower();
                const QString name = tag.attrs.value(QStringLiteral("name")).toString().trimmed().toLower();
                if (property == QLatin1String("og:url")
                    || property == QLatin1String("twitter:url")
                    || name == QLatin1String("twitter:url")) {
                    appendResolvedUrlIfValid(result, baseUrl, tag.attrs.value(QStringLiteral("content")).toString());
                }
            }
        }
    }
    return result;
}

std::vector<SpiderHtmlForm> DomSpiderHtmlExtractor::extractForms(const QString &html, const QUrl &baseUrl) const
{
    std::vector<SpiderHtmlForm> forms;
    const auto tags = tokenizeHtml(html);
    for (std::size_t i = 0; i < tags.size(); ++i) {
        const auto &tag = tags[i];
        if (tag.closing || tag.name != QLatin1String("form")) {
            continue;
        }

        SpiderHtmlForm form;
        form.actionUrl = baseUrl.resolved(QUrl(tag.attrs.value(QStringLiteral("action")).toString()));
        form.method = tag.attrs.value(QStringLiteral("method")).toString().trimmed().toUpper();
        if (!form.actionUrl.isValid()) {
            form.actionUrl = baseUrl;
        }
        if (form.method.isEmpty()) {
            form.method = QStringLiteral("GET");
        }

        bool hasPassword = false;
        bool hasIdentity = false;
        for (std::size_t j = i + 1; j < tags.size(); ++j) {
            const auto &child = tags[j];
            if (!child.closing && child.name == QLatin1String("form")) {
                break;
            }
            if (child.closing && child.name == QLatin1String("form")) {
                i = j;
                break;
            }
            if (child.closing) {
                continue;
            }
            if (child.name != QLatin1String("input")
                && child.name != QLatin1String("select")
                && child.name != QLatin1String("textarea")) {
                continue;
            }

            const QString fieldName = child.attrs.value(QStringLiteral("name")).toString().trimmed();
            const QString fieldType = RegexSpiderHtmlExtractor::normalizedFieldType(child.name,
                                                                                   child.attrs.value(QStringLiteral("type")).toString());
            const QString autoComplete = child.attrs.value(QStringLiteral("autocomplete")).toString().toLower();
            const QString fieldValue = child.attrs.value(QStringLiteral("value")).toString();
            if (fieldName.isEmpty()) {
                continue;
            }
            const QString role = RegexSpiderHtmlExtractor::classifyFieldRole(fieldName, fieldType, autoComplete);
            form.fieldNames << fieldName;
            form.fields.push_back({fieldName, fieldType, role, fieldValue});

            const QString loweredName = fieldName.toLower();
            if (fieldType == QLatin1String("password") || loweredName.contains(QStringLiteral("password")) || autoComplete.contains(QStringLiteral("current-password"))) {
                hasPassword = true;
            }
            if (fieldType == QLatin1String("email")
                || loweredName.contains(QStringLiteral("user"))
                || loweredName.contains(QStringLiteral("mail"))
                || loweredName.contains(QStringLiteral("login"))
                || loweredName.contains(QStringLiteral("account"))
                || autoComplete.contains(QStringLiteral("username"))) {
                hasIdentity = true;
            }
        }

        form.loginLike = hasPassword && hasIdentity;
        form.sourceSummary = QStringList{
            form.method,
            form.loginLike ? QStringLiteral("login-form") : QStringLiteral("form"),
            QStringLiteral("%1 alan").arg(form.fieldNames.size())
        }.join(' ');
        forms.push_back(std::move(form));
    }
    return forms;
}

std::vector<SpiderHtmlAction> DomSpiderHtmlExtractor::extractInteractionActions(const QString &html, const QUrl &baseUrl) const
{
    std::vector<SpiderHtmlAction> actions;
    const auto tags = tokenizeHtml(html);
    for (const auto &tag : tags) {
        if (tag.closing) {
            continue;
        }
        if (tag.name == QLatin1String("button")
            || tag.name == QLatin1String("a")
            || tag.attrs.value(QStringLiteral("role")).toString().compare(QStringLiteral("button"), Qt::CaseInsensitive) == 0) {
            QString raw = tag.attrs.value(QStringLiteral("data-url")).toString();
            if (raw.isEmpty()) raw = tag.attrs.value(QStringLiteral("data-href")).toString();
            if (raw.isEmpty()) raw = tag.attrs.value(QStringLiteral("href")).toString();
            if (raw.isEmpty()) raw = routeLikeValue(tag.attrs.value(QStringLiteral("onclick")).toString());
            if (raw.isEmpty()) raw = routeLikeValue(tag.attrs.value(QStringLiteral("data-action")).toString());
            if (raw.isEmpty()) raw = routeLikeValue(tag.attrs.value(QStringLiteral("data-target")).toString());
            if (raw.isEmpty()) raw = routeLikeValue(tag.attrs.value(QStringLiteral("data-bs-target")).toString());
            if (raw.isEmpty()) raw = routeLikeValue(tag.attrs.value(QStringLiteral("aria-controls")).toString());
            if (!isInterestingUrl(raw)) {
                continue;
            }
            const QUrl resolved = baseUrl.resolved(QUrl(raw));
            if (!resolved.isValid()) {
                continue;
            }
            actions.push_back({QStringLiteral("interactive"),
                               tagLabelHint(html, tag),
                               resolved,
                               QStringLiteral("GET"),
                               selectorHintForTag(tag),
                               QStringLiteral("buttonish")});
        } else if (!tag.attrs.value(QStringLiteral("tabindex")).toString().isEmpty()) {
            QString raw = routeLikeValue(tag.attrs.value(QStringLiteral("onclick")).toString());
            if (raw.isEmpty()) raw = routeLikeValue(tag.attrs.value(QStringLiteral("data-url")).toString());
            if (!isInterestingUrl(raw)) {
                continue;
            }
            const QUrl resolved = baseUrl.resolved(QUrl(raw));
            if (!resolved.isValid()) {
                continue;
            }
            actions.push_back({QStringLiteral("interactive-focus"),
                               tagLabelHint(html, tag),
                               resolved,
                               QStringLiteral("GET"),
                               selectorHintForTag(tag),
                               QStringLiteral("focusable")});
        }
    }
    return actions;
}

QStringList DomSpiderHtmlExtractor::extractInterestingLiterals(const QString &body) const
{
    return RegexSpiderHtmlExtractor().extractInterestingLiterals(body);
}

QStringList DomSpiderHtmlExtractor::extractJsRoutes(const QString &body) const
{
    QStringList routes = RegexSpiderHtmlExtractor().extractJsRoutes(body);
    const auto tags = tokenizeHtml(body);
    for (const auto &tag : tags) {
        if (tag.closing) {
            continue;
        }
        for (const QString &key : {QStringLiteral("onclick"), QStringLiteral("routerlink"), QStringLiteral("data-url"), QStringLiteral("data-href"), QStringLiteral("data-action"), QStringLiteral("data-target"), QStringLiteral("data-bs-target"), QStringLiteral("aria-controls"), QStringLiteral("ng-href"), QStringLiteral("ng-src")}) {
            const QString route = routeLikeValue(tag.attrs.value(key).toString());
            if (!route.isEmpty()) {
                routes << route;
            }
        }
    }
    routes.removeDuplicates();
    return routes;
}

QString Html5SpiderHtmlExtractor::backendName() const
{
#ifdef PENGUFOCE_WITH_GUMBO
    return QStringLiteral("html5-gumbo");
#elif defined(PENGUFOCE_WITH_HTML5_PARSER)
    return QStringLiteral("html5-parser");
#else
    return QStringLiteral("html5-adapter-fallback");
#endif
}

QString Html5SpiderHtmlExtractor::extractPageTitle(const QString &html) const
{
#ifdef PENGUFOCE_WITH_GUMBO
    QByteArray utf8 = html.toUtf8();
    GumboOutput *output = gumbo_parse_with_options(&kGumboDefaultOptions, utf8.constData(), utf8.size());
    QString result;
    QVector<const GumboNode *> titles;
    collectGumboElements(output->root, GUMBO_TAG_TITLE, titles);
    if (!titles.isEmpty()) {
        result = gumboNodeText(titles.first()).left(120);
    }
    gumbo_destroy_output(&kGumboDefaultOptions, output);
    return result;
#else
    return DomSpiderHtmlExtractor().extractPageTitle(html);
#endif
}

QStringList Html5SpiderHtmlExtractor::extractHeadingHints(const QString &html) const
{
#ifdef PENGUFOCE_WITH_GUMBO
    QByteArray utf8 = html.toUtf8();
    GumboOutput *output = gumbo_parse_with_options(&kGumboDefaultOptions, utf8.constData(), utf8.size());
    QStringList headings;
    for (const GumboTag tag : {GUMBO_TAG_H1, GUMBO_TAG_H2, GUMBO_TAG_H3}) {
        QVector<const GumboNode *> nodes;
        collectGumboElements(output->root, tag, nodes);
        for (const GumboNode *node : nodes) {
            const QString text = gumboNodeText(node).left(80);
            if (!text.isEmpty()) {
                headings << text;
            }
        }
    }
    headings.removeDuplicates();
    gumbo_destroy_output(&kGumboDefaultOptions, output);
    return headings.mid(0, 4);
#else
    return DomSpiderHtmlExtractor().extractHeadingHints(html);
#endif
}

std::vector<QUrl> Html5SpiderHtmlExtractor::extractLinks(const QString &html, const QUrl &baseUrl) const
{
#ifdef PENGUFOCE_WITH_GUMBO
    QByteArray utf8 = html.toUtf8();
    GumboOutput *output = gumbo_parse_with_options(&kGumboDefaultOptions, utf8.constData(), utf8.size());
    std::vector<QUrl> links;
    QVector<const GumboNode *> nodes;
    collectGumboInterestingNodes(output->root, nodes);
    for (const GumboNode *node : nodes) {
        for (const char *attrName : {"href", "src", "action", "formaction", "data-href", "data-url", "data-src", "ng-href", "ng-src", "routerlink", "xlink:href", "poster"}) {
            const QString raw = gumboAttr(node, attrName);
            appendResolvedUrlIfValid(links, baseUrl, raw);
        }
        const QString srcset = gumboAttr(node, "srcset");
        if (!srcset.isEmpty()) {
            appendSrcsetUrls(links, baseUrl, srcset);
        }
    }
    QVector<const GumboNode *> metaNodes;
    collectGumboElements(output->root, GUMBO_TAG_META, metaNodes);
    for (const GumboNode *metaNode : metaNodes) {
        const QString equiv = gumboAttr(metaNode, "http-equiv").toLower();
        if (equiv == QLatin1String("refresh")) {
            appendResolvedUrlIfValid(links, baseUrl, metaRefreshTarget(gumboAttr(metaNode, "content")));
            continue;
        }
        const QString property = gumboAttr(metaNode, "property").toLower();
        const QString name = gumboAttr(metaNode, "name").toLower();
        if (property == QLatin1String("og:url")
            || property == QLatin1String("twitter:url")
            || name == QLatin1String("twitter:url")) {
            appendResolvedUrlIfValid(links, baseUrl, gumboAttr(metaNode, "content"));
        }
    }
    gumbo_destroy_output(&kGumboDefaultOptions, output);
    return links;
#else
    return DomSpiderHtmlExtractor().extractLinks(html, baseUrl);
#endif
}

std::vector<SpiderHtmlForm> Html5SpiderHtmlExtractor::extractForms(const QString &html, const QUrl &baseUrl) const
{
#ifdef PENGUFOCE_WITH_GUMBO
    QByteArray utf8 = html.toUtf8();
    GumboOutput *output = gumbo_parse_with_options(&kGumboDefaultOptions, utf8.constData(), utf8.size());
    std::vector<SpiderHtmlForm> forms;
    QVector<const GumboNode *> formNodes;
    collectGumboElements(output->root, GUMBO_TAG_FORM, formNodes);
    for (const GumboNode *formNode : formNodes) {
        SpiderHtmlForm form;
        form.actionUrl = baseUrl.resolved(QUrl(gumboAttr(formNode, "action")));
        if (!form.actionUrl.isValid()) {
            form.actionUrl = baseUrl;
        }
        form.method = gumboAttr(formNode, "method").trimmed().toUpper();
        if (form.method.isEmpty()) {
            form.method = QStringLiteral("GET");
        }

        QVector<const GumboNode *> fieldNodes;
        collectGumboInterestingNodes(formNode, fieldNodes);
        bool hasPassword = false;
        bool hasIdentity = false;
        for (const GumboNode *fieldNode : fieldNodes) {
            if (fieldNode->type != GUMBO_NODE_ELEMENT) {
                continue;
            }
            const GumboTag tag = fieldNode->v.element.tag;
            if (tag != GUMBO_TAG_INPUT && tag != GUMBO_TAG_TEXTAREA && tag != GUMBO_TAG_SELECT) {
                continue;
            }
            const QString tagName = QString::fromUtf8(gumbo_normalized_tagname(tag));
            const QString fieldName = gumboAttr(fieldNode, "name");
            const QString fieldType = RegexSpiderHtmlExtractor::normalizedFieldType(tagName, gumboAttr(fieldNode, "type"));
            const QString autocomplete = gumboAttr(fieldNode, "autocomplete").toLower();
            const QString fieldValue = gumboAttr(fieldNode, "value");
            if (!fieldName.isEmpty()) {
                form.fieldNames << fieldName;
                form.fields.push_back({fieldName,
                                       fieldType,
                                       RegexSpiderHtmlExtractor::classifyFieldRole(fieldName, fieldType, autocomplete),
                                       fieldValue});
            }
            const QString loweredName = fieldName.toLower();
            if (fieldType == QLatin1String("password") || loweredName.contains(QStringLiteral("password"))) {
                hasPassword = true;
            }
            if (fieldType == QLatin1String("email")
                || loweredName.contains(QStringLiteral("user"))
                || loweredName.contains(QStringLiteral("mail"))
                || loweredName.contains(QStringLiteral("login"))
                || autocomplete.contains(QStringLiteral("username"))) {
                hasIdentity = true;
            }
        }

        form.loginLike = hasPassword && hasIdentity;
        form.sourceSummary = form.loginLike ? QStringLiteral("login-form") : QStringLiteral("html5-form");
        forms.push_back(std::move(form));
    }
    gumbo_destroy_output(&kGumboDefaultOptions, output);
    return forms;
#else
    return DomSpiderHtmlExtractor().extractForms(html, baseUrl);
#endif
}

std::vector<SpiderHtmlAction> Html5SpiderHtmlExtractor::extractInteractionActions(const QString &html, const QUrl &baseUrl) const
{
#ifdef PENGUFOCE_WITH_GUMBO
    QByteArray utf8 = html.toUtf8();
    GumboOutput *output = gumbo_parse_with_options(&kGumboDefaultOptions, utf8.constData(), utf8.size());
    std::vector<SpiderHtmlAction> actions;
    QVector<const GumboNode *> nodes;
    collectGumboInterestingNodes(output->root, nodes);
    for (const GumboNode *node : nodes) {
        if (node->type != GUMBO_NODE_ELEMENT) {
            continue;
        }
        const QString explicitRoute = !gumboAttr(node, "data-url").isEmpty()
                                          ? gumboAttr(node, "data-url")
                                          : (!gumboAttr(node, "href").isEmpty()
                                                 ? gumboAttr(node, "href")
                                                 : (!gumboAttr(node, "data-href").isEmpty()
                                                        ? gumboAttr(node, "data-href")
                                                        : (!gumboAttr(node, "data-action").isEmpty()
                                                               ? gumboAttr(node, "data-action")
                                                               : (!gumboAttr(node, "data-target").isEmpty()
                                                                      ? gumboAttr(node, "data-target")
                                                                      : (!gumboAttr(node, "aria-controls").isEmpty()
                                                                             ? gumboAttr(node, "aria-controls")
                                                                             : gumboAttr(node, "onclick"))))));
        const QString route = routeLikeValue(explicitRoute);
        if (route.isEmpty()) {
            continue;
        }

        SpiderHtmlAction action;
        action.kind = QStringLiteral("html5-action");
        action.label = gumboNodeText(node).left(80);
        action.targetUrl = baseUrl.resolved(QUrl(route));
        action.method = QStringLiteral("GET");
        const QString id = gumboAttr(node, "id");
        action.selectorHint = id.isEmpty()
                                  ? QString::fromUtf8(gumbo_normalized_tagname(node->v.element.tag))
                                  : QStringLiteral("#%1").arg(id);
        action.triggerKind = QStringLiteral("html5-dom");
        if (action.targetUrl.isValid()) {
            actions.push_back(std::move(action));
        }
    }
    gumbo_destroy_output(&kGumboDefaultOptions, output);
    return actions;
#else
    return DomSpiderHtmlExtractor().extractInteractionActions(html, baseUrl);
#endif
}

QStringList Html5SpiderHtmlExtractor::extractInterestingLiterals(const QString &body) const
{
    return DomSpiderHtmlExtractor().extractInterestingLiterals(body);
}

QStringList Html5SpiderHtmlExtractor::extractJsRoutes(const QString &body) const
{
    return DomSpiderHtmlExtractor().extractJsRoutes(body);
}

std::unique_ptr<ISpiderHtmlExtractor> createBestSpiderHtmlExtractor()
{
    const QString configured = QProcessEnvironment::systemEnvironment()
                                   .value(QStringLiteral("PENGUFOCE_SPIDER_EXTRACTOR"))
                                   .trimmed()
                                   .toLower();
    if (configured == QLatin1String("html5") || configured == QLatin1String("html5-parser")) {
        return std::make_unique<Html5SpiderHtmlExtractor>();
    }
    if (configured == QLatin1String("regex")) {
        return createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::Regex);
    }
    if (configured == QLatin1String("fast") || configured == QLatin1String("fast-tokenizer")) {
        return createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::FastTokenizer);
    }
#ifdef PENGUFOCE_WITH_GUMBO
    return std::make_unique<Html5SpiderHtmlExtractor>();
#endif
    return createSpiderHtmlExtractor(SpiderHtmlExtractorBackend::DomLite);
}

std::unique_ptr<ISpiderHtmlExtractor> createSpiderHtmlExtractor(SpiderHtmlExtractorBackend backend)
{
    switch (backend) {
    case SpiderHtmlExtractorBackend::Regex:
        return std::make_unique<RegexSpiderHtmlExtractor>();
    case SpiderHtmlExtractorBackend::FastTokenizer:
        return std::make_unique<FastSpiderHtmlExtractor>();
    case SpiderHtmlExtractorBackend::DomLite:
    default:
        return std::make_unique<DomSpiderHtmlExtractor>();
    }
}
