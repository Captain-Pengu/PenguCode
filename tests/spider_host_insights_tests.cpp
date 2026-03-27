#include "modules/spider/engine/spiderhostinsights.h"

#include <QCoreApplication>

#include <algorithm>
#include <iostream>

namespace {

bool require(bool condition, const QString &message)
{
    if (!condition) {
        std::cerr << message.toStdString() << std::endl;
        return false;
    }
    return true;
}

}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    int failures = 0;

    {
        QVariantList endpoints = {
            QVariantMap{{"url", QStringLiteral("https://portal.example.com/a")}},
            QVariantMap{{"url", QStringLiteral("https://portal.example.com/b")}},
            QVariantMap{{"url", QStringLiteral("https://api.example.com/me")}}
        };

        QVariantList assets = {
            QVariantMap{{"kind", QStringLiteral("workflow-submit-result")}, {"value", QStringLiteral("ok")}, {"source", QStringLiteral("https://portal.example.com/login")}},
            QVariantMap{{"kind", QStringLiteral("host-pressure")}, {"value", QStringLiteral("score=7 | state=WAF | reason=retry+waf | host=portal.example.com")}, {"source", QStringLiteral("")}},
            QVariantMap{{"kind", QStringLiteral("retry-after")}, {"value", QStringLiteral("delay=1000 ms | host=portal.example.com")}, {"source", QStringLiteral("")}},
            QVariantMap{{"kind", QStringLiteral("waf-vendor")}, {"value", QStringLiteral("cloudflare")}, {"source", QStringLiteral("https://portal.example.com/login")}},
            QVariantMap{{"kind", QStringLiteral("scope-outlier")}, {"value", QStringLiteral("https://cdn.example.net/font.css")}, {"source", QStringLiteral("https://cdn.example.net/font.css")}},
            QVariantMap{{"kind", QStringLiteral("workflow-action-candidate")}, {"value", QStringLiteral("candidate")}, {"source", QStringLiteral("https://api.example.com/console")}}
        };

        const SpiderHostInsightsSummary summary = buildSpiderHostInsights(endpoints, assets);
        if (!require(summary.rows.size() == 3, QStringLiteral("host insight row sayisi yanlis"))) {
            ++failures;
        }
        if (!require(summary.wafHosts == 1, QStringLiteral("waf host sayisi yanlis"))) {
            ++failures;
        }
        if (!require(summary.guardedHosts == 1, QStringLiteral("guarded host sayisi yanlis"))) {
            ++failures;
        }

        const auto portalIt = std::find_if(summary.rows.cbegin(), summary.rows.cend(), [](const SpiderHostInsightRow &row) {
            return row.host == QLatin1String("portal.example.com");
        });
        if (!require(portalIt != summary.rows.cend(), QStringLiteral("portal host bulunamadi"))) {
            ++failures;
        } else {
            if (!require(portalIt->endpoints == 2, QStringLiteral("portal endpoint sayisi yanlis"))) {
                ++failures;
            }
            if (!require(portalIt->pressureScore == 7, QStringLiteral("portal pressure score yanlis"))) {
                ++failures;
            }
            if (!require(portalIt->vendorHint == QLatin1String("cloudflare"), QStringLiteral("portal vendor hint yanlis"))) {
                ++failures;
            }
        }
    }

    if (failures == 0) {
        std::cout << "spider host insights tests passed" << std::endl;
        return 0;
    }

    std::cerr << "spider host insights tests failed: " << failures << std::endl;
    return 1;
}
