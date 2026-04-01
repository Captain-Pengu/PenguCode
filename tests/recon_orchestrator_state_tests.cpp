#include "modules/recon/engine/reconorchestratorstate.h"
#include "modules/recon/engine/reconreportbuilder.h"

#include <QCoreApplication>
#include <QTextStream>

namespace {

void fail(const QString &message)
{
    QTextStream(stderr) << "[FAIL] " << message << Qt::endl;
}

bool expect(bool condition, const QString &message)
{
    if (!condition) {
        fail(message);
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    bool ok = true;

    ReconOrchestratorState state;
    state.reset();

    ok &= expect(state.activeJobs() == 0, QStringLiteral("initial active jobs failed"));
    ok &= expect(!state.finishEmitted(), QStringLiteral("initial finish emitted failed"));

    ok &= expect(state.markStarted(ReconOrchestratorState::JobKind::Dns), QStringLiteral("dns start failed"));
    ok &= expect(!state.markStarted(ReconOrchestratorState::JobKind::Dns), QStringLiteral("duplicate dns start guard failed"));
    ok &= expect(state.markStarted(ReconOrchestratorState::JobKind::PortScan), QStringLiteral("port start failed"));
    ok &= expect(state.activeJobs() == 2, QStringLiteral("active jobs increment failed"));

    ok &= expect(!state.markFinished(ReconOrchestratorState::JobKind::Osint), QStringLiteral("finish unopened job guard failed"));
    ok &= expect(!state.markFinished(ReconOrchestratorState::JobKind::Dns), QStringLiteral("dns finish should not emit final"));
    ok &= expect(state.activeJobs() == 1, QStringLiteral("active jobs decrement failed"));
    ok &= expect(state.markFinished(ReconOrchestratorState::JobKind::PortScan), QStringLiteral("last job should emit finish"));
    ok &= expect(state.finishEmitted(), QStringLiteral("finish emitted flag failed"));
    ok &= expect(!state.markFinished(ReconOrchestratorState::JobKind::PortScan), QStringLiteral("duplicate finish guard failed"));

    state.reset();
    ok &= expect(!state.finishEmitted() && state.activeJobs() == 0, QStringLiteral("reset failed"));

    {
        const QVariantMap baseline{
            {"sanitizedTarget", QStringLiteral("baseline")},
            {"openPorts", QVariantList{QVariantMap{{"port", 80}, {"service", "http"}}}},
            {"subdomains", QVariantList{QStringLiteral("a.example.com")}},
            {"findings", QVariantList{QVariantMap{{"severity", "medium"}, {"title", "CSP eksik"}}}}
        };
        const QVariantMap current{
            {"sanitizedTarget", QStringLiteral("current")},
            {"openPorts", QVariantList{
                QVariantMap{{"port", 80}, {"service", "http"}},
                QVariantMap{{"port", 443}, {"service", "https"}}
            }},
            {"subdomains", QVariantList{QStringLiteral("a.example.com"), QStringLiteral("b.example.com")}},
            {"findings", QVariantList{
                QVariantMap{{"severity", "medium"}, {"title", "CSP eksik"}},
                QVariantMap{{"severity", "high"}, {"title", "HSTS eksik"}}
            }}
        };

        const QString diff = buildReconDiffSummary(current, baseline);
        ok &= expect(diff.contains(QStringLiteral("443/https")), QStringLiteral("diff new port missing"));
        ok &= expect(diff.contains(QStringLiteral("b.example.com")), QStringLiteral("diff new subdomain missing"));
        ok &= expect(diff.contains(QStringLiteral("high|HSTS eksik")), QStringLiteral("diff new finding missing"));
    }

    if (!ok) {
        return 1;
    }

    QTextStream(stdout) << "[PASS] recon_orchestrator_state_tests" << Qt::endl;
    return 0;
}
