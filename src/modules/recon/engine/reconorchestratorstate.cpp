#include "modules/recon/engine/reconorchestratorstate.h"

void ReconOrchestratorState::reset()
{
    m_activeJobs = 0;
    m_portScanPending = false;
    m_dnsPending = false;
    m_osintPending = false;
    m_finishEmitted = false;
}

bool ReconOrchestratorState::markStarted(JobKind kind)
{
    bool *flag = flagFor(kind);
    if (!flag || *flag) {
        return false;
    }

    *flag = true;
    ++m_activeJobs;
    m_finishEmitted = false;
    return true;
}

bool ReconOrchestratorState::markFinished(JobKind kind)
{
    bool *flag = flagFor(kind);
    if (!flag || !*flag) {
        return false;
    }

    *flag = false;
    if (m_activeJobs > 0) {
        --m_activeJobs;
    }

    if (m_activeJobs == 0 && !m_finishEmitted) {
        m_finishEmitted = true;
        return true;
    }

    return false;
}

bool ReconOrchestratorState::isPending(JobKind kind) const
{
    const bool *flag = flagFor(kind);
    return flag ? *flag : false;
}

bool *ReconOrchestratorState::flagFor(JobKind kind)
{
    switch (kind) {
    case JobKind::PortScan:
        return &m_portScanPending;
    case JobKind::Dns:
        return &m_dnsPending;
    case JobKind::Osint:
        return &m_osintPending;
    }
    return nullptr;
}

const bool *ReconOrchestratorState::flagFor(JobKind kind) const
{
    switch (kind) {
    case JobKind::PortScan:
        return &m_portScanPending;
    case JobKind::Dns:
        return &m_dnsPending;
    case JobKind::Osint:
        return &m_osintPending;
    }
    return nullptr;
}
