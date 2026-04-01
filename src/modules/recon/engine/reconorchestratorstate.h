#pragma once

class ReconOrchestratorState
{
public:
    enum class JobKind
    {
        PortScan,
        Dns,
        Osint
    };

    void reset();
    bool markStarted(JobKind kind);
    bool markFinished(JobKind kind);

    int activeJobs() const { return m_activeJobs; }
    bool finishEmitted() const { return m_finishEmitted; }
    bool isPending(JobKind kind) const;

private:
    bool *flagFor(JobKind kind);
    const bool *flagFor(JobKind kind) const;

    int m_activeJobs = 0;
    bool m_portScanPending = false;
    bool m_dnsPending = false;
    bool m_osintPending = false;
    bool m_finishEmitted = false;
};
