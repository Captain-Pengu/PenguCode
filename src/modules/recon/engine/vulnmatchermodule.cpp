#include "vulnmatchermodule.h"

#include <QMetaObject>
#include <QRegularExpression>

namespace {

struct SignatureRule
{
    QString serviceNeedle;
    QRegularExpression versionRegex;
    QString cveId;
    QString severity;
    QString summary;
};

class VulnMatchTask final : public QRunnable
{
public:
    VulnMatchTask(ServiceFingerprint fingerprint, VulnMatcherModule *owner)
        : m_fingerprint(std::move(fingerprint))
        , m_owner(owner)
    {
        setAutoDelete(true);
    }

    void run() override
    {
        static const QList<SignatureRule> rules = {
            {"openssh", QRegularExpression("OpenSSH[_/ ]([0-7]\\.[0-9p]+)", QRegularExpression::CaseInsensitiveOption),
             "CVE-2018-15473", "medium", "Legacy OpenSSH user enumeration exposure"},
            {"apache", QRegularExpression("Apache/?([0-2]\\.[0-4]\\.[0-9]+)", QRegularExpression::CaseInsensitiveOption),
             "CVE-2021-41773", "high", "Apache path traversal candidate"},
            {"nginx", QRegularExpression("nginx/?([0-1]\\.[0-9]+\\.[0-9]+)", QRegularExpression::CaseInsensitiveOption),
             "CVE-2013-2028", "medium", "Historic nginx chunked parser issue signature"},
            {"redis", QRegularExpression("([0-4]\\.[0-9]+\\.[0-9]+)", QRegularExpression::CaseInsensitiveOption),
             "CVE-2022-0543", "high", "Redis/Lua sandbox escape candidate"},
            {"postgres", QRegularExpression("([0-9]{1,2}\\.[0-9]{1,2})", QRegularExpression::CaseInsensitiveOption),
             "CVE-2021-23222", "medium", "PostgreSQL extension privilege escalation candidate"}
        };

        const QString haystack = (m_fingerprint.service + " " + m_fingerprint.banner + " " + m_fingerprint.version).toLower();
        for (const SignatureRule &rule : rules) {
            if (!haystack.contains(rule.serviceNeedle)) {
                continue;
            }

            const auto match = rule.versionRegex.match(m_fingerprint.banner + " " + m_fingerprint.version);
            if (!match.hasMatch()) {
                continue;
            }

            const VulnerabilityMatch finding{
                m_fingerprint.host,
                m_fingerprint.port,
                m_fingerprint.service,
                match.captured(1),
                rule.cveId,
                rule.summary,
                rule.severity
            };

            QMetaObject::invokeMethod(
                m_owner,
                [owner = m_owner, finding]() {
                    emit owner->vulnerabilityMatched(finding);
                    emit owner->statusMessage(QString("%1 matched on %2:%3")
                                                  .arg(finding.cveId, finding.host)
                                                  .arg(finding.port));
                },
                Qt::QueuedConnection);
        }
    }

private:
    ServiceFingerprint m_fingerprint;
    VulnMatcherModule *m_owner = nullptr;
};

} // namespace

VulnMatcherModule::VulnMatcherModule(QObject *parent)
    : QObject(parent)
{
    m_threadPool.setMaxThreadCount(2);
}

VulnMatcherModule::~VulnMatcherModule()
{
    m_threadPool.waitForDone();
}

void VulnMatcherModule::matchServiceAsync(const ServiceFingerprint &fingerprint)
{
    if (fingerprint.banner.isEmpty() && fingerprint.service.isEmpty()) {
        return;
    }

    m_threadPool.start(new VulnMatchTask(fingerprint, this));
}
