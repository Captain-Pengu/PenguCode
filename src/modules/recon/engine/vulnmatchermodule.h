#pragma once

#include "scantypes.h"

#include <QObject>
#include <QThreadPool>

class VulnMatcherModule : public QObject
{
    Q_OBJECT

public:
    explicit VulnMatcherModule(QObject *parent = nullptr);
    ~VulnMatcherModule() override;

public slots:
    void matchServiceAsync(const ServiceFingerprint &fingerprint);

signals:
    void vulnerabilityMatched(const VulnerabilityMatch &match);
    void statusMessage(const QString &message);

private:
    QThreadPool m_threadPool;
};
