#pragma once

#include "pengucore/model/packettypes.h"

#include <QVector>

namespace pengufoce::pengucore {

class FlowTracker
{
public:
    QVector<FlowStats> build(const QVector<PacketRecord> &packets) const;
};

} // namespace pengufoce::pengucore
