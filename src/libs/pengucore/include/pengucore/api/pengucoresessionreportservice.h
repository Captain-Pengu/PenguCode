#pragma once

#include "pengucore/model/packettypes.h"

#include <QJsonObject>
#include <functional>

namespace pengufoce::pengucore {

class PenguCoreEngine;

QJsonObject buildPacketJsonObject(const PacketRecord &packet);
QJsonObject buildSessionReportObject(const PenguCoreEngine &engine,
                                     const QVector<int> &visiblePacketIndices,
                                     const QVector<int> &visibleFlowIndices,
                                     bool visibleOnly,
                                     const std::function<QString(const PacketRecord &)> &protocolLabelForPacket,
                                     const std::function<QString(const FlowStats &)> &flowDetailBuilder);

} // namespace pengufoce::pengucore
