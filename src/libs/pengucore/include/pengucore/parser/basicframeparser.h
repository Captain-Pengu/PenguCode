#pragma once

#include "pengucore/model/packettypes.h"

namespace pengufoce::pengucore {

class BasicFrameParser
{
public:
    PacketRecord parse(const RawFrame &frame) const;
};

} // namespace pengufoce::pengucore
