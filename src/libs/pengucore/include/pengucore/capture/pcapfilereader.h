#pragma once

#include "pengucore/model/packettypes.h"

#include <QString>
#include <QVector>

namespace pengufoce::pengucore {

class PcapFileReader
{
public:
    struct Result
    {
        bool success = false;
        bool pcapngDetected = false;
        QString errorMessage;
        QVector<RawFrame> frames;
    };

    Result readFile(const QString &filePath) const;
};

} // namespace pengufoce::pengucore
