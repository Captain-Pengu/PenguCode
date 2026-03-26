#pragma once

#include "pengucore/model/packettypes.h"

#include <QFile>
#include <QString>

namespace pengufoce::pengucore {

class PcapFileWriter
{
public:
    bool open(const QString &filePath, const QString &format = QString(), QString *errorMessage = nullptr);
    void close();
    bool isOpen() const;
    QString filePath() const;
    bool writeFrame(const RawFrame &frame, QString *errorMessage = nullptr);

private:
    bool writeGlobalHeader(QString *errorMessage);
    bool writePcapNgHeaders(QString *errorMessage);
    bool writePcapRecord(const RawFrame &frame, QString *errorMessage);
    bool writePcapNgRecord(const RawFrame &frame, QString *errorMessage);

    QFile m_file;
    bool m_writePcapNg = false;
};

} // namespace pengufoce::pengucore
