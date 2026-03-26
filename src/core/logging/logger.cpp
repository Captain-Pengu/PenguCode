#include "logger.h"

#include "logmodel.h"

#include <QDateTime>
#include <QFile>
#include <QTextStream>

Logger::Logger(QObject *parent)
    : QObject(parent)
    , m_model(new LogModel(this))
{
}

LogModel *Logger::model() const
{
    return m_model;
}

void Logger::debug(const QString &channel, const QString &message)
{
    append("DEBUG", channel, message);
}

void Logger::info(const QString &channel, const QString &message)
{
    append("INFO", channel, message);
}

void Logger::warning(const QString &channel, const QString &message)
{
    append("WARN", channel, message);
}

void Logger::error(const QString &channel, const QString &message)
{
    append("ERROR", channel, message);
}

bool Logger::exportToFile(const QString &filePath) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream stream(&file);
    for (const auto &line : m_lines) {
        stream << line << '\n';
    }
    return true;
}

void Logger::append(const QString &level, const QString &channel, const QString &message)
{
    const QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    const QString line = QString("[%1] [%2] [%3] %4").arg(timestamp, level, channel, message);
    m_lines.append(line);
    m_model->append(level, channel, message, timestamp, line);
}
