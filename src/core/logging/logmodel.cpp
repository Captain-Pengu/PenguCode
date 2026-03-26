#include "logmodel.h"

LogModel::LogModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

int LogModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }

    return m_entries.size();
}

QVariant LogModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_entries.size()) {
        return {};
    }

    const auto &entry = m_entries.at(index.row());
    switch (role) {
    case LevelRole:
        return entry.level;
    case ChannelRole:
        return entry.channel;
    case MessageRole:
        return entry.message;
    case TimestampRole:
        return entry.timestamp;
    case FormattedRole:
        return entry.formatted;
    default:
        return {};
    }
}

QHash<int, QByteArray> LogModel::roleNames() const
{
    return {
        {LevelRole, "level"},
        {ChannelRole, "channel"},
        {MessageRole, "message"},
        {TimestampRole, "timestamp"},
        {FormattedRole, "formatted"}
    };
}

void LogModel::append(const QString &level, const QString &channel, const QString &message,
                      const QString &timestamp, const QString &formatted)
{
    beginInsertRows(QModelIndex(), m_entries.size(), m_entries.size());
    m_entries.push_back({level, channel, message, timestamp, formatted});
    endInsertRows();
}
