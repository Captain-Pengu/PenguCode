#pragma once

#include <QAbstractListModel>

struct LogEntry
{
    QString level;
    QString channel;
    QString message;
    QString timestamp;
    QString formatted;
};

class LogModel : public QAbstractListModel
{
    Q_OBJECT

public:
    enum Roles {
        LevelRole = Qt::UserRole + 1,
        ChannelRole,
        MessageRole,
        TimestampRole,
        FormattedRole
    };
    Q_ENUM(Roles)

    explicit LogModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    void append(const QString &level, const QString &channel, const QString &message,
                const QString &timestamp, const QString &formatted);

private:
    QList<LogEntry> m_entries;
};
