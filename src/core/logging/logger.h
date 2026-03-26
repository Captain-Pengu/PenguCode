#pragma once

#include <QObject>
#include <QStringList>
#include "logmodel.h"

class Logger : public QObject
{
    Q_OBJECT
    Q_PROPERTY(LogModel *model READ model CONSTANT)

public:
    explicit Logger(QObject *parent = nullptr);

    LogModel *model() const;

    Q_INVOKABLE void debug(const QString &channel, const QString &message);
    Q_INVOKABLE void info(const QString &channel, const QString &message);
    Q_INVOKABLE void warning(const QString &channel, const QString &message);
    Q_INVOKABLE void error(const QString &channel, const QString &message);
    Q_INVOKABLE bool exportToFile(const QString &filePath) const;

private:
    void append(const QString &level, const QString &channel, const QString &message);

    LogModel *m_model;
    QStringList m_lines;
};
