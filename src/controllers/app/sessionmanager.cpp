#include "sessionmanager.h"

#include "core/logging/logger.h"
#include "core/framework/modulemanager.h"

#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

SessionManager::SessionManager(ModuleManager *moduleManager, Logger *logger, QObject *parent)
    : QObject(parent)
    , m_moduleManager(moduleManager)
    , m_logger(logger)
{
}

bool SessionManager::saveSession(const QString &filePath) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        m_logger->error("session", QString("Failed to save session to %1").arg(filePath));
        return false;
    }

    QJsonObject root{
        {"savedAt", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
        {"moduleCount", m_moduleManager->rowCount()}
    };

    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    m_logger->info("session", QString("Session saved to %1").arg(filePath));
    return true;
}

QVariantMap SessionManager::loadSession(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        m_logger->error("session", QString("Failed to open session file %1").arg(filePath));
        return {};
    }

    const auto json = QJsonDocument::fromJson(file.readAll()).object().toVariantMap();
    m_logger->info("session", QString("Session loaded from %1").arg(filePath));
    return json;
}
