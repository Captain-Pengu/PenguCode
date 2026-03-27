#pragma once

#include <QAbstractListModel>
#include <QPointer>
#include "core/framework/moduleinterface.h"
#include <memory>
#include <vector>

class SettingsManager;
class Logger;

class ModuleManager : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(ModuleInterface *activeModule READ activeModule NOTIFY activeModuleChanged)

public:
    enum Roles {
        IdRole = Qt::UserRole + 1,
        NameRole,
        DescriptionRole,
        IconRole,
        PageSourceRole,
        ModuleRole
    };
    Q_ENUM(Roles)

    explicit ModuleManager(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    void loadModules(SettingsManager *settings, Logger *logger);
    QList<ModuleInterface *> modules() const;
    ModuleInterface *moduleById(const QString &moduleId) const;

    ModuleInterface *activeModule() const;

    Q_INVOKABLE void setActiveIndex(int index);
    Q_INVOKABLE QVariantMap get(int index) const;

signals:
    void activeModuleChanged();

private:
    std::vector<std::unique_ptr<ModuleInterface>> m_modules;
    QPointer<ModuleInterface> m_activeModule;
};
