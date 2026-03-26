#include "modulemanager.h"

#include "core/logging/logger.h"
#include "core/framework/moduleinterface.h"
#include "core/framework/moduleregistry.h"
#include "core/settings/settingsmanager.h"

ModuleManager::ModuleManager(QObject *parent)
    : QAbstractListModel(parent)
{
}

int ModuleManager::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }

    return static_cast<int>(m_modules.size());
}

QVariant ModuleManager::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return {};
    }

    const auto &module = m_modules.at(static_cast<size_t>(index.row()));

    switch (role) {
    case IdRole:
        return module->id();
    case NameRole:
        return module->name();
    case DescriptionRole:
        return module->description();
    case IconRole:
        return module->icon();
    case PageSourceRole:
        return module->pageSource();
    case ModuleRole:
        return QVariant::fromValue(module.get());
    default:
        return {};
    }
}

QHash<int, QByteArray> ModuleManager::roleNames() const
{
    return {
        {IdRole, "moduleId"},
        {NameRole, "name"},
        {DescriptionRole, "description"},
        {IconRole, "icon"},
        {PageSourceRole, "pageSource"},
        {ModuleRole, "moduleObject"},
    };
}

void ModuleManager::loadModules(SettingsManager *settings, Logger *logger)
{
    beginResetModel();
    m_modules.clear();

    for (const auto &factory : ModuleRegistry::instance().factories()) {
        auto module = factory.creator();
        settings->ensureModuleDefaults(factory.id, module->defaultSettings());
        module->initialize(settings, logger);
        m_modules.push_back(std::move(module));
    }

    endResetModel();

    if (!m_modules.empty()) {
        m_activeModule = m_modules.front().get();
        emit activeModuleChanged();
    }

    logger->info("system", QString("Loaded %1 modules").arg(m_modules.size()));
}

ModuleInterface *ModuleManager::activeModule() const
{
    return m_activeModule;
}

void ModuleManager::setActiveIndex(int index)
{
    if (index < 0 || index >= rowCount()) {
        return;
    }

    auto *next = m_modules.at(static_cast<size_t>(index)).get();
    if (next == m_activeModule) {
        return;
    }

    m_activeModule = next;
    emit activeModuleChanged();
}

QVariantMap ModuleManager::get(int index) const
{
    if (index < 0 || index >= rowCount()) {
        return {};
    }

    const auto &module = m_modules.at(static_cast<size_t>(index));
    return {
        {"moduleId", module->id()},
        {"name", module->name()},
        {"description", module->description()},
        {"icon", module->icon()},
        {"pageSource", module->pageSource()},
        {"moduleObject", QVariant::fromValue(module.get())}
    };
}
