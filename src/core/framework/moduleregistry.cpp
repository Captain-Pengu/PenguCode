#include "moduleregistry.h"

ModuleRegistry &ModuleRegistry::instance()
{
    static ModuleRegistry registry;
    return registry;
}

void ModuleRegistry::registerFactory(const ModuleFactoryInfo &factory)
{
    m_factories.push_back(factory);
}

const std::vector<ModuleFactoryInfo> &ModuleRegistry::factories() const
{
    return m_factories;
}

ModuleRegistrar::ModuleRegistrar(const ModuleFactoryInfo &factory)
{
    ModuleRegistry::instance().registerFactory(factory);
}
