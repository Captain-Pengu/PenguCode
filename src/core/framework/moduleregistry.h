#pragma once

#include <QString>
#include <functional>
#include <memory>
#include <vector>

class ModuleInterface;

struct ModuleFactoryInfo
{
    using Creator = std::function<std::unique_ptr<ModuleInterface>()>;

    QString id;
    Creator creator;
};

class ModuleRegistry
{
public:
    static ModuleRegistry &instance();

    void registerFactory(const ModuleFactoryInfo &factory);
    const std::vector<ModuleFactoryInfo> &factories() const;

private:
    std::vector<ModuleFactoryInfo> m_factories;
};

class ModuleRegistrar
{
public:
    explicit ModuleRegistrar(const ModuleFactoryInfo &factory);
};

#define REGISTER_MODULE(MODULE_CLASS, MODULE_ID) \
    static ModuleRegistrar MODULE_CLASS##_registrar({ \
        MODULE_ID, \
        []() { return std::make_unique<MODULE_CLASS>(); } \
    })
