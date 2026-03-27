#include "controllers/app/sessionmanager.h"
#include "core/framework/moduleinterface.h"
#include "core/framework/modulemanager.h"
#include "core/framework/moduleregistry.h"
#include "core/logging/logger.h"
#include "core/settings/settingsmanager.h"
#include "core/theme/themeengine.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QStandardPaths>

namespace {

class DummyStateModule : public ModuleInterface
{
public:
    QString id() const override { return QStringLiteral("dummy_state"); }
    QString name() const override { return QStringLiteral("DummyState"); }
    QString description() const override { return QStringLiteral("Test module"); }
    QString icon() const override { return QStringLiteral("test"); }
    QUrl pageSource() const override { return {}; }
    void initialize(SettingsManager *settings, Logger *logger) override
    {
        Q_UNUSED(settings);
        Q_UNUSED(logger);
    }
    QVariantMap defaultSettings() const override
    {
        return {{"value", 7}};
    }
    QVariantMap saveState() const override
    {
        return {{"counter", m_counter}};
    }
    bool loadState(const QVariantMap &state) override
    {
        m_counter = state.value("counter").toInt();
        return true;
    }
    QString healthStatus() const override
    {
        return m_counter > 0 ? QStringLiteral("BUSY") : QStringLiteral("HEALTHY");
    }
    void start() override { ++m_counter; }
    void stop() override {}
    int counter() const { return m_counter; }

private:
    int m_counter = 0;
};

REGISTER_MODULE(DummyStateModule, "dummy_state");

bool testTypedSettingsAndMigration()
{
    SettingsManager settings;
    if (settings.schemaVersion() != SettingsManager::kCurrentSchemaVersion) {
        return false;
    }

    settings.setTypedValue("tests/schema", "intValue", "int", "41");
    settings.setTypedValue("tests/schema", "boolValue", "bool", 1);
    settings.setTypedValue("tests/schema", "stringValue", "string", 99);
    settings.sync();

    return settings.typedValue("tests/schema", "intValue", "int").toInt() == 41
        && settings.typedValue("tests/schema", "boolValue", "bool").toBool()
        && settings.typedValue("tests/schema", "stringValue", "string").toString() == QStringLiteral("99");
}

bool testSessionSaveLoad()
{
    SettingsManager settings;
    Logger logger;
    ThemeEngine theme;
    theme.loadSettings(&settings);
    ModuleManager moduleManager;
    moduleManager.loadModules(&settings, &logger);

    DummyStateModule *dummy = dynamic_cast<DummyStateModule *>(moduleManager.moduleById(QStringLiteral("dummy_state")));
    if (!dummy) {
        return false;
    }
    dummy->start();
    dummy->start();

    SessionManager session(&moduleManager, &logger);
    session.setSettingsManager(&settings);
    session.setThemeEngine(&theme);

    const QString sessionPath = QDir(QStandardPaths::writableLocation(QStandardPaths::TempLocation))
                                    .filePath(QStringLiteral("pengufoce_state_test.json"));
    QFile::remove(sessionPath);
    if (!session.saveSession(sessionPath)) {
        return false;
    }

    dummy->loadState({{"counter", 0}});
    theme.setCurrentTheme(QStringLiteral("light"));

    const QVariantMap loaded = session.loadSession(sessionPath);
    return !loaded.isEmpty()
        && dummy->counter() == 2
        && loaded.value("moduleCount").toInt() >= 1
        && loaded.value("theme").toMap().value("currentTheme").toString() == QStringLiteral("dark");
}

}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    const bool ok = testTypedSettingsAndMigration()
        && testSessionSaveLoad();
    return ok ? 0 : 1;
}
