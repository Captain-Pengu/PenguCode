#include <QApplication>

#include "controllers/app/appcontroller.h"
#include "ui/shell/mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("PenguFoce");
    app.setOrganizationName("PenguFoce");
    QApplication::setEffectEnabled(Qt::UI_AnimateTooltip, false);
    QApplication::setEffectEnabled(Qt::UI_FadeTooltip, false);

    AppController controller;
    MainWindow window(&controller);
    window.show();

    return app.exec();
}
