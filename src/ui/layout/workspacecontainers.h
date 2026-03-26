#pragma once

#include <QMargins>

class QFrame;
class QGridLayout;
class QVBoxLayout;
class QWidget;

namespace pengufoce::ui::layout {

QVBoxLayout *createPageRoot(QWidget *owner, int spacing = 16);
QFrame *createHeroCard(QWidget *parent, const QMargins &margins = QMargins(24, 22, 24, 22), int spacing = 12);
QFrame *createCard(QWidget *parent, const QString &objectName = QStringLiteral("cardPanel"), const QMargins &margins = QMargins(20, 18, 20, 18), int spacing = 12);
QGridLayout *createGrid(int horizontalSpacing = 12, int verticalSpacing = 12);

} // namespace pengufoce::ui::layout
