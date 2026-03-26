#include "workspacecontainers.h"

#include <QFrame>
#include <QGridLayout>
#include <QVBoxLayout>

namespace pengufoce::ui::layout {

QVBoxLayout *createPageRoot(QWidget *owner, int spacing)
{
    auto *layout = new QVBoxLayout(owner);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(spacing);
    return layout;
}

QFrame *createHeroCard(QWidget *parent, const QMargins &margins, int spacing)
{
    auto *card = new QFrame(parent);
    card->setObjectName(QStringLiteral("heroPanel"));
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(margins);
    layout->setSpacing(spacing);
    return card;
}

QFrame *createCard(QWidget *parent, const QString &objectName, const QMargins &margins, int spacing)
{
    auto *card = new QFrame(parent);
    card->setObjectName(objectName);
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(margins);
    layout->setSpacing(spacing);
    return card;
}

QGridLayout *createGrid(int horizontalSpacing, int verticalSpacing)
{
    auto *grid = new QGridLayout();
    grid->setHorizontalSpacing(horizontalSpacing);
    grid->setVerticalSpacing(verticalSpacing);
    return grid;
}

} // namespace pengufoce::ui::layout
