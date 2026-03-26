#include "settingsdialog.h"

#include "controllers/app/appcontroller.h"
#include "core/settings/settingsmanager.h"
#include "core/theme/themeengine.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"

#include <QColorDialog>
#include <QComboBox>
#include <QCursor>
#include <QDialogButtonBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QToolButton>
#include <QToolTip>
#include <QVBoxLayout>

SettingsDialog::SettingsDialog(AppController *controller, QWidget *parent)
    : QDialog(parent)
    , m_controller(controller)
    , m_themeEngine(controller ? controller->themeEngine() : nullptr)
{
    setWindowTitle(tr("Tema Ayarlari"));
    resize(720, 620);
    setModal(true);

    auto *root = pengufoce::ui::layout::createPageRoot(this, 14);
    root->setContentsMargins(18, 18, 18, 18);

    auto *title = new QLabel(tr("Tema Degiskenleri"), this);
    title->setObjectName("sectionTitle");
    auto *desc = new QLabel(tr("Sadece renk paleti burada yonetilir. Degerler aninda arayuze uygulanir."), this);
    desc->setObjectName("mutedText");
    desc->setWordWrap(true);
    root->addWidget(title);
    root->addWidget(desc);

    auto *modeCard = pengufoce::ui::layout::createCard(this, QStringLiteral("cardPanel"), QMargins(18, 18, 18, 18), 12);
    auto *modeCardLayout = qobject_cast<QVBoxLayout *>(modeCard->layout());
    auto *modeLayout = pengufoce::ui::layout::createGrid(14, 12);
    modeCardLayout->addLayout(modeLayout);
    m_themeModeCombo = new QComboBox(modeCard);
    m_themeModeCombo->addItem(tr("Koyu"), "dark");
    m_themeModeCombo->addItem(tr("Acik"), "light");
    modeLayout->addWidget(createInfoLabel(tr("Tema Modu"), tr("Duzenlemek istedigin paleti sec.")), 0, 0);
    modeLayout->addWidget(m_themeModeCombo, 0, 1);
    m_presetCombo = new QComboBox(modeCard);
    m_applyPresetButton = new QPushButton(tr("Hazir Temayi Uygula"), modeCard);
    modeLayout->addWidget(createInfoLabel(tr("Hazir Tema"), tr("On tanimli paletleri tek tikla alanlara doldurur.")), 1, 0);
    modeLayout->addWidget(m_presetCombo, 1, 1);
    modeLayout->addWidget(m_applyPresetButton, 1, 2);
    root->addWidget(modeCard);

    auto *paletteCard = pengufoce::ui::layout::createCard(this, QStringLiteral("cardPanel"), QMargins(18, 18, 18, 18), 12);
    auto *paletteCardLayout = qobject_cast<QVBoxLayout *>(paletteCard->layout());
    auto *paletteLayout = pengufoce::ui::layout::createGrid(14, 12);
    paletteCardLayout->addLayout(paletteLayout);
    paletteLayout->setColumnStretch(1, 1);

    const QList<QPair<QString, QString>> fields = {
        {"window", tr("Pencere zemini")},
        {"panel", tr("Panel zemini")},
        {"panelAlt", tr("Alternatif panel")},
        {"border", tr("Cerceve rengi")},
        {"text", tr("Ana metin")},
        {"mutedText", tr("Ikincil metin")},
        {"accent", tr("Vurgu rengi")},
        {"accentSoft", tr("Yumusak vurgu")},
        {"success", tr("Basari")},
        {"warning", tr("Uyari")},
        {"danger", tr("Tehlike")}
    };

    int row = 0;
    for (const auto &field : fields) {
        auto *input = new QLineEdit(paletteCard);
        input->setPlaceholderText("#000000");
        m_colorInputs.insert(field.first, input);
        connect(input, &QLineEdit::textChanged, this, [this, key = field.first](const QString &value) {
            QWidget *preview = m_colorPreviews.value(key);
            if (preview && QColor(value).isValid()) {
                preview->setStyleSheet(QString("background:%1; border:1px solid #4b5563; border-radius:6px;").arg(value));
            }
        });
        auto *chooseButton = new QPushButton(tr("Sec"), paletteCard);
        chooseButton->setProperty("colorKey", field.first);
        connect(chooseButton, &QPushButton::clicked, this, &SettingsDialog::chooseColor);

        auto *preview = createColorPreview(field.first);
        m_colorPreviews.insert(field.first, preview);

        paletteLayout->addWidget(createInfoLabel(field.second, tr("Hex renk degeri. Ornek: #8f1732")), row, 0);
        paletteLayout->addWidget(input, row, 1);
        paletteLayout->addWidget(preview, row, 2);
        paletteLayout->addWidget(chooseButton, row, 3);
        ++row;
    }

    root->addWidget(paletteCard, 1);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::applySettings);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttons);

    const int currentIndex = m_themeModeCombo->findData(m_themeEngine ? m_themeEngine->currentTheme() : "dark");
    if (currentIndex >= 0) {
        m_themeModeCombo->setCurrentIndex(currentIndex);
    }
    connect(m_applyPresetButton, &QPushButton::clicked, this, &SettingsDialog::applyPreset);
    connect(m_themeModeCombo, &QComboBox::currentIndexChanged, this, &SettingsDialog::refreshInputs);
    refreshInputs();
}

QWidget *SettingsDialog::createInfoLabel(const QString &title, const QString &tooltip) const
{
    auto *container = new QWidget(const_cast<SettingsDialog *>(this));
    auto *layout = new QHBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    auto *label = new QLabel(title, container);
    label->setObjectName("mutedText");
    auto *button = new QToolButton(container);
    button->setObjectName("infoButton");
    button->setText("i");
    button->setFixedSize(18, 18);
    button->setCursor(Qt::PointingHandCursor);
    button->setToolTip(tooltip);
    connect(button, &QToolButton::clicked, button, [button, tooltip]() {
        QToolTip::showText(QCursor::pos(), tooltip, button);
    });

    layout->addWidget(label);
    layout->addWidget(button);
    layout->addStretch();
    return container;
}

QWidget *SettingsDialog::createColorPreview(const QString &key)
{
    auto *preview = new QFrame(this);
    preview->setObjectName(QStringLiteral("preview_%1").arg(key));
    preview->setFixedSize(44, 24);
    return preview;
}

QString SettingsDialog::currentThemeKey() const
{
    return m_themeModeCombo->currentData().toString();
}

QVariantMap SettingsDialog::presetPalette(const QString &theme, const QString &presetId) const
{
    if (theme == "light") {
        if (presetId == "mint_console") {
            return {
                {"window", "#e8f3ef"},
                {"panel", "#f8fffc"},
                {"panelAlt", "#dcece6"},
                {"border", "#b4cbc1"},
                {"text", "#15221d"},
                {"mutedText", "#5f7168"},
                {"accent", "#1d7f68"},
                {"accentSoft", "#d4ebe4"},
                {"success", "#2f8f57"},
                {"warning", "#af7d1a"},
                {"danger", "#c14b4f"}
            };
        }
        if (presetId == "ivory_blue") {
            return {
                {"window", "#f2f4f7"},
                {"panel", "#ffffff"},
                {"panelAlt", "#e5ebf3"},
                {"border", "#c4cfde"},
                {"text", "#192432"},
                {"mutedText", "#667488"},
                {"accent", "#2b5f9e"},
                {"accentSoft", "#dae6f6"},
                {"success", "#1f7f63"},
                {"warning", "#b47d16"},
                {"danger", "#ca4752"}
            };
        }
        if (presetId == "rose_paper") {
            return {
                {"window", "#f6edea"},
                {"panel", "#fff8f5"},
                {"panelAlt", "#f0dfd8"},
                {"border", "#d3bbb1"},
                {"text", "#2c1f21"},
                {"mutedText", "#796267"},
                {"accent", "#a64d64"},
                {"accentSoft", "#f1d6de"},
                {"success", "#478453"},
                {"warning", "#b57a22"},
                {"danger", "#c84a4a"}
            };
        }
        if (presetId == "sandstone") {
            return {
                {"window", "#f3ede3"},
                {"panel", "#fffaf2"},
                {"panelAlt", "#efe4d2"},
                {"border", "#c8b89f"},
                {"text", "#2a241d"},
                {"mutedText", "#6d6253"},
                {"accent", "#9a3f24"},
                {"accentSoft", "#efd4c4"},
                {"success", "#3f7f4a"},
                {"warning", "#b7771b"},
                {"danger", "#c24130"}
            };
        }
        if (presetId == "slate_light") {
            return {
                {"window", "#e8edf3"},
                {"panel", "#f8fbff"},
                {"panelAlt", "#dde6f0"},
                {"border", "#b7c3d1"},
                {"text", "#16202b"},
                {"mutedText", "#61707f"},
                {"accent", "#27567a"},
                {"accentSoft", "#d8e5f0"},
                {"success", "#1f7a58"},
                {"warning", "#ad7a15"},
                {"danger", "#c03b4e"}
            };
        }
        return {
            {"window", "#eceef1"},
            {"panel", "#ffffff"},
            {"panelAlt", "#f3f4f6"},
            {"border", "#ced4dd"},
            {"text", "#161a20"},
            {"mutedText", "#596273"},
            {"accent", "#a61b3f"},
            {"accentSoft", "#f4d9e1"},
            {"success", "#15803d"},
            {"warning", "#b45309"},
            {"danger", "#dc2626"}
        };
    }

    if (presetId == "amber_grid") {
        return {
            {"window", "#0d0f11"},
            {"panel", "#171a1e"},
            {"panelAlt", "#22262b"},
            {"border", "#4a4032"},
            {"text", "#f1eadf"},
            {"mutedText", "#ada58f"},
            {"accent", "#b8701f"},
            {"accentSoft", "#2f2112"},
            {"success", "#4eb26f"},
            {"warning", "#d19b2b"},
            {"danger", "#cc5a4c"}
        };
    }
    if (presetId == "polar_night") {
        return {
            {"window", "#081019"},
            {"panel", "#101b28"},
            {"panelAlt", "#172433"},
            {"border", "#35516d"},
            {"text", "#edf5ff"},
            {"mutedText", "#8fa8c0"},
            {"accent", "#4d87c7"},
            {"accentSoft", "#132233"},
            {"success", "#31b47c"},
            {"warning", "#d6a12f"},
            {"danger", "#dc5f67"}
        };
    }
    if (presetId == "ember_wire") {
        return {
            {"window", "#110b0c"},
            {"panel", "#1b1215"},
            {"panelAlt", "#26191d"},
            {"border", "#5a343b"},
            {"text", "#f5e8e5"},
            {"mutedText", "#b7a19c"},
            {"accent", "#c14332"},
            {"accentSoft", "#321515"},
            {"success", "#54b26b"},
            {"warning", "#d89b25"},
            {"danger", "#ea5447"}
        };
    }
    if (presetId == "steel_blue") {
        return {
            {"window", "#09111a"},
            {"panel", "#101c28"},
            {"panelAlt", "#162636"},
            {"border", "#2c455d"},
            {"text", "#e3edf7"},
            {"mutedText", "#91a7bb"},
            {"accent", "#1d6fa5"},
            {"accentSoft", "#112635"},
            {"success", "#1fa971"},
            {"warning", "#d79a24"},
            {"danger", "#dd4f5f"}
        };
    }
    if (presetId == "olive_ops") {
        return {
            {"window", "#0d100d"},
            {"panel", "#171c17"},
            {"panelAlt", "#212921"},
            {"border", "#475448"},
            {"text", "#e8eadf"},
            {"mutedText", "#a4ab98"},
            {"accent", "#627d2c"},
            {"accentSoft", "#222919"},
            {"success", "#67b34d"},
            {"warning", "#c8a33a"},
            {"danger", "#c45144"}
        };
    }
    return {
        {"window", "#0a0d12"},
        {"panel", "#121720"},
        {"panelAlt", "#1a2230"},
        {"border", "#2f3846"},
        {"text", "#ece7e2"},
        {"mutedText", "#a5acb8"},
        {"accent", "#8f1732"},
        {"accentSoft", "#261018"},
        {"success", "#22c55e"},
        {"warning", "#f59e0b"},
        {"danger", "#ef4444"}
    };
}

void SettingsDialog::refreshPresetOptions()
{
    const QString theme = currentThemeKey();
    const QSignalBlocker blocker(m_presetCombo);
    m_presetCombo->clear();
    if (theme == "light") {
        m_presetCombo->addItem(tr("Hazir: Paper Ash"), "paper_ash");
        m_presetCombo->addItem(tr("Hazir: Sandstone"), "sandstone");
        m_presetCombo->addItem(tr("Hazir: Slate Light"), "slate_light");
        m_presetCombo->addItem(tr("Hazir: Mint Console"), "mint_console");
        m_presetCombo->addItem(tr("Hazir: Ivory Blue"), "ivory_blue");
        m_presetCombo->addItem(tr("Hazir: Rose Paper"), "rose_paper");
        return;
    }

    m_presetCombo->addItem(tr("Hazir: Tactical Crimson"), "tactical_crimson");
    m_presetCombo->addItem(tr("Hazir: Steel Blue"), "steel_blue");
    m_presetCombo->addItem(tr("Hazir: Olive Ops"), "olive_ops");
    m_presetCombo->addItem(tr("Hazir: Amber Grid"), "amber_grid");
    m_presetCombo->addItem(tr("Hazir: Polar Night"), "polar_night");
    m_presetCombo->addItem(tr("Hazir: Ember Wire"), "ember_wire");
}

void SettingsDialog::chooseColor()
{
    auto *button = qobject_cast<QPushButton *>(sender());
    if (!button) {
        return;
    }

    const QString key = button->property("colorKey").toString();
    QLineEdit *input = m_colorInputs.value(key);
    if (!input) {
        return;
    }

    const QColor chosen = QColorDialog::getColor(QColor(input->text()), this, tr("Renk Sec"));
    if (!chosen.isValid()) {
        return;
    }

    input->setText(chosen.name(QColor::HexRgb));
}

void SettingsDialog::applyPreset()
{
    const QVariantMap palette = presetPalette(currentThemeKey(), m_presetCombo->currentData().toString());
    for (auto it = m_colorInputs.begin(); it != m_colorInputs.end(); ++it) {
        const QString value = palette.value(it.key()).toString();
        it.value()->setText(value);
        QWidget *preview = m_colorPreviews.value(it.key());
        if (preview) {
            preview->setStyleSheet(QString("background:%1; border:1px solid #4b5563; border-radius:6px;").arg(value));
        }
    }

    if (m_controller && m_controller->settingsManager()) {
        m_controller->settingsManager()->setValue(QString("theme/%1").arg(currentThemeKey()),
                                                  "presetId",
                                                  m_presetCombo->currentData().toString());
    }
}

void SettingsDialog::applySettings()
{
    if (!m_controller || !m_themeEngine) {
        reject();
        return;
    }

    SettingsManager *settings = m_controller->settingsManager();
    const QString theme = currentThemeKey();
    settings->setValue(QString("theme/%1").arg(theme), "presetId", m_presetCombo->currentData().toString());
    for (auto it = m_colorInputs.cbegin(); it != m_colorInputs.cend(); ++it) {
        const QString value = it.value()->text().trimmed();
        settings->setValue(QString("theme/%1").arg(theme), it.key(), value);
        m_themeEngine->setPaletteValue(theme, it.key(), value);
    }
    settings->setValue("theme", "currentTheme", theme);
    m_themeEngine->setCurrentTheme(theme);

    emit settingsApplied();
    accept();
}

void SettingsDialog::refreshInputs()
{
    if (!m_themeEngine) {
        return;
    }

    refreshPresetOptions();
    if (m_controller && m_controller->settingsManager()) {
        const QString presetId = m_controller->settingsManager()->value(QString("theme/%1").arg(currentThemeKey()),
                                                                        "presetId",
                                                                        m_presetCombo->currentData()).toString();
        const int presetIndex = m_presetCombo->findData(presetId);
        if (presetIndex >= 0) {
            m_presetCombo->setCurrentIndex(presetIndex);
        }
    }

    const QString originalTheme = m_themeEngine->currentTheme();
    if (currentThemeKey() != originalTheme) {
        m_themeEngine->setCurrentTheme(currentThemeKey());
    }
    const QVariantMap palette = m_themeEngine->palette();
    if (currentThemeKey() != originalTheme) {
        m_themeEngine->setCurrentTheme(originalTheme);
    }

    for (auto it = m_colorInputs.begin(); it != m_colorInputs.end(); ++it) {
        const QString value = palette.value(it.key()).toString();
        const QSignalBlocker blocker(it.value());
        it.value()->setText(value);
        QWidget *preview = m_colorPreviews.value(it.key());
        if (preview) {
            preview->setStyleSheet(QString("background:%1; border:1px solid #4b5563; border-radius:6px;").arg(value));
        }
    }
}
