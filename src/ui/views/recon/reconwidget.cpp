#include "reconwidget.h"

#include "core/settings/settingsmanager.h"
#include "modules/recon/reconmodule.h"
#include "modules/recon/engine/pengufoce_masterscanner.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"

#include <QApplication>
#include <QClipboard>
#include <QCursor>
#include <QDateTime>
#include <QDialog>
#include <QElapsedTimer>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QInputDialog>
#include <QMenu>
#include <QPainter>
#include <QPageLayout>
#include <QProgressBar>
#include <QPageSize>
#include <QPlainTextEdit>
#include <QPdfWriter>
#include <QPushButton>
#include <QSet>
#include <QTextDocument>
#include <QTextEdit>
#include <QTextStream>
#include <QTabWidget>
#include <QTimer>
#include <QToolButton>
#include <QToolTip>
#include <QVBoxLayout>

namespace {

ScanReport scanReportFromVariantMap(const QVariantMap &map)
{
    ScanReport report;
    report.originalTarget = map.value("originalTarget").toString();
    report.sanitizedTarget = map.value("sanitizedTarget").toString();
    report.host = map.value("host").toString();
    report.scheme = map.value("scheme").toString();
    report.resolvedIp = map.value("resolvedIp").toString();
    report.openPorts = map.value("openPorts").toList();
    report.dnsRecords = map.value("dnsRecords").toList();
    report.findings = map.value("findings").toList();
    report.webObservations = map.value("webObservations").toList();
    report.osintObservations = map.value("osintObservations").toList();
    report.subdomains = map.value("subdomains").toList();
    report.archivedUrls = map.value("archivedUrls").toList();
    report.jsFindings = map.value("jsFindings").toList();
    report.cveMatches = map.value("cveMatches").toList();
    report.whoisInfo = map.value("whoisInfo").toMap();
    report.spiderEndpoints = map.value("spiderEndpoints").toList();
    report.spiderParameters = map.value("spiderParameters").toList();
    report.spiderAssets = map.value("spiderAssets").toList();
    return report;
}

QString sanitizedFileStem(QString text)
{
    text = text.trimmed();
    if (text.isEmpty()) {
        return QStringLiteral("pengufoce-resmi-pentest-raporu");
    }

    text.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9]+")), QStringLiteral("-"));
    text = text.trimmed();
    while (text.contains(QStringLiteral("--"))) {
        text.replace(QStringLiteral("--"), QStringLiteral("-"));
    }
    text = text.trimmed();
    text.remove(QRegularExpression(QStringLiteral("^-+|-+$")));
    return text.isEmpty() ? QStringLiteral("pengufoce-resmi-pentest-raporu") : text.toLower();
}

QString corporateReportFileName(const QString &company, const QString &target, const QString &extension)
{
    const QString companyStem = sanitizedFileStem(company);
    const QString targetStem = sanitizedFileStem(target);
    const QString dateStamp = QDate::currentDate().toString("yyyyMMdd");
    return QString("%1-sizma-testi-raporu-%2-v1.0-%3.%4")
        .arg(companyStem,
             targetStem,
             dateStamp,
             extension);
}

QString renderSpiderEndpointHtml(const QVariantList &endpoints)
{
    QString html;
    for (const QVariant &value : endpoints) {
        const QVariantMap row = value.toMap();
        const QString sessionState = row.value("sessionState").toString();
        const QString sessionBadge = sessionState == QLatin1String("oturumlu-yeni-yuzey")
            ? QObject::tr(" | oturum sonrasi yeni yuzey")
            : (sessionState == QLatin1String("oturumlu-ortak") ? QObject::tr(" | oturumlu ortak") : QString());
        html += QString("<li><b>%1</b> - %2 (derinlik %3, HTTP %4, tip %5%6)</li>")
                    .arg(row.value("kind").toString().toHtmlEscaped(),
                         row.value("url").toString().toHtmlEscaped(),
                         row.value("depth").toString().toHtmlEscaped(),
                         row.value("statusCode").toString().toHtmlEscaped(),
                         row.value("contentType").toString().toHtmlEscaped(),
                         sessionBadge.toHtmlEscaped());
    }
    if (html.isEmpty()) {
        html = "<li>Spider endpoint kaydi bulunmadi.</li>";
    }
    return html;
}

QString renderSpiderParameterHtml(const QVariantList &parameters)
{
    QString html;
    for (const QVariant &value : parameters) {
        const QVariantMap row = value.toMap();
        QString origin = row.value("origin").toString();
        origin.replace(':', " / ");
        html += QString("<li><b>%1</b> - %2 - kaynak: %3</li>")
                    .arg(row.value("name").toString().toHtmlEscaped(),
                         row.value("url").toString().toHtmlEscaped(),
                         origin.toHtmlEscaped());
    }
    if (html.isEmpty()) {
        html = "<li>Spider parametre veya form girdisi kaydi bulunmadi.</li>";
    }
    return html;
}

QString renderSpiderAssetHtml(const QVariantList &assets)
{
    QString html;
    for (const QVariant &value : assets) {
        const QVariantMap row = value.toMap();
        html += QString("<li><b>%1</b> - %2 <span style='color:#5b6677'>(kaynak: %3)</span></li>")
                    .arg(row.value("kind").toString().toHtmlEscaped(),
                         row.value("value").toString().toHtmlEscaped(),
                         row.value("source").toString().toHtmlEscaped());
    }
    if (html.isEmpty()) {
        html = "<li>Spider asset veya literal kaydi bulunmadi.</li>";
    }
    return html;
}

QString renderSpiderAuthHtml(const QVariantList &assets)
{
    QString html;
    for (const QVariant &value : assets) {
        const QVariantMap row = value.toMap();
        const QString kind = row.value("kind").toString();
        if (!kind.startsWith("auth-") && kind != "redirect-chain" && kind != "response-signature") {
            continue;
        }
        html += QString("<li><b>%1</b> - %2 <span style='color:#5b6677'>(kaynak: %3)</span></li>")
                    .arg(kind.toHtmlEscaped(),
                         row.value("value").toString().toHtmlEscaped(),
                         row.value("source").toString().toHtmlEscaped());
    }
    if (html.isEmpty()) {
        html = "<li>Auth veya oturum kaniti kaydi bulunmadi.</li>";
    }
    return html;
}

QString renderSpiderDeltaHtml(const QVariantList &assets)
{
    QString html;
    for (const QVariant &value : assets) {
        const QVariantMap row = value.toMap();
        if (row.value("kind").toString() != QLatin1String("auth-surface-delta")) {
            continue;
        }
        html += QString("<li>%1 <span style='color:#5b6677'>(kaynak: %2)</span></li>")
                    .arg(row.value("value").toString().toHtmlEscaped(),
                         row.value("source").toString().toHtmlEscaped());
    }
    if (html.isEmpty()) {
        html = "<li>Oturum sonrasi yeni yuzey farki kaydi bulunmadi.</li>";
    }
    return html;
}

QString renderSpiderSegmentHtml(const QVariantMap &segments)
{
    const QList<QPair<QString, QString>> orderedSegments = {
        {QStringLiteral("auth"), QObject::tr("Kimlik ve Oturum")},
        {QStringLiteral("admin"), QObject::tr("Yonetim Yuzeyi")},
        {QStringLiteral("upload"), QObject::tr("Dosya Yukleme")},
        {QStringLiteral("render"), QObject::tr("Rendered Yuzey")},
        {QStringLiteral("automation"), QObject::tr("Browser Automation")},
        {QStringLiteral("secret"), QObject::tr("Gizli Literal")}
    };

    QString html;
    for (const auto &segment : orderedSegments) {
        const QVariantList values = segments.value(segment.first).toList();
        html += QString("<li><b>%1</b> - %2 kayit").arg(segment.second.toHtmlEscaped()).arg(values.size());
        if (!values.isEmpty()) {
            html += QStringLiteral("<ul>");
            int shown = 0;
            for (const QVariant &value : values) {
                const QVariantMap row = value.toMap();
                html += QString("<li>%1 - %2</li>")
                            .arg(row.value("label").toString().toHtmlEscaped(),
                                 row.value("value").toString().toHtmlEscaped());
                if (++shown >= 4) {
                    break;
                }
            }
            html += QStringLiteral("</ul>");
        }
        html += QStringLiteral("</li>");
    }

    if (html.isEmpty()) {
        html = QStringLiteral("<li>Segment bazli kritik yuzey kaydi bulunmadi.</li>");
    }
    return html;
}

QVariantMap developerGuidanceForFinding(const QString &title, const QString &description)
{
    QVariantMap map{
        {"riskNames", QObject::tr("Bilgi toplama, temel maruziyet analizi")},
        {"impact", QObject::tr("Bu bulgu saldiri yuzeyini genisletebilir veya guvenlik durusunu zayiflatabilir.")},
        {"attackerPlay", QObject::tr("Bilgi toplama, maruziyet haritalama ve sonraki asama erisim denemeleri icin kullanilabilir.")},
        {"action", QObject::tr("Servis ihtiyaci, maruziyet ve koruma kontrolleri birlikte degerlendirilerek duzeltici aksiyon alinmalidir.")},
        {"developerNotes", QObject::tr("Ilgili servis veya uygulama konfigurasyonu kod, reverse proxy, deployment ve altyapi katmanlarinda birlikte incelenmelidir.")}
    };

    if (title.contains("TLS", Qt::CaseInsensitive) || title.contains("HSTS", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("Ortadaki adam saldirisi, TLS dusurme, oturum gozetleme");
        map["impact"] = QObject::tr("Iletisim gizliligi ve butunlugu zayiflayabilir; istemci ile sunucu arasindaki trafik dusurulebilir veya gozetlenebilir.");
        map["attackerPlay"] = QObject::tr("Aradaki adam saldirilari, sifreleme dusurme ve oturum/cookie gozetleme senaryolari denenebilir.");
        map["action"] = QObject::tr("TLS konfigrasyonu guncellenmeli, eski protokoller kapatilmali ve HSTS gibi koruyucu basliklar etkinlestirilmelidir.");
        map["developerNotes"] = QObject::tr("Uygulama load balancer, reverse proxy ve web sunucusu tarafinda HSTS, TLS 1.2+ ve guvenli cipher suite konfigurasyonu ile yayinlanmali; sertifika yenileme sureci otomatiklestirilmelidir.");
    } else if (title.contains("SPF", Qt::CaseInsensitive) || title.contains("DMARC", Qt::CaseInsensitive) || title.contains("MX", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("E-posta sahteciligi, phishing, alan adi itibari istismari");
        map["impact"] = QObject::tr("E-posta sahteciligi, alan adi guveni kaybi ve teslimat sorunlari olusabilir.");
        map["attackerPlay"] = QObject::tr("Spoofed e-posta gonderimi, phishing ve alan adi itibarini suistimal eden sosyal muhendislik akislari yapilabilir.");
        map["action"] = QObject::tr("DNS politika kayitlari kurumsal posta mimarisine gore duzenlenmeli ve yaptirim moduna alinmalidir.");
        map["developerNotes"] = QObject::tr("SPF kaydi kullanilan e-posta servisleriyle sinirlandirilmali, DMARC politikasi once p=quarantine ardindan p=reject olacak sekilde olgunlastirilmali, degisiklikler DNS propagation sonrasi test edilmelidir.");
    } else if (title.contains("CSP", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("XSS etki genislemesi, istemci tarafli kod enjeksiyonu");
        map["impact"] = QObject::tr("Tarayiciya yuklenen zararlı scriptlerin etkisi artabilir ve istemci tarafli veri guvenligi zayiflayabilir.");
        map["attackerPlay"] = QObject::tr("Reflected veya stored XSS bulgulari varsa daha kolay istismar edilir; ucuncu taraf script zinciri suistimal edilebilir.");
        map["action"] = QObject::tr("Kaynak bazli, dar kapsamli bir Content-Security-Policy tanimlanmali; inline script kullanimi azaltılmali ve nonce/hash mekanizmasi uygulanmalidir.");
        map["developerNotes"] = QObject::tr("Frontend build ciktisi, CDN kaynaklari, analytics ve inline script kullanimi analiz edilerek asamali CSP rollout yapilmali; raporlama modu ile ihlaller izlenmelidir.");
    } else if (title.contains("X-Frame-Options", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("Clickjacking, arayuz istismari");
        map["impact"] = QObject::tr("Sayfa baska bir site icinde gizlice cercevelenerek kullanici etkileşimi manipule edilebilir.");
        map["attackerPlay"] = QObject::tr("Kullanici fark etmeden kritik butonlara tiklatma veya oturum acik kullanicidan islem alma girisimleri yapilabilir.");
        map["action"] = QObject::tr("X-Frame-Options SAMEORIGIN veya CSP frame-ancestors politikasi tanimlanmalidir.");
        map["developerNotes"] = QObject::tr("Uygulama iframe icinde mesru bir kullanim gerektirmiyorsa reverse proxy ve uygulama cevabinda frame engelleme basliklari zorunlu kilinmalidir.");
    } else if (title.contains("HttpOnly", Qt::CaseInsensitive) || title.contains("cookie", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("Oturum cerezinin calinmasi, istemci tarafli script istismari");
        map["impact"] = QObject::tr("Tarayici tarafli zararlı scriptler cerezlere erişebilir ve oturum ele gecirme riski artar.");
        map["attackerPlay"] = QObject::tr("XSS ile birlesen durumlarda session hijacking ve yetkisiz islem calistirma senaryolari denenebilir.");
        map["action"] = QObject::tr("Kimlik dogrulama cerezlerinde HttpOnly, Secure ve uygun SameSite bayraklari zorunlu hale getirilmelidir.");
        map["developerNotes"] = QObject::tr("Session middleware ve reverse proxy tarafindaki Set-Cookie davranisi incelenmeli; framework konfigurasyonu ile tum kimlik dogrulama cerezleri standardize edilmelidir.");
    } else if (title.contains("port", Qt::CaseInsensitive) || title.contains("servis", Qt::CaseInsensitive) || title.contains("Docker", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("Yetkisiz erisim, brute force, servis istismari, yanal hareket");
        map["impact"] = QObject::tr("Gereksiz veya kritik servis maruziyeti dogrudan ilk erisim vektoru saglayabilir.");
        map["attackerPlay"] = QObject::tr("Banner toplama, varsayilan parola denemeleri, servis istismari ve yanal hareket hazirligi yapilabilir.");
        map["action"] = QObject::tr("Acik servisler sadece gerekli ag segmentlerinde tutulmali, yonetim portlari kisitlanmali ve erisim kontrolleri sertlestirilmelidir.");
        map["developerNotes"] = QObject::tr("Konteyner, veritabani, cache ve yonetim servisleri internetten dogrudan erisilemez olmali; security group, firewall, bind address ve authentication ayarlari kod disi deployment katmaninda dogrulanmalidir.");
    } else if (title.contains("OSINT", Qt::CaseInsensitive) || title.contains("sizinti", Qt::CaseInsensitive) || title.contains("tehdit", Qt::CaseInsensitive)) {
        map["riskNames"] = QObject::tr("Kimlik bilgisi doldurma, hedefli phishing, parola tekrar kullanim istismari");
        map["impact"] = QObject::tr("Harici kaynaklardaki izler hedefin saldiri planlamasini kolaylastirabilir ve veri sizintisi riskine isaret eder.");
        map["attackerPlay"] = QObject::tr("Kimlik bilgisi doldurma, parola tekrar kullanim analizi, hedefli phishing ve altyapi haritalama yapilabilir.");
        map["action"] = QObject::tr("Harici platformlardaki gorunurluk izlenmeli, sizinti kayitlari dogrulanmali ve etkilenen varliklar icin olay mudahalesi baslatilmalidir.");
        map["developerNotes"] = QObject::tr("Etkilenen kullanici ve servis hesaplari icin parola reset, MFA zorunlulugu, token iptali ve audit log incelemesi uygulanmalidir.");
    }

    if (description.contains("WAF", Qt::CaseInsensitive) || title.contains("WAF", Qt::CaseInsensitive)) {
        map["developerNotes"] = QObject::tr("WAF tespiti tek basina acik degildir; ancak mimari akista ters vekil, cache ve rate limiting katmanlarinin goz onunde bulundurulmasi gerekir.");
    }

    return map;
}

QColor severityColorForLabel(const QString &severity)
{
    const QString normalized = severity.trimmed().toLower();
    if (normalized.contains("yuksek") || normalized == QLatin1String("high")) {
        return QColor("#ef6b6b");
    }
    if (normalized.contains("orta") || normalized == QLatin1String("medium")) {
        return QColor("#f2b35b");
    }
    if (normalized.contains("dusuk") || normalized == QLatin1String("low")) {
        return QColor("#7fd39a");
    }
    return QColor("#8db9ff");
}

QWidget *makeInfoBlock(QWidget *parent, const QString &title, QLabel **valueLabel)
{
    auto *card = new QFrame(parent);
    card->setObjectName("summaryCard");
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(6);

    auto *titleLabel = new QLabel(title, card);
    titleLabel->setObjectName("mutedText");
    *valueLabel = new QLabel("--", card);
    (*valueLabel)->setObjectName("statValue");
    layout->addWidget(titleLabel);
    layout->addWidget(*valueLabel);
    return card;
}

class ReconPulseWidget : public QWidget
{
public:
    explicit ReconPulseWidget(QWidget *parent = nullptr)
        : QWidget(parent)
        , m_timer(new QTimer(this))
    {
        setObjectName("reconPulse");
        setMinimumSize(140, 140);
        m_timer->setInterval(40);
        m_timer->start();
        connect(m_timer, &QTimer::timeout, this, [this]() {
            m_phase += m_active ? 0.045 : 0.018;
            if (m_phase > 1.0) {
                m_phase = 0.0;
            }
            m_sweep += m_active ? 5.0 : 1.8;
            if (m_sweep >= 360.0) {
                m_sweep = 0.0;
            }
            update();
        });
    }

    void setActive(bool active)
    {
        m_active = active;
        update();
    }

    void setAnimationEnabled(bool enabled)
    {
        if (enabled) {
            if (!m_timer->isActive()) {
                m_timer->start();
            }
        } else {
            m_timer->stop();
        }
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const QRectF circleRect = rect().adjusted(20, 20, -20, -20);
        const QPointF c = circleRect.center();

        painter.setPen(QPen(QColor(255, 255, 255, 26), 1.0));
        for (int i = 0; i < 4; ++i) {
            const qreal inset = i * 12.0;
            painter.drawEllipse(circleRect.adjusted(inset, inset, -inset, -inset));
        }

        painter.setPen(QPen(QColor(164, 29, 60, 190), 1.8));
        painter.drawArc(circleRect.adjusted(8, 8, -8, -8), 32 * 16, 248 * 16);

        QColor pulse(196, 42, 81, 60);
        pulse.setAlphaF(m_active ? (0.16 + (0.22 * (1.0 - m_phase))) : 0.08);
        painter.setBrush(pulse);
        painter.setPen(Qt::NoPen);
        const qreal pulseRadius = m_active ? (18.0 + (m_phase * 34.0)) : (16.0 + (m_phase * 10.0));
        painter.drawEllipse(c, pulseRadius, pulseRadius);

        painter.setPen(QPen(QColor(244, 96, 130, m_active ? 220 : 90), m_active ? 2.2 : 1.2));
        painter.drawArc(circleRect.adjusted(14, 14, -14, -14),
                        static_cast<int>((90.0 - m_sweep) * 16.0),
                        52 * 16);

        if (m_active) {
            painter.setBrush(pulse);
            painter.drawEllipse(c, 12.0 + (m_phase * 10.0), 12.0 + (m_phase * 10.0));
        }

        painter.setBrush(QColor("#f5f7fb"));
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(c, 4.0, 4.0);
    }

private:
    QTimer *m_timer = nullptr;
    bool m_active = false;
    qreal m_phase = 0.0;
    qreal m_sweep = 0.0;
};

class ReportPreviewDialog : public QDialog
{
public:
    explicit ReportPreviewDialog(QWidget *parent = nullptr)
        : QDialog(parent)
    {
        setWindowTitle(QObject::tr("PDF Onizleme"));
        resize(980, 780);

        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(16, 16, 16, 16);
        layout->setSpacing(12);

        auto *title = new QLabel(QObject::tr("Rapor Onizlemesi"), this);
        title->setObjectName("sectionTitle");
        auto *info = new QLabel(QObject::tr("Bu pencere PDF ciktisinin onizlemesini gosterir. Kaydetme islemleri sadece burada yapilir."), this);
        info->setObjectName("mutedText");
        info->setWordWrap(true);
        layout->addWidget(title);
        layout->addWidget(info);

        m_view = new QTextEdit(this);
        m_view->setReadOnly(true);
        m_view->setStyleSheet("QTextEdit { background: #ffffff; color: #171a20; border: 1px solid #c7cdd8; border-radius: 10px; padding: 20px; }");
        layout->addWidget(m_view, 1);

        auto *buttons = new QHBoxLayout();
        m_savePdfButton = new QPushButton(QObject::tr("PDF Kaydet"), this);
        m_saveHtmlButton = new QPushButton(QObject::tr("HTML Kaydet"), this);
        auto *closeButton = new QPushButton(QObject::tr("Kapat"), this);
        buttons->addStretch();
        buttons->addWidget(m_savePdfButton);
        buttons->addWidget(m_saveHtmlButton);
        buttons->addWidget(closeButton);
        layout->addLayout(buttons);

        connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
    }

    QTextEdit *view() const { return m_view; }
    QPushButton *savePdfButton() const { return m_savePdfButton; }
    QPushButton *saveHtmlButton() const { return m_saveHtmlButton; }

private:
    QTextEdit *m_view = nullptr;
    QPushButton *m_savePdfButton = nullptr;
    QPushButton *m_saveHtmlButton = nullptr;
};

} // namespace

ReconWidget::ReconWidget(ReconModule *module, QWidget *parent)
    : QWidget(parent)
    , m_module(module)
    , m_masterScanner(module ? module->masterScanner() : nullptr)
    , m_scanTimer(new QElapsedTimer())
{
    buildUi();
    m_spiderRefreshTimer = new QTimer(this);
    m_spiderRefreshTimer->setInterval(1200);
    connect(m_spiderRefreshTimer, &QTimer::timeout, this, &ReconWidget::refreshSpiderEvidence);
    m_spiderRefreshTimer->start();

    if (m_masterScanner) {
        connect(m_masterScanner, &PenguFoceMasterScanner::statusMessage, this, &ReconWidget::handleStatus);
        connect(m_masterScanner, &PenguFoceMasterScanner::scanProgress, this, &ReconWidget::handleProgress);
        connect(m_masterScanner, &PenguFoceMasterScanner::findingDiscovered, this, &ReconWidget::handleFinding);
        connect(m_masterScanner, &PenguFoceMasterScanner::scanFinished, this, &ReconWidget::handleFinished);
    }

    reloadSettings();
    refreshSpiderEvidence();
    setActiveView(false);
}

void ReconWidget::loadRecentTargets()
{
    if (!m_recentTargetCombo || !m_module || !m_module->settingsManager()) {
        return;
    }

    const QString currentText = m_recentTargetCombo->currentText();
    m_recentTargetCombo->clear();
    m_recentTargetCombo->addItem(tr("Son hedefler"));
    const QStringList recentTargets = m_module->settingsManager()->value("modules/recon", "recentTargets").toStringList();
    for (const QString &target : recentTargets) {
        if (!target.trimmed().isEmpty()) {
            m_recentTargetCombo->addItem(target.trimmed());
        }
    }

    const int currentIndex = m_recentTargetCombo->findText(currentText);
    if (currentIndex >= 0) {
        m_recentTargetCombo->setCurrentIndex(currentIndex);
    } else {
        m_recentTargetCombo->setCurrentIndex(0);
    }
}

void ReconWidget::loadRecentSessions()
{
    if (!m_recentSessionCombo || !m_module || !m_module->settingsManager()) {
        return;
    }

    const QString currentData = m_recentSessionCombo->currentData().toString();
    m_recentSessionCombo->clear();
    m_recentSessionCombo->addItem(tr("Son oturumlar"), QString());
    const QStringList recentSessions = m_module->settingsManager()->value("modules/recon", "recentSessions").toStringList();
    for (const QString &path : recentSessions) {
        if (!path.trimmed().isEmpty()) {
            m_recentSessionCombo->addItem(QFileInfo(path).fileName(), path);
        }
    }

    for (int i = 0; i < m_recentSessionCombo->count(); ++i) {
        if (m_recentSessionCombo->itemData(i).toString() == currentData) {
            m_recentSessionCombo->setCurrentIndex(i);
            return;
        }
    }
    m_recentSessionCombo->setCurrentIndex(0);
}

void ReconWidget::saveRecentTarget(const QString &target)
{
    if (!m_module || !m_module->settingsManager()) {
        return;
    }

    QString normalized = target.trimmed();
    if (normalized.isEmpty()) {
        return;
    }

    QStringList recentTargets = m_module->settingsManager()->value("modules/recon", "recentTargets").toStringList();
    recentTargets.removeAll(normalized);
    recentTargets.prepend(normalized);
    while (recentTargets.size() > 8) {
        recentTargets.removeLast();
    }
    m_module->settingsManager()->setValue("modules/recon", "recentTargets", recentTargets);
    loadRecentTargets();
}

void ReconWidget::saveRecentSessionPath(const QString &path)
{
    if (!m_module || !m_module->settingsManager() || path.trimmed().isEmpty()) {
        return;
    }

    QStringList recentSessions = m_module->settingsManager()->value("modules/recon", "recentSessions").toStringList();
    recentSessions.removeAll(path);
    recentSessions.prepend(path);
    while (recentSessions.size() > 10) {
        recentSessions.removeLast();
    }
    m_module->settingsManager()->setValue("modules/recon", "recentSessions", recentSessions);
    loadRecentSessions();
}

void ReconWidget::reloadSettings()
{
    if (!m_module || !m_module->settingsManager()) {
        return;
    }

    SettingsManager *settings = m_module->settingsManager();
    m_targetEdit->setText(settings->value("modules/recon", "defaultTarget", "scanme.nmap.org").toString());
    m_endpointEdit->setText(settings->value("modules/recon", "defaultEndpoint", "").toString());
    m_companyEdit->setText(settings->value("report", "companyName", "PenguFoce Security Lab").toString());
    m_clientEdit->setText(settings->value("report", "clientName", "Belirtilmedi").toString());
    m_testerEdit->setText(settings->value("report", "testerName", "Operator").toString());
    m_classificationEdit->setText(settings->value("report", "classification", "Kurum Ici").toString());
    m_scopeEdit->setText(settings->value("report", "scopeSummary", "DNS, web guvenligi, TLS, OSINT ve acik servis degerlendirmesi").toString());
    loadRecentTargets();
    loadRecentSessions();
}

void ReconWidget::setActiveView(bool active)
{
    if (m_spiderRefreshTimer) {
        if (active) {
            if (!m_spiderRefreshTimer->isActive()) {
                m_spiderRefreshTimer->start();
            }
        } else {
            m_spiderRefreshTimer->stop();
        }
    }

    if (auto *pulse = static_cast<ReconPulseWidget *>(m_pulseWidget)) {
        pulse->setAnimationEnabled(active);
    }
}

void ReconWidget::startRecon()
{
    if (!m_masterScanner) {
        return;
    }

    m_dnsList->clear();
    m_surfaceList->clear();
    m_osintList->clear();
    if (m_subdomainList) m_subdomainList->clear();
    if (m_archiveList) m_archiveList->clear();
    if (m_jsFindingList) m_jsFindingList->clear();
    if (m_cveList) m_cveList->clear();
    m_findingsList->clear();
    if (m_spiderEndpointList) m_spiderEndpointList->clear();
    if (m_spiderParameterList) m_spiderParameterList->clear();
    if (m_spiderAssetList) m_spiderAssetList->clear();
    if (m_spiderHighValueList) m_spiderHighValueList->clear();
    if (m_spiderTimelineList) m_spiderTimelineList->clear();
    if (m_whoisSummaryView) {
        m_whoisSummaryView->setHtml(tr("<p>Whois bilgisi bekleniyor.</p>"));
    }
    m_findingDetailView->clear();
    m_feedConsole->clear();
    m_previewReportButton->setEnabled(false);
    if (m_exportJsonButton) {
        m_exportJsonButton->setEnabled(false);
    }
    if (m_exportCsvButton) {
        m_exportCsvButton->setEnabled(false);
    }
    if (m_saveSessionButton) {
        m_saveSessionButton->setEnabled(false);
    }
    m_lastReportHtml.clear();
    m_lastReportJson.clear();
    m_lastReportVariant.clear();
    m_findingNotes.clear();
    m_phaseHistory.clear();
    refreshSummaryCards();
    refreshCategoryCards();
    m_statusValue->setText(tr("Calisiyor"));
    m_scoreValue->setText("--");
    m_activityValue->setText(tr("Hedef ayrisiyor ve tarama boru hatti baslatiliyor"));
    m_progressBar->setValue(3);
    m_scanTimer->restart();
    if (auto *pulse = static_cast<ReconPulseWidget *>(m_pulseWidget)) {
        pulse->setActive(true);
    }
    if (m_module && m_module->settingsManager()) {
        SettingsManager *settings = m_module->settingsManager();
        settings->setValue("report", "companyName", m_companyEdit->text().trimmed());
        settings->setValue("report", "clientName", m_clientEdit->text().trimmed());
        settings->setValue("report", "testerName", m_testerEdit->text().trimmed());
        settings->setValue("report", "classification", m_classificationEdit->text().trimmed());
        settings->setValue("report", "scopeSummary", m_scopeEdit->text().trimmed());
    }
    appendFeed(tr("Kesif taramasi baslatildi: %1").arg(m_targetEdit->text()));
    saveRecentTarget(m_targetEdit->text());
    refreshSpiderEvidence();
    m_masterScanner->startScan(m_targetEdit->text(), QUrl(m_endpointEdit->text()));
}

void ReconWidget::stopRecon()
{
    if (!m_masterScanner) {
        return;
    }

    m_masterScanner->stop();
    m_statusValue->setText(tr("Durduruldu"));
    m_activityValue->setText(tr("Tarama operator tarafindan durduruldu"));
    m_progressBar->setValue(0);
    if (auto *pulse = static_cast<ReconPulseWidget *>(m_pulseWidget)) {
        pulse->setActive(false);
    }
    appendFeed(tr("Kesif taramasi durdurma istegi gonderildi"));
}

void ReconWidget::handleStatus(const QString &message)
{
    m_statusValue->setText(tr("Calisiyor"));
    m_activityValue->setText(message);
    const QString phase = phaseLabelForMessage(message);
    if (!phase.isEmpty() && (m_phaseHistory.isEmpty() || m_phaseHistory.constLast() != phase)) {
        m_phaseHistory << phase;
        if (m_phaseSummaryValue) {
            m_phaseSummaryValue->setText(m_phaseHistory.join(QStringLiteral("  ->  ")));
        }
    }
    appendFeed(message);
}

void ReconWidget::handleProgress(int percent)
{
    m_statusValue->setText(QString("%1%").arg(percent));
    m_progressBar->setValue(percent);
}

void ReconWidget::handleFinding(const QString &severity, const QString &title, const QString &description)
{
    appendFeed(QString("[%1] %2 - %3").arg(severity, title, description));
    if (title.contains("SPF", Qt::CaseInsensitive) || title.contains("DMARC", Qt::CaseInsensitive)
        || title.contains("MX", Qt::CaseInsensitive) || title.contains("DNS", Qt::CaseInsensitive)) {
        insertSeverityItem(m_dnsList, severity, title, description);
    } else if (title.contains("OSINT", Qt::CaseInsensitive) || title.contains("sizinti", Qt::CaseInsensitive)
               || title.contains("tehdit", Qt::CaseInsensitive)) {
        insertSeverityItem(m_osintList, severity, title, description);
    } else {
        insertSeverityItem(m_surfaceList, severity, title, description);
    }

    insertSeverityItem(m_findingsList, severity, title, description);
    if (m_findingsList->currentRow() < 0 && m_findingsList->count() > 0) {
        m_findingsList->setCurrentRow(0);
    }
    refreshFindingFilters();
}

void ReconWidget::handleFinished(const ScanReport &report, int securityScore)
{
    m_statusValue->setText(tr("Tamamlandi"));
    m_scoreValue->setText(QString::number(securityScore));
    m_activityValue->setText(tr("Tarama tamamlandi, bulgular panellere dagitildi"));
    m_progressBar->setValue(100);
    if (auto *pulse = static_cast<ReconPulseWidget *>(m_pulseWidget)) {
        pulse->setActive(false);
    }
    appendFeed(tr("Ana tarama tamamlandi: %1, puan %2").arg(report.host).arg(securityScore));
    refreshSpiderEvidence();
    m_lastReportHtml = buildReportHtml(report, securityScore);
    m_lastReportJson = QString::fromUtf8(QJsonDocument::fromVariant(report.toVariantMap()).toJson(QJsonDocument::Indented));
    m_previewReportButton->setEnabled(true);
    if (m_exportJsonButton) {
        m_exportJsonButton->setEnabled(true);
    }
    if (m_exportCsvButton) {
        m_exportCsvButton->setEnabled(true);
    }
    if (m_saveSessionButton) {
        m_saveSessionButton->setEnabled(true);
    }

    for (const QVariant &recordValue : report.dnsRecords) {
        const QVariantMap record = recordValue.toMap();
        m_dnsList->insertItem(0, QString("%1  %2").arg(record.value("type").toString(), record.value("value").toString()));
    }

    for (const QVariant &findingValue : report.osintObservations) {
        const QVariantMap finding = findingValue.toMap();
        const QString source = finding.value("source").toString();
        const QString details = finding.value("details").toString().isEmpty()
                                    ? (finding.value("resultCount").isValid()
                                           ? tr("%1 kayit").arg(finding.value("resultCount").toInt())
                                           : tr("OSINT bulgusu"))
                                    : finding.value("details").toString();
        insertSeverityItem(m_osintList, tr("orta"), source, details);
    }

    for (const QVariant &portValue : report.openPorts) {
        const QVariantMap port = portValue.toMap();
        insertSeverityItem(m_surfaceList,
                           tr("dusuk"),
                           tr("Acik servis %1").arg(port.value("port").toString()),
                           port.value("service").toString());
    }

    if (m_subdomainList) {
        m_subdomainList->clear();
        for (const QVariant &value : report.subdomains) {
            const QString subdomain = value.toString().trimmed();
            if (!subdomain.isEmpty()) {
                m_subdomainList->addItem(subdomain);
            }
        }
        if (m_subdomainList->count() == 0) {
            m_subdomainList->addItem(tr("Dogrulanmis alt alan adi kaydi bulunmadi."));
        }
    }

    if (m_archiveList) {
        m_archiveList->clear();
        for (const QVariant &value : report.archivedUrls) {
            const QString archivedUrl = value.toString().trimmed();
            if (!archivedUrl.isEmpty()) {
                m_archiveList->addItem(archivedUrl);
            }
        }
        if (m_archiveList->count() == 0) {
            m_archiveList->addItem(tr("Wayback veya gizli endpoint kaydi bulunmadi."));
        }
    }

    if (m_jsFindingList) {
        m_jsFindingList->clear();
        for (const QVariant &value : report.jsFindings) {
            const QVariantMap finding = value.toMap();
            const QString type = finding.value("type").toString();
            const QString payload = finding.value("value").toString();
            const QString source = finding.value("source").toString();
            auto *item = new QListWidgetItem(QString("[%1] %2").arg(type, payload));
            if (!source.isEmpty()) {
                item->setToolTip(source);
            }
            m_jsFindingList->addItem(item);
        }
        if (m_jsFindingList->count() == 0) {
            m_jsFindingList->addItem(tr("JavaScript analizi bulgusu uretilmedi."));
        }
    }

    if (m_cveList) {
        m_cveList->clear();
        for (const QVariant &value : report.cveMatches) {
            const QVariantMap cve = value.toMap();
            const QString severity = cve.value("severity").toString().trimmed();
            auto *item = new QListWidgetItem(QString("[%1] %2 %3 -> %4")
                                                 .arg(severity.isEmpty() ? tr("bilgi") : severity.toUpper(),
                                                      cve.value("product").toString(),
                                                      cve.value("version").toString(),
                                                      cve.value("cve").toString()));
            item->setToolTip(cve.value("summary").toString());
            m_cveList->addItem(item);
        }
        if (m_cveList->count() == 0) {
            m_cveList->addItem(tr("Yerel CVE eslesmesi bulunmadi."));
        }
    }

    if (m_whoisSummaryView) {
        if (report.whoisInfo.isEmpty()) {
            m_whoisSummaryView->setHtml(tr("<p>Whois bilgisi toplanamadi.</p>"));
        } else {
            QString nameServersHtml;
            for (const QVariant &value : report.whoisInfo.value("nameServers").toList()) {
                nameServersHtml += QString("<li>%1</li>").arg(value.toString().toHtmlEscaped());
            }
            if (nameServersHtml.isEmpty()) {
                nameServersHtml = QStringLiteral("<li>-</li>");
            }

            m_whoisSummaryView->setHtml(QString(
                "<h3 style='margin-top:0;'>Whois Ozeti</h3>"
                "<p><b>Domain:</b> %1<br>"
                "<b>Registry:</b> %2<br>"
                "<b>Registrar:</b> %3<br>"
                "<b>Created:</b> %4<br>"
                "<b>Updated:</b> %5<br>"
                "<b>Expiry:</b> %6<br>"
                "<b>Status:</b> %7</p>"
                "<p><b>Name Server'lar</b></p><ul>%8</ul>"
                "<p><b>Ham Ozet</b><br>%9</p>")
                .arg(report.whoisInfo.value("domain").toString().toHtmlEscaped(),
                     report.whoisInfo.value("registry").toString().toHtmlEscaped(),
                     report.whoisInfo.value("registrar").toString().toHtmlEscaped(),
                     report.whoisInfo.value("created").toString().toHtmlEscaped(),
                     report.whoisInfo.value("updated").toString().toHtmlEscaped(),
                     report.whoisInfo.value("expiry").toString().toHtmlEscaped(),
                     report.whoisInfo.value("status").toString().toHtmlEscaped(),
                     nameServersHtml,
                     report.whoisInfo.value("raw").toString().left(1200).toHtmlEscaped()));
        }
    }

    m_lastReportVariant = report.toVariantMap();
    refreshSummaryCards(&report);
    refreshCategoryCards(&report);
    refreshFindingFilters();
    refreshEvidenceFilters();
    refreshRelationshipView(m_lastReportVariant);
    if (m_analysisTimelineList) {
        m_analysisTimelineList->clear();
        for (const QString &phase : std::as_const(m_phaseHistory)) {
            auto *item = new QListWidgetItem(tr("Faz: %1").arg(phase));
            item->setData(Qt::UserRole + 10, phase);
            m_analysisTimelineList->addItem(item);
        }
        const QStringList feedLines = m_feedConsole ? m_feedConsole->toPlainText().split('\n', Qt::SkipEmptyParts) : QStringList{};
        for (const QString &line : feedLines) {
            auto *item = new QListWidgetItem(line);
            item->setData(Qt::UserRole + 10, phaseLabelForMessage(line));
            m_analysisTimelineList->addItem(item);
        }
        refreshTimelineFilter();
    }
    if (m_diffSummaryValue) {
        m_diffSummaryValue->setText(m_compareBaselineVariant.isEmpty()
                                        ? tr("Karsilastirma icin once bir oturum yukle veya yeni bir baseline olustur.")
                                        : buildDiffSummary(m_lastReportVariant, m_compareBaselineVariant));
    }
}

void ReconWidget::refreshSummaryCards(const ScanReport *report)
{
    if (m_findingsCountValue) {
        m_findingsCountValue->setText(report ? QString::number(report->findings.size()) : QStringLiteral("0"));
    }
    if (m_portsCountValue) {
        m_portsCountValue->setText(report ? QString::number(report->openPorts.size()) : QStringLiteral("0"));
    }
    if (m_subdomainCountValue) {
        m_subdomainCountValue->setText(report ? QString::number(report->subdomains.size()) : QStringLiteral("0"));
    }
    if (m_archiveCountValue) {
        const int archiveCount = report ? (report->archivedUrls.size() + report->jsFindings.size()) : 0;
        m_archiveCountValue->setText(QString::number(archiveCount));
    }
}

void ReconWidget::refreshCategoryCards(const ScanReport *report)
{
    if (m_dnsCountValue) {
        m_dnsCountValue->setText(report ? QString::number(report->dnsRecords.size()) : QStringLiteral("0"));
    }
    if (m_surfaceCountValue) {
        const int surfaceCount = report ? (report->openPorts.size() + report->webObservations.size() + report->cveMatches.size()) : 0;
        m_surfaceCountValue->setText(QString::number(surfaceCount));
    }
    if (m_osintCountValue) {
        const int osintCount = report ? (report->osintObservations.size() + report->subdomains.size() + (report->whoisInfo.isEmpty() ? 0 : 1)) : 0;
        m_osintCountValue->setText(QString::number(osintCount));
    }
    if (m_spiderCountValue) {
        const int spiderCount = report ? (report->spiderEndpoints.size() + report->spiderParameters.size() + report->spiderAssets.size()) : 0;
        m_spiderCountValue->setText(QString::number(spiderCount));
    }
    if (m_phaseSummaryValue && m_phaseHistory.isEmpty()) {
        m_phaseSummaryValue->setText(tr("Hazir"));
    }
}

void ReconWidget::refreshFindingFilters()
{
    if (!m_findingsList) {
        return;
    }

    const QString severityFilter = m_findingsSeverityFilter ? m_findingsSeverityFilter->currentText().trimmed().toLower() : QString();
    const QString needle = m_findingsSearchEdit ? m_findingsSearchEdit->text().trimmed() : QString();

    for (int i = 0; i < m_findingsList->count(); ++i) {
        QListWidgetItem *item = m_findingsList->item(i);
        if (!item) {
            continue;
        }

        const QString itemSeverity = item->data(Qt::UserRole + 1).toString().trimmed().toLower();
        const QString title = item->data(Qt::UserRole + 2).toString();
        const QString description = item->data(Qt::UserRole + 3).toString();
        const bool severityMatches = severityFilter.isEmpty()
                                     || severityFilter == tr("tum seviyeler").toLower()
                                     || itemSeverity == severityFilter
                                     || (severityFilter == tr("yuksek").toLower() && itemSeverity == QStringLiteral("high"))
                                     || (severityFilter == tr("orta").toLower() && itemSeverity == QStringLiteral("medium"))
                                     || (severityFilter == tr("dusuk").toLower() && itemSeverity == QStringLiteral("low"));
        const bool textMatches = needle.isEmpty()
                                 || title.contains(needle, Qt::CaseInsensitive)
                                 || description.contains(needle, Qt::CaseInsensitive);
        item->setHidden(!(severityMatches && textMatches));
    }
}

QString ReconWidget::phaseLabelForMessage(const QString &message) const
{
    const QString lower = message.toLower();
    if (lower.contains("dns")) return tr("DNS");
    if (lower.contains("port")) return tr("Port");
    if (lower.contains("web") || lower.contains("tls") || lower.contains("cms")) return tr("Web/TLS");
    if (lower.contains("osint") || lower.contains("sizinti") || lower.contains("tehdit")) return tr("OSINT");
    if (lower.contains("wayback")) return tr("Wayback");
    if (lower.contains("whois")) return tr("Whois");
    if (lower.contains("alt alan")) return tr("Subdomain");
    if (lower.contains("fuzz")) return tr("Fuzz");
    if (lower.contains("javascript") || lower.contains("js")) return tr("JS");
    if (lower.contains("tamam")) return tr("Final");
    return {};
}

QString ReconWidget::buildDiffSummary(const QVariantMap &currentReport, const QVariantMap &baselineReport) const
{
    if (currentReport.isEmpty() || baselineReport.isEmpty()) {
        return tr("Karsilastirma verisi hazir degil.");
    }

    const QVariantList currentPorts = currentReport.value("openPorts").toList();
    const QVariantList baselinePorts = baselineReport.value("openPorts").toList();
    const QVariantList currentSubs = currentReport.value("subdomains").toList();
    const QVariantList baselineSubs = baselineReport.value("subdomains").toList();
    const QVariantList currentFindings = currentReport.value("findings").toList();
    const QVariantList baselineFindings = baselineReport.value("findings").toList();

    QSet<QString> currentPortSet;
    for (const QVariant &value : currentPorts) {
        const QVariantMap row = value.toMap();
        currentPortSet.insert(QString("%1/%2").arg(row.value("port").toString(), row.value("service").toString()));
    }
    QSet<QString> baselinePortSet;
    for (const QVariant &value : baselinePorts) {
        const QVariantMap row = value.toMap();
        baselinePortSet.insert(QString("%1/%2").arg(row.value("port").toString(), row.value("service").toString()));
    }
    QSet<QString> currentSubSet;
    for (const QVariant &value : currentSubs) currentSubSet.insert(value.toString());
    QSet<QString> baselineSubSet;
    for (const QVariant &value : baselineSubs) baselineSubSet.insert(value.toString());
    QSet<QString> currentFindingSet;
    for (const QVariant &value : currentFindings) {
        const QVariantMap row = value.toMap();
        currentFindingSet.insert(QString("%1|%2").arg(row.value("severity").toString(), row.value("title").toString()));
    }
    QSet<QString> baselineFindingSet;
    for (const QVariant &value : baselineFindings) {
        const QVariantMap row = value.toMap();
        baselineFindingSet.insert(QString("%1|%2").arg(row.value("severity").toString(), row.value("title").toString()));
    }

    const QStringList newPorts = QStringList((currentPortSet - baselinePortSet).values());
    const QStringList lostPorts = QStringList((baselinePortSet - currentPortSet).values());
    const QStringList newSubs = QStringList((currentSubSet - baselineSubSet).values());
    const QStringList newFindings = QStringList((currentFindingSet - baselineFindingSet).values());

    return tr("Baz hedef: %1\nYeni portlar: %2\nKaybolan portlar: %3\nYeni subdomainler: %4\nYeni bulgular: %5")
        .arg(baselineReport.value("sanitizedTarget").toString(),
             newPorts.isEmpty() ? tr("-") : newPorts.join(", "),
             lostPorts.isEmpty() ? tr("-") : lostPorts.join(", "),
             newSubs.isEmpty() ? tr("-") : newSubs.join(", "),
             newFindings.isEmpty() ? tr("-") : newFindings.join(" | "));
}

void ReconWidget::refreshRelationshipView(const QVariantMap &reportVariant)
{
    if (!m_relationshipView) {
        return;
    }

    if (reportVariant.isEmpty()) {
        m_relationshipView->setHtml(tr("<p>Iliski ozeti henuz olusmadi.</p>"));
        return;
    }

    const QString target = reportVariant.value("sanitizedTarget").toString();
    const QString ip = reportVariant.value("resolvedIp").toString();
    const QVariantList ports = reportVariant.value("openPorts").toList();
    const QVariantList subs = reportVariant.value("subdomains").toList();
    const QVariantList jsFindings = reportVariant.value("jsFindings").toList();
    const QVariantList cves = reportVariant.value("cveMatches").toList();

    QString portHtml;
    for (const QVariant &value : ports) {
        const QVariantMap row = value.toMap();
        portHtml += QString("<li>%1/%2</li>").arg(row.value("port").toString().toHtmlEscaped(),
                                                  row.value("service").toString().toHtmlEscaped());
    }
    if (portHtml.isEmpty()) portHtml = QStringLiteral("<li>-</li>");

    QString subHtml;
    for (const QVariant &value : subs) {
        subHtml += QString("<li>%1</li>").arg(value.toString().toHtmlEscaped());
    }
    if (subHtml.isEmpty()) subHtml = QStringLiteral("<li>-</li>");

    QString jsHtml;
    for (const QVariant &value : jsFindings) {
        const QVariantMap row = value.toMap();
        jsHtml += QString("<li>%1: %2</li>").arg(row.value("type").toString().toHtmlEscaped(),
                                                 row.value("value").toString().toHtmlEscaped());
    }
    if (jsHtml.isEmpty()) jsHtml = QStringLiteral("<li>-</li>");

    QString cveHtml;
    for (const QVariant &value : cves) {
        const QVariantMap row = value.toMap();
        cveHtml += QString("<li>%1 %2 -> %3</li>").arg(row.value("product").toString().toHtmlEscaped(),
                                                       row.value("version").toString().toHtmlEscaped(),
                                                       row.value("cve").toString().toHtmlEscaped());
    }
    if (cveHtml.isEmpty()) cveHtml = QStringLiteral("<li>-</li>");

    m_relationshipView->setHtml(QString(
        "<h3 style='margin-top:0;'>Iliski Ozeti</h3>"
        "<p><b>Hedef:</b> %1<br><b>Cozumlenen IP:</b> %2</p>"
        "<p><b>Acik Servisler</b></p><ul>%3</ul>"
        "<p><b>Alt Alan Adlari</b></p><ul>%4</ul>"
        "<p><b>JavaScript Izleri</b></p><ul>%5</ul>"
        "<p><b>CVE Eslesmeleri</b></p><ul>%6</ul>")
        .arg(target.toHtmlEscaped(), ip.toHtmlEscaped(), portHtml, subHtml, jsHtml, cveHtml));
}

void ReconWidget::applySessionVariant(const QVariantMap &reportVariant, int securityScore, const QStringList &phaseHistory, const QStringList &feedEntries)
{
    const ScanReport report = scanReportFromVariantMap(reportVariant);
    m_phaseHistory = phaseHistory;
    if (m_phaseSummaryValue) {
        m_phaseSummaryValue->setText(m_phaseHistory.isEmpty() ? tr("Hazir") : m_phaseHistory.join(QStringLiteral("  ->  ")));
    }
    if (m_feedConsole) {
        m_feedConsole->setPlainText(feedEntries.join('\n'));
    }
    handleFinished(report, securityScore);
}

void ReconWidget::refreshTimelineFilter()
{
    if (!m_analysisTimelineList || !m_timelineFilterCombo) {
        return;
    }

    const QString filter = m_timelineFilterCombo->currentText().trimmed().toLower();
    for (int i = 0; i < m_analysisTimelineList->count(); ++i) {
        QListWidgetItem *item = m_analysisTimelineList->item(i);
        if (!item) {
            continue;
        }
        const QString phase = item->data(Qt::UserRole + 10).toString().trimmed().toLower();
        const bool visible = filter.isEmpty()
                             || filter == tr("tum timeline").toLower()
                             || phase == filter
                             || item->text().contains(filter, Qt::CaseInsensitive);
        item->setHidden(!visible);
    }
}

void ReconWidget::refreshEvidenceFilters()
{
    const QString needle = m_evidenceSearchEdit ? m_evidenceSearchEdit->text().trimmed() : QString();
    const QList<QListWidget *> lists = {
        m_dnsList,
        m_surfaceList,
        m_osintList,
        m_subdomainList,
        m_archiveList,
        m_jsFindingList,
        m_cveList,
        m_spiderEndpointList,
        m_spiderParameterList,
        m_spiderAssetList,
        m_spiderHighValueList,
        m_spiderTimelineList
    };

    for (QListWidget *list : lists) {
        if (!list) {
            continue;
        }
        for (int i = 0; i < list->count(); ++i) {
            QListWidgetItem *item = list->item(i);
            if (!item) {
                continue;
            }
            const bool matches = needle.isEmpty()
                                 || item->text().contains(needle, Qt::CaseInsensitive)
                                 || item->toolTip().contains(needle, Qt::CaseInsensitive);
            item->setHidden(!matches);
        }
    }
}

void ReconWidget::buildUi()
{
    auto *root = pengufoce::ui::layout::createPageRoot(this, 18);

    auto *hero = pengufoce::ui::layout::createHeroCard(this);
    auto *heroLayout = qobject_cast<QVBoxLayout *>(hero->layout());

    auto *heroTopBar = new QHBoxLayout();
    heroTopBar->setSpacing(12);

    auto *title = new QLabel(tr("Kesif Orbiti"), hero);
    title->setObjectName("heroTitle");
    auto *subtitle = new QLabel(tr("Tek hedef girdisiyle DNS, web guvenligi, OSINT ve acik servis analizini ayri panellerde gosteren otomatik kesif modulu."), hero);
    subtitle->setObjectName("mutedText");
    subtitle->setWordWrap(true);
    m_previewReportButton = new QPushButton(tr("PDF Onizle"), hero);
    m_previewReportButton->setEnabled(false);
    heroTopBar->addWidget(title);
    heroTopBar->addStretch();
    heroTopBar->addWidget(m_previewReportButton, 0, Qt::AlignTop);

    auto *summaryHost = new QWidget(hero);
    auto *summary = new FlowLayout(summaryHost, 0, 12, 12);
    auto *statusCard = makeInfoBlock(hero, tr("Durum"), &m_statusValue);
    QLabel *targetValue = nullptr;
    auto *targetCard = makeInfoBlock(hero, tr("Hedef"), &targetValue);
    auto *scoreCard = makeInfoBlock(hero, tr("Guvenlik Puani"), &m_scoreValue);
    auto *findingsCountCard = makeInfoBlock(hero, tr("Bulgu"), &m_findingsCountValue);
    auto *portsCountCard = makeInfoBlock(hero, tr("Acik Port"), &m_portsCountValue);
    auto *subdomainCountCard = makeInfoBlock(hero, tr("Subdomain"), &m_subdomainCountValue);
    auto *artifactCountCard = makeInfoBlock(hero, tr("URL + JS"), &m_archiveCountValue);
    statusCard->setMinimumWidth(150);
    targetCard->setMinimumWidth(150);
    scoreCard->setMinimumWidth(150);
    findingsCountCard->setMinimumWidth(130);
    portsCountCard->setMinimumWidth(130);
    subdomainCountCard->setMinimumWidth(130);
    artifactCountCard->setMinimumWidth(130);
    targetValue->setText(tr("Canli"));
    m_scoreValue->setText("--");
    m_findingsCountValue->setText("0");
    m_portsCountValue->setText("0");
    m_subdomainCountValue->setText("0");
    m_archiveCountValue->setText("0");
    summary->addWidget(statusCard);
    summary->addWidget(targetCard);
    summary->addWidget(scoreCard);
    summary->addWidget(findingsCountCard);
    summary->addWidget(portsCountCard);
    summary->addWidget(subdomainCountCard);
    summary->addWidget(artifactCountCard);
    summaryHost->setLayout(summary);

    auto *categoryHost = new QWidget(hero);
    auto *categorySummary = new FlowLayout(categoryHost, 0, 12, 12);
    auto *dnsCountCard = makeInfoBlock(hero, tr("DNS Kaydi"), &m_dnsCountValue);
    auto *surfaceCountCard = makeInfoBlock(hero, tr("Yuzey"), &m_surfaceCountValue);
    auto *osintCountCard = makeInfoBlock(hero, tr("OSINT"), &m_osintCountValue);
    auto *spiderCountCard = makeInfoBlock(hero, tr("Spider"), &m_spiderCountValue);
    dnsCountCard->setMinimumWidth(130);
    surfaceCountCard->setMinimumWidth(130);
    osintCountCard->setMinimumWidth(130);
    spiderCountCard->setMinimumWidth(130);
    m_dnsCountValue->setText("0");
    m_surfaceCountValue->setText("0");
    m_osintCountValue->setText("0");
    m_spiderCountValue->setText("0");
    categorySummary->addWidget(dnsCountCard);
    categorySummary->addWidget(surfaceCountCard);
    categorySummary->addWidget(osintCountCard);
    categorySummary->addWidget(spiderCountCard);
    categoryHost->setLayout(categorySummary);

    heroLayout->addLayout(heroTopBar);
    heroLayout->addWidget(subtitle);
    heroLayout->addWidget(summaryHost);
    heroLayout->addWidget(categoryHost);

    auto *feedCard = new QFrame(this);
    feedCard->setObjectName("cardPanel");
    auto *feedLayout = new QVBoxLayout(feedCard);
    feedLayout->setContentsMargins(20, 20, 20, 20);
    feedLayout->setSpacing(12);
    auto *feedHeader = new QHBoxLayout();
    auto *feedTitle = new QLabel(tr("Canli Islem Konsolu"), feedCard);
    feedTitle->setObjectName("sectionTitle");
    auto *feedInfo = new QLabel(tr("Tarayicinin attigi her adim burada terminal akisi gibi gorunur. Her kayit zaman damgasi ve gecen sure ile yazilir."), feedCard);
    feedInfo->setObjectName("mutedText");
    feedInfo->setWordWrap(true);

    auto *pulse = new ReconPulseWidget(feedCard);
    pulse->setMinimumSize(120, 120);
    m_pulseWidget = pulse;

    m_feedConsole = new QPlainTextEdit(feedCard);
    m_feedConsole->setReadOnly(true);
    m_feedConsole->setMinimumHeight(180);
    m_feedConsole->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_feedConsole->setPlaceholderText(tr("[hazir] Tarama baslatildiginda canli adimlar burada gorunecek."));

    feedHeader->addWidget(feedTitle);
    feedHeader->addStretch();
    feedHeader->addWidget(pulse);
    feedLayout->addLayout(feedHeader);
    feedLayout->addWidget(feedInfo);
    feedLayout->addWidget(m_feedConsole);

    auto *opsCard = new QFrame(this);
    opsCard->setObjectName("cardPanel");
    auto *opsLayout = new QHBoxLayout(opsCard);
    opsLayout->setContentsMargins(20, 20, 20, 20);
    opsLayout->setSpacing(18);

    auto *opsTextLayout = new QVBoxLayout();
    opsTextLayout->setSpacing(10);
    auto *opsTitle = new QLabel(tr("Canli Tarama Durumu"), opsCard);
    opsTitle->setObjectName("sectionTitle");
    m_activityValue = new QLabel(tr("Hazir. Baslattiginda DNS, web guvenligi, port ve OSINT adimlari burada canli gorunur."), opsCard);
    m_activityValue->setObjectName("mutedText");
    m_activityValue->setWordWrap(true);
    m_progressBar = new QProgressBar(opsCard);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setTextVisible(false);
    m_phaseSummaryValue = new QLabel(tr("Hazir"), opsCard);
    m_phaseSummaryValue->setObjectName("mutedText");
    m_phaseSummaryValue->setWordWrap(true);
    opsTextLayout->addWidget(opsTitle);
    opsTextLayout->addWidget(m_activityValue);
    opsTextLayout->addWidget(m_progressBar);
    opsTextLayout->addWidget(m_phaseSummaryValue);
    opsTextLayout->addStretch();
    opsLayout->addLayout(opsTextLayout, 1);

    auto *setupCard = new QFrame(this);
    setupCard->setObjectName("cardPanel");
    auto *setupOuterLayout = new QHBoxLayout(setupCard);
    setupOuterLayout->setContentsMargins(20, 20, 20, 20);
    setupOuterLayout->setSpacing(0);
    auto *setupFormHost = new QWidget(setupCard);
    setupFormHost->setMinimumWidth(760);
    setupFormHost->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    auto *setupLayout = new QGridLayout(setupFormHost);
    setupLayout->setContentsMargins(0, 0, 0, 0);
    setupLayout->setHorizontalSpacing(18);
    setupLayout->setVerticalSpacing(12);
    setupLayout->setColumnMinimumWidth(0, 120);
    setupLayout->setColumnMinimumWidth(1, 190);
    setupLayout->setColumnMinimumWidth(2, 120);
    setupLayout->setColumnMinimumWidth(3, 190);
    setupLayout->setColumnStretch(0, 1);
    setupLayout->setColumnStretch(1, 3);
    setupLayout->setColumnStretch(2, 1);
    setupLayout->setColumnStretch(3, 3);

    m_targetEdit = new QLineEdit(setupCard);
    m_endpointEdit = new QLineEdit(setupCard);
    m_targetPresetCombo = new QComboBox(setupCard);
    m_recentTargetCombo = new QComboBox(setupCard);
    m_scanProfileCombo = new QComboBox(setupCard);
    m_recentSessionCombo = new QComboBox(setupCard);
    m_companyEdit = new QLineEdit(setupCard);
    m_clientEdit = new QLineEdit(setupCard);
    m_testerEdit = new QLineEdit(setupCard);
    m_classificationEdit = new QLineEdit(setupCard);
    m_scopeEdit = new QLineEdit(setupCard);
    m_endpointEdit->setPlaceholderText("https://ornek-osint-ucnokta/api/search");
    const QList<QLineEdit *> edits = {m_targetEdit, m_endpointEdit, m_companyEdit, m_clientEdit, m_testerEdit, m_classificationEdit, m_scopeEdit};
    for (QLineEdit *edit : edits) {
        edit->setMinimumWidth(180);
        edit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }
    m_targetPresetCombo->addItem(tr("Hazir hedefler"));
    m_targetPresetCombo->addItem(QStringLiteral("scanme.nmap.org"));
    m_targetPresetCombo->addItem(QStringLiteral("example.com"));
    m_targetPresetCombo->addItem(QStringLiteral("testphp.vulnweb.com"));
    m_targetPresetCombo->addItem(QStringLiteral("demo.testfire.net"));
    m_targetPresetCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_recentTargetCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_scanProfileCombo->addItems({tr("Tam Kesif"), tr("Alan Adi Istihbarati"), tr("Web Yuzeyi"), tr("Hizli Bakis")});
    m_scanProfileCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_recentSessionCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    setupLayout->addWidget(createInfoLabel(tr("Hedef"), tr("Alan adi, IP veya tam URL girebilirsin. Sistem uygun formata cevirip tek tusla tarar.")), 0, 0);
    setupLayout->addWidget(m_targetEdit, 0, 1);
    setupLayout->addWidget(createInfoLabel(tr("OSINT API"), tr("Istege bagli tehdit istihbarati veya sizinti servisi ucnoktasi. Bos birakirsan sadece yerel kontroller calisir.")), 0, 2);
    setupLayout->addWidget(m_endpointEdit, 0, 3);
    setupLayout->addWidget(createInfoLabel(tr("Hazirlayan Kurum"), tr("PDF kapak ve yonetici ozeti icin kullanilir.")), 1, 0);
    setupLayout->addWidget(m_companyEdit, 1, 1);
    setupLayout->addWidget(createInfoLabel(tr("Musteri"), tr("Raporun teslim edilecegi kurum veya birim adi.")), 1, 2);
    setupLayout->addWidget(m_clientEdit, 1, 3);
    setupLayout->addWidget(createInfoLabel(tr("Test Uzmani"), tr("Raporu hazirlayan uzman veya ekip.")), 2, 0);
    setupLayout->addWidget(m_testerEdit, 2, 1);
    setupLayout->addWidget(createInfoLabel(tr("Siniflandirma"), tr("Ornek: Kurum Ici, Gizli, Kisitli Dagitim.")), 2, 2);
    setupLayout->addWidget(m_classificationEdit, 2, 3);
    setupLayout->addWidget(createInfoLabel(tr("Kapsam Ozeti"), tr("PDF raporunda metodoloji ve kapsam basligi altinda gosterilir.")), 3, 0);
    setupLayout->addWidget(m_scopeEdit, 3, 1, 1, 3);
    setupLayout->addWidget(createInfoLabel(tr("Hazir Hedef"), tr("Demo veya test ortamlari icin hizli hedef secimi.")), 4, 0);
    setupLayout->addWidget(m_targetPresetCombo, 4, 1);
    setupLayout->addWidget(createInfoLabel(tr("Tarama Profili"), tr("Hazir profil secimi kapsam ozetini hizla doldurur.")), 4, 2);
    setupLayout->addWidget(m_scanProfileCombo, 4, 3);
    setupLayout->addWidget(createInfoLabel(tr("Son Hedefler"), tr("En son kullandigin hedefleri tek tikla geri cagirir.")), 5, 0);
    setupLayout->addWidget(m_recentTargetCombo, 5, 1, 1, 3);

    auto *buttonsHost = new QWidget(setupCard);
    auto *buttons = new FlowLayout(buttonsHost, 0, 10, 10);
    m_startButton = new QPushButton(tr("Kesifi Baslat"), setupCard);
    m_startButton->setObjectName("accentButton");
    m_stopButton = new QPushButton(tr("Durdur"), setupCard);
    buttons->addWidget(m_startButton);
    buttons->addWidget(m_stopButton);
    buttonsHost->setLayout(buttons);
    setupLayout->addWidget(buttonsHost, 6, 0, 1, 4);
    setupOuterLayout->addStretch();
    setupOuterLayout->addWidget(setupFormHost);
    setupOuterLayout->addStretch();

    auto makeListCard = [this](const QString &titleText, QListWidget **listWidget) {
        auto *card = new QFrame(this);
        card->setObjectName("cardPanel");
        auto *layout = new QVBoxLayout(card);
        layout->setContentsMargins(20, 20, 20, 20);
        layout->setSpacing(12);
        auto *titleLabel = new QLabel(titleText, card);
        titleLabel->setObjectName("sectionTitle");
        *listWidget = new QListWidget(card);
        (*listWidget)->setAlternatingRowColors(true);
        layout->addWidget(titleLabel);
        layout->addWidget(*listWidget);
        return card;
    };

    auto *findingsCard = new QFrame(this);
    findingsCard->setObjectName("cardPanel");
    auto *findingsLayout = new QHBoxLayout(findingsCard);
    findingsLayout->setContentsMargins(20, 20, 20, 20);
    findingsLayout->setSpacing(16);

    auto *findingsColumn = new QVBoxLayout();
    findingsColumn->setSpacing(12);
    auto *findingsTitle = new QLabel(tr("Oncelikli Bulgular"), findingsCard);
    findingsTitle->setObjectName("sectionTitle");
    auto *findingsInfo = new QLabel(tr("Tum aciklar tek listede yuksek riskten dusuge siralanir. Bir bulguya tikladiginda neden var oldugunu, etkisini ve onerilen aksiyonu sag panelde gorursun."), findingsCard);
    findingsInfo->setObjectName("mutedText");
    findingsInfo->setWordWrap(true);
    auto *findingsFilterHost = new QWidget(findingsCard);
    auto *findingsFilterLayout = new FlowLayout(findingsFilterHost, 0, 10, 10);
    m_findingsSeverityFilter = new QComboBox(findingsCard);
    m_findingsSeverityFilter->addItems({tr("Tum seviyeler"), tr("Yuksek"), tr("Orta"), tr("Dusuk"), tr("Bilgi")});
    m_findingsSearchEdit = new QLineEdit(findingsCard);
    m_findingsSearchEdit->setPlaceholderText(tr("Bulgu ara"));
    m_addManualFindingButton = new QPushButton(tr("Manuel Bulgu Ekle"), findingsCard);
    findingsFilterLayout->addWidget(m_findingsSeverityFilter);
    findingsFilterLayout->addWidget(m_findingsSearchEdit);
    findingsFilterLayout->addWidget(m_addManualFindingButton);
    findingsFilterHost->setLayout(findingsFilterLayout);
    m_findingsList = new QListWidget(findingsCard);
    m_findingsList->setMinimumWidth(300);
    m_findingsList->setMinimumHeight(240);
    findingsColumn->addWidget(findingsTitle);
    findingsColumn->addWidget(findingsInfo);
    findingsColumn->addWidget(findingsFilterHost);
    findingsColumn->addWidget(m_findingsList, 1);

    auto *detailColumn = new QVBoxLayout();
    detailColumn->setSpacing(12);
    auto *detailTitle = new QLabel(tr("Bulgu Detayi"), findingsCard);
    detailTitle->setObjectName("sectionTitle");
    m_copyDetailButton = new QPushButton(tr("Detayi Kopyala"), findingsCard);
    auto *detailHeader = new QHBoxLayout();
    detailHeader->addWidget(detailTitle);
    detailHeader->addStretch();
    detailHeader->addWidget(m_copyDetailButton);
    m_findingDetailView = new QTextEdit(findingsCard);
    m_findingDetailView->setReadOnly(true);
    m_findingDetailView->setMinimumHeight(240);
    m_findingDetailView->setHtml(tr("<h3>Bir bulgu sec</h3><p>Listeden bir risk secildiginde burada neden var oldugu, neye yol acabilecegi ve nasil kapatilacagi gorunur.</p>"));
    auto *noteTitle = new QLabel(tr("Bulguya Bagli Analist Notu"), findingsCard);
    noteTitle->setObjectName("sectionTitle");
    m_findingNoteEdit = new QTextEdit(findingsCard);
    m_findingNoteEdit->setPlaceholderText(tr("Secili bulgu icin manuel not, dogrulama veya aksiyon yaz."));
    m_findingNoteEdit->setMaximumHeight(120);
    m_saveFindingNoteButton = new QPushButton(tr("Bulgu Notunu Kaydet"), findingsCard);
    detailColumn->addLayout(detailHeader);
    detailColumn->addWidget(m_findingDetailView, 1);
    detailColumn->addWidget(noteTitle);
    detailColumn->addWidget(m_findingNoteEdit);
    detailColumn->addWidget(m_saveFindingNoteButton, 0, Qt::AlignRight);

    findingsLayout->addLayout(findingsColumn, 3);
    findingsLayout->addLayout(detailColumn, 4);

    auto *evidenceCard = pengufoce::ui::layout::createCard(this, QStringLiteral("cardPanel"), QMargins(20, 20, 20, 20), 12);
    auto *evidenceLayout = qobject_cast<QVBoxLayout *>(evidenceCard->layout());
    auto *evidenceTitle = new QLabel(tr("Teknik Kanitlar"), evidenceCard);
    evidenceTitle->setObjectName("sectionTitle");
    auto *evidenceInfo = new QLabel(tr("Kucuk kucuk ayri paneller yerine kanitlar burada sekmeli yapida toplanir."), evidenceCard);
    evidenceInfo->setObjectName("mutedText");
    evidenceInfo->setWordWrap(true);
    auto *evidenceFilterHost = new QWidget(evidenceCard);
    auto *evidenceFilterLayout = new FlowLayout(evidenceFilterHost, 0, 10, 10);
    m_evidenceSearchEdit = new QLineEdit(evidenceCard);
    m_evidenceSearchEdit->setPlaceholderText(tr("Tum kanitlarda ara"));
    evidenceFilterLayout->addWidget(m_evidenceSearchEdit);
    evidenceFilterHost->setLayout(evidenceFilterLayout);
    auto *evidenceTabs = new QTabWidget(evidenceCard);
    evidenceTabs->setDocumentMode(true);
    evidenceTabs->setUsesScrollButtons(true);
    auto *dnsCard = makeListCard(tr("DNS Kayitlari"), &m_dnsList);
    auto *surfaceCard = makeListCard(tr("Web, TLS ve Acik Servisler"), &m_surfaceList);
    auto *osintCard = makeListCard(tr("OSINT ve Sizinti Kayitlari"), &m_osintList);
    auto *subdomainCard = makeListCard(tr("Alt Alan Adlari"), &m_subdomainList);
    auto *archiveCard = makeListCard(tr("Wayback ve Gizli URL Kayitlari"), &m_archiveList);
    auto *jsCard = makeListCard(tr("JavaScript ve Secret Izleri"), &m_jsFindingList);
    auto *cveCard = makeListCard(tr("CVE ve Surum Eslestirmeleri"), &m_cveList);
    auto *spiderEndpointCard = makeListCard(tr("Spider Endpoint ve Yuzey Buluntulari"), &m_spiderEndpointList);
    auto *spiderParameterCard = makeListCard(tr("Spider Parametre ve Form Girdileri"), &m_spiderParameterList);
    auto *spiderAssetCard = makeListCard(tr("Spider Asset ve Literal Bulgulari"), &m_spiderAssetList);
    auto *spiderHighValueCard = makeListCard(tr("Spider Kritik Yuzey"), &m_spiderHighValueList);
    auto *spiderTimelineCard = makeListCard(tr("Spider Coverage Timeline"), &m_spiderTimelineList);
    auto *whoisCard = new QFrame(evidenceTabs);
    whoisCard->setObjectName("cardPanel");
    auto *whoisLayout = new QVBoxLayout(whoisCard);
    whoisLayout->setContentsMargins(20, 20, 20, 20);
    whoisLayout->setSpacing(12);
    auto *whoisTitle = new QLabel(tr("Whois ve Kayit Otoritesi Ozeti"), whoisCard);
    whoisTitle->setObjectName("sectionTitle");
    m_whoisSummaryView = new QTextEdit(whoisCard);
    m_whoisSummaryView->setReadOnly(true);
    m_whoisSummaryView->setHtml(tr("<p>Whois bilgisi bekleniyor.</p>"));
    whoisLayout->addWidget(whoisTitle);
    whoisLayout->addWidget(m_whoisSummaryView, 1);
    auto *relationshipCard = new QFrame(evidenceTabs);
    relationshipCard->setObjectName("cardPanel");
    auto *relationshipLayout = new QVBoxLayout(relationshipCard);
    relationshipLayout->setContentsMargins(20, 20, 20, 20);
    relationshipLayout->setSpacing(12);
    auto *relationshipTitle = new QLabel(tr("Varlik Iliskileri"), relationshipCard);
    relationshipTitle->setObjectName("sectionTitle");
    m_relationshipView = new QTextEdit(relationshipCard);
    m_relationshipView->setReadOnly(true);
    m_relationshipView->setHtml(tr("<p>Iliski ozeti henuz olusmadi.</p>"));
    relationshipLayout->addWidget(relationshipTitle);
    relationshipLayout->addWidget(m_relationshipView, 1);
    auto *analysisTimelineCard = new QFrame(evidenceTabs);
    analysisTimelineCard->setObjectName("cardPanel");
    auto *analysisTimelineLayout = new QVBoxLayout(analysisTimelineCard);
    analysisTimelineLayout->setContentsMargins(20, 20, 20, 20);
    analysisTimelineLayout->setSpacing(12);
    auto *analysisTimelineTitle = new QLabel(tr("Analiz Timeline"), analysisTimelineCard);
    analysisTimelineTitle->setObjectName("sectionTitle");
    m_timelineFilterCombo = new QComboBox(analysisTimelineCard);
    m_timelineFilterCombo->addItems({tr("Tum Timeline"), tr("DNS"), tr("Port"), tr("Web/TLS"), tr("OSINT"), tr("Wayback"), tr("Whois"), tr("Subdomain"), tr("Fuzz"), tr("JS"), tr("Final")});
    m_analysisTimelineList = new QListWidget(analysisTimelineCard);
    analysisTimelineLayout->addWidget(analysisTimelineTitle);
    analysisTimelineLayout->addWidget(m_timelineFilterCombo);
    analysisTimelineLayout->addWidget(m_analysisTimelineList, 1);
    auto *spiderHighValueLayout = qobject_cast<QVBoxLayout *>(spiderHighValueCard->layout());
    m_spiderCoverageLabel = new QLabel(tr("Spider coverage bilgisi bekleniyor."), spiderHighValueCard);
    m_spiderCoverageLabel->setObjectName("mutedText");
    m_spiderCoverageLabel->setWordWrap(true);
    spiderHighValueLayout->insertWidget(2, m_spiderCoverageLabel);
    evidenceTabs->addTab(dnsCard, tr("DNS"));
    evidenceTabs->addTab(surfaceCard, tr("Yuzey"));
    evidenceTabs->addTab(osintCard, tr("OSINT"));
    evidenceTabs->addTab(subdomainCard, tr("Subdomain"));
    evidenceTabs->addTab(archiveCard, tr("Wayback"));
    evidenceTabs->addTab(jsCard, tr("JS"));
    evidenceTabs->addTab(cveCard, tr("CVE"));
    evidenceTabs->addTab(whoisCard, tr("Whois"));
    evidenceTabs->addTab(relationshipCard, tr("Iliski"));
    evidenceTabs->addTab(analysisTimelineCard, tr("Timeline"));
    evidenceTabs->addTab(spiderEndpointCard, tr("Spider Yuzey"));
    evidenceTabs->addTab(spiderParameterCard, tr("Spider Girdi"));
    evidenceTabs->addTab(spiderAssetCard, tr("Spider Asset"));
    evidenceTabs->addTab(spiderHighValueCard, tr("Spider Kritik"));
    evidenceTabs->addTab(spiderTimelineCard, tr("Spider Timeline"));
    evidenceLayout->addWidget(evidenceTitle);
    evidenceLayout->addWidget(evidenceInfo);
    evidenceLayout->addWidget(evidenceFilterHost);
    evidenceLayout->addWidget(evidenceTabs);

    auto *reportCard = pengufoce::ui::layout::createCard(this, QStringLiteral("cardPanel"), QMargins(20, 20, 20, 20), 12);
    auto *reportLayout = qobject_cast<QVBoxLayout *>(reportCard->layout());
    auto *reportTitle = new QLabel(tr("Resmi Pentest Raporu"), reportCard);
    reportTitle->setObjectName("sectionTitle");
    auto *reportInfo = new QLabel(tr("PDF onizleme hizli erisim icin ust sagdadir. Buradaki alanlar rapor kapagi ve yonetici ozeti icin kullanilir."), reportCard);
    reportInfo->setObjectName("mutedText");
    reportInfo->setWordWrap(true);
    auto *reportActionsHost = new QWidget(reportCard);
    auto *reportActions = new FlowLayout(reportActionsHost, 0, 10, 10);
    m_exportJsonButton = new QPushButton(tr("JSON Disa Aktar"), reportCard);
    m_exportCsvButton = new QPushButton(tr("CSV Disa Aktar"), reportCard);
    m_saveSessionButton = new QPushButton(tr("Oturumu Kaydet"), reportCard);
    m_openSessionButton = new QPushButton(tr("Oturum Ac"), reportCard);
    m_exportJsonButton->setEnabled(false);
    m_exportCsvButton->setEnabled(false);
    m_saveSessionButton->setEnabled(false);
    auto *sessionArchiveHost = new QWidget(reportCard);
    auto *sessionArchiveLayout = new FlowLayout(sessionArchiveHost, 0, 10, 10);
    m_recentSessionCombo = m_recentSessionCombo ? m_recentSessionCombo : new QComboBox(reportCard);
    sessionArchiveLayout->addWidget(m_recentSessionCombo);
    sessionArchiveHost->setLayout(sessionArchiveLayout);
    reportActions->addWidget(m_exportJsonButton);
    reportActions->addWidget(m_exportCsvButton);
    reportActions->addWidget(m_saveSessionButton);
    reportActions->addWidget(m_openSessionButton);
    reportActionsHost->setLayout(reportActions);
    auto *diffCard = new QFrame(reportCard);
    diffCard->setObjectName("cardPanel");
    auto *diffLayout = new QVBoxLayout(diffCard);
    diffLayout->setContentsMargins(16, 16, 16, 16);
    diffLayout->setSpacing(8);
    auto *diffTitle = new QLabel(tr("Oturum Karsilastirma"), diffCard);
    diffTitle->setObjectName("sectionTitle");
    m_diffSummaryValue = new QLabel(tr("Karsilastirma icin once bir oturum yukle veya yeni bir baseline olustur."), diffCard);
    m_diffSummaryValue->setObjectName("mutedText");
    m_diffSummaryValue->setWordWrap(true);
    diffLayout->addWidget(diffTitle);
    diffLayout->addWidget(m_diffSummaryValue);
    auto *notesCard = new QFrame(reportCard);
    notesCard->setObjectName("cardPanel");
    auto *notesLayout = new QVBoxLayout(notesCard);
    notesLayout->setContentsMargins(16, 16, 16, 16);
    notesLayout->setSpacing(8);
    auto *notesTitle = new QLabel(tr("Analist Notlari"), notesCard);
    notesTitle->setObjectName("sectionTitle");
    m_analystNotesEdit = new QTextEdit(notesCard);
    m_analystNotesEdit->setPlaceholderText(tr("Buraya manuel gozlem, dogrulama notu veya sonraki aksiyonlarini yazabilirsin."));
    notesLayout->addWidget(notesTitle);
    notesLayout->addWidget(m_analystNotesEdit, 1);
    reportLayout->addWidget(reportTitle);
    reportLayout->addWidget(reportInfo);
    reportLayout->addWidget(reportActionsHost);
    reportLayout->addWidget(sessionArchiveHost);
    reportLayout->addWidget(diffCard);
    reportLayout->addWidget(notesCard);

    root->addWidget(hero);
    root->addWidget(setupCard);
    root->addWidget(feedCard);
    root->addWidget(opsCard);
    root->addWidget(findingsCard);
    root->addWidget(evidenceCard);
    root->addWidget(reportCard);

    connect(m_startButton, &QPushButton::clicked, this, &ReconWidget::startRecon);
    connect(m_stopButton, &QPushButton::clicked, this, &ReconWidget::stopRecon);
    connect(m_targetPresetCombo, &QComboBox::currentTextChanged, this, [this](const QString &text) {
        if (text == tr("Hazir hedefler") || text.trimmed().isEmpty()) {
            return;
        }
        m_targetEdit->setText(text);
    });
    connect(m_scanProfileCombo, &QComboBox::currentTextChanged, this, [this](const QString &text) {
        if (text == tr("Alan Adi Istihbarati")) {
            m_scopeEdit->setText(tr("DNS, subdomain, Wayback, Whois ve OSINT odakli alan adi istihbarati"));
        } else if (text == tr("Web Yuzeyi")) {
            m_scopeEdit->setText(tr("Web guvenligi, TLS, acik servis, fuzzing ve JavaScript yuzey analizi"));
        } else if (text == tr("Hizli Bakis")) {
            m_scopeEdit->setText(tr("Hizli DNS, web ve port gorunurlugu kontrolu"));
        } else {
            m_scopeEdit->setText(tr("DNS, web guvenligi, TLS, OSINT ve acik servis degerlendirmesi"));
        }
    });
    connect(m_recentTargetCombo, &QComboBox::currentTextChanged, this, [this](const QString &text) {
        if (text == tr("Son hedefler") || text.trimmed().isEmpty()) {
            return;
        }
        m_targetEdit->setText(text);
    });
    connect(m_recentSessionCombo, &QComboBox::currentTextChanged, this, [this](const QString &) {
        const QString path = m_recentSessionCombo ? m_recentSessionCombo->currentData().toString() : QString();
        if (path.isEmpty()) {
            return;
        }
        openSession();
    });
    connect(m_previewReportButton, &QPushButton::clicked, this, &ReconWidget::exportReport);
    connect(m_exportJsonButton, &QPushButton::clicked, this, [this]() {
        if (m_lastReportJson.isEmpty()) {
            appendFeed(tr("JSON disa aktarmak icin once bir kesif taramasi tamamlanmali."));
            return;
        }

        const QString companyName = m_companyEdit ? m_companyEdit->text() : QString();
        const QString targetName = m_targetEdit ? m_targetEdit->text() : QString();
        const QString jsonDefaultName = corporateReportFileName(companyName, targetName, "json");
        const QString path = QFileDialog::getSaveFileName(this,
                                                          tr("JSON Kaydet"),
                                                          jsonDefaultName,
                                                          tr("JSON (*.json)"));
        if (path.isEmpty()) {
            return;
        }

        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            appendFeed(tr("JSON rapor dosyasi acilamadi: %1").arg(path));
            return;
        }

        QTextStream stream(&file);
        stream << m_lastReportJson;
        appendFeed(tr("JSON raporu kaydedildi: %1").arg(path));
    });
    connect(m_exportCsvButton, &QPushButton::clicked, this, &ReconWidget::exportCsvReport);
    connect(m_saveSessionButton, &QPushButton::clicked, this, &ReconWidget::saveSession);
    connect(m_openSessionButton, &QPushButton::clicked, this, &ReconWidget::openSession);
    connect(m_timelineFilterCombo, &QComboBox::currentTextChanged, this, [this]() { refreshTimelineFilter(); });
    connect(m_copyDetailButton, &QPushButton::clicked, this, [this]() {
        if (!m_findingDetailView) {
            return;
        }
        QApplication::clipboard()->setText(m_findingDetailView->toPlainText());
        appendFeed(tr("Bulgu detayi panodan kopyalandi."));
    });
    connect(m_addManualFindingButton, &QPushButton::clicked, this, [this]() {
        const QStringList severities = {tr("Yuksek"), tr("Orta"), tr("Dusuk"), tr("Bilgi")};
        bool ok = false;
        const QString severity = QInputDialog::getItem(this, tr("Manuel Bulgu"), tr("Seviye"), severities, 1, false, &ok);
        if (!ok || severity.isEmpty()) {
            return;
        }
        const QString title = QInputDialog::getText(this, tr("Manuel Bulgu"), tr("Baslik"), QLineEdit::Normal, QString(), &ok);
        if (!ok || title.trimmed().isEmpty()) {
            return;
        }
        const QString description = QInputDialog::getMultiLineText(this, tr("Manuel Bulgu"), tr("Aciklama"), QString(), &ok);
        if (!ok || description.trimmed().isEmpty()) {
            return;
        }
        insertSeverityItem(m_findingsList, severity, title.trimmed(), description.trimmed(), QStringLiteral("manual"));
        QVariantList findings = m_lastReportVariant.value("findings").toList();
        findings.prepend(QVariantMap{{"severity", severity.toLower()}, {"title", title.trimmed()}, {"description", description.trimmed()}, {"category", QStringLiteral("manual")}});
        m_lastReportVariant.insert("findings", findings);
        const ScanReport updatedReport = scanReportFromVariantMap(m_lastReportVariant);
        refreshSummaryCards(&updatedReport);
        refreshFindingFilters();
        appendFeed(tr("Manuel bulgu eklendi: %1").arg(title.trimmed()));
    });
    connect(m_saveFindingNoteButton, &QPushButton::clicked, this, [this]() {
        QListWidgetItem *item = m_findingsList ? m_findingsList->currentItem() : nullptr;
        if (!item || !m_findingNoteEdit) {
            return;
        }
        const QString key = item->data(Qt::UserRole + 2).toString();
        m_findingNotes.insert(key, m_findingNoteEdit->toPlainText());
        updateFindingDetail();
        appendFeed(tr("Bulgu notu kaydedildi: %1").arg(key));
    });
    connect(m_findingsSeverityFilter, &QComboBox::currentTextChanged, this, [this]() { refreshFindingFilters(); });
    connect(m_findingsSearchEdit, &QLineEdit::textChanged, this, [this]() { refreshFindingFilters(); });
    connect(m_evidenceSearchEdit, &QLineEdit::textChanged, this, [this]() { refreshEvidenceFilters(); });
    connect(m_findingsList, &QListWidget::currentRowChanged, this, &ReconWidget::updateFindingDetail);

    const QList<QListWidget *> evidenceLists = {
        m_dnsList, m_surfaceList, m_osintList, m_subdomainList, m_archiveList, m_jsFindingList, m_cveList,
        m_spiderEndpointList, m_spiderParameterList, m_spiderAssetList, m_spiderHighValueList, m_spiderTimelineList
    };
    for (QListWidget *list : evidenceLists) {
        if (!list) {
            continue;
        }
        list->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(list, &QListWidget::customContextMenuRequested, this, [this, list](const QPoint &pos) {
            QListWidgetItem *item = list->itemAt(pos);
            if (!item) {
                return;
            }
            QMenu menu(this);
            QAction *copyText = menu.addAction(tr("Kaydi Kopyala"));
            QAction *copyTooltip = nullptr;
            if (!item->toolTip().isEmpty()) {
                copyTooltip = menu.addAction(tr("Kaynak / Tooltip Kopyala"));
            }
            QAction *logAction = menu.addAction(tr("Konsola Gonder"));
            QAction *selected = menu.exec(list->viewport()->mapToGlobal(pos));
            if (selected == copyText) {
                QApplication::clipboard()->setText(item->text());
            } else if (copyTooltip && selected == copyTooltip) {
                QApplication::clipboard()->setText(item->toolTip());
            } else if (selected == logAction) {
                appendFeed(tr("Kanit notu: %1").arg(item->text()));
            }
        });
    }

    m_findingsList->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_findingsList, &QListWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        QListWidgetItem *item = m_findingsList->itemAt(pos);
        if (!item) {
            return;
        }
        const QString severity = item->data(Qt::UserRole + 1).toString();
        const QString titleText = item->data(Qt::UserRole + 2).toString();
        const QString description = item->data(Qt::UserRole + 3).toString();
        QMenu menu(this);
        QAction *copyTitle = menu.addAction(tr("Basligi Kopyala"));
        QAction *copyDetail = menu.addAction(tr("Detayi Kopyala"));
        QAction *logAction = menu.addAction(tr("Konsola Gonder"));
        QAction *selected = menu.exec(m_findingsList->viewport()->mapToGlobal(pos));
        if (selected == copyTitle) {
            QApplication::clipboard()->setText(titleText);
        } else if (selected == copyDetail) {
            QApplication::clipboard()->setText(QString("[%1] %2\n%3").arg(severity, titleText, description));
        } else if (selected == logAction) {
            appendFeed(tr("Bulgu notu: [%1] %2 - %3").arg(severity, titleText, description));
        }
    });
}

void ReconWidget::exportCsvReport()
{
    if (m_lastReportJson.isEmpty()) {
        appendFeed(tr("CSV disa aktarmak icin once bir kesif taramasi tamamlanmali."));
        return;
    }

    const QString companyName = m_companyEdit ? m_companyEdit->text() : QString();
    const QString targetName = m_targetEdit ? m_targetEdit->text() : QString();
    const QString csvDefaultName = corporateReportFileName(companyName, targetName, "csv");
    const QString path = QFileDialog::getSaveFileName(this,
                                                      tr("CSV Kaydet"),
                                                      csvDefaultName,
                                                      tr("CSV (*.csv)"));
    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        appendFeed(tr("CSV rapor dosyasi acilamadi: %1").arg(path));
        return;
    }

    QTextStream stream(&file);
    stream << "section,severity,title,description,extra\n";
    for (int i = 0; i < m_findingsList->count(); ++i) {
        QListWidgetItem *item = m_findingsList->item(i);
        if (!item) {
            continue;
        }
        const QString severity = item->data(Qt::UserRole + 1).toString();
        const QString title = item->data(Qt::UserRole + 2).toString().replace('"', "'");
        const QString description = item->data(Qt::UserRole + 3).toString().replace('"', "'");
        stream << QString("finding,\"%1\",\"%2\",\"%3\",\"\"\n").arg(severity, title, description);
    }

    auto writeList = [&stream](const QString &section, QListWidget *list) {
        if (!list) {
            return;
        }
        for (int i = 0; i < list->count(); ++i) {
            QListWidgetItem *item = list->item(i);
            if (!item || item->isHidden()) {
                continue;
            }
            const QString text = item->text().replace('"', "'");
            const QString tooltip = item->toolTip().replace('"', "'");
            stream << QString("%1,\"\",\"%2\",\"\",\"%3\"\n").arg(section, text, tooltip);
        }
    };

    writeList(QStringLiteral("dns"), m_dnsList);
    writeList(QStringLiteral("surface"), m_surfaceList);
    writeList(QStringLiteral("osint"), m_osintList);
    writeList(QStringLiteral("subdomain"), m_subdomainList);
    writeList(QStringLiteral("wayback"), m_archiveList);
    writeList(QStringLiteral("js"), m_jsFindingList);
    writeList(QStringLiteral("cve"), m_cveList);

    appendFeed(tr("CSV raporu kaydedildi: %1").arg(path));
}

void ReconWidget::saveSession()
{
    if (m_lastReportVariant.isEmpty()) {
        appendFeed(tr("Oturum kaydetmek icin once bir kesif taramasi tamamlanmali."));
        return;
    }

    const QString companyName = m_companyEdit ? m_companyEdit->text() : QString();
    const QString targetName = m_targetEdit ? m_targetEdit->text() : QString();
    const QString defaultName = corporateReportFileName(companyName, targetName, "recon.json");
    const QString path = QFileDialog::getSaveFileName(this,
                                                      tr("Recon Oturumu Kaydet"),
                                                      defaultName,
                                                      tr("Recon Session (*.json)"));
    if (path.isEmpty()) {
        return;
    }

    QVariantMap payload;
    payload.insert("meta", QVariantMap{
        {"savedAt", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
        {"securityScore", m_scoreValue ? m_scoreValue->text().toInt() : 0},
        {"phaseHistory", m_phaseHistory},
        {"notes", m_analystNotesEdit ? m_analystNotesEdit->toPlainText() : QString()},
        {"feedEntries", m_feedConsole ? m_feedConsole->toPlainText().split('\n', Qt::SkipEmptyParts) : QStringList{}},
        {"findingNotes", m_findingNotes}
    });
    payload.insert("report", m_lastReportVariant);

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        appendFeed(tr("Recon oturum dosyasi acilamadi: %1").arg(path));
        return;
    }

    file.write(QJsonDocument::fromVariant(payload).toJson(QJsonDocument::Indented));
    saveRecentSessionPath(path);
    appendFeed(tr("Recon oturumu kaydedildi: %1").arg(path));
}

void ReconWidget::openSession()
{
    QString path = m_recentSessionCombo ? m_recentSessionCombo->currentData().toString() : QString();
    if (path.isEmpty()) {
        path = QFileDialog::getOpenFileName(this,
                                           tr("Recon Oturumu Ac"),
                                           QString(),
                                           tr("Recon Session (*.json)"));
    }
    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        appendFeed(tr("Recon oturum dosyasi acilamadi: %1").arg(path));
        return;
    }

    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    const QVariantMap payload = document.toVariant().toMap();
    const QVariantMap meta = payload.value("meta").toMap();
    const QVariantMap reportVariant = payload.value("report").toMap();
    if (reportVariant.isEmpty()) {
        appendFeed(tr("Recon oturum dosyasi gecerli bir rapor icermiyor: %1").arg(path));
        return;
    }

    if (!m_lastReportVariant.isEmpty()) {
        m_compareBaselineVariant = m_lastReportVariant;
    }
    const int securityScore = meta.value("securityScore").toInt();
    const QStringList phaseHistory = meta.value("phaseHistory").toStringList();
    const QStringList feedEntries = meta.value("feedEntries").toStringList();
    m_findingNotes = meta.value("findingNotes").toMap();
    if (m_analystNotesEdit) {
        m_analystNotesEdit->setPlainText(meta.value("notes").toString());
    }

    applySessionVariant(reportVariant, securityScore, phaseHistory, feedEntries);
    saveRecentSessionPath(path);
    m_statusValue->setText(tr("Oturum Acildi"));
    m_activityValue->setText(tr("Kaydedilmis recon oturumu yuklendi"));
    appendFeed(tr("Recon oturumu yuklendi: %1").arg(path));
}

void ReconWidget::appendFeed(const QString &message)
{
    if (!m_feedConsole) {
        return;
    }

    const QString elapsedText = (m_scanTimer && m_scanTimer->isValid())
                                    ? QString("+%1 sn").arg(QString::number(m_scanTimer->elapsed() / 1000.0, 'f', 1))
                                    : QStringLiteral("+0.0 sn");
    const QString line = QString("[%1] [%2] %3")
                             .arg(QDateTime::currentDateTime().toString("HH:mm:ss"),
                                  elapsedText,
                                  message);
    m_feedConsole->appendPlainText(line);
}

void ReconWidget::refreshSpiderEvidence()
{
    if (!m_module || !m_module->settingsManager()) {
        return;
    }

    const QVariantList endpoints = m_module->settingsManager()->value("modules/spider_snapshot", "endpoints").toList();
    const QVariantList parameters = m_module->settingsManager()->value("modules/spider_snapshot", "parameters").toList();
    const QVariantList assets = m_module->settingsManager()->value("modules/spider_snapshot", "assets").toList();
    const QVariantList highValueTargets = m_module->settingsManager()->value("modules/spider_snapshot", "highValueTargets").toList();
    const QVariantList coverageTimeline = m_module->settingsManager()->value("modules/spider_snapshot", "coverageTimeline").toList();
    const QVariantMap coverageBreakdown = m_module->settingsManager()->value("modules/spider_snapshot", "coverageBreakdown").toMap();
    const int coverageScore = m_module->settingsManager()->value("modules/spider_snapshot", "coverageScore", 0).toInt();
    const QString coverageSummary = m_module->settingsManager()->value("modules/spider_snapshot", "coverageSummary").toString();
    const QString benchmarkSummary = m_module->settingsManager()->value("modules/spider_snapshot", "benchmarkSummary").toString();
    const QString automationSafetyStatus = m_module->settingsManager()->value("modules/spider_snapshot", "automationSafetyStatus").toString();

    if (m_spiderEndpointList) {
        m_spiderEndpointList->clear();
        for (const QVariant &value : endpoints) {
            const QVariantMap row = value.toMap();
            const QString kind = row.value("kind").toString();
            const QString sessionState = row.value("sessionState").toString();
            const QString sessionBadge = sessionState == QLatin1String("oturumlu-yeni-yuzey")
                ? tr("YENI")
                : (sessionState == QLatin1String("oturumlu-ortak") ? tr("OTURUMLU") : tr("ANONIM"));
            QString badge = tr("YUZEY");
            QColor color("#d7dde7");
            if (kind == QLatin1String("login-wall") || kind == QLatin1String("access-denied") || kind == QLatin1String("waf-challenge")) {
                badge = tr("KORUNAN");
                color = QColor("#f2a65a");
            } else if (kind == QLatin1String("soft-404") || row.value("statusCode").toInt() == 404) {
                badge = tr("404");
                color = QColor("#9aa4b2");
            } else if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
                badge = tr("YENI");
                color = QColor("#79d292");
            } else if (kind == QLatin1String("js-route")) {
                badge = tr("JS");
                color = QColor("#72c7ff");
            }
            auto *item = new QListWidgetItem(QString("[%1] %2  |  %3  d%4 HTTP %5")
                                              .arg(badge,
                                                   row.value("url").toString(),
                                                   sessionBadge,
                                                   row.value("depth").toString(),
                                                   row.value("statusCode").toString()));
            item->setForeground(color);
            m_spiderEndpointList->addItem(item);
        }
    }

    if (m_spiderParameterList) {
        m_spiderParameterList->clear();
        for (const QVariant &value : parameters) {
            const QVariantMap row = value.toMap();
            m_spiderParameterList->addItem(QString("%1  [%2]  ->  %3")
                                               .arg(row.value("name").toString(),
                                                    row.value("origin").toString().replace(':', " / "),
                                                    row.value("url").toString()));
        }
    }

    if (m_spiderAssetList) {
        m_spiderAssetList->clear();
        for (const QVariant &value : assets) {
            const QVariantMap row = value.toMap();
            auto *item = new QListWidgetItem(QString("[%1] %2").arg(row.value("kind").toString(),
                                                                    row.value("value").toString()));
            const QString kind = row.value("kind").toString();
            if (kind.startsWith(QLatin1String("auth-"))) {
                item->setForeground(QColor("#f2a65a"));
            } else if (kind.startsWith(QLatin1String("render-"))) {
                item->setForeground(QColor("#79d292"));
            } else if (kind.startsWith(QLatin1String("automation-"))) {
                item->setForeground(QColor("#72c7ff"));
            }
            m_spiderAssetList->addItem(item);
        }
    }

    if (m_spiderHighValueList) {
        m_spiderHighValueList->clear();
        for (const QVariant &value : highValueTargets) {
            const QVariantMap row = value.toMap();
            auto *item = new QListWidgetItem(QString("[%1] %2").arg(row.value("label").toString(),
                                                                    row.value("value").toString()));
            item->setForeground(severityColorForLabel(row.value("label").toString()));
            m_spiderHighValueList->addItem(item);
        }
    }

    if (m_spiderTimelineList) {
        m_spiderTimelineList->clear();
        for (const QVariant &value : coverageTimeline) {
            const QVariantMap row = value.toMap();
            m_spiderTimelineList->addItem(QString("[%1] [%2] %3 -> %4")
                                              .arg(row.value("time").toString(),
                                                   row.value("stage").toString(),
                                                   row.value("title").toString(),
                                                   row.value("detail").toString()));
        }
    }

    if (m_spiderCoverageLabel) {
        m_spiderCoverageLabel->setText(
            tr("Coverage %1/100 | %2\nAutomation: %3\nBenchmark: %4\nKirilim: auth %5 | form %6 | js %7 | secret %8 | admin %9 | upload %10 | delta %11 | korunan %12 | 404 %13 | render %14 | automation %15")
                .arg(coverageScore)
                .arg(coverageSummary)
                .arg(automationSafetyStatus)
                .arg(benchmarkSummary)
                .arg(coverageBreakdown.value("auth").toInt())
                .arg(coverageBreakdown.value("form").toInt())
                .arg(coverageBreakdown.value("js").toInt())
                .arg(coverageBreakdown.value("secret").toInt())
                .arg(coverageBreakdown.value("admin").toInt())
                .arg(coverageBreakdown.value("upload").toInt())
                .arg(coverageBreakdown.value("delta").toInt())
                .arg(coverageBreakdown.value("protected").toInt())
                .arg(coverageBreakdown.value("missing").toInt())
                .arg(coverageBreakdown.value("render").toInt())
                .arg(coverageBreakdown.value("automation").toInt()));
    }

    rebuildSpiderWarnings(endpoints, parameters, assets, highValueTargets, coverageBreakdown, coverageScore);
}

QWidget *ReconWidget::createInfoLabel(const QString &title, const QString &tooltip) const
{
    auto *container = new QWidget(const_cast<ReconWidget *>(this));
    auto *layout = new QHBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    auto *label = new QLabel(title, container);
    label->setObjectName("mutedText");
    auto *infoButton = new QToolButton(container);
    infoButton->setText("i");
    infoButton->setToolTip(tooltip);
    infoButton->setAutoRaise(true);
    infoButton->setCursor(Qt::PointingHandCursor);
    infoButton->setObjectName("infoButton");
    infoButton->setFixedSize(18, 18);
    connect(infoButton, &QToolButton::clicked, infoButton, [infoButton, tooltip]() {
        QToolTip::showText(QCursor::pos(), tooltip, infoButton);
    });

    layout->addWidget(label);
    layout->addWidget(infoButton);
    layout->addStretch();
    return container;
}

void ReconWidget::insertSeverityItem(QListWidget *list, const QString &severity, const QString &title, const QString &description)
{
    insertSeverityItem(list, severity, title, description, QStringLiteral("default"));
}

void ReconWidget::insertSeverityItem(QListWidget *list,
                                     const QString &severity,
                                     const QString &title,
                                     const QString &description,
                                     const QString &sourceTag)
{
    if (!list) {
        return;
    }

    const QString normalized = severity.trimmed().toLower();
    QString severityLabel = normalized;
    if (normalized == "high") severityLabel = tr("yuksek");
    else if (normalized == "medium") severityLabel = tr("orta");
    else if (normalized == "low") severityLabel = tr("dusuk");
    else if (normalized == "info") severityLabel = tr("bilgi");

    auto *item = new QListWidgetItem(QString("[%1] %2").arg(severityLabel.toUpper(), title));
    item->setData(Qt::UserRole, severityRank(severityLabel));
    item->setData(Qt::UserRole + 1, severityLabel);
    item->setData(Qt::UserRole + 2, title);
    item->setData(Qt::UserRole + 3, description);
    item->setData(Qt::UserRole + 4, sourceTag);
    item->setForeground(severityColorForLabel(severityLabel));

    int insertRow = 0;
    while (insertRow < list->count()) {
        if (severityRank(severityLabel) > list->item(insertRow)->data(Qt::UserRole).toInt()) {
            break;
        }
        ++insertRow;
    }
    list->insertItem(insertRow, item);
}

void ReconWidget::removeTaggedItems(QListWidget *list, const QString &sourceTag)
{
    if (!list) {
        return;
    }

    for (int i = list->count() - 1; i >= 0; --i) {
        if (list->item(i)->data(Qt::UserRole + 4).toString() == sourceTag) {
            delete list->takeItem(i);
        }
    }
}

void ReconWidget::rebuildSpiderWarnings(const QVariantList &endpoints,
                                        const QVariantList &parameters,
                                        const QVariantList &assets,
                                        const QVariantList &highValueTargets,
                                        const QVariantMap &coverageBreakdown,
                                        int coverageScore)
{
    const QString spiderTag = QStringLiteral("spider-warning");
    removeTaggedItems(m_findingsList, spiderTag);
    removeTaggedItems(m_surfaceList, spiderTag);

    QSet<QString> emittedKeys;
    auto emitSpiderWarning = [this, &emittedKeys, &spiderTag](const QString &severity,
                                                              const QString &title,
                                                              const QString &description) {
        const QString key = QStringLiteral("%1|%2|%3").arg(severity, title, description);
        if (emittedKeys.contains(key)) {
            return;
        }
        emittedKeys.insert(key);
        insertSeverityItem(m_findingsList, severity, title, description, spiderTag);
        insertSeverityItem(m_surfaceList, severity, title, description, spiderTag);
    };

    for (const QVariant &value : endpoints) {
        const QVariantMap row = value.toMap();
        const QString kind = row.value("kind").toString();
        const QString url = row.value("url").toString();
        const int status = row.value("statusCode").toInt();
        const QString sessionState = row.value("sessionState").toString();

        if (sessionState == QLatin1String("oturumlu-yeni-yuzey")) {
            emitSpiderWarning(tr("orta"),
                              tr("Oturum sonrasi yeni yuzey bulundu"),
                              tr("Spider anonim taramada gorunmeyen ve oturum sonrasinda acilan yeni bir endpoint yakaladi: %1. Yetki kontrolu, dogrudan nesne erisimi ve yatay/dusey erisim testleri icin degerlidir.").arg(url));
        }

        if (kind == "login-wall") {
            emitSpiderWarning(tr("orta"),
                              tr("Spider login duvari tespit etti"),
                              tr("Spider ayni oturum acma imzasina veya yonlendirme davranisina sahip bir giris duvari tespit etti: %1. Kimlik dogrulama arkasi yuzey manuel test planina alinmali.").arg(url));
        } else if (kind == "soft-404") {
            emitSpiderWarning(tr("dusuk"),
                              tr("Spider soft-404 davranisi tespit etti"),
                              tr("HTTP %1 ile donen ancak bulunamayan sayfa kalibi gosteren bir endpoint bulundu: %2. Bu durum brute-force ve yuzey kesfinde yaniltici sonuclar uretebilir.").arg(status).arg(url));
        } else if (kind == "access-denied") {
            emitSpiderWarning(tr("orta"),
                              tr("Erisim reddi siniri bulundu"),
                              tr("Spider yetki veya kimlik dogrulama gerektiren bir endpoint yakaladi: %1. Rol bazli yetki atlama, dogrudan nesne erisimi ve auth boundary testleri icin degerlidir.").arg(url));
        } else if (kind == "waf-challenge") {
            emitSpiderWarning(tr("dusuk"),
                              tr("WAF veya challenge davranisi tespit edildi"),
                              tr("Spider hedefte challenge veya WAF davranisi gordu: %1. Bu durum tarama kapsamini etkileyebilir ve manuel dogrulama gerektirir.").arg(url));
        } else if (kind == "js-route") {
            emitSpiderWarning(tr("orta"),
                              tr("Spider JavaScript icinden route cikardi"),
                              tr("JavaScript dosyalari icinden yeni endpoint izleri bulundu: %1. Bu rotalar ek uygulama yüzeyi olusturabilir.").arg(url));
        } else if (kind.startsWith("form:") || kind == "login-form") {
            emitSpiderWarning(kind == "login-form" ? tr("orta") : tr("dusuk"),
                              kind == "login-form" ? tr("Kimlik dogrulama formu bulundu") : tr("Yeni form endpointi bulundu"),
                              tr("Spider form action yuzeyi yakaladi: %1. Bu nokta girdi dogrulama, yetkilendirme ve is akisi testleri icin adaydir.").arg(url));
        }
    }

    for (const QVariant &value : parameters) {
        const QVariantMap row = value.toMap();
        const QString name = row.value("name").toString();
        const QString origin = row.value("origin").toString();
        const QString url = row.value("url").toString();

        if (origin.contains("parola")) {
            emitSpiderWarning(tr("orta"),
                              tr("Parola alani tespit edildi"),
                              tr("Spider bir parola alani buldu: %1 (%2). Kimlik dogrulama akisinda brute-force, MFA ve rate-limit kontrolleri degerlendirilmelidir.").arg(name, url));
        } else if (origin.contains("csrf")) {
            emitSpiderWarning(tr("bilgi"),
                              tr("CSRF koruma alani bulundu"),
                              tr("Spider bir CSRF veya token alani buldu: %1 (%2). Form koruma mekanizmalarinin varligi ve dogrulugu manuel olarak teyit edilmelidir.").arg(name, url));
        } else if (origin.contains("dosya-yukleme")) {
            emitSpiderWarning(tr("yuksek"),
                              tr("Dosya yukleme alani bulundu"),
                              tr("Spider dosya yukleme alanini yakaladi: %1 (%2). Dosya tipi, virus taramasi, depolama yolu ve yetki kontrolleri acisindan kritik test yuzeyidir.").arg(name, url));
        } else if (origin.contains("admin-filtresi")) {
            emitSpiderWarning(tr("orta"),
                              tr("Yonetim veya filtre alani bulundu"),
                              tr("Spider yonetim/filtre benzeri girdi alani tespit etti: %1 (%2). Bu alanlar yetki kontrolu ve listeleme mantigi acisindan incelenmelidir.").arg(name, url));
        } else if (origin.contains("yorum")) {
            emitSpiderWarning(tr("orta"),
                              tr("Yorum veya serbest metin alani bulundu"),
                              tr("Spider yorum/mesaj tipinde girdi alani tespit etti: %1 (%2). XSS ve icerik filtreleme kontrolleri icin uygun bir hedeftir.").arg(name, url));
        } else if (origin.contains("arama")) {
            emitSpiderWarning(tr("dusuk"),
                              tr("Arama parametresi bulundu"),
                              tr("Spider arama veya query girdisi buldu: %1 (%2). Reflected XSS ve sorgu mantigi acisindan hizli test edilebilir.").arg(name, url));
        }
    }

    for (const QVariant &value : assets) {
        const QVariantMap row = value.toMap();
        const QString kind = row.value("kind").toString();
        const QString literal = row.value("value").toString();

        if (kind == "secret" || literal.startsWith("secret:")) {
            emitSpiderWarning(tr("yuksek"),
                              tr("Olasi gizli bilgi izi bulundu"),
                              tr("Spider istemci tarafi veya dokuman icinde secret benzeri bir literal yakaladi: %1. Bu veri gercek kimlik bilgisi veya token sizintisi olabilir.").arg(literal));
        } else if (kind == "js-literal" && (literal.startsWith("jwt:") || literal.startsWith("aws-key:"))) {
            emitSpiderWarning(tr("yuksek"),
                              tr("Kritik token veya anahtar izi bulundu"),
                              tr("Spider JavaScript icinde kritik gorunen bir literal yakaladi: %1. Kaynak dosyalar ve build artefaktlari acilen dogrulanmalidir.").arg(literal));
        } else if (kind == "login-form") {
            emitSpiderWarning(tr("orta"),
                              tr("Login akisina ait asset izi bulundu"),
                              tr("Spider login akisina bagli bir form/action izi buldu: %1. Oturum acma akisi ek tarama planina alinmalidir.").arg(literal));
        } else if (kind == "auth-surface-delta") {
            emitSpiderWarning(tr("orta"),
                              tr("Oturum sonrasi ek uygulama yuzeyi bulundu"),
                              tr("Spider oturum sonrasinda yeni bir link, form veya route yakaladi: %1. Bu alanlar rol tabanli yetki ve is akisi zafiyetleri icin incelenmelidir.").arg(literal));
        } else if (kind == "render-state-delta") {
            emitSpiderWarning(tr("yuksek"),
                              tr("Rendered DOM yeni uygulama yuzeyi cikardi"),
                              tr("Spider ham HTML'de gorunmeyen ancak render sonrasi ortaya cikan bir endpoint yakaladi: %1. Bu durum JS/SPA tarafinda gizli is akisi veya ek yetkili yuzey olabilecegini gosterir.").arg(literal));
        } else if (kind == "render-form-delta") {
            emitSpiderWarning(tr("yuksek"),
                              tr("Rendered DOM yeni form akisina isaret ediyor"),
                              tr("Spider render sonrasi yeni bir form action buldu: %1. Bu, sadece istemci tarafinda olusan workflow veya gizli operasyon paneli yuzeyi olabilir.").arg(literal));
        } else if (kind == "render-route-delta") {
            emitSpiderWarning(tr("orta"),
                              tr("Rendered DOM yeni rota cikardi"),
                              tr("Spider render sonrasi ham HTML'de olmayan bir rota buldu: %1. SPA icinde gizli kalmis endpoint veya workflow sayfasi olabilir.").arg(literal));
        } else if (kind == "render-action-delta") {
            emitSpiderWarning(tr("yuksek"),
                              tr("Rendered DOM etkileşim adayi cikardi"),
                              tr("Spider render sonrasi button, onclick veya data-action tabanli yeni bir etkileşim hedefi yakaladi: %1. Bu, normal link taramasinda gorunmeyen uygulama workflow adimi olabilir.").arg(literal));
        } else if (kind == "workflow-submit-candidate") {
            emitSpiderWarning(tr("orta"),
                              tr("Replay edilebilir guvenli form akisi bulundu"),
                              tr("Spider rendered DOM icinden guvenli gorunen bir GET form akisini tekrar oynatmaya aday olarak isaretledi: %1. Bu, filtreleme, arama ve listeleme workflow'larinda yeni yuzeyler cikartabilir.").arg(literal));
        } else if (kind == "workflow-action-candidate") {
            emitSpiderWarning(tr("orta"),
                              tr("Replay edilebilir etkileşim workflow'u bulundu"),
                              tr("Spider rendered DOM icinde tekrar oynatilabilir bir etkileşim adayi tespit etti: %1. Bu, JS ile acilan gizli panel veya alt akis yuzeyi olabilir.").arg(literal));
        } else if (kind == "automation-live-action") {
            emitSpiderWarning(tr("yuksek"),
                              tr("Canli browser uzerinde etkilesim adayi bulundu"),
                              tr("Spider CDP uzerinden canli browser oturumunda yeni bir etkilesim adayi yakaladi: %1. Bu durum normal HTML taramasinda gorunmeyen, browser durumuna bagli bir workflow veya panel akisina isaret edebilir.").arg(literal));
        } else if (kind == "automation-live-title") {
            emitSpiderWarning(tr("dusuk"),
                              tr("Canli browser sayfa basligi kaydedildi"),
                              tr("Spider CDP baglantisi ile browser icindeki canli sayfa basligini dogruladi: %1. Bu bilgi auth ve workflow gecislerini dogrulamak icin yardimci kanit olarak kullanilabilir.").arg(literal));
        } else if (kind == "automation-cdp-failed") {
            emitSpiderWarning(tr("dusuk"),
                              tr("Canli browser otomasyonu baglanamadi"),
                              tr("Spider headless browser acsa da CDP kanalina baglanamadi: %1. Bu durum browser otomasyon coverage'ini dusurebilir; tarayici yolu ve debug port akisina tekrar bakilmalidir.").arg(literal));
        } else if (kind == "auth-boundary") {
            emitSpiderWarning(tr("orta"),
                              tr("Oturum siniri davranisi kaydedildi"),
                              tr("Spider auth sonrasi cookie veya redirect sinirini kaydetti: %1. Session sabitleme, eksik logout ve yetki siniri testleri icin degerli bir sinyaldir.").arg(literal));
        } else if (kind == "auth-new-cookie") {
            emitSpiderWarning(tr("dusuk"),
                              tr("Yeni oturum cerezi olustu"),
                              tr("Spider auth akisinda yeni bir cookie adi yakaladi: %1. Session ve kimlik dogrulama cerezlerinin bayraklari manuel olarak dogrulanmalidir.").arg(literal));
        }
    }

    if (coverageScore >= 65) {
        emitSpiderWarning(tr("orta"),
                          tr("Spider yuksek saldiri yuzeyi kapsami yakaladi"),
                          tr("Spider coverage skoru %1/100 seviyesine ulasti. Auth, form, JS ve kritik yuzey katmanlari bir arada gorunuyor; hedef daha derin manuel test planina alinmali.").arg(coverageScore));
    }

    if (coverageBreakdown.value("secret").toInt() > 0) {
        emitSpiderWarning(tr("yuksek"),
                          tr("Spider gizli literal veya token izi buldu"),
                          tr("Spider JS veya sayfa iceriginde gizli literal/tanecik izleri yakaladi. Bu durum istemci tarafina sizan anahtar, token veya ic servis izleri olabilecegini gosterir."));
    }

    if (coverageBreakdown.value("upload").toInt() > 0) {
        emitSpiderWarning(tr("yuksek"),
                          tr("Spider dosya yukleme yuzeyi cikardi"),
                          tr("Spider coverage kiriliminda dosya yukleme girdileri bulundu. Bu tip alanlar uzaktan kod yukleme, zararlı icerik tasima ve depolama yolu istismari icin kritik yuzeydir."));
    }

    if (coverageBreakdown.value("delta").toInt() > 0 && coverageBreakdown.value("auth").toInt() > 0) {
        emitSpiderWarning(tr("yuksek"),
                          tr("Oturum sonrasi farkli uygulama yuzeyi aciliyor"),
                          tr("Kimlik dogrulama sonrasinda anonim taramada gorunmeyen yeni endpoint'ler yakalandi. Bu, rol bazli erisim kontrolleri ve yetki atlama senaryolari icin oncelikli bir sinyaldir."));
    }

    if (coverageBreakdown.value("protected").toInt() > 0) {
        emitSpiderWarning(tr("orta"),
                          tr("Korunan yuzeyler belirgin sekilde ayrisiyor"),
                          tr("Spider %1 adet korunan veya challenge arkasindaki yuzey tespit etti. Bu alanlar auth boundary, role check ve koruma mekanizmasi davranisi icin oncelikli manuel test adayidir.").arg(coverageBreakdown.value("protected").toInt()));
    }

    if (coverageBreakdown.value("render").toInt() > 0) {
        emitSpiderWarning(tr("orta"),
                          tr("Rendered yuzey klasik taramayi genisletti"),
                          tr("Spider rendered DOM katmaninda %1 adet ek sinyal uretmis durumda. Bu, istemci tarafli uygulama akislarinin klasik link taramasindan daha genis oldugunu gosterir.").arg(coverageBreakdown.value("render").toInt()));
    }

    if (coverageBreakdown.value("automation").toInt() > 0) {
        emitSpiderWarning(tr("yuksek"),
                          tr("Canli browser automation sinyali olustu"),
                          tr("Spider canli browser oturumundan %1 adet automation sinyali topladi. Bu, browser durumuna bagli workflow ve panel akislarinin var olduguna guclu bir isarettir.").arg(coverageBreakdown.value("automation").toInt()));
    }

    for (const QVariant &value : highValueTargets) {
        const QVariantMap row = value.toMap();
        const QString label = row.value("label").toString();
        const QString target = row.value("value").toString();
        if (label.contains(tr("Yonetim"), Qt::CaseInsensitive)) {
            emitSpiderWarning(tr("orta"),
                              tr("Yonetim yuzeyi dogrudan tespit edildi"),
                              tr("Spider yonetim niteliginde bir hedef buldu: %1. Yetki kontrolleri, IP kisitlari ve admin workflow korumalari test edilmelidir.").arg(target));
        } else if (label.contains(tr("Kimlik"), Qt::CaseInsensitive)) {
            emitSpiderWarning(tr("orta"),
                              tr("Kimlik dogrulama yuzeyi oncelikli hedef olarak isaretlendi"),
                              tr("Spider kimlik dogrulama akisi veya giris duvarini kritik yuzey olarak isaretledi: %1. Brute-force korumalari, MFA ve session fixation testleri icin onceliklidir.").arg(target));
        }
    }
}

void ReconWidget::updateFindingDetail()
{
    if (!m_findingsList || !m_findingDetailView) {
        return;
    }

    QListWidgetItem *item = m_findingsList->currentItem();
    if (!item) {
        m_findingDetailView->setHtml(tr("<h3>Bulgu secilmedi</h3><p>Detay gormek icin soldaki listeden bir kayit sec.</p>"));
        if (m_findingNoteEdit) {
            m_findingNoteEdit->clear();
        }
        return;
    }

    m_findingDetailView->setHtml(detailHtmlForFinding(item->data(Qt::UserRole + 1).toString(),
                                                      item->data(Qt::UserRole + 2).toString(),
                                                      item->data(Qt::UserRole + 3).toString()));
    if (m_findingNoteEdit) {
        const QString key = item->data(Qt::UserRole + 2).toString();
        m_findingNoteEdit->setPlainText(m_findingNotes.value(key).toString());
    }
}

QString ReconWidget::detailHtmlForFinding(const QString &severity, const QString &title, const QString &description) const
{
    const QString normalized = severity.trimmed().toLower();
    const QVariantMap guidance = developerGuidanceForFinding(title, description);

    const QString severityColor = normalized.contains("yuksek") ? "#d14343"
                                : normalized.contains("orta") ? "#d08b2e"
                                : normalized.contains("dusuk") ? "#5c7cfa"
                                : "#7b8794";

    return QString(
               "<html><body style='font-family:Bahnschrift;padding:10px;font-size:11pt;'>"
               "<h2 style='margin:0 0 8px 0;'>%1</h2>"
               "<p><b>Risk Seviyesi:</b> <span style='color:%2;font-weight:700;'>%3</span></p>"
               "<p><b>Olasi Risk Adlari:</b> %4</p>"
               "<h3>Neden Var?</h3><p>%5</p>"
               "<h3>Muhtemel Etki</h3><p>%6</p>"
               "<h3>Bu Acik Uzerinden Neler Yapilabilir?</h3><p>%7</p>"
               "<h3>Yazilim Ekibi Icin Cozum Rehberi</h3><p>%8</p>"
               "<h3>Onerilen Aksiyon</h3><p>%9</p>"
               "<h3>Analist Notu</h3><p>%10</p>"
               "</body></html>")
        .arg(title.toHtmlEscaped(),
             severityColor,
             severity.toUpper().toHtmlEscaped(),
             guidance.value("riskNames").toString().toHtmlEscaped(),
             description.toHtmlEscaped(),
             guidance.value("impact").toString().toHtmlEscaped(),
             guidance.value("attackerPlay").toString().toHtmlEscaped(),
             guidance.value("developerNotes").toString().toHtmlEscaped(),
             guidance.value("action").toString().toHtmlEscaped(),
             m_findingNotes.value(title).toString().isEmpty()
                 ? tr("Bu bulgu icin manuel analist notu eklenmedi.").toHtmlEscaped()
                 : m_findingNotes.value(title).toString().toHtmlEscaped());
}

int ReconWidget::severityRank(const QString &severity) const
{
    const QString normalized = severity.trimmed().toLower();
    if (normalized == "high" || normalized == tr("yuksek")) return 4;
    if (normalized == "medium" || normalized == tr("orta")) return 3;
    if (normalized == "low" || normalized == tr("dusuk")) return 2;
    return 1;
}

QString ReconWidget::buildReportHtml(const ScanReport &report, int securityScore) const
{
    const QString companyName = m_companyEdit ? m_companyEdit->text().trimmed() : QStringLiteral("PenguFoce Security Lab");
    const QString clientName = m_clientEdit ? m_clientEdit->text().trimmed() : QStringLiteral("Belirtilmedi");
    const QString testerName = m_testerEdit ? m_testerEdit->text().trimmed() : QStringLiteral("Operator");
    const QString classification = m_classificationEdit ? m_classificationEdit->text().trimmed() : QStringLiteral("Kurum Ici");
    const QString scopeSummary = m_scopeEdit ? m_scopeEdit->text().trimmed()
                                             : QStringLiteral("DNS, web guvenligi, TLS, OSINT ve acik servis degerlendirmesi");
    const SettingsManager *settings = (m_module ? m_module->settingsManager() : nullptr);
    const QVariantList spiderEndpoints = settings ? settings->value("modules/spider_snapshot", "endpoints").toList() : QVariantList{};
    const QVariantList spiderParameters = settings ? settings->value("modules/spider_snapshot", "parameters").toList() : QVariantList{};
    const QVariantList spiderAssets = settings ? settings->value("modules/spider_snapshot", "assets").toList() : QVariantList{};
    const QVariantList spiderHighValueTargets = settings ? settings->value("modules/spider_snapshot", "highValueTargets").toList() : QVariantList{};
    const QVariantList spiderCoverageTimeline = settings ? settings->value("modules/spider_snapshot", "coverageTimeline").toList() : QVariantList{};
    const QVariantMap spiderCoverageBreakdown = settings ? settings->value("modules/spider_snapshot", "coverageBreakdown").toMap() : QVariantMap{};
    const QVariantMap spiderHighValueSegments = settings ? settings->value("modules/spider_snapshot", "highValueSegments").toMap() : QVariantMap{};
    const int spiderCoverageScore = settings ? settings->value("modules/spider_snapshot", "coverageScore", 0).toInt() : 0;
    const QString spiderCoverageSummary = settings ? settings->value("modules/spider_snapshot", "coverageSummary").toString() : QString();
    const QString spiderCapturedAt = settings ? settings->value("modules/spider_snapshot", "capturedAt").toString() : QString();
    const QString spiderBenchmarkSummary = settings ? settings->value("modules/spider_snapshot", "benchmarkSummary").toString() : QString();
    const QString spiderBenchmarkDiffSummary = settings ? settings->value("modules/spider_snapshot", "benchmarkDiffSummary").toString() : QString();

    auto riskLevel = [securityScore]() {
        if (securityScore >= 85) return QStringLiteral("Dusuk");
        if (securityScore >= 65) return QStringLiteral("Orta");
        return QStringLiteral("Yuksek");
    };

    auto scoreGrade = [securityScore]() {
        if (securityScore >= 85) return QStringLiteral("A");
        if (securityScore >= 70) return QStringLiteral("B");
        if (securityScore >= 55) return QStringLiteral("C");
        return QStringLiteral("D");
    };

    QString findingsHtml;
    QString detailedFindingsHtml;
    for (const QVariant &value : report.findings) {
        const QVariantMap finding = value.toMap();
        const QString category = finding.value("category").toString();
        const QString title = finding.value("title").toString();
        const QString description = finding.value("description").toString();
        const QVariantMap guidance = developerGuidanceForFinding(title, description);
        QString recommendation = tr("Servis ihtiyaci, maruziyet ve is etkisi birlikte degerlendirilerek duzeltici aksiyon tanimlanmali.");
        if (category == "web") {
            recommendation = tr("Eksik web guvenlik basliklari ve sunucu sertlestirmesi devreye alinmali.");
        } else if (category == "dns") {
            recommendation = tr("SPF, DMARC ve MX politikasi kurumsal e-posta mimarisine uygun sekilde tamamlanmali.");
        } else if (category == "ports") {
            recommendation = tr("Acik servis maruziyeti en aza indirilmeli, yonetim portlari kisitlanmali.");
        } else if (category == "tls") {
            recommendation = tr("TLS sertifikasi yenilenmeli ve eski protokoller kapatilmalidir.");
        } else if (category == "osint") {
            recommendation = tr("Harici kaynaklarda gorunen veri ve varlik izi azaltilmali, sizinti takibi yapilmalidir.");
        }

        findingsHtml += QString("<tr><td>%1</td><td>%2</td><td>%3</td><td>%4</td><td>%5</td></tr>")
                            .arg(finding.value("severity").toString().toUpper(),
                                 title.toHtmlEscaped(),
                                 description.toHtmlEscaped(),
                                 category.toHtmlEscaped(),
                                 recommendation.toHtmlEscaped());

        detailedFindingsHtml += QString(
                                    "<div style='margin:0 0 18px 0; padding:12px 14px; border:1px solid #cfd6df; border-radius:8px;'>"
                                    "<h3 style='margin:0 0 8px 0; font-size:13pt;'>%1</h3>"
                                    "<p style='margin:0 0 6px 0;'><b>Oncelik:</b> %2</p>"
                                    "<p style='margin:0 0 6px 0;'><b>Acigin Teknik Nedeni:</b> %3</p>"
                                    "<p style='margin:0 0 6px 0;'><b>Olasi Riskler:</b> %4</p>"
                                    "<p style='margin:0 0 6px 0;'><b>Saldirgan Ne Yapabilir?</b> %5</p>"
                                    "<p style='margin:0 0 6px 0;'><b>Yazilim Ekibi Icin Uygulama Notu:</b> %6</p>"
                                    "<p style='margin:0;'><b>Kapatma ve Iyilestirme Adimi:</b> %7</p>"
                                    "</div>")
                                    .arg(title.toHtmlEscaped(),
                                         finding.value("severity").toString().toUpper(),
                                         description.toHtmlEscaped(),
                                         guidance.value("riskNames").toString().toHtmlEscaped(),
                                         guidance.value("attackerPlay").toString().toHtmlEscaped(),
                                         guidance.value("developerNotes").toString().toHtmlEscaped(),
                                         guidance.value("action").toString().toHtmlEscaped());
    }
    if (findingsHtml.isEmpty()) {
        findingsHtml = "<tr><td colspan='5'>Kritik bulgu kaydi olusmadi.</td></tr>";
        detailedFindingsHtml = "<p>Detaylandirilacak teknik bulgu kaydi olusmadi.</p>";
    }

    QString portHtml;
    for (const QVariant &value : report.openPorts) {
        const QVariantMap row = value.toMap();
        portHtml += QString("<li>%1 / %2</li>")
                        .arg(row.value("port").toString().toHtmlEscaped(),
                             row.value("service").toString().toHtmlEscaped());
    }
    if (portHtml.isEmpty()) {
        portHtml = "<li>Acik servis tespit edilmedi.</li>";
    }

    QString dnsHtml;
    for (const QVariant &value : report.dnsRecords) {
        const QVariantMap row = value.toMap();
        dnsHtml += QString("<li><b>%1</b>: %2</li>")
                       .arg(row.value("type").toString().toHtmlEscaped(),
                            row.value("value").toString().toHtmlEscaped());
    }
    if (dnsHtml.isEmpty()) {
        dnsHtml = "<li>DNS kaydi toplanamadi.</li>";
    }

    QString webHtml;
    for (const QVariant &value : report.webObservations) {
        const QVariantMap row = value.toMap();
        const QString waf = row.value("waf").toString();
        const QString wafText = waf.isEmpty()
                                    ? tr("WAF izi gorulmedi")
                                    : tr("WAF: %1").arg(waf);
        webHtml += QString("<li>%1 - HTTP %2 - Sunucu: %3 - Surum izi: %4 - %5</li>")
                       .arg(row.value("url").toString().toHtmlEscaped(),
                            row.value("status").toString().toHtmlEscaped(),
                            row.value("server").toString().toHtmlEscaped(),
                            row.value("version").toString().toHtmlEscaped(),
                            wafText.toHtmlEscaped());
    }
    if (webHtml.isEmpty()) {
        webHtml = "<li>Web guvenligi verisi toplanamadi.</li>";
    }

    QString osintHtml;
    for (const QVariant &value : report.osintObservations) {
        const QVariantMap row = value.toMap();
        const QString details = row.value("details").toString().isEmpty()
                                    ? tr("Harici kayit veya gosterge bulundu")
                                    : row.value("details").toString();
        osintHtml += QString("<li>%1 - %2</li>")
                         .arg(row.value("source").toString().toHtmlEscaped(),
                              details.toHtmlEscaped());
    }
    if (osintHtml.isEmpty()) {
        osintHtml = "<li>OSINT veya sizinti kaydi bulunmadi.</li>";
    }

    QString subdomainHtml;
    for (const QVariant &value : report.subdomains) {
        subdomainHtml += QString("<li>%1</li>").arg(value.toString().toHtmlEscaped());
    }
    if (subdomainHtml.isEmpty()) {
        subdomainHtml = "<li>Dogrulanmis alt alan adi kaydi bulunmadi.</li>";
    }

    QString archiveHtml;
    for (const QVariant &value : report.archivedUrls) {
        archiveHtml += QString("<li>%1</li>").arg(value.toString().toHtmlEscaped());
    }
    if (archiveHtml.isEmpty()) {
        archiveHtml = "<li>Wayback veya gizli endpoint kaydi bulunmadi.</li>";
    }

    QString jsHtml;
    for (const QVariant &value : report.jsFindings) {
        const QVariantMap row = value.toMap();
        jsHtml += QString("<li>%1 - %2 (%3)</li>")
                      .arg(row.value("type").toString().toHtmlEscaped(),
                           row.value("value").toString().toHtmlEscaped(),
                           row.value("source").toString().toHtmlEscaped());
    }
    if (jsHtml.isEmpty()) {
        jsHtml = "<li>JavaScript analizi bulgusu uretilmedi.</li>";
    }

    QString cveHtml;
    for (const QVariant &value : report.cveMatches) {
        const QVariantMap row = value.toMap();
        cveHtml += QString("<li>%1 %2 - %3 - %4</li>")
                       .arg(row.value("product").toString().toHtmlEscaped(),
                            row.value("version").toString().toHtmlEscaped(),
                            row.value("cve").toString().toHtmlEscaped(),
                            row.value("summary").toString().toHtmlEscaped());
    }
    if (cveHtml.isEmpty()) {
        cveHtml = "<li>Yerel CVE eslesmesi bulunmadi.</li>";
    }

    QString nameServersHtml;
    for (const QVariant &value : report.whoisInfo.value("nameServers").toList()) {
        nameServersHtml += QString("<li>%1</li>").arg(value.toString().toHtmlEscaped());
    }
    if (nameServersHtml.isEmpty()) {
        nameServersHtml = "<li>Name server bilgisi parse edilemedi.</li>";
    }

    const QString whoisHtml = report.whoisInfo.isEmpty()
                                  ? QStringLiteral("<p>Whois bilgisi toplanamadi.</p>")
                                  : QString(
                                        "<p><b>Domain:</b> %1<br>"
                                        "<b>Kayit Otoritesi:</b> %2<br>"
                                        "<b>Registrar:</b> %3<br>"
                                        "<b>Kayit Tarihi:</b> %4<br>"
                                        "<b>Guncelleme Tarihi:</b> %5<br>"
                                        "<b>Bitis Tarihi:</b> %6<br>"
                                        "<b>Durum:</b> %7</p>"
                                        "<p><b>Name Server'lar:</b></p><ul>%8</ul>"
                                        "<p><b>Ham Ozet:</b><br>%9</p>")
                                        .arg(report.whoisInfo.value("domain").toString().toHtmlEscaped(),
                                             report.whoisInfo.value("registry").toString().toHtmlEscaped(),
                                             report.whoisInfo.value("registrar").toString().toHtmlEscaped(),
                                             report.whoisInfo.value("created").toString().toHtmlEscaped(),
                                             report.whoisInfo.value("updated").toString().toHtmlEscaped(),
                                             report.whoisInfo.value("expiry").toString().toHtmlEscaped(),
                                             report.whoisInfo.value("status").toString().toHtmlEscaped(),
                                        nameServersHtml,
                                         report.whoisInfo.value("raw").toString().toHtmlEscaped());
    const QString spiderEndpointHtml = renderSpiderEndpointHtml(spiderEndpoints);
    const QString spiderParameterHtml = renderSpiderParameterHtml(spiderParameters);
    const QString spiderAssetHtml = renderSpiderAssetHtml(spiderAssets);
    const QString spiderAuthHtml = renderSpiderAuthHtml(spiderAssets);
    const QString spiderDeltaHtml = renderSpiderDeltaHtml(spiderAssets);
    QString spiderHighValueHtml;
    for (const QVariant &value : spiderHighValueTargets) {
        const QVariantMap row = value.toMap();
        spiderHighValueHtml += QString("<li><b>%1</b> - %2</li>")
                                   .arg(row.value("label").toString().toHtmlEscaped(),
                                        row.value("value").toString().toHtmlEscaped());
    }
    if (spiderHighValueHtml.isEmpty()) {
        spiderHighValueHtml = "<li>Yuksek degerli spider yuzeyi kaydi bulunmadi.</li>";
    }
    const QString spiderSegmentHtml = renderSpiderSegmentHtml(spiderHighValueSegments);
    QString spiderTimelineHtml;
    for (const QVariant &value : spiderCoverageTimeline) {
        const QVariantMap row = value.toMap();
        spiderTimelineHtml += QString("<li>[%1] <b>%2</b> - %3 <span style='color:#5b6677'>(%4)</span></li>")
                                  .arg(row.value("time").toString().toHtmlEscaped(),
                                       row.value("title").toString().toHtmlEscaped(),
                                       row.value("detail").toString().toHtmlEscaped(),
                                       row.value("stage").toString().toHtmlEscaped());
    }
    if (spiderTimelineHtml.isEmpty()) {
        spiderTimelineHtml = "<li>Coverage timeline kaydi bulunmadi.</li>";
    }
    const QString spiderCoverageHtml = tr("Coverage %1/100 | %2 | auth %3 | form %4 | js %5 | secret %6 | admin %7 | upload %8 | delta %9 | korunan %10 | render %11 | automation %12")
                                           .arg(spiderCoverageScore)
                                           .arg(spiderCoverageSummary)
                                           .arg(spiderCoverageBreakdown.value("auth").toInt())
                                           .arg(spiderCoverageBreakdown.value("form").toInt())
                                           .arg(spiderCoverageBreakdown.value("js").toInt())
                                           .arg(spiderCoverageBreakdown.value("secret").toInt())
                                           .arg(spiderCoverageBreakdown.value("admin").toInt())
                                           .arg(spiderCoverageBreakdown.value("upload").toInt())
                                           .arg(spiderCoverageBreakdown.value("delta").toInt())
                                           .arg(spiderCoverageBreakdown.value("protected").toInt())
                                           .arg(spiderCoverageBreakdown.value("render").toInt())
                                           .arg(spiderCoverageBreakdown.value("automation").toInt());
    const QString spiderSummaryHtml = spiderCapturedAt.isEmpty()
                                          ? tr("Bu rapora bagli son spider snapshot kaydi bulunmadi.")
                                          : tr("Spider bulgulari bu rapora otomatik olarak dahil edildi. Son snapshot zamani: %1").arg(QDateTime::fromString(spiderCapturedAt, Qt::ISODate).toString("dd.MM.yyyy HH:mm:ss"));
    const QString spiderBenchmarkHtml = spiderBenchmarkSummary.isEmpty()
                                            ? tr("Benchmark ozeti bulunmadi.")
                                            : tr("Benchmark: %1").arg(spiderBenchmarkSummary);
    const QString spiderBenchmarkDiffHtml = spiderBenchmarkDiffSummary.isEmpty()
                                                ? tr("Onceki kosa gore degisim bilgisi bulunmadi.")
                                                : tr("Karsilastirma: %1").arg(spiderBenchmarkDiffSummary);

    return QString(
               "<html><body style='font-family:Bahnschrift;font-size:12pt;line-height:1.45;padding:0;color:#171a20;'>"
               "<div style='border-bottom:2px solid #8f1732;padding-bottom:12px;margin-bottom:18px;'>"
               "<h1 style='margin:0;font-size:24pt;'>PenguFoce Sizma Testi ve Kesif Raporu</h1>"
               "<p style='margin:8px 0 0 0;font-size:11pt;'><b>Hazirlayan Kurum:</b> %1<br><b>Musteri:</b> %2<br><b>Test Uzmani:</b> %3<br><b>Siniflandirma:</b> %4<br><b>Rapor Tarihi:</b> %5</p>"
               "</div>"
               "<h2 style='font-size:16pt;'>1. Yonetici Ozeti</h2>"
               "<p>Bu rapor, hedef varlik uzerinde otomatik kesif ve ilk seviye guvenlik degerlendirmesi ile elde edilen teknik bulgularin yonetsel ozetini sunar. Hedef icin hesaplanan guvenlik puani <b>%6/100</b>, olgunluk notu <b>%7</b> ve genel risk seviyesi <b>%8</b> olarak hesaplanmistir.</p>"
               "<h2 style='font-size:16pt;'>2. Kapsam ve Metodoloji</h2>"
               "<p><b>Hedef:</b> %9<br><b>Cozumlenen IP:</b> %10<br><b>Kapsam:</b> %11</p>"
               "<p>Calisma; DNS kayitlarinin incelenmesi, web guvenlik basliklarinin kontrolu, TLS sertifika/protokol gozlemleri, acik servis tespiti, opsiyonel OSINT veri kaynaklarinin korelasyonu ve mevcutsa spider tabanli uygulama yuzeyi kesfi ile yurutulmustur.</p>"
               "<h2 style='font-size:16pt;'>3. Acik Servis Ozetleri</h2><ul>%12</ul>"
               "<h2 style='font-size:16pt;'>4. DNS ve Politika Gozlemleri</h2><ul>%13</ul>"
               "<h2 style='font-size:16pt;'>5. Web ve TLS Gozlemleri</h2><ul>%14</ul>"
               "<h2 style='font-size:16pt;'>6. OSINT ve Sizinti Gozlemleri</h2><ul>%15</ul>"
               "<h2 style='font-size:16pt;'>7. Alt Alan Adi ve Yuzey Genisleme Sonuclari</h2><ul>%16</ul>"
               "<h2 style='font-size:16pt;'>8. Wayback ve Gizli Endpoint Gozlemleri</h2><ul>%17</ul>"
               "<h2 style='font-size:16pt;'>9. JavaScript Analizi</h2><ul>%18</ul>"
               "<h2 style='font-size:16pt;'>10. CVE ve Surum Eslestirmeleri</h2><ul>%19</ul>"
               "<h2 style='font-size:16pt;'>11. Whois Bilgileri</h2>%20"
               "<h2 style='font-size:16pt;'>12. Spider Endpoint Ozetleri</h2><p>%21</p><ul>%22</ul>"
               "<h2 style='font-size:16pt;'>13. Spider Parametre ve Form Girdileri</h2><ul>%23</ul>"
               "<h2 style='font-size:16pt;'>14. Spider Asset ve Literal Bulgulari</h2><ul>%24</ul>"
               "<h2 style='font-size:16pt;'>15. Spider Oturum ve Kanit Izleri</h2><ul>%25</ul>"
               "<h2 style='font-size:16pt;'>16. Oturum Sonrasi Yeni Yuzey Farklari</h2><ul>%26</ul>"
               "<h2 style='font-size:16pt;'>17. Spider Coverage, Benchmark ve Kritik Yuzey</h2><p>%27</p><p>%28</p><p>%29</p><h3 style='font-size:13pt;'>Segment Bazli Kritik Yuzey</h3><ul>%30</ul><h3 style='font-size:13pt;'>Yuksek Degerli Hedefler</h3><ul>%31</ul><h3 style='font-size:13pt;'>Coverage Timeline</h3><ul>%32</ul>"
               "<h2 style='font-size:16pt;'>18. Detayli Bulgu Tablosu</h2>"
               "<table border='1' cellspacing='0' cellpadding='8' width='100%%' style='font-size:10.5pt;border-collapse:collapse;'>"
               "<tr><th>Oncelik</th><th>Baslik</th><th>Aciklama</th><th>Kategori</th><th>Onerilen Aksiyon</th></tr>%33</table>"
               "<h2 style='font-size:16pt;'>19. Gelistirici Ekip Icin Teknik Bulgular</h2>%34"
               "<h2 style='font-size:16pt;'>20. Sonuc ve Oneri</h2>"
               "<p>Yuksek ve orta oncelikli bulgular birinci asamada ele alinmali, ardindan servis maruziyeti ve DNS politika eksikleri giderilmelidir. Kritik sistemlerde otomatik kesif bulgulari mutlaka manuel dogrulama ve ikinci asama uygulama testi ile desteklenmelidir. Uygulama ekibi, operasyon ekibi ve altyapi sorumlulari bulgulari ortak backlog olarak ele alip her bulgu icin sahiplik atamalidir.</p>"
               "</body></html>")
        .arg(companyName.toHtmlEscaped(),
             clientName.toHtmlEscaped(),
             testerName.toHtmlEscaped(),
             classification.toHtmlEscaped(),
             QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm"),
             QString::number(securityScore),
             scoreGrade(),
             riskLevel(),
             report.sanitizedTarget.toHtmlEscaped(),
             report.resolvedIp.toHtmlEscaped(),
             scopeSummary.toHtmlEscaped(),
             portHtml,
             dnsHtml,
             webHtml,
             osintHtml,
             subdomainHtml,
             archiveHtml,
             jsHtml,
             cveHtml,
             whoisHtml,
             spiderSummaryHtml.toHtmlEscaped(),
             spiderEndpointHtml,
             spiderParameterHtml,
             spiderAssetHtml,
             spiderAuthHtml,
             spiderDeltaHtml,
             spiderCoverageHtml.toHtmlEscaped(),
             spiderBenchmarkHtml.toHtmlEscaped(),
             spiderBenchmarkDiffHtml.toHtmlEscaped(),
             spiderSegmentHtml,
             spiderHighValueHtml,
             spiderTimelineHtml,
             findingsHtml,
             detailedFindingsHtml);
}

void ReconWidget::exportReport()
{
    if (m_lastReportHtml.isEmpty()) {
        appendFeed(tr("Once bir kesif taramasi tamamlanmali, sonra PDF onizleme acilabilir."));
        return;
    }

    delete m_reportPreviewDialog;
    auto *dialog = new ReportPreviewDialog(this);
    m_reportPreviewDialog = dialog;
    m_reportPreviewView = dialog->view();
    m_reportPreviewView->setHtml(m_lastReportHtml);
    const QString companyName = m_companyEdit ? m_companyEdit->text() : QString();
    const QString targetName = m_targetEdit ? m_targetEdit->text() : QString();
    const QString pdfDefaultName = corporateReportFileName(companyName, targetName, "pdf");
    const QString htmlDefaultName = corporateReportFileName(companyName, targetName, "html");

    connect(dialog->savePdfButton(), &QPushButton::clicked, dialog, [this, dialog, pdfDefaultName]() {
        const QString path = QFileDialog::getSaveFileName(dialog,
                                                          tr("PDF Kaydet"),
                                                          pdfDefaultName,
                                                          tr("PDF (*.pdf)"));
        if (path.isEmpty()) {
            return;
        }

        QPdfWriter writer(path);
        writer.setResolution(144);
        writer.setPageSize(QPageSize(QPageSize::A4));
        writer.setPageMargins(QMarginsF(18, 18, 18, 18), QPageLayout::Millimeter);
        writer.setTitle(tr("PenguFoce Pentest Raporu"));

        QTextDocument document;
        document.setDocumentMargin(18.0);
        document.setHtml(m_lastReportHtml);
        document.setPageSize(writer.pageLayout().paintRectPixels(writer.resolution()).size());
        document.print(&writer);
        appendFeed(tr("PDF raporu kaydedildi: %1").arg(path));
    });

    connect(dialog->saveHtmlButton(), &QPushButton::clicked, dialog, [this, dialog, htmlDefaultName]() {
        const QString path = QFileDialog::getSaveFileName(dialog,
                                                          tr("HTML Kaydet"),
                                                          htmlDefaultName,
                                                          tr("HTML (*.html)"));
        if (path.isEmpty()) {
            return;
        }

        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            appendFeed(tr("Rapor dosyasi acilamadi: %1").arg(path));
            return;
        }

        QTextStream stream(&file);
        stream << m_lastReportHtml;
        appendFeed(tr("HTML raporu kaydedildi: %1").arg(path));
    });

    dialog->exec();
}
