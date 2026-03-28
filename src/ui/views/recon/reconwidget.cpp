#include "reconwidget.h"

#include "core/settings/settingsmanager.h"
#include "modules/recon/reconmodule.h"
#include "modules/recon/engine/pengufoce_masterscanner.h"
#include "modules/recon/engine/reconreportbuilder.h"
#include "ui/layout/flowlayout.h"
#include "ui/layout/workspacecontainers.h"
#include "ui/views/recon/reconcontrolpanel.h"
#include "ui/views/recon/reconevidencepanel.h"
#include "ui/views/recon/reconfindingspanel.h"
#include "ui/views/recon/reconlivepanel.h"
#include "ui/views/recon/reconreportpanel.h"
#include "ui/views/recon/reconsummarypanel.h"
#include "ui/widgets/reportpreviewdialog.h"

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
#include <QScrollArea>
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

    if (m_livePanel) {
        m_livePanel->setPulseAnimationEnabled(active);
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
    if (m_livePanel) {
        m_livePanel->setPulseActive(true);
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
    if (m_livePanel) {
        m_livePanel->setPulseActive(false);
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
    if (m_livePanel) {
        m_livePanel->setPulseActive(false);
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
    return buildReconDiffSummary(currentReport, baselineReport);
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
    auto *outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    auto *scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    auto *page = new QWidget(scrollArea);
    auto *root = pengufoce::ui::layout::createPageRoot(page, 18);

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

    auto *summaryPanel = new ReconSummaryPanel(hero);
    m_statusValue = summaryPanel->statusValue();
    m_scoreValue = summaryPanel->scoreValue();
    m_findingsCountValue = summaryPanel->findingsCountValue();
    m_portsCountValue = summaryPanel->portsCountValue();
    m_subdomainCountValue = summaryPanel->subdomainCountValue();
    m_archiveCountValue = summaryPanel->archiveCountValue();
    m_dnsCountValue = summaryPanel->dnsCountValue();
    m_surfaceCountValue = summaryPanel->surfaceCountValue();
    m_osintCountValue = summaryPanel->osintCountValue();
    m_spiderCountValue = summaryPanel->spiderCountValue();

    heroLayout->addLayout(heroTopBar);
    heroLayout->addWidget(subtitle);
    heroLayout->addWidget(summaryPanel);

    m_livePanel = new ReconLivePanel(this);
    m_pulseWidget = m_livePanel->pulseWidget();
    m_feedConsole = m_livePanel->feedConsole();
    m_activityValue = m_livePanel->activityValue();
    m_progressBar = m_livePanel->progressBar();
    m_phaseSummaryValue = m_livePanel->phaseSummaryValue();

    auto *setupCard = new ReconControlPanel(this);
    m_targetEdit = setupCard->targetEdit();
    m_endpointEdit = setupCard->endpointEdit();
    m_companyEdit = setupCard->companyEdit();
    m_clientEdit = setupCard->clientEdit();
    m_testerEdit = setupCard->testerEdit();
    m_classificationEdit = setupCard->classificationEdit();
    m_scopeEdit = setupCard->scopeEdit();
    m_targetPresetCombo = setupCard->targetPresetCombo();
    m_recentTargetCombo = setupCard->recentTargetCombo();
    m_scanProfileCombo = setupCard->scanProfileCombo();
    m_startButton = setupCard->startButton();
    m_stopButton = setupCard->stopButton();

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

    auto *findingsCard = new ReconFindingsPanel(this);
    m_findingsSeverityFilter = findingsCard->severityFilter();
    m_findingsSearchEdit = findingsCard->searchEdit();
    m_addManualFindingButton = findingsCard->addManualFindingButton();
    m_findingsList = findingsCard->findingsList();
    m_copyDetailButton = findingsCard->copyDetailButton();
    m_findingDetailView = findingsCard->findingDetailView();
    m_findingNoteEdit = findingsCard->findingNoteEdit();
    m_saveFindingNoteButton = findingsCard->saveFindingNoteButton();

    auto *evidenceCard = new ReconEvidencePanel(this);
    m_evidenceSearchEdit = evidenceCard->evidenceSearchEdit();
    m_dnsList = evidenceCard->dnsList();
    m_surfaceList = evidenceCard->surfaceList();
    m_osintList = evidenceCard->osintList();
    m_subdomainList = evidenceCard->subdomainList();
    m_archiveList = evidenceCard->archiveList();
    m_jsFindingList = evidenceCard->jsFindingList();
    m_cveList = evidenceCard->cveList();
    m_whoisSummaryView = evidenceCard->whoisSummaryView();
    m_relationshipView = evidenceCard->relationshipView();
    m_analysisTimelineList = evidenceCard->analysisTimelineList();
    m_spiderEndpointList = evidenceCard->spiderEndpointList();
    m_spiderParameterList = evidenceCard->spiderParameterList();
    m_spiderAssetList = evidenceCard->spiderAssetList();
    m_spiderHighValueList = evidenceCard->spiderHighValueList();
    m_spiderTimelineList = evidenceCard->spiderTimelineList();
    m_spiderCoverageLabel = evidenceCard->spiderCoverageLabel();
    m_timelineFilterCombo = new QComboBox(evidenceCard);
    m_timelineFilterCombo->addItems({tr("Tum Timeline"), tr("DNS"), tr("Port"), tr("Web/TLS"), tr("OSINT"), tr("Wayback"), tr("Whois"), tr("Subdomain"), tr("Fuzz"), tr("JS"), tr("Final")});
    if (m_analysisTimelineList && m_analysisTimelineList->parentWidget()) {
        if (auto *analysisLayout = qobject_cast<QVBoxLayout *>(m_analysisTimelineList->parentWidget()->layout())) {
            analysisLayout->insertWidget(1, m_timelineFilterCombo);
        }
    }

    auto *reportCard = new ReconReportPanel(this);
    m_exportJsonButton = reportCard->exportJsonButton();
    m_exportCsvButton = reportCard->exportCsvButton();
    m_saveSessionButton = reportCard->saveSessionButton();
    m_openSessionButton = reportCard->openSessionButton();
    m_recentSessionCombo = reportCard->recentSessionCombo();
    m_diffSummaryValue = reportCard->diffSummaryValue();
    m_analystNotesEdit = reportCard->analystNotesEdit();

    root->addWidget(hero);
    root->addWidget(setupCard);
    root->addWidget(m_livePanel);
    root->addWidget(findingsCard);
    root->addWidget(evidenceCard);
    root->addWidget(reportCard);
    page->setLayout(root);
    scrollArea->setWidget(page);
    outerLayout->addWidget(scrollArea);

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
    return buildReconFindingDetailHtml(severity, title, description, m_findingNotes.value(title).toString());
}

int ReconWidget::severityRank(const QString &severity) const
{
    return reconSeverityRank(severity);
}

QString ReconWidget::buildReportHtml(const ScanReport &report, int securityScore) const
{
    ReconReportContext context;
    context.companyName = m_companyEdit ? m_companyEdit->text().trimmed() : QString();
    context.clientName = m_clientEdit ? m_clientEdit->text().trimmed() : QString();
    context.testerName = m_testerEdit ? m_testerEdit->text().trimmed() : QString();
    context.classification = m_classificationEdit ? m_classificationEdit->text().trimmed() : QString();
    context.scopeSummary = m_scopeEdit ? m_scopeEdit->text().trimmed() : QString();
    if (const SettingsManager *settings = (m_module ? m_module->settingsManager() : nullptr)) {
        context.spiderSnapshot = QVariantMap{
            {"endpoints", settings->value("modules/spider_snapshot", "endpoints").toList()},
            {"parameters", settings->value("modules/spider_snapshot", "parameters").toList()},
            {"assets", settings->value("modules/spider_snapshot", "assets").toList()},
            {"highValueTargets", settings->value("modules/spider_snapshot", "highValueTargets").toList()},
            {"coverageTimeline", settings->value("modules/spider_snapshot", "coverageTimeline").toList()},
            {"coverageBreakdown", settings->value("modules/spider_snapshot", "coverageBreakdown").toMap()},
            {"highValueSegments", settings->value("modules/spider_snapshot", "highValueSegments").toMap()},
            {"coverageScore", settings->value("modules/spider_snapshot", "coverageScore", 0)},
            {"coverageSummary", settings->value("modules/spider_snapshot", "coverageSummary")},
            {"capturedAt", settings->value("modules/spider_snapshot", "capturedAt")},
            {"benchmarkSummary", settings->value("modules/spider_snapshot", "benchmarkSummary")},
            {"benchmarkDiffSummary", settings->value("modules/spider_snapshot", "benchmarkDiffSummary")}
        };
    }
    context.findingNotes = m_findingNotes;
    return buildReconReportHtml(context, report, securityScore);
}

void ReconWidget::exportReport()
{
    if (m_lastReportHtml.isEmpty()) {
        appendFeed(tr("Once bir kesif taramasi tamamlanmali, sonra PDF onizleme acilabilir."));
        return;
    }

    delete m_reportPreviewDialog;
    auto *dialog = new ReportPreviewDialog(tr("Rapor Onizlemesi"),
                                           tr("Bu pencere PDF ciktisinin onizlemesini gosterir. Kaydetme islemleri sadece burada yapilir."),
                                           tr("PDF Kaydet"),
                                           tr("HTML Kaydet"),
                                           this);
    m_reportPreviewDialog = dialog;
    dialog->view()->setHtml(m_lastReportHtml);
    const QString companyName = m_companyEdit ? m_companyEdit->text() : QString();
    const QString targetName = m_targetEdit ? m_targetEdit->text() : QString();
    const QString pdfDefaultName = reconCorporateReportFileName(companyName, targetName, "pdf");
    const QString htmlDefaultName = reconCorporateReportFileName(companyName, targetName, "html");

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
