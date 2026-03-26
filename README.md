# 🐧 PenguFoce

> Modüler Masaüstü Siber Güvenlik Workbench’i  
> Recon • Trafik Analizi • Crawling • Proxy • OSINT — hepsi tek uygulamada

---

# ⚙️ KURULUM (ÖNCE BURAYI OKU ⚠️)

## 🧱 1. Gereksinimler

| Araç | Gerekli |
|------|--------|
| CMake | ✅ |
| C++ Derleyici (MSVC / GCC / Clang) | ✅ |
| Git | ✅ |
| Python (opsiyonel ama önerilir) | ⚡ |

---

## 📡 2. Dış Bağımlılıklar (KRİTİK)

> ⚠️ Bu bağımlılıklar zorunludur. Kurulmazsa bazı modüller çalışmaz.

---

### 🔹 Npcap (Windows - Canlı Ağ Dinleme)

İndir: https://npcap.com/#download

Kurarken:
- WinPcap API Compatible Mode aktif olsun
- Kurulumu yönetici olarak yap

---

### 🔹 libpcap (Linux - Paket Yakalama)

```bash
sudo apt update
sudo apt install libpcap-dev
```

---

### 🔹 Nmap (Recon & Port Tarama)

```bash
sudo apt install nmap
```

Windows:
https://nmap.org/download.html

---

### 🔹 OpenSSL (HTTPS / TLS Analizi)

```bash
sudo apt install libssl-dev
```

Windows:
https://slproweb.com/products/Win32OpenSSL.html

---

### 🔹 Python (Spider / OSINT için)

```bash
sudo apt install python3 python3-pip
pip install requests bs4 selenium
```

---

## 📥 3. Projeyi Çek

```bash
git clone <repo-url>
cd PenguFoce
```

---

## 🔨 4. Derleme (Build)

```bash
cmake -S . -B build
cmake --build build
```

---

## 🧪 5. Test

```bash
ctest --test-dir build --output-on-failure
```

---

## ▶️ 6. Çalıştırma

Linux:
```bash
./build/PenguFoce
```

Windows:
```bash
build\PenguFoce.exe
```

---

# 🚀 ÖZELLİKLER

- Hedef keşfi ve yüzey haritalama  
- Modern web crawling (JS aware)  
- Canlı & offline paket analizi  
- HTTP/HTTPS proxy gözlemi  
- Oturum bazlı raporlama  

---

# 🧩 MODÜLLER

## 🧠 PenguCore
- Live & offline packet analizi  
- TCP / UDP / DNS / HTTP / TLS parsing  
- Flow & session takibi  

## 🌍 Recon
- DNS ve domain keşfi  
- Port ve servis tarama  
- Teknoloji tespiti  

## 🕷️ Spider
- JS route keşfi  
- Form & parametre toplama  
- Auth-aware crawling  

## 🔌 Proxy
- HTTP/HTTPS interception  
- Request/response analizi  

## ⚡ Port Scanner
- Hızlı port tarama  
- Banner grabbing  

---

# 🏗️ MİMARİ

```bash
src/
  controllers/
  core/
  libs/
    pengucore/
  modules/
  ui/
tests/
tools/
```

---

# 🧠 WORKFLOW (KULLANIM AKIŞI)

```text
Recon → Spider → PenguCore → Proxy → Rapor
```

---

# ⚠️ ÖNEMLİ NOTLAR

- Admin/root olmadan packet capture çalışmaz  
- Firewall bazı scan sonuçlarını etkileyebilir  
- HTTPS proxy için sertifika eklemek gerekir  
- Sadece yetkili sistemlerde test amaçlı kullanılmalıdır  

---

# 📊 PROJE DURUMU

| Alan | Durum |
|------|------|
| UI Shell | Stabil |
| PenguCore | Stabil |
| Recon | Stabil |
| Spider | Gelişiyor |
| AI Fuzzing | Planlanıyor |

---

# 🎯 HEDEF

PenguFoce bir tool değil,  
analistin tüm workflow’unu yöneten bir sistemdir

---

# 🔥 YOL HARİTASI

- [ ] AI destekli fuzzing motoru  
- [ ] Gelişmiş stream reassembly  
- [ ] Headless browser crawling  
- [ ] Plugin sistemi  

---

# 🤝 KATKI

Pull request’lere açığız.  
Büyük değişiklikler için önce issue aç.

---

# 📜 LİSANS

MIT (veya tercih ettiğin)

