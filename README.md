# PenguFoce

PenguFoce, masaustu odakli moduler bir siber guvenlik calisma ortami olarak tasarlanmis bir projedir. Amaci; ag trafigi analizi, hedef kesfi, web yuzeyi kazima, proxy tabanli gozlem ve operasyonel notlama gibi farkli guvenlik is akislarini tek bir uygulama icinde toplamak ve bunlari ortak bir arayuz diliyle yonetebilmektir.

Proje tek bir araca donusmek yerine, birbirini tamamlayan birden fazla uzman modulu ayni shell icinde barindirir. Bu sayede kullanici bir hedefi once `Recon` ile haritalayip, sonra `Spider` ile web yuzeyini derinlestirip, ardindan `PenguCore` ile trafik tarafini inceleyebilir.

## Ne Yapar?

PenguFoce bugunku haliyle su ana alanlara odaklanir:

- hedef kesfi ve yuzey haritalama
- acik port, servis ve temel teknoloji sinyali toplama
- modern web uygulamalarinda route, form, action ve auth sonrasi state kesfi
- offline ve live packet analizi
- HTTP/HTTPS akislarinin proxy uzerinden gozlemlenmesi
- oturum, rapor ve kanit export akislari

Bu yonuyle proje, tek amacli bir utility degil; analist odakli, masaustu bir guvenlik workbench'i olarak dusunulmelidir.

## Ana Moduller

### PenguCore

PenguCore, projenin ag analiz cekirdegidir. Hem offline `pcap/pcapng` dosyalarini okuyabilir hem de live capture akislarini sinirli ama operasyonel bir pencere icinde gosterebilir. Parser hatti su anda Ethernet, IPv4, ARP, TCP, UDP, ICMP, DNS, HTTP ve TLS metadata seviyesinde anlamli cozumleme yapar.

One cikan yetenekler:

- live ve offline packet analizi
- flow/session takibi
- DNS query/answer parse
- HTTP request/response header ve body preview
- TLS ClientHello / ServerHello / Certificate metadata
- stream preview, arama, export ve raporlama

### Recon

Recon modulu hedefin ilk haritasini cikarmaya odaklanir. DNS, port, teknoloji ve OSINT sinyallerini tek raporda toplar. Ayrica `Spider` modulunden gelen web yuzeyi kanitlarini da rapora baglayabilir.

One cikan yetenekler:

- DNS ve alan adi odakli kesif
- port ve servis tarama
- teknoloji ve yuzey sinyali toplama
- bulgu, kanit ve oturum bazli raporlama
- onceki oturumlarla karsilastirma

### Spider

Spider modulu, modern web uygulamalarinda klasik link toplamanin otesine gecmek icin gelistirilmistir. HTML linkleri, form action'lari, inline script route'lari, JS bundle route izleri, rendered DOM farklari, service worker ve manifest tabanli yuzeyleri birlikte kazimaya odaklanir.

One cikan yetenekler:

- async crawl ve kapsam kontrollu gezme
- form/action/parameter toplama
- JS route mining
- auth-aware crawl
- rendered DOM ve browser automation tabanli state kesfi
- manifest, service worker ve cache zinciri yuzeyi

### Proxy

Proxy modulu, lokal ve kontrollu ortamlarda HTTP/HTTPS akislarini gozlemlemek icin kullanilir. Trafik akisi, waterfall gorunumu ve istek/yanit eksenli analiz bu modulu destekler.

### Port Scanner

Port Scanner modulu, hizli port yoklamasi ve temel banner/sinyal toplamaya odaklanir. Tek basina kullanilabildigi gibi Recon akisi icinde de deger uretir.

### Ayarlar / Gunlukler

Kontrol merkezi niteligindeki bu alan, tema, ayar, genel durum ve uygulama loglarini tek yerde toplar.

## Mimari Yaklasim

Proje genel olarak uc katmanli bir duzene yaklasir:

1. `libs`
   Gercek cekirdek mantik burada bulunur. Su an en belirgin ic kutuphane `pengucore`'dur.

2. `modules`
   Moduller, cekirdek servisleri ve uygulama shell'i arasindaki kopru katmandir.

3. `ui`
   Widget, shell, panel ve ekranlar burada bulunur.

Bu ayrim sayesinde UI ile motor mantigi birbirinden ayrilmis olur. Ozellikle `PenguCore` artik dogrudan `src/libs/pengucore` altinda yasayan bir internal library olarak gelistirilmektedir.

## Klasor Yapisi

Projenin ozet yapisi su mantikla okunabilir:

```text
src/
  controllers/   Uygulama akisi ve app seviyesinde yonetim
  core/          Ortak altyapi, framework, ayar, log, tema
  libs/          Internal kutuphaneler
    pengucore/   Packet capture ve analiz cekirdegi
  modules/       Modul bazli is akisi kopruleri
  ui/            Shell, layout, panel ve ekranlar
tests/           Otomatik testler ve fixture dosyalari
tools/           Yardimci scriptler ve fixture ureticileri
```

## UI Yaklasimi

Arayuz, tek tek ekran bazli degil, ortak bir layout mantigiyla ilerler:

- solda sabit genislikli orb/sidebar alani
- sagda genisleyebilir ana calisma alani
- ustte kontrol ve ozet bloklari
- altta kalan alani dolduran ana veri/analiz paneli

Bu sayede moduller arasinda daha tutarli bir gezinme ve daha az karmasa hedeflenir.

## Teknolojik Notlar

Uygulama yerel masaustu odaklidir. UI, shell ve widget katmani masaustu pencere mantigiyla ilerler. Ag, capture, parser ve crawl taraflari moduler siniflar ve ic servisler uzerinden kurgulanmistir.

Spider tarafinda hem klasik fetch tabanli crawl hem de browser-state exploration mantigi vardir. PenguCore tarafinda ise parser ve capture hatti tek cekirdekte birlestirilir.

## Build ve Test

Projeyi derlemek icin:

```powershell
cmake -S . -B build
cmake --build build
```

Testleri calistirmak icin:

```powershell
ctest --test-dir build --output-on-failure
```

## Su Anki Durum

Proje aktif gelisim halindedir. En olgun alanlar:

- UI shell ve ortak layout omurgasi
- PenguCore packet analysis hatti
- Recon raporlama ve kesif akisi
- Spider'in modern web yuzeyi kazima yetenekleri

Gelismeye acik alanlar:

- Spider'i daha da stateful ve zorlu hedeflerde daha adaptif hale getirmek
- PenguCore'da daha derin stream/reassembly kabiliyetleri
- saha kalitesini artiracak daha genis test fixture setleri

## Tasarim Hedefi

PenguFoce'nin uzun vadeli hedefi, farkli guvenlik araclarini tek ekranda yigmak degil; analistin gercek is akisina uyan, moduler ama birlikte calisan bir urun ortaya cikarmaktir. Bu nedenle proje, her modulu ayni seviyede buyutmek yerine, ozellikle `PenguCore`, `Recon` ve `Spider` etrafinda guclu bir cekirdek olusturmaya odaklanmaktadir.

