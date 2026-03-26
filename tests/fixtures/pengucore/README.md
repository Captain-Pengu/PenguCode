# PenguCore Test Fixtures

Bu klasordeki `pcap` ve `pcapng` dosyalari `PenguCore` cekirdegini adim adim test etmek icin uretilir.

Mevcut fixture seti:

- `tcp_ipv4_sample.pcap`
- `udp_ipv4_sample.pcap`
- `multi_dns_sample.pcap`
- `http_ipv4_sample.pcap`
- `http_response_sample.pcap`
- `http_exchange_sample.pcap`
- `pcapng_http_sample.pcapng`
- `arp_sample.pcap`
- `short_frame_sample.pcap`
- `mixed_sample.pcap`

Dosyalari yeniden uretmek icin:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\generate_pengucore_test_pcaps.ps1
```

Beklenen parser sonuclari:

- `tcp_ipv4_sample.pcap`: `Ethernet / IPv4 / TCP`
- `udp_ipv4_sample.pcap`: `Ethernet / IPv4 / UDP / DNS Query example.com`
- `multi_dns_sample.pcap`: iki farkli DNS query ve iki ayri UDP flow
- `http_ipv4_sample.pcap`: `Ethernet / IPv4 / TCP / HTTP GET /`
- `http_response_sample.pcap`: `Ethernet / IPv4 / TCP / HTTP Response 200`
- `http_exchange_sample.pcap`: iki request-response ciftini ve iki HTTP flow'unu gosterir
- `pcapng_http_sample.pcapng`: `Ethernet / IPv4 / TCP / HTTP`
- `arp_sample.pcap`: `Ethernet / ARP / Request`
- `short_frame_sample.pcap`: `Kisa frame`
- `mixed_sample.pcap`: DNS, HTTP, ARP ve kisa frame davranislarini ayni oturumda test eder
