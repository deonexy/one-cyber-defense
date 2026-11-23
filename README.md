# Cyber Defense & Command Center

**Layer Pelengkap Wazuh & SIEM yang Ramah Lintas Tim (Tim Development, Support IT, Helpdesk & Pimpinan) + Rekomendasi Tindakan Respons Insiden**

![Mode](https://img.shields.io/badge/Mode-Live%20%26%20Demo%20Sandbox-10b981)
![Stack](https://img.shields.io/badge/Stack-React%2019%20%2B%20Express%20%2B%20Tailwind%20v4-0ea5e9)
![Node](https://img.shields.io/badge/Node.js-%3E%3D%2020.x-339933)

---

## Ringkasan Aplikasi

**Cyber Defense & Command Center** adalah dasbor operasional keamanan siber (*Security Operations Center* / SOC) yang dirancang sebagai **jembatan komunikasi dan eksekusi** di atas mesin deteksi teknis seperti **Wazuh, Nginx/Apache WAF, dan SIEM**.

Sering kali alert mentah dari SIEM/Wazuh terlalu teknis (*rule ID*, *regex*, *log raw JSON*) sehingga sulit langsung dipahami oleh **Tim Development**, **Support IT / Helpdesk**, maupun **Pimpinan / CTO**. Aplikasi ini menerjemahkan telemetri keamanan nyata menjadi:
- **Bahasa bisnis & dampak layanan** yang mudah dipahami lintas divisi.
- **Saran tindakan langkah demi langkah (*Action Advisor*)** beserta estimasi prioritas SLA ketika terdeteksi serangan, anomali, atau kelemahan konfigurasi.
- **Eksekusi Playbook & Mitigasi (*SOAR Workflow*)** untuk merespons alert secara terstruktur dan terdokumentasi.
- **Laporan Eksekutif Siap Cetak / Ekspor** untuk kebutuhan audit dan rapat pimpinan.

---

## Mode Operasi: Live Mode vs Demo Sandbox Mode

Di bagian **Top Bar Header** (selalu terlihat di setiap halaman), tersedia tombol switch untuk beralih antara dua mode operasi:

### 1. Live Mode *(Default)*
- Menampilkan **data telemetri nyata apa adanya** hasil probe server-side (`HTTP/TLS/DNS`), pemindaian integritas konten, webhook SIEM/Wazuh nyata (`POST /api/ingest/siem`), feed Global Open CTI, serta mesin FIM/SCA lokal.
- **Tampilan bersih tanpa teks panduan belajar (*guidance-free*)** agar ruang kerja tetap lapang saat operasional harian.
- Dilengkapi **Hover Tooltip (`ActionTooltip`)** pada setiap tombol, tautan, dan kontrol interaktif untuk menjelaskan fungsi tombol dan mencegah salah klik saat penanganan insiden nyata.

### 2. Demo Mode *(Training Sandbox)*
- Mengaktifkan **paket data pelatihan SOC lengkap** secara terisolasi (tidak mencemari data produksi di disk), mencakup simulasi serangan **SQL Injection / Credential Stuffing**, simulasi **Defacement / SEO Poisoning (Googlebot Cloaking)**, feed CTI latihan, serta skenario eksekusi playbook.
- Cocok digunakan untuk onboarding tim baru, simulasi *tabletop exercise*, dan latihan *best practice* penanganan insiden.
- Dilengkapi tombol **`Salin ke Live`** (*Copy to Live*) jika hasil latihan/draf laporan ingin dipindahkan ke modul Live Report, serta tombol **`Reset Demo`** untuk mengulang skenario latihan dari awal.

---

## Daftar 14 Fitur & Modul Command Center

1. **Command Overview**
   Ringkasan postur keamanan *real-time*, metrik latensi & SLA endpoint web, peta topologi infrastruktur, serta *24-Hour Incident Timeline Scrubber* untuk meninjau kronologi kejadian per jam.
2. **Action Advisor (Saran Tindakan)**
   Menerjemahkan temuan teknis dan ancaman aktif menjadi **rencana tindakan konkret** yang dikategorikan untuk **Tim Development**, **Tim Infrastruktur / SysAdmin**, dan **Support IT / Helpdesk**, lengkap dengan prioritas urgensi dan panduan verifikasi perbaikan.
3. **IR Playbooks (Incident Response Playbook Integration)**
   Menampilkan daftar `ThreatIntelAlert` berstatus `OPEN` dengan tombol **`Run Playbook`** untuk mengeksekusi langkah respons terstruktur, serta daftar `LiveAttackEvent` (`DETECTED` / `CHALLENGED`) dengan tombol **`Mitigate`** (beserta dialog konfirmasi) yang mencatat aktor mitigasi (`SOC-Analyst-Auto`) dan *timestamp* secara dinamis.
4. **Support IT & Health**
   Panel diagnostik ramah Helpdesk/Support IT untuk mengecek kesehatan portal, membedakan gangguan jaringan vs serangan keamanan, matriks eskalasi kontak PIC antar-divisi, serta *template* balasan komunikasi pengguna saat terjadi gangguan.
5. **Board & CTO Report (Executive Report)**
   Menyusun ringkasan postur keamanan, eksposur ancaman, dan peta jalan penguatan (*Security Strengthening Roadmap*) yang dapat diekspor ke **HTML / Word (`.doc`), Markdown (`.md`), dan CSV**.
6. **Incident Reports (Dual-UA Content & Cloaking Scanner)**
   Pencatatan laporan insiden manual/internal serta pemindai integritas konten HTTP dengan **Dual User-Agent** (membandingkan respons *Browser Normal* vs *Search Engine Crawler/Googlebot*) untuk mendeteksi *defacement* terselubung atau injeksi *SEO Spam/Cloaking*.
7. **Incident Triage Wizard** *(terintegrasi di alur pelaporan)*
   Panduan triase cepat **3 langkah** untuk membantu tim non-teknis mengklasifikasikan gejala insiden, mengisolasi dampak awal, dan menentukan rute eskalasi (`INFRA_OPS`, `ORG_CSIRT`, `GOV_CERT`, `INTERNAL_STAFF`).
8. **Local SIEM / XDR (FIM & SCA Engine)**
   Mesin lokal berbasis Node.js untuk **File Integrity Monitoring (FIM)** berbasis hash SHA-256, **Security Configuration Assessment (SCA)** mengacu standar CIS Benchmark, serta korelasi log lokal tanpa ketergantungan layanan eksternal.
9. **Local Agent Config**
   Pengaturan path target pemantauan FIM lokal, direktori webroot/Nginx, jadwal interval pemindaian, serta ekspor konfigurasi agen lokal dalam format JSON.
10. **Global Threat Intel (6 Open CTI Feeds)**
    Mengambil dan mengorelasikan data intelijen ancaman terbuka secara langsung dari sumber publik (CISA KEV, NVD CVE, URLhaus, ThreatFox, OpenPhish, dan Certificate Transparency `crt.sh`), termasuk pencocokan kata kunci domain/merek organisasi.
11. **Headers & TLS Audit**
    Inspeksi langsung (*live socket & HTTP*) terhadap sertifikat TLS/SSL (masa berlaku, *cipher suite*, protokol), cookie flags (`HttpOnly`, `Secure`, `SameSite`), serta *HTTP Security Headers* (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
12. **DNS & Anti-Spoofing Audit**
    Pemeriksaan catatan DNS domain utama (`SPF`, `DMARC`, `DKIM`, `CAA`, `MX`, `NS`) untuk mencegah penyalahgunaan domain (*email spoofing* / *phishing*).
13. **Verified Findings**
    Daftar seluruh temuan keamanan terverifikasi beserta status progres penanganannya (`OPEN`, `IN_PROGRESS`, `RESOLVED`, `ACCEPTED_RISK`) untuk memantau tindak lanjut perbaikan oleh tim teknis.
14. **Cyber Academy & Living Glossary**
    Kamus istilah keamanan siber interaktif yang bisa ditambah/disesuaikan oleh tim internal (`soc-custom-glossary.json`), dilengkapi kuis pemahaman insiden dan ringkasan advisori terbaru.
15. **Audit Log & Export**
    Jejak audit kronologis seluruh aktivitas probe, pemindaian, eksekusi playbook, dan mitigasi dengan dukungan ekspor **CSV** dan **JSON**.

---

## Arsitektur & Stack Teknologi

- **Frontend:** React 19, TypeScript, Tailwind CSS v4, Lucide Icons, Motion, Recharts, D3-Geo + TopoJSON.
- **Backend Proxy & Collector:** Express 4 (`server.ts`) berjalan di port `3000` (dev & production), menyediakan REST API + **Server-Sent Events (`GET /api/real/stream`)** untuk pembaruan telemetri *real-time*.
- **Inspeksi Native Server-Side:** Modul `node:tls`, `node:dns/promises`, `node:crypto`, dan `fetch` server-side sehingga pemeriksaan TLS/DNS/HTTP bebas dari kendala CORS browser.
- **Penyimpanan Lokal Ringan:** State laporan insiden, konfigurasi agen lokal, dan glosarium kustom disimpan dalam file JSON lokal (`data/`, `soc-local-config.json`, `soc-custom-glossary.json`) yang sudah di-*exclude* di `.gitignore`.

---

## Konfigurasi Environment (`.env`)

Salin `.env.example` menjadi `.env` sebelum menjalankan aplikasi. Seluruh konfigurasi sensitif dan spesifik organisasi dibaca hanya di sisi server:

| Variabel | Keterangan | Contoh |
| --- | --- | --- |
| `PORT` | Port server HTTP Express & Vite | `3000` |
| `ORG_NAME` | Nama organisasi yang tampil pada dasbor & laporan | `Acme Enterprise` |
| `TARGET_PORTAL_URL` | URL portal utama yang dipantau kesehatannya (HTTP/TLS) | `https://example.org` |
| `TARGET_SECONDARY_URL` | URL portal/layanan sekunder (opsional) | `https://status.example.org` |
| `TARGET_LOGIN_URL` | Endpoint autentikasi/SSO untuk pemantauan latensi login (opsional) | `https://sso.example.org/login` |
| `TARGET_ROOT_DOMAIN` | Root domain untuk audit DNS SPF/DMARC/CAA & `crt.sh` | `example.org` |
| `CTI_BRAND_KEYWORDS` | Kata kunci pencocokan feed OpenPhish (dipisahkan koma) | `acme,portal,sso,login` |
| `INGEST_SHARED_SECRET` | Secret token opsional untuk proteksi webhook `POST /api/ingest/siem` | `rahasia-webhook-soc` |
| `SIEM_STREAM_URL` / `SIEM_API_KEY` | Endpoint & kunci API Wazuh / Elastic SIEM upstream (opsional) | - |
| `WAF_WEBHOOK_URL` / `SOAR_WEBHOOK_URL` | Endpoint webhook orkestrasi WAF/SOAR dua arah (opsional) | - |
| `OPENCTI_GRAPHQL_URL` / `GOV_CERT_TAXII_URL` | Endpoint feed OpenCTI / STIX2-TAXII (opsional) | - |

---

## Tutorial Instalasi Lokal (Step-by-Step)

### 1. Prasyarat Sistem
Pastikan perangkat lokal/server Anda sudah terpasang:
- **Git**
- **Node.js** versi `>= 20.x` (disarankan **Node.js v22.18+ / v23+** jika ingin menjalankan `npm start` secara native tanpa transpiler tambahan)
- **npm** (terpasang otomatis bersama Node.js)

Cek versi di terminal:
```bash
node -v
npm -v
git --version
```

### 2. Clone Repository
```bash
git clone https://github.com/deonexy/cyber-defense.git
cd cyber-defense
```

### 3. Instalasi Dependensi
```bash
npm install
```

### 4. Konfigurasi Variabel Lingkungan (`.env`)
Salin file template `.env.example` menjadi `.env`:
```bash
cp .env.example .env
```
Lalu buka file `.env` dan sesuaikan target pemantauan organisasi Anda:
```env
PORT=3000
ORG_NAME="Perusahaan Anda"
TARGET_PORTAL_URL="https://portal-anda.example.org"
TARGET_SECONDARY_URL=""
TARGET_LOGIN_URL=""
TARGET_ROOT_DOMAIN="example.org"
CTI_BRAND_KEYWORDS="portal,sso,login"
INGEST_SHARED_SECRET="ganti-dengan-token-acak-yang-kuat"
```

### 5. Menjalankan Aplikasi

#### A. Mode Development (dengan Vite Middleware)
```bash
npm run dev
```
Server akan aktif dan dapat diakses melalui browser di:
```text
http://localhost:3000
```

#### B. Mode Production
Bangun aset frontend terlebih dahulu lalu jalankan server Express:
```bash
npm run build
NODE_ENV=production npx tsx server.ts
```
*(Jika menggunakan **Node.js v22.18+ / v23+**, Anda juga dapat langsung menjalankan `NODE_ENV=production npm start` karena Node sudah mendukung eksekusi TypeScript native.)*

### 6. Verifikasi TypeScript & Kualitas Kode
```bash
npm run lint
npm run build
```

---

## Contoh Integrasi Webhook SIEM / Wazuh / WAF

Aplikasi menyediakan endpoint `POST /api/ingest/siem` untuk menerima alert nyata dari **Wazuh Active Response**, **Nginx/ModSecurity**, **Cloudflare**, atau script log forwarder internal Anda.

Contoh pengujian pengiriman event serangan dari terminal:
```bash
curl -X POST http://localhost:3000/api/ingest/siem \
  -H "Content-Type: application/json" \
  -H "x-soc-ingest-secret: ganti-dengan-token-acak-yang-kuat" \
  -d '{
    "rule_id": "31103",
    "severity": "HIGH",
    "attack_type": "SQL Injection Attempt",
    "source_ip": "198.51.100.42",
    "target_path": "/api/v1/auth/login",
    "method": "POST",
    "action_taken": "DETECTED",
    "summary": "Deteksi pola payload UNION SELECT pada parameter username"
  }'
```
Event yang masuk akan langsung disiarkan melalui SSE (`/api/real/stream`) ke dasbor **Live Mode** dan muncul pada modul **IR Playbooks** untuk ditindaklanjuti dengan tombol **Mitigate**.

---

## Panduan Sinkronisasi Git Lokal ke GitHub

Jika Anda melakukan modifikasi lokal dan ingin mengunggah perubahan ke repository GitHub:

```bash
# 1. Pastikan status bersih dan tidak ada file .env atau data sensitif yang ikut ter-stage
git status

# 2. Tambahkan perubahan
git add .

# 3. Buat commit
git commit -m "docs: update configuration and documentation"

# 4. Push ke branch main
git push -u origin main
```

---

## Lisensi & Catatan Keamanan Publik

- Jangan pernah mengunggah file `.env`, kredensial API, atau file dump data insiden nyata (`data/`, `soc-local-config.json`, `soc-custom-glossary.json`) ke repository publik. Semua file runtime tersebut telah dikecualikan secara otomatis di `.gitignore`.
- Data simulasi pada **Demo Mode** menggunakan domain dan rentang IP standar dokumentasi (**RFC 5737 / RFC 6996** seperti `example-corp.test`, `203.0.113.*`, dan `AS64512`).
