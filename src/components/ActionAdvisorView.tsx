import React, { useMemo, useState } from 'react';
import {
  Compass,
  Users,
  Code2,
  Headphones,
  Briefcase,
  Copy,
  Check,
  Search,
  ChevronDown,
  ChevronUp,
  Send,
  ArrowUpRight,
  CheckCircle2,
  FilePlus2,
  RefreshCw,
} from 'lucide-react';
import {
  ContentIntegrityScan,
  GlobalThreatIntelSnapshot,
  IncidentReportCategory,
  LocalWazuhSnapshot,
  ManualIncidentReport,
  RealDnsSecurityAudit,
  RealEndpointProbe,
  RealSecurityFinding,
  RealSocView,
  Severity,
} from '../types/soc';
import { SeverityBadge, CATEGORY_LABELS } from './IncidentReportsView';
import { ActionTooltip } from './ActionTooltip';
import { useSocMode } from '../context/SocModeContext';
import { formatShortDateTime } from '../utils/socFormatters';

interface ActionAdvisorViewProps {
  endpoints: RealEndpointProbe[];
  dnsAudit: RealDnsSecurityAudit | null;
  findings: RealSecurityFinding[];
  contentScans: ContentIntegrityScan[];
  incidentReports: ManualIncidentReport[];
  localWazuh: LocalWazuhSnapshot | null;
  threatIntel: GlobalThreatIntelSnapshot | null;
  scanningNow: boolean;
  onRunLiveScan: () => Promise<void>;
  onCreateIncident: (
    payload: Omit<ManualIncidentReport, 'id' | 'reportedAt' | 'updatedAt'>
  ) => Promise<void>;
  onNavigateView: (view: RealSocView) => void;
}

type RoleLens = 'ALL' | 'SUPPORT_IT' | 'DEVELOPMENT' | 'LEADERSHIP';
type AdvisorySourceFilter =
  | 'ALL'
  | 'CONTENT_DEFACEMENT'
  | 'INCIDENT_REPORT'
  | 'HTTP_TLS'
  | 'DNS_EMAIL'
  | 'WAZUH_SIEM'
  | 'GLOBAL_CTI';

type SnippetStack = 'nginx' | 'apache' | 'nodejs' | 'php';
type EscalationChannel = 'infra' | 'csirt' | 'whatsapp';

interface FixSnippets {
  nginx?: string;
  apache?: string;
  nodejs?: string;
  php?: string;
}

interface ActionAdvisory {
  id: string;
  severity: Severity;
  sourceGroup: Exclude<AdvisorySourceFilter, 'ALL'>;
  sourceLabel: string;
  target: string;
  detectedAt: string;
  title: string;
  plainSummary: string;
  businessImpact: string;
  evidence: string;
  picOwner: string;
  slaTarget: string;
  needsInfraEscalation: boolean;
  supportSteps: string[];
  devSteps: string[];
  leadershipSteps: string[];
  fixSnippets?: FixSnippets;
  incidentCategory: IncidentReportCategory;
  alreadyIncidentReport: boolean;
  relatedView: RealSocView;
}

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const SOURCE_LABELS: Record<Exclude<AdvisorySourceFilter, 'ALL'>, string> = {
  CONTENT_DEFACEMENT: 'Konten & Defacement',
  INCIDENT_REPORT: 'Laporan Insiden',
  HTTP_TLS: 'Header, TLS & Uptime',
  DNS_EMAIL: 'DNS & Anti-Spoofing',
  WAZUH_SIEM: 'SIEM / Wazuh Layer',
  GLOBAL_CTI: 'Global CTI',
};

function getHeaderFixSnippets(titleLower: string): FixSnippets | undefined {
  if (titleLower.includes('content-security-policy') || titleLower.includes('csp')) {
    return {
      nginx: `# Tambahkan di blok server {} Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'; object-src 'none';" always;`,
      apache: `# Tambahkan di .htaccess atau VirtualHost Apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'; object-src 'none';"`,
      nodejs: `// Gunakan middleware helmet pada Express / Node.js
import helmet from 'helmet';
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    frameAncestors: ["'none'"],
    objectSrc: ["'none'"],
  },
}));`,
      php: `// Tambahkan pada middleware/bootstrap PHP atau Laravel
header("Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none';");`,
    };
  }

  if (titleLower.includes('strict-transport-security') || titleLower.includes('hsts')) {
    return {
      nginx: `# Paksa seluruh koneksi browser memakai HTTPS (HSTS 1 tahun)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
      apache: `# Tambahkan di VirtualHost HTTPS (port 443)
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
      nodejs: `import helmet from 'helmet';
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));`,
      php: `header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');`,
    };
  }

  if (titleLower.includes('x-frame-options') || titleLower.includes('clickjacking')) {
    return {
      nginx: `# Cegah portal organisasi disematkan ke iframe situs phishing
add_header X-Frame-Options "DENY" always;`,
      apache: `Header always set X-Frame-Options "DENY"`,
      nodejs: `import helmet from 'helmet';
app.use(helmet.frameguard({ action: 'deny' }));`,
      php: `header('X-Frame-Options: DENY');`,
    };
  }

  if (titleLower.includes('x-content-type-options') || titleLower.includes('nosniff')) {
    return {
      nginx: `# Cegah browser menebak tipe file (MIME sniffing)
add_header X-Content-Type-Options "nosniff" always;`,
      apache: `Header always set X-Content-Type-Options "nosniff"`,
      nodejs: `import helmet from 'helmet';
app.use(helmet.noSniff());`,
      php: `header('X-Content-Type-Options: nosniff');`,
    };
  }

  if (titleLower.includes('referrer-policy')) {
    return {
      nginx: `# Batasi kebocoran URL/token sesi saat user klik link keluar
add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
      apache: `Header always set Referrer-Policy "strict-origin-when-cross-origin"`,
      nodejs: `import helmet from 'helmet';
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));`,
      php: `header('Referrer-Policy: strict-origin-when-cross-origin');`,
    };
  }

  if (titleLower.includes('permissions-policy')) {
    return {
      nginx: `# Nonaktifkan akses fitur browser yang tidak diperlukan portal
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;`,
      apache: `Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"`,
      nodejs: `app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  next();
});`,
      php: `header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');`,
    };
  }

  if (titleLower.includes('server') || titleLower.includes('powered-by') || titleLower.includes('disclosure')) {
    return {
      nginx: `# Sembunyikan versi Nginx agar penyerang tidak mudah memetakan CVE
server_tokens off;
proxy_hide_header X-Powered-By;`,
      apache: `# Tambahkan di httpd.conf / apache2.conf
ServerTokens Prod
ServerSignature Off
Header always unset X-Powered-By`,
      nodejs: `// Nonaktifkan header X-Powered-By di Express
app.disable('x-powered-by');`,
      php: `; Ubah di php.ini lalu reload PHP-FPM
expose_php = Off`,
    };
  }

  if (titleLower.includes('cookie')) {
    return {
      nginx: `# Paksa atribut keamanan cookie pada reverse proxy
proxy_cookie_flags ~ secure httponly samesite=lax;`,
      nodejs: `res.cookie('session_id', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
});`,
      php: `; Konfigurasi session cookie aman di php.ini / .env Laravel
session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = "Lax"`,
    };
  }

  return undefined;
}

function buildEscalationDraft(
  adv: ActionAdvisory,
  channel: EscalationChannel
): string {
  const timeStr = `${formatShortDateTime(adv.detectedAt)} WIB`;

  if (channel === 'infra') {
    return `[TIKET ESKALASI KEAMANAN -> TIM INFRA / SERVER OPS]
Prioritas / Severity : ${adv.severity} (Target SLA: ${adv.slaTarget})
Waktu Deteksi        : ${timeStr}
Sistem / Target      : ${adv.target}
Sumber Pemantauan    : ${adv.sourceLabel} (Cyber Defense SOC Layer)

RINGKASAN TEMUAN:
${adv.title}
${adv.plainSummary}

BUKTI AWAL (EVIDENCE):
${adv.evidence}

PERMOHONAN TINDAK LANJUT (TIM INFRA / PENGELOLA SERVER):
${adv.devSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}

Mohon nomor tiket penanganan dan estimasi waktu perbaikan untuk kami laporkan pada rapat CTO & Manajemen. Terima kasih.`;
  }

  if (channel === 'csirt') {
    return `[NOTIFIKASI INSIDEN KEAMANAN — INTERNAL CSIRT / GOV-CERT]
Kategori  : ${CATEGORY_LABELS[adv.incidentCategory]}
Severity  : ${adv.severity}
Target    : ${adv.target}
Waktu     : ${timeStr}

Deskripsi Singkat:
${adv.plainSummary}

Dampak Potensial:
${adv.businessImpact}

Indikator / Bukti Teknis:
${adv.evidence}

Langkah Awal Tim SOC:
${adv.supportSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}

Mohon asistensi verifikasi dan koordinasi mitigasi lintas unit bersama Tim Infrastruktur.`;
  }

  // WhatsApp Executive Brief for CTO / Pimpinan
  return `*Update Keamanan Layanan Organisasi [${adv.severity}]*
Sistem: ${adv.target}
Waktu: ${timeStr}

*Situasi:* ${adv.title}
${adv.plainSummary}

*Dampak Layanan/Reputasi:* ${adv.businessImpact}

*Tindakan Saat Ini:*
• PIC: ${adv.picOwner} (Target SLA: ${adv.slaTarget})
• Langkah Pimpinan: ${adv.leadershipSteps[0] ?? 'Pantau progres tindak lanjut bersama Tim Infra & Tim TI.'}

_Dihasilkan dari Cyber Defense Command Center._`;
}

function buildLiveActionAdvisories(params: {
  endpoints: RealEndpointProbe[];
  dnsAudit: RealDnsSecurityAudit | null;
  findings: RealSecurityFinding[];
  contentScans: ContentIntegrityScan[];
  incidentReports: ManualIncidentReport[];
  localWazuh: LocalWazuhSnapshot | null;
  threatIntel: GlobalThreatIntelSnapshot | null;
}): ActionAdvisory[] {
  const {
    findings,
    contentScans,
    incidentReports,
    localWazuh,
    threatIntel,
    dnsAudit,
  } = params;

  const list: ActionAdvisory[] = [];

  // 1. Live HTML Defacement & Googlebot Cloaking alerts
  for (const scan of contentScans) {
    if (scan.riskLevel === 'CLEAN') continue;
    const kws = Array.from(
      new Set([...scan.browserKeywordsFound, ...scan.googlebotKeywordsFound])
    );
    const isCritical = scan.riskLevel === 'CRITICAL';
    list.push({
      id: `adv-scan-${scan.endpointId}`,
      severity: isCritical ? 'CRITICAL' : 'HIGH',
      sourceGroup: 'CONTENT_DEFACEMENT',
      sourceLabel: 'Live Defacement & Cloaking Scanner',
      target: scan.url,
      detectedAt: scan.scannedAt,
      title: scan.defacementSuspected
        ? `Indikasi Injeksi Konten / Defacement pada ${scan.hostname}`
        : scan.cloakingSuspected
        ? `Perbedaan Respons Browser vs Googlebot (Indikasi Cloaking) pada ${scan.hostname}`
        : `Perubahan Hash Konten HTML di Luar Baseline pada ${scan.hostname}`,
      plainSummary: scan.defacementSuspected
        ? `Halaman web publik menampilkan kata kunci mencurigakan (${kws.join(', ')}) yang tidak seharusnya ada pada layanan resmi organisasi.`
        : scan.cloakingSuspected
        ? `Halaman yang tampil di pengunjung normal berbeda dengan halaman yang diberikan ke robot mesin pencari Google—pola khas serangan SEO judi online.`
        : `Isi kode HTML pada halaman berubah dibandingkan baseline resmi yang terakhir disetujui. Perlu dipastikan apakah ini rilis resmi atau perubahan tidak sah.`,
      businessImpact:
        'Risiko tinggi terhadap reputasi publik organisasi di hasil pencarian Google, serta potensi pengalihan pengguna ke situs ilegal.',
      evidence: `Browser Title: "${scan.browserTitle ?? '-'}" | Googlebot Title: "${scan.googlebotTitle ?? '-'}" | Keywords: ${kws.join(', ') || 'None'} | SHA-256: ${scan.browserHashSha256?.slice(0, 16) ?? '-'}`,
      picOwner: 'Tim Infra / Server Ops + Tim Dev + Internal CSIRT',
      slaTarget: isCritical ? '< 1 Jam' : '< 4 Jam',
      needsInfraEscalation: true,
      supportSteps: [
        'Buka URL terdampak di mode Incognito dan cek hasil pencarian Google (site:domain) lalu ambil tangkapan layar (screenshot) sebagai barang bukti.',
        'Jangan langsung menghapus bukti sebelum tim teknis mengambil salinan log akses & file terdampak.',
        'Kirim tiket eskalasi prioritas tinggi ke Tim Infra / Server Ops dan catat nomor tiket pada halaman Incident Reports.',
      ],
      devSteps: [
        'Audit file webroot, .htaccess, index.php, dan folder upload untuk mencari script tersembunyi (webshell) atau aturan rewrite khusus User-Agent Googlebot.',
        'Pulihkan kode aplikasi dari repositori Git / backup bersih yang sudah terverifikasi, lalu ganti seluruh kredensial FTP/SSH/CMS/DB.',
        'Setelah bersih, ajukan re-indexing dan penghapusan URL spam melalui Google Search Console.',
      ],
      leadershipSteps: [
        'Berikan otorisasi maintenance halaman sementara jika konten ilegal terlihat langsung oleh publik.',
        'Koordinasikan eskalasi pimpinan ke Tim Infra & CSIRT agar audit server dilakukan menyeluruh.',
        'Siapkan klarifikasi singkat bersama tim komunikasi jika temuan sempat beredar di media sosial.',
      ],
      fixSnippets: {
        nginx: `# Cegah eksekusi skrip PHP/CGI di folder upload (pencegahan webshell)
location ~* ^/(uploads|storage|files)/.*\\.(php|phtml|phar|cgi|pl)$ {
    deny all;
    return 403;
}`,
        apache: `# Letakkan di folder uploads/.htaccess untuk memblokir eksekusi webshell
<FilesMatch "\\.(php|phtml|phar|cgi|pl|sh)$">
    Require all denied
</FilesMatch>
Options -Indexes`,
      },
      incidentCategory: scan.cloakingSuspected
        ? 'GOOGLE_CLOAKING'
        : kws.length > 0
        ? 'SEO_POISONING_JUDOL'
        : 'WEB_DEFACEMENT',
      alreadyIncidentReport: false,
      relatedView: 'incident-reports',
    });
  }

  // 2. Active Recorded Incident Reports (Infra / Manual / Triaged)
  for (const rep of incidentReports) {
    if (rep.status === 'CLOSED') continue;
    const isPhishing = rep.category === 'PHISHING_IMPERSONATION';
    const isCredLeak = rep.category === 'CREDENTIAL_LEAK';
    list.push({
      id: `adv-inc-${rep.id}`,
      severity: rep.severity,
      sourceGroup: 'INCIDENT_REPORT',
      sourceLabel: `Incident Report (${rep.id})`,
      target: rep.affectedUrl,
      detectedAt: rep.occurredAt,
      title: rep.title,
      plainSummary:
        rep.description ||
        `Insiden aktif berkategori ${CATEGORY_LABELS[rep.category]} sedang berada pada tahap penanganan (${rep.status}).`,
      businessImpact: isPhishing
        ? 'Pengguna atau mitra berisiko memasukkan username/password ke situs palsu yang mengatasnamakan organisasi.'
        : isCredLeak
        ? 'Akun berisiko disalahgunakan untuk mengakses data sensitif atau mengubah data transaksi pengguna.'
        : 'Berpotensi mengganggu layanan publik organisasi, merusak integritas halaman web, dan menurunkan kepercayaan pengguna.',
      evidence:
        rep.evidenceSnippet ||
        `Pelapor: ${rep.reporterName} | Status saat ini: ${rep.status}`,
      picOwner: isPhishing
        ? 'Internal CSIRT + Gov-CERT + Komunikasi Publik'
        : 'Tim Infra / Server Ops + Tim TI / Dev',
      slaTarget:
        rep.severity === 'CRITICAL'
          ? '< 1 Jam'
          : rep.severity === 'HIGH'
          ? '< 4 Jam'
          : '1–3 Hari Kerja',
      needsInfraEscalation: true,
      supportSteps: [
        'Pastikan seluruh bukti terbaru (screenshot, URL, nomor tiket eskalasi) telah diperbarui di tabel Incident Reports.',
        isPhishing
          ? 'Informasikan ke Helpdesk untuk memperingatkan pengguna agar hanya mengakses domain resmi organisasi.'
          : 'Pantau keluhan masuk dari pengguna terkait layanan terdampak dan kumpulkan laporan error yang muncul.',
        'Lakukan follow-up berkala ke PIC Tim Infra/CSIRT sampai status dapat ditutup (Mitigated/Closed).',
      ],
      devSteps: isPhishing
        ? [
            'Periksa konfigurasi SPF/DKIM/DMARC domain email agar penyerang tidak bisa memalsukan email resmi organisasi.',
            'Tambahkan domain/IP phishing ke daftar blokir internal dan bantu pengumpulan data WHOIS untuk permintaan takedown.',
          ]
        : isCredLeak
        ? [
            'Cabut seluruh sesi aktif (revoke token/session), paksa reset password akun terdampak, dan wajibkan MFA.',
            'Audit log aktivitas 7–30 hari terakhir untuk memastikan tidak ada perubahan data atau akun backdoor baru.',
          ]
        : [
            'Verifikasi integritas kode sumber & konfigurasi server bersama Tim Infra sesuai checklist mitigasi pada Incident Triage Wizard.',
            'Pastikan celah akar penyebab (root cause) sudah ditambal sebelum layanan dibuka penuh kembali.',
          ],
      leadershipSteps: [
        'Pantau status penyelesaian insiden ini agar tidak melewati target SLA dan pastikan sudah dicentang untuk masuk Laporan CTO & BoD.',
        'Bantu eskalasi lintas unit (Tim Infra / CSIRT / Gov-CERT) jika tindak lanjut teknis terhambat.',
      ],
      incidentCategory: rep.category,
      alreadyIncidentReport: true,
      relatedView: 'incident-reports',
    });
  }

  // 3. Verified Live Findings (HTTP Headers, TLS, DNS, Availability, Info Disclosure)
  for (const f of findings) {
    if (f.status === 'RESOLVED') continue;
    const titleLower = `${f.title} ${f.evidence}`.toLowerCase();
    const isDns = f.category === 'DNS_EMAIL';
    const isAvail = f.category === 'AVAILABILITY';
    const isTls = f.category === 'TLS_CERT';
    const snippets = getHeaderFixSnippets(titleLower);

    let plainSummary =
      'Sistem pemantau menemukan konfigurasi keamanan eksternal yang belum optimal pada layanan publik organisasi.';
    let businessImpact =
      'Meningkatkan risiko eksploitasi sisi browser pengguna atau melemahkan pertahanan lapis luar layanan publik.';
    let supportSteps: string[] = [
      'Verifikasi status temuan ini di halaman Headers & TLS Audit atau DNS Audit untuk melihat detail endpoint terdampak.',
      'Koordinasikan jadwal penerapan perbaikan konfigurasi dengan Tim Development dan Tim Infrastruktur.',
    ];
    let devSteps: string[] = [
      f.remediation ||
        'Terapkan konfigurasi penguatan keamanan sesuai standar OWASP pada web server atau reverse proxy.',
      'Uji ulang di lingkungan staging untuk memastikan tidak ada fitur portal yang terganggu, lalu klik "Run Live Scan" untuk verifikasi otomatis.',
    ];
    let leadershipSteps: string[] = [
      'Jadikan temuan ini sebagai agenda penguatan (hardening) rutin pada rapat evaluasi TI bersama Tim Infrastruktur.',
      'Pastikan ada target tanggal penyelesaian yang jelas agar skor postur keamanan meningkat di laporan manajemen berikutnya.',
    ];

    if (isAvail) {
      plainSummary =
        'Layanan web terdeteksi tidak dapat diakses atau merespons sangat lambat dari jaringan luar.';
      businessImpact =
        'Pengguna tidak dapat mengakses portal layanan secara langsung; berpotensi memicu lonjakan keluhan ke Helpdesk.';
      supportSteps = [
        'Cek apakah sedang ada jadwal pemeliharaan (maintenance) resmi dari Tim Infra / Server Ops.',
        'Uji akses portal dari jaringan berbeda (misal data seluler) untuk membedakan gangguan lokal vs gangguan server pusat.',
        'Jika benar down di luar jadwal maintenance, segera buka tiket prioritas kritis ke Tim Infra dan informasikan tim Helpdesk.',
      ];
      devSteps = [
        'Periksa status layanan web server, beban CPU/RAM, koneksi database, serta log error aplikasi bersama Tim Infra.',
        'Cek apakah terjadi lonjakan trafik abnormal (indikasi DDoS L7 / bot scraping) pada WAF/load balancer.',
      ];
      leadershipSteps = [
        'Pantau estimasi waktu pemulihan (ETA) dari Tim Infra, khususnya saat jam sibuk layanan publik.',
        'Pertimbangkan publikasi pengumuman resmi di kanal komunikasi organisasi jika gangguan berlangsung > 30 menit.',
      ];
    } else if (isTls) {
      plainSummary =
        'Sertifikat enkripsi HTTPS (SSL/TLS) mendekati masa kedaluwarsa atau menggunakan konfigurasi enkripsi yang perlu diperbarui.';
      businessImpact =
        'Jika sertifikat kedaluwarsa, seluruh browser pengguna akan menampilkan peringatan merah "Situs Tidak Aman" dan menghalangi akses portal.';
      supportSteps = [
        'Catat tanggal kedaluwarsa sertifikat dari halaman Headers & TLS Audit dan buat pengingat eskalasi H-30 dan H-14.',
        'Hubungi PIC manajemen sertifikat Tim Infra untuk memastikan proses perpanjangan sudah dijadwalkan.',
      ];
      devSteps = [
        'Siapkan CSR/perpanjangan sertifikat TLS dan pastikan protokol TLS 1.2 / TLS 1.3 aktif tanpa cipher lemah.',
        'Setelah sertifikat dipasang, verifikasi rantai sertifikat (certificate chain) tidak terputus menggunakan tombol Run Live Scan.',
      ];
      leadershipSteps = [
        'Pastikan proses perpanjangan sertifikat masuk kalender operasional agar tidak pernah terjadi downtime akibat sertifikat kedaluwarsa.',
      ];
    } else if (isDns) {
      plainSummary =
        'Pengaturan anti-pemalsuan email/domain (SPF, DMARC, atau CAA) pada DNS masih longgar atau belum lengkap.';
      businessImpact =
        'Penyerang lebih mudah mengirim email palsu (phishing) yang mengaku sebagai organisasi atau menerbitkan sertifikat tidak sah atas nama domain.';
      supportSteps = [
        'Edukasi pegawai & pengguna untuk selalu memverifikasi keaslian email yang meminta data pribadi atau transfer dana.',
        'Teruskan hasil audit DNS ini kepada pengelola DNS / Tim Infrastruktur.',
      ];
      devSteps = [
        f.remediation,
        'Koordinasikan pembaruan TXT record (SPF/DMARC) dan CAA record di authoritative DNS secara bertahap (monitoring -> quarantine -> reject).',
      ];
      leadershipSteps = [
        'Dorong kebijakan penerapan DMARC reject/quarantine bersama Tim Infra untuk melindungi masyarakat dari penipuan email mengatasnamakan organisasi.',
      ];
    } else if (titleLower.includes('csp') || titleLower.includes('content-security-policy')) {
      plainSummary =
        'Portal belum mengirim aturan keamanan browser (Content-Security-Policy) untuk membatasi skrip asing yang boleh berjalan di halaman.';
      businessImpact =
        'Jika penyerang menyusupkan skrip berbahaya (XSS / injeksi banner ilegal), browser pengguna tidak memiliki pagar otomatis untuk memblokirnya.';
    } else if (titleLower.includes('hsts') || titleLower.includes('strict-transport-security')) {
      plainSummary =
        'Browser pengguna belum dipaksa secara permanen memakai koneksi terenkripsi HTTPS saat mengakses portal.';
      businessImpact =
        'Pengguna di jaringan Wi-Fi publik berisiko terkena serangan penyadapan/downgrade koneksi saat pertama kali mengetik alamat portal.';
    } else if (titleLower.includes('x-frame-options')) {
      plainSummary =
        'Halaman portal masih berpotensi disematkan ke dalam bingkai tersembunyi (iframe) di situs penipuan (Clickjacking).';
      businessImpact =
        'Pengguna bisa tertipu mengklik tombol penting tanpa sadar saat mengunjungi situs palsu.';
    } else if (titleLower.includes('server') || titleLower.includes('powered-by')) {
      plainSummary =
        'Server mempublikasikan nama/versi perangkat lunak web pada header respons HTTP.';
      businessImpact =
        'Mempermudah penyerang otomatis mencari kelemahan (CVE) yang cocok dengan versi server yang sedang digunakan.';
    }

    list.push({
      id: `adv-find-${f.finding_id}`,
      severity: f.severity,
      sourceGroup: isDns ? 'DNS_EMAIL' : 'HTTP_TLS',
      sourceLabel: isDns ? 'DNS & Anti-Spoofing Audit' : 'Live HTTP & TLS Audit',
      target: f.target,
      detectedAt: f.detected_at,
      title: f.title,
      plainSummary,
      businessImpact,
      evidence: f.evidence,
      picOwner: isDns
        ? 'Pengelola DNS & Tim Infrastruktur'
        : isAvail || isTls
        ? 'Tim Infra / Server Ops'
        : 'Tim Development + Admin Web Server',
      slaTarget:
        f.severity === 'CRITICAL'
          ? '< 2 Jam'
          : f.severity === 'HIGH'
          ? '1–3 Hari Kerja'
          : '7–14 Hari Kerja',
      needsInfraEscalation: isDns || isAvail || isTls || f.severity === 'HIGH' || f.severity === 'CRITICAL',
      supportSteps,
      devSteps,
      leadershipSteps,
      fixSnippets: snippets,
      incidentCategory: 'VULNERABILITY_REPORT',
      alreadyIncidentReport: false,
      relatedView: isDns ? 'dns-audit' : 'headers-tls',
    });
  }

  // 4. Local SIEM / Wazuh-Style Alerts (Host FIM / SCA / Network / Log Alerts)
  if (localWazuh) {
    const topAlerts = localWazuh.alerts.slice(0, 8);
    for (const al of topAlerts) {
      list.push({
        id: `adv-wazuh-${al.alert_id}`,
        severity: al.severity,
        sourceGroup: 'WAZUH_SIEM',
        sourceLabel: `SIEM / Wazuh Rule #${al.rule_id} (${al.source})`,
        target: `${al.agent_name} · ${al.target}`,
        detectedAt: al.timestamp,
        title: al.title,
        plainSummary:
          al.source === 'FIM'
            ? `File sensitif pada host lokal mengalami perubahan di luar baseline SHA-256 yang disetujui.`
            : al.source === 'NET_SENSOR'
            ? `Terdeteksi port jaringan terbuka pada host lokal yang tidak termasuk daftar port yang diizinkan.`
            : al.source === 'LOGCOLLECTOR'
            ? `Pola aktivitas mencurigakan terdeteksi pada log sistem/web server lokal (indikasi percobaan serangan atau brute-force).`
            : `Audit konfigurasi keamanan host (SCA) menemukan pengaturan sistem yang belum memenuhi standar pengerasan CIS.`,
        businessImpact:
          'Jika terjadi pada server produksi, kondisi ini dapat menjadi pintu masuk pengambilalihan server atau perubahan file aplikasi tanpa izin.',
        evidence: `${al.detail} | MITRE ATT&CK: ${al.mitre_id} (${al.mitre_tactic}) | Rule Level: ${al.rule_level}/15`,
        picOwner: 'Tim Infrastruktur / Admin Server',
        slaTarget:
          al.severity === 'CRITICAL'
            ? '< 1 Jam'
            : al.severity === 'HIGH'
            ? '< 4 Jam'
            : '3–7 Hari Kerja',
        needsInfraEscalation: al.severity === 'CRITICAL' || al.severity === 'HIGH',
        supportSteps: [
          'Konfirmasikan ke tim teknis apakah ada aktivitas pemeliharaan, update aplikasi, atau perubahan konfigurasi yang memang sedang berlangsung.',
          'Jika tidak ada jadwal perubahan resmi, segera eskalasikan ke admin server/Tim Infra sebagai anomali keamanan.',
        ],
        devSteps: [
          al.source === 'FIM'
            ? 'Bandingkan isi file saat ini dengan repositori/backup resmi. Jika perubahan sah, perbarui baseline lewat tombol "Accept Baseline" di Local SIEM.'
            : al.source === 'NET_SENSOR'
            ? 'Identifikasi proses yang membuka port tersebut (ss -tulpn) dan tutup layanan yang tidak diperlukan atau batasi di firewall.'
            : 'Periksa sumber IP/log terkait, terapkan rate-limiting/firewall block, dan tambal konfigurasi yang lemah.',
        ],
        leadershipSteps: [
          'Pastikan perubahan konfigurasi server selalu melalui prosedur Change Management agar alarm keamanan tidak bercampur dengan rilis tidak tercatat.',
        ],
        incidentCategory:
          al.source === 'FIM' ? 'WEB_DEFACEMENT' : 'VULNERABILITY_REPORT',
        alreadyIncidentReport: false,
        relatedView: 'wazuh-dashboard',
      });
    }
  }

  // 5. Global CTI Proactive Signals (Brand/ID Phishing or IP Reputation Alerts or Priority CISA KEV)
  if (threatIntel) {
    const listedIps = threatIntel.ipReputation.filter((ip) => ip.listedInThreatFeeds);
    for (const ip of listedIps) {
      list.push({
        id: `adv-cti-ip-${ip.ip}`,
        severity: 'CRITICAL',
        sourceGroup: 'GLOBAL_CTI',
        sourceLabel: 'Global CTI · IP Reputation',
        target: `${ip.hostname} (${ip.ip})`,
        detectedAt: ip.checkedAt,
        title: `IP Layanan (${ip.ip}) Tercatat pada Threat Feed Global`,
        plainSummary: `Alamat IP publik server (${ip.hostname}) muncul pada daftar pantau ancaman global (${ip.matchedFeeds.join(', ')}).`,
        businessImpact:
          'Email atau akses layanan berisiko diblokir oleh ISP/antivirus pengguna, atau menandakan adanya komponen terkompromi yang mengirim trafik berbahaya keluar.',
        evidence: `IP: ${ip.ip} | ASN: ${ip.asn ?? '-'} | Feed Match: ${ip.matchedFeeds.join(', ')}`,
        picOwner: 'Tim Infra Ops + Internal CSIRT',
        slaTarget: '< 2 Jam',
        needsInfraEscalation: true,
        supportSteps: [
          'Laporkan segera ke Tim Infra Ops untuk memeriksa trafik keluar (outbound) dari IP publik tersebut.',
        ],
        devSteps: [
          'Audit seluruh server yang berbagi NAT/IP publik tersebut terhadap indikasi malware, spam mailer, atau proxy ilegal.',
          'Ajukan delisting ke penyedia threat feed setelah sumber trafik anomali dipastikan bersih.',
        ],
        leadershipSteps: [
          'Koordinasikan pembersihan dan pengajuan delisting bersama Tim Infra agar akses pengguna ke portal tidak terhambat.',
        ],
        incidentCategory: 'OTHER',
        alreadyIncidentReport: false,
        relatedView: 'threat-intel',
      });
    }

    if (threatIntel.openPhish.brandOrIndonesiaMatches.length > 0) {
      const sample = threatIntel.openPhish.brandOrIndonesiaMatches.slice(0, 3);
      list.push({
        id: 'adv-cti-phish-id',
        severity: 'HIGH',
        sourceGroup: 'GLOBAL_CTI',
        sourceLabel: 'Global CTI · OpenPhish Radar',
        target: sample.map((s) => s.domain).join(', '),
        detectedAt: threatIntel.lastSyncedAt ?? new Date().toISOString(),
        title: `Terdeteksi ${threatIntel.openPhish.brandOrIndonesiaMatches.length} URL Phishing Aktif Berkaitan Keyword Brand/Target`,
        plainSummary:
          'Radar phishing global mendeteksi situs penipuan aktif yang cocok dengan daftar kata kunci pengawasan organisasi.',
        businessImpact:
          'Meningkatkan risiko penipuan siber terhadap pegawai maupun pengguna layanan resmi melalui tautan palsu.',
        evidence: sample.map((s) => s.url).join(' | '),
        picOwner: 'Tim Support IT + Internal CSIRT',
        slaTarget: '< 24 Jam',
        needsInfraEscalation: false,
        supportSteps: [
          'Periksa daftar URL di menu Global Threat Intel untuk memastikan tidak ada yang meniru domain resmi organisasi.',
          'Jika ada yang meniru identitas organisasi, segera buka Incident Triage Wizard kategori Phishing dan laporkan ke CSIRT/Registrar untuk takedown.',
        ],
        devSteps: [
          'Pastikan seluruh domain phishing yang relevan diblokir pada DNS/proxy jaringan internal kantor.',
        ],
        leadershipSteps: [
          'Pertimbangkan imbauan kewaspadaan berkala bagi pengguna melalui kanal komunikasi resmi organisasi.',
        ],
        incidentCategory: 'PHISHING_IMPERSONATION',
        alreadyIncidentReport: false,
        relatedView: 'threat-intel',
      });
    }

    // Also surface DNS audit summary recommendation if score < 100 and not already covered by a DNS finding
    if (
      dnsAudit &&
      dnsAudit.score < 100 &&
      !list.some((a) => a.sourceGroup === 'DNS_EMAIL')
    ) {
      list.push({
        id: 'adv-dns-posture',
        severity: dnsAudit.dmarc.policy === 'MISSING' ? 'HIGH' : 'MEDIUM',
        sourceGroup: 'DNS_EMAIL',
        sourceLabel: 'DNS & Anti-Spoofing Audit',
        target: dnsAudit.rootDomain,
        detectedAt: dnsAudit.checkedAt,
        title: `Penguatan Kebijakan Email & DNS (${dnsAudit.rootDomain} · Skor ${dnsAudit.score}/100)`,
        plainSummary: `Konfigurasi keamanan DNS (SPF: ${dnsAudit.spf.policy}, DMARC: ${dnsAudit.dmarc.policy}, CAA: ${dnsAudit.caa.present ? 'Ada' : 'Belum Ada'}) masih dapat diperketat.`,
        businessImpact:
          'Mengurangi peluang pihak tidak bertanggung jawab mengirim email palsu mengatasnamakan organisasi.',
        evidence: `SPF: ${dnsAudit.spf.record ?? 'Missing'} | DMARC: ${dnsAudit.dmarc.record ?? 'Missing'}`,
        picOwner: 'Pengelola DNS & Tim Infrastruktur',
        slaTarget: '7–14 Hari Kerja',
        needsInfraEscalation: true,
        supportSteps: [
          'Teruskan hasil audit DNS dari halaman DNS & Anti-Spoofing kepada pengelola DNS / Tim Infrastruktur.',
        ],
        devSteps: [
          'Pastikan seluruh aplikasi pengirim email notifikasi terdaftar sah di SPF dan menandatangani email dengan DKIM sebelum DMARC dinaikkan ke p=reject.',
        ],
        leadershipSteps: [
          'Dukung penerapan DMARC penuh lintas sub-unit agar komunikasi email resmi organisasi terlindungi dari pemalsuan.',
        ],
        incidentCategory: 'VULNERABILITY_REPORT',
        alreadyIncidentReport: false,
        relatedView: 'dns-audit',
      });
    }
  }

  return list.sort((a, b) => {
    const rankDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (rankDiff !== 0) return rankDiff;
    return new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime();
  });
}

export const ActionAdvisorView: React.FC<ActionAdvisorViewProps> = ({
  endpoints,
  dnsAudit,
  findings,
  contentScans,
  incidentReports,
  localWazuh,
  threatIntel,
  scanningNow,
  onRunLiveScan,
  onCreateIncident,
  onNavigateView,
}) => {
  const { isDemo } = useSocMode();
  const [roleLens, setRoleLens] = useState<RoleLens>('ALL');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');
  const [sourceFilter, setSourceFilter] = useState<AdvisorySourceFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Per-card UI state
  const [expandedCards, setExpandedCards] = useState<Record<string, boolean>>({});
  const [snippetStackByCard, setSnippetStackByCard] = useState<
    Record<string, SnippetStack>
  >({});
  const [escalationCardId, setEscalationCardId] = useState<string | null>(null);
  const [escalationChannel, setEscalationChannel] =
    useState<EscalationChannel>('infra');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [escalatingId, setEscalatingId] = useState<string | null>(null);
  const [escalatedIds, setEscalatedIds] = useState<Record<string, boolean>>({});

  const advisories = useMemo(
    () =>
      buildLiveActionAdvisories({
        endpoints,
        dnsAudit,
        findings,
        contentScans,
        incidentReports,
        localWazuh,
        threatIntel,
      }),
    [
      endpoints,
      dnsAudit,
      findings,
      contentScans,
      incidentReports,
      localWazuh,
      threatIntel,
    ]
  );

  const filteredAdvisories = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return advisories.filter((a) => {
      if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
      if (sourceFilter !== 'ALL' && a.sourceGroup !== sourceFilter) return false;
      if (!q) return true;
      return (
        a.title.toLowerCase().includes(q) ||
        a.target.toLowerCase().includes(q) ||
        a.plainSummary.toLowerCase().includes(q) ||
        a.picOwner.toLowerCase().includes(q) ||
        a.evidence.toLowerCase().includes(q)
      );
    });
  }, [advisories, severityFilter, sourceFilter, searchQuery]);

  const stats = useMemo(() => {
    const urgent = advisories.filter(
      (a) => a.severity === 'CRITICAL' || a.severity === 'HIGH'
    ).length;
    const withFix = advisories.filter((a) => Boolean(a.fixSnippets)).length;
    const needsInfra = advisories.filter((a) => a.needsInfraEscalation).length;
    return { total: advisories.length, urgent, withFix, needsInfra };
  }, [advisories]);

  const handleCopy = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
      }, 2200);
    } catch {
      // Fallback ignored gracefully in restricted contexts
    }
  };

  const handlePromoteToIncident = async (adv: ActionAdvisory) => {
    setEscalatingId(adv.id);
    try {
      await onCreateIncident({
        title: adv.title,
        affectedUrl: adv.target,
        category: adv.incidentCategory,
        severity: adv.severity,
        source:
          adv.sourceGroup === 'CONTENT_DEFACEMENT'
            ? 'AUTO_SCANNER'
            : 'INTERNAL_STAFF',
        reporterName: `Action Advisor (${adv.sourceLabel})`,
        occurredAt: adv.detectedAt,
        description: `${adv.plainSummary} Dampak: ${adv.businessImpact}`,
        evidenceSnippet: adv.evidence,
        coordinationNotes: `PIC: ${adv.picOwner} | Target SLA: ${adv.slaTarget}`,
        actionTaken: adv.devSteps.join(' | '),
        status: adv.needsInfraEscalation ? 'ESCALATED_INFRA' : 'OPEN',
        includeInBoardReport: true,
      });
      setEscalatedIds((prev) => ({ ...prev, [adv.id]: true }));
    } finally {
      setEscalatingId(null);
    }
  };

  const toggleCard = (id: string) => {
    setExpandedCards((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="space-y-5">
      {/* Header Control Bar */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Compass className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100">
              Action Advisor — Saran Tindakan Otomatis di Atas Layer Wazuh
            </h2>
          </div>
          {isDemo && (
            <p className="text-xs text-zinc-400 max-w-3xl leading-relaxed">
              Menerjemahkan temuan teknis (Header/TLS, DNS, Defacement/Cloaking, CTI, &amp; Alert SIEM/Wazuh) menjadi panduan tindakan berbahasa sederhana untuk <strong className="text-zinc-200">Support IT</strong>, <strong className="text-zinc-200">Tim Development</strong>, dan <strong className="text-zinc-200">Pimpinan</strong>—lengkap dengan kode perbaikan &amp; draft eskalasi ke Tim Infra/CSIRT.
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ActionTooltip
            label="Refresh Analisis"
            description="Jalankan pemindaian ulang portal, DNS, dan CTI untuk memperbarui daftar rekomendasi."
          >
            <button
              type="button"
              disabled={scanningNow}
              onClick={() => void onRunLiveScan()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${scanningNow ? 'animate-spin' : ''}`}
              />
              {scanningNow ? 'Memindai...' : 'Refresh Analisis Live'}
            </button>
          </ActionTooltip>

          <ActionTooltip
            label="Buka Incident Reports"
            description="Kelola tiket insiden manual, eskalasi infra, dan pemindaian HTML cloaking."
          >
            <button
              type="button"
              onClick={() => onNavigateView('incident-reports')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Buka Incident Reports
              <ArrowUpRight className="w-3.5 h-3.5 text-zinc-400" />
            </button>
          </ActionTooltip>
        </div>
      </section>

      {/* 4-Column Live KPI Summary Strip */}
      <section
        aria-label="Action Advisor Summary Metrics"
        className="grid grid-cols-2 xl:grid-cols-4 divide-y xl:divide-y-0 xl:divide-x divide-zinc-800/80 bg-zinc-900/40 border border-zinc-800/80 rounded-lg"
      >
        <div className="p-4">
          <p className="text-xs text-zinc-400">Total Saran Tindakan Aktif</p>
          <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-zinc-100">
            {stats.total}
          </p>
          {isDemo && (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Diturunkan dari hasil scan &amp; insiden aktif
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">Prioritas Kritis &amp; Tinggi</p>
          <p
            className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${
              stats.urgent > 0 ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {stats.urgent}
          </p>
          {isDemo && (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Membutuhkan respon cepat &amp; pantauan pimpinan
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">Tersedia Fix Snippet Dev</p>
          <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-emerald-400">
            {stats.withFix}
          </p>
          {isDemo && (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Panduan konfigurasi Nginx / Apache / Node / PHP
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">Perlu Koordinasi Infra / CSIRT</p>
          <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-amber-400">
            {stats.needsInfra}
          </p>
          {isDemo && (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Siap salin draft tiket resmi 1-klik
            </p>
          )}
        </div>
      </section>

      {/* Role Perspective Switcher & Filters */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Interactive Role Lens Buttons */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-zinc-500 mr-1 whitespace-nowrap">
              Sudut Pandang:
            </span>
            {(
              [
                {
                  id: 'ALL',
                  label: 'Semua Peran',
                  Icon: Users,
                  desc: 'Tampilkan langkah untuk Support IT, Development, dan Pimpinan sekaligus.',
                },
                {
                  id: 'SUPPORT_IT',
                  label: 'Support IT',
                  Icon: Headphones,
                  desc: 'Fokus pada langkah verifikasi cepat & komunikasi Helpdesk.',
                },
                {
                  id: 'DEVELOPMENT',
                  label: 'Tim Development',
                  Icon: Code2,
                  desc: 'Fokus pada perbaikan teknis serta snippet Nginx/Apache/Node/PHP.',
                },
                {
                  id: 'LEADERSHIP',
                  label: 'Pimpinan (CTO/BoD)',
                  Icon: Briefcase,
                  desc: 'Fokus pada keputusan manajerial, SLA, dan koordinasi Tim Infra.',
                },
              ] as const
            ).map(({ id, label, Icon, desc }) => {
              const active = roleLens === id;
              return (
                <ActionTooltip key={id} label={`Fokus ${label}`} description={desc}>
                  <button
                    type="button"
                    onClick={() => setRoleLens(id)}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                      active
                        ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-zinc-950 text-zinc-400 hover:text-zinc-200 border border-zinc-800'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5 shrink-0" />
                    {label}
                  </button>
                </ActionTooltip>
              );
            })}
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <ActionTooltip
              label="Filter Severity"
              description="Saring saran tindakan berdasarkan tingkat kekritisan."
            >
              <select
                value={severityFilter}
                onChange={(e) =>
                  setSeverityFilter(e.target.value as 'ALL' | Severity)
                }
                aria-label="Filter severity saran tindakan"
                className="bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs font-mono text-zinc-200"
              >
                <option value="ALL">Semua Severity</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </ActionTooltip>

            <ActionTooltip
              label="Filter Sumber Temuan"
              description="Saring saran berdasarkan modul sumber (HTML Scanner, HTTP/TLS, DNS, SIEM, CTI)."
            >
              <select
                value={sourceFilter}
                onChange={(e) =>
                  setSourceFilter(e.target.value as AdvisorySourceFilter)
                }
                aria-label="Filter sumber deteksi"
                className="bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-200"
              >
                <option value="ALL">Semua Sumber</option>
                {(
                  Object.entries(SOURCE_LABELS) as Array<
                    [Exclude<AdvisorySourceFilter, 'ALL'>, string]
                  >
                ).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </ActionTooltip>

            <div className="relative w-52">
              <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Cari temuan, URL, PIC..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
              />
            </div>
          </div>
        </div>

        {/* Advisory Cards Feed */}
        {filteredAdvisories.length === 0 ? (
          <div className="p-10 text-center space-y-2.5">
            <CheckCircle2 className="w-7 h-7 text-emerald-400 mx-auto" />
            <p className="text-sm font-semibold text-zinc-100">
              {advisories.length === 0
                ? 'Semua sistem terpantau dalam kondisi bersih — tidak ada saran tindakan mendesak'
                : 'Tidak ada saran tindakan yang cocok dengan filter aktif'}
            </p>
            {isDemo && (
              <p className="text-xs text-zinc-400 max-w-lg mx-auto">
                {advisories.length === 0
                  ? 'Setiap kali scanner menemukan kelemahan header/TLS/DNS, indikasi defacement, atau insiden baru, panduan tindakan otomatis per peran akan muncul di sini.'
                  : 'Ubah filter severity, sumber deteksi, atau kata kunci pencarian untuk melihat saran tindakan lainnya.'}
              </p>
            )}
            {advisories.length > 0 && (
              <ActionTooltip
                label="Reset Filter"
                description="Tampilkan kembali seluruh saran tindakan aktif."
              >
                <button
                  type="button"
                  onClick={() => {
                    setSeverityFilter('ALL');
                    setSourceFilter('ALL');
                    setSearchQuery('');
                  }}
                  className="mt-1 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md cursor-pointer"
                >
                  Reset Filter
                </button>
              </ActionTooltip>
            )}
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/80">
            {filteredAdvisories.map((adv, index) => {
              // Auto-expand top 2 critical/high cards by default unless toggled explicitly
              const isExpanded =
                expandedCards[adv.id] !== undefined
                  ? expandedCards[adv.id]
                  : index < 2;
              const availableStacks = adv.fixSnippets
                ? (Object.keys(adv.fixSnippets) as SnippetStack[]).filter(
                    (k) => Boolean(adv.fixSnippets?.[k])
                  )
                : [];
              const activeStack: SnippetStack =
                snippetStackByCard[adv.id] ?? availableStacks[0] ?? 'nginx';
              const activeCode = adv.fixSnippets?.[activeStack];
              const isEscalationOpen = escalationCardId === adv.id;
              const escalationText = isEscalationOpen
                ? buildEscalationDraft(adv, escalationChannel)
                : '';
              const isAlreadyPromoted =
                adv.alreadyIncidentReport || Boolean(escalatedIds[adv.id]);

              return (
                <article
                  key={adv.id}
                  className="p-5 space-y-4 hover:bg-zinc-900/30 transition-colors"
                >
                  {/* Top Row: Severity Badge, Metadata, Title & Primary Actions */}
                  <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-3">
                    <div className="space-y-1.5 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono tabular-nums">
                        <SeverityBadge severity={adv.severity} />
                        <span className="text-zinc-300">{adv.sourceLabel}</span>
                        <span className="text-zinc-700">·</span>
                        <span className="text-zinc-400">
                          PIC: {adv.picOwner}
                        </span>
                        <span className="text-zinc-700">·</span>
                        <span className="text-amber-300">
                          SLA: {adv.slaTarget}
                        </span>
                        <span className="text-zinc-700">·</span>
                        <span className="text-zinc-500">
                          {formatShortDateTime(adv.detectedAt)} WIB
                        </span>
                      </div>

                      <h3 className="text-sm font-semibold text-zinc-100 leading-snug">
                        {adv.title}
                      </h3>

                      <p className="font-mono text-[11px] text-emerald-400 break-all">
                        {adv.target}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <ActionTooltip
                        label="Buat Draft Eskalasi"
                        description="Generate template pesan siap salin untuk Tim Infra Ops, CSIRT, atau WhatsApp Pimpinan."
                      >
                        <button
                          type="button"
                          onClick={() =>
                            setEscalationCardId((prev) =>
                              prev === adv.id ? null : adv.id
                            )
                          }
                          className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            isEscalationOpen
                              ? 'bg-emerald-600/20 text-emerald-300 border-emerald-500/40'
                              : 'bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border-zinc-800'
                          }`}
                        >
                          <Send className="w-3.5 h-3.5 text-emerald-400" />
                          Draft Eskalasi
                        </button>
                      </ActionTooltip>

                      {!isAlreadyPromoted ? (
                        <ActionTooltip
                          label="Catat ke Incident Reports"
                          description="Promosikan temuan ini menjadi tiket insiden resmi beserta langkah mitigasi."
                        >
                          <button
                            type="button"
                            disabled={escalatingId === adv.id}
                            onClick={() => void handlePromoteToIncident(adv)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
                          >
                            <FilePlus2 className="w-3.5 h-3.5 text-amber-400" />
                            {escalatingId === adv.id
                              ? 'Mencatat...'
                              : 'Catat ke Incident'}
                          </button>
                        </ActionTooltip>
                      ) : (
                        <ActionTooltip
                          label="Lihat di Incident Reports"
                          description="Temuan ini sudah tercatat. Klik untuk membuka daftar Incident Reports."
                        >
                          <button
                            type="button"
                            onClick={() => onNavigateView('incident-reports')}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-950 text-emerald-400 border border-zinc-800 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Tercatat di Incident
                          </button>
                        </ActionTooltip>
                      )}

                      <ActionTooltip
                        label={isExpanded ? 'Ringkas Panduan' : 'Lihat Panduan Langkah'}
                        description="Tampilkan atau sembunyikan panduan Support IT, Development, Pimpinan, serta snippet perbaikan."
                      >
                        <button
                          type="button"
                          onClick={() => toggleCard(adv.id)}
                          aria-expanded={isExpanded}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs bg-zinc-950 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          {isExpanded ? (
                            <>
                              <span>Ringkas</span>
                              <ChevronUp className="w-3.5 h-3.5" />
                            </>
                          ) : (
                            <>
                              <span>Lihat Panduan</span>
                              <ChevronDown className="w-3.5 h-3.5" />
                            </>
                          )}
                        </button>
                      </ActionTooltip>
                    </div>
                  </div>

                  {/* Plain-Language Summary & Business Impact (Always visible for instant non-technical understanding) */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs bg-zinc-950/60 border border-zinc-800/70 rounded-md p-3.5">
                    <div>
                      <span className="text-[11px] font-mono text-zinc-500 block mb-1">
                        Penjelasan Bahasa Sederhana (Apa yang Terjadi?)
                      </span>
                      <p className="text-zinc-200 leading-relaxed">
                        {adv.plainSummary}
                      </p>
                    </div>
                    <div>
                      <span className="text-[11px] font-mono text-zinc-500 block mb-1">
                        Dampak ke Layanan &amp; Reputasi Organisasi
                      </span>
                      <p className="text-zinc-300 leading-relaxed">
                        {adv.businessImpact}
                      </p>
                    </div>
                  </div>

                  {/* Draft Eskalasi Panel (Infra Ops / CSIRT / WhatsApp Pimpinan) */}
                  {isEscalationOpen && (
                    <div className="bg-zinc-950 border border-emerald-500/30 rounded-md p-4 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-xs font-semibold text-zinc-100 mr-1">
                            Template Pesan Eskalasi:
                          </span>
                          {(
                            [
                              { id: 'infra', label: 'Tiket Infra / Server Ops' },
                              { id: 'csirt', label: 'Laporan CSIRT / CERT' },
                              { id: 'whatsapp', label: 'Ringkasan WA Pimpinan' },
                            ] as const
                          ).map((ch) => (
                            <ActionTooltip
                              key={ch.id}
                              label={`Format ${ch.label}`}
                              description="Ganti format template draft pesan eskalasi."
                            >
                              <button
                                type="button"
                                onClick={() => setEscalationChannel(ch.id)}
                                className={`px-2.5 py-1 rounded text-[11px] font-medium whitespace-nowrap cursor-pointer transition-colors ${
                                  escalationChannel === ch.id
                                    ? 'bg-emerald-600 text-white'
                                    : 'bg-zinc-900 text-zinc-400 hover:text-zinc-200 border border-zinc-800'
                                }`}
                              >
                                {ch.label}
                              </button>
                            </ActionTooltip>
                          ))}
                        </div>

                        <ActionTooltip
                          label="Salin Draft Eskalasi"
                          description="Salin teks template pesan di bawah ini ke clipboard."
                        >
                          <button
                            type="button"
                            onClick={() =>
                              void handleCopy(
                                escalationText,
                                `esc-${adv.id}-${escalationChannel}`
                              )
                            }
                            className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-emerald-300 border border-zinc-700 rounded transition-colors cursor-pointer"
                          >
                            {copiedKey === `esc-${adv.id}-${escalationChannel}` ? (
                              <>
                                <Check className="w-3.5 h-3.5" />
                                Tersalin
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                Salin Draft Pesan
                              </>
                            )}
                          </button>
                        </ActionTooltip>
                      </div>

                      <pre className="bg-zinc-900/80 border border-zinc-800 rounded p-3 text-[11px] font-mono text-zinc-200 whitespace-pre-wrap leading-relaxed overflow-x-auto">
                        {escalationText}
                      </pre>
                    </div>
                  )}

                  {/* Expanded Role-Specific Action Guidance & Developer Fix Snippets */}
                  {isExpanded && (
                    <div className="space-y-4">
                      {/* Role Action Columns */}
                      <div
                        className={`grid grid-cols-1 gap-3 ${
                          roleLens === 'ALL' ? 'lg:grid-cols-3' : 'lg:grid-cols-1'
                        }`}
                      >
                        {(roleLens === 'ALL' || roleLens === 'SUPPORT_IT') && (
                          <div className="bg-zinc-950/50 border border-zinc-800/80 rounded-md p-3.5 space-y-2">
                            <div className="flex items-center gap-1.5 text-xs font-semibold text-sky-300">
                              <Headphones className="w-3.5 h-3.5 shrink-0" />
                              <span>Aksi Tim Support IT (0–15 Menit)</span>
                            </div>
                            <ol className="space-y-1.5 text-xs text-zinc-300 list-decimal list-inside leading-relaxed">
                              {adv.supportSteps.map((step, i) => (
                                <li key={i}>{step}</li>
                              ))}
                            </ol>
                          </div>
                        )}

                        {(roleLens === 'ALL' || roleLens === 'DEVELOPMENT') && (
                          <div className="bg-zinc-950/50 border border-zinc-800/80 rounded-md p-3.5 space-y-2">
                            <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                              <Code2 className="w-3.5 h-3.5 shrink-0" />
                              <span>Aksi Tim Development &amp; Server</span>
                            </div>
                            <ol className="space-y-1.5 text-xs text-zinc-300 list-decimal list-inside leading-relaxed">
                              {adv.devSteps.map((step, i) => (
                                <li key={i}>{step}</li>
                              ))}
                            </ol>
                          </div>
                        )}

                        {(roleLens === 'ALL' || roleLens === 'LEADERSHIP') && (
                          <div className="bg-zinc-950/50 border border-zinc-800/80 rounded-md p-3.5 space-y-2">
                            <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-300">
                              <Briefcase className="w-3.5 h-3.5 shrink-0" />
                              <span>Arahan untuk Pimpinan (CTO / BoD)</span>
                            </div>
                            <ol className="space-y-1.5 text-xs text-zinc-300 list-decimal list-inside leading-relaxed">
                              {adv.leadershipSteps.map((step, i) => (
                                <li key={i}>{step}</li>
                              ))}
                            </ol>
                          </div>
                        )}
                      </div>

                      {/* Developer Copy-Paste Fix Snippets */}
                      {activeCode &&
                        (roleLens === 'ALL' || roleLens === 'DEVELOPMENT') && (
                          <div className="bg-zinc-950 border border-zinc-800/90 rounded-md overflow-hidden">
                            <div className="px-3.5 py-2 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-[11px] font-semibold text-zinc-200">
                                  Contoh Perbaikan Siap Pakai (Developer / Admin Server)
                                </span>
                              </div>

                              <div className="flex items-center gap-1.5">
                                {availableStacks.map((st) => (
                                  <ActionTooltip
                                    key={st}
                                    label={`Stack ${st.toUpperCase()}`}
                                    description={`Tampilkan snippet konfigurasi perbaikan untuk ${st.toUpperCase()}.`}
                                  >
                                    <button
                                      type="button"
                                      onClick={() =>
                                        setSnippetStackByCard((prev) => ({
                                          ...prev,
                                          [adv.id]: st,
                                        }))
                                      }
                                      className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase cursor-pointer transition-colors ${
                                        activeStack === st
                                          ? 'bg-zinc-800 text-emerald-300 border border-zinc-700'
                                          : 'text-zinc-500 hover:text-zinc-200'
                                      }`}
                                    >
                                      {st}
                                    </button>
                                  </ActionTooltip>
                                ))}
                                <ActionTooltip
                                  label="Salin Snippet Kode"
                                  description="Salin blok konfigurasi perbaikan ke clipboard."
                                >
                                  <button
                                    type="button"
                                    onClick={() =>
                                      void handleCopy(
                                        activeCode,
                                        `fix-${adv.id}-${activeStack}`
                                      )
                                    }
                                    className="ml-1 inline-flex items-center gap-1 px-2 py-0.5 text-[11px] bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded cursor-pointer"
                                  >
                                    {copiedKey === `fix-${adv.id}-${activeStack}` ? (
                                      <>
                                        <Check className="w-3 h-3 text-emerald-400" />
                                        Copied
                                      </>
                                    ) : (
                                      <>
                                        <Copy className="w-3 h-3 text-zinc-400" />
                                        Copy
                                      </>
                                    )}
                                  </button>
                                </ActionTooltip>
                              </div>
                            </div>
                            <pre className="p-3.5 text-[11px] font-mono text-emerald-300/90 overflow-x-auto leading-relaxed">
                              {activeCode}
                            </pre>
                          </div>
                        )}

                      {/* Technical Evidence Footer + Jump to Detail View */}
                      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-zinc-500 pt-1">
                        <span className="truncate max-w-3xl">
                          Bukti Teknis: <span className="text-zinc-400">{adv.evidence}</span>
                        </span>
                        <ActionTooltip
                          label="Buka Modul Sumber"
                          description="Loncat ke halaman detail teknis yang menghasilkan temuan ini."
                        >
                          <button
                            type="button"
                            onClick={() => onNavigateView(adv.relatedView)}
                            className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 font-sans font-medium whitespace-nowrap cursor-pointer"
                          >
                            Lihat Data Sumber
                            <ArrowUpRight className="w-3 h-3" />
                          </button>
                        </ActionTooltip>
                      </div>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
};
