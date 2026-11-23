import React, { useMemo, useState } from 'react';
import {
  BookOpen,
  RefreshCw,
  Search,
  Compass,
  Plus,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Newspaper,
  GraduationCap,
  Activity,
} from 'lucide-react';
import {
  CustomGlossaryTerm,
  CyberKnowledgeSnapshot,
  GlobalThreatIntelSnapshot,
  LocalWazuhSnapshot,
  RealDnsSecurityAudit,
  RealEndpointProbe,
} from '../types/soc';
import { formatShortDateTime } from '../utils/socFormatters';
import { useSocMode } from '../context/SocModeContext';
import { ActionTooltip } from './ActionTooltip';

interface CyberAcademyViewProps {
  knowledge: CyberKnowledgeSnapshot | null;
  endpoints: RealEndpointProbe[];
  dnsAudit: RealDnsSecurityAudit | null;
  threatIntel: GlobalThreatIntelSnapshot | null;
  localWazuh: LocalWazuhSnapshot | null;
  updating: boolean;
  onUpdateKnowledge: () => void;
  onAddCustomTerm: (
    term: Omit<CustomGlossaryTerm, 'id' | 'addedAt'>
  ) => Promise<void>;
}

type CategoryFilter =
  | 'ALL'
  | 'Threat Intelligence'
  | 'SIEM & Wazuh'
  | 'Web & DNS Security'
  | 'Serangan & MITRE';

type AcademyTab = 'glossary' | 'briefings' | 'quiz';

interface ConceptItem {
  id: string;
  term: string;
  acronym?: string;
  category: Exclude<CategoryFilter, 'ALL'>;
  definition: string;
  analogy: string;
  orgRelevance: string;
  liveStatus?: string;
  liveTone?: 'ok' | 'warn' | 'info';
  isCustom?: boolean;
}

const QUIZ_QUESTIONS = [
  {
    id: 'q1',
    question:
      'Apa perbedaan utama antara Open Threat Intelligence (CTI) dan SIEM internal seperti Wazuh?',
    options: [
      'CTI memantau ancaman global dari luar (CVE, phishing, botnet); SIEM memantau log & perubahan di dalam server lokal.',
      'CTI hanya digunakan untuk antivirus laptop, sedangkan SIEM hanya untuk email.',
      'Keduanya sama persis dan tidak saling melengkapi.',
    ],
    answerIndex: 0,
    explanation:
      'Tepat! Open CTI bertindak seperti radar cuaca/peringatan dini global, sementara SIEM (seperti Wazuh) bertindak seperti sensor CCTV & alarm di dalam server lokal organisasi.',
  },
  {
    id: 'q2',
    question:
      'Mengapa kebijakan DMARC p=none pada domain utama organisasi perlu ditingkatkan ke p=quarantine / p=reject?',
    options: [
      'Agar ukuran file email menjadi lebih kecil.',
      'Karena p=none hanya memantau tanpa menolak email palsu (spoofing) yang mengatasnamakan organisasi resmi.',
      'Karena p=none membuat website HTTPS tidak bisa dibuka.',
    ],
    answerIndex: 1,
    explanation:
      'Benar! DMARC dengan p=none bersifat monitor-only. Dengan p=quarantine atau p=reject, penyedia email penerima (Gmail/Outlook) otomatis memblokir email phishing yang memalsukan alamat pengirim resmi.',
  },
  {
    id: 'q3',
    question:
      'Apa fungsi modul FIM (File Integrity Monitoring) pada Wazuh / Local SIEM?',
    options: [
      'Mempercepat koneksi internet server.',
      'Memeriksa sidik jari kriptografi (SHA-256) file kritis agar segera tahu jika ada file konfigurasi atau web yang diubah tanpa izin.',
      'Mengganti password pengguna secara otomatis tiap hari.',
    ],
    answerIndex: 1,
    explanation:
      'Tepat! Jika penyerang menanam web shell atau mengubah konfigurasi Nginx/.env, hash SHA-256 langsung berubah dan FIM memicu alert kritis (Rule 550).',
  },
  {
    id: 'q4',
    question:
      'Mengapa header HTTP Strict-Transport-Security (HSTS) penting bagi portal layanan publik atau transaksi?',
    options: [
      'Memaksa browser pengguna selalu mengakses portal lewat HTTPS terenkripsi dan mencegah serangan downgrade ke HTTP.',
      'Menyimpan data pengguna di komputer lokal.',
      'Menonaktifkan sertifikat SSL saat trafik tinggi.',
    ],
    answerIndex: 0,
    explanation:
      'Benar! HSTS melindungi akun dan dokumen pengguna dari serangan Man-in-the-Middle (MitM) di Wi-Fi publik dengan memaksa koneksi HTTPS sejak awal.',
  },
  {
    id: 'q5',
    question: 'Apa itu CISA KEV (Known Exploited Vulnerabilities)?',
    options: [
      'Daftar software gratis untuk kampus.',
      'Katalog resmi celah keamanan (CVE) yang sudah terbukti sedang aktif dieksploitasi oleh penyerang di dunia nyata.',
      'Nama protokol enkripsi pengganti TLS.',
    ],
    answerIndex: 1,
    explanation:
      'Tepat! CISA KEV membantu tim IT memprioritaskan patching pada celah yang benar-benar sedang dipakai hacker hari ini, bukan sekadar celah teoritis.',
  },
];

export const CyberAcademyView: React.FC<CyberAcademyViewProps> = ({
  knowledge,
  endpoints,
  dnsAudit,
  threatIntel,
  localWazuh,
  updating,
  onUpdateKnowledge,
  onAddCustomTerm,
}) => {
  const { isDemo } = useSocMode();
  const [activeTab, setActiveTab] = useState<AcademyTab>('glossary');
  const [category, setCategory] = useState<CategoryFilter>('ALL');
  const [search, setSearch] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);

  // Add custom term state
  const [newTerm, setNewTerm] = useState('');
  const [newCat, setNewCat] =
    useState<CustomGlossaryTerm['category']>('Threat Intelligence');
  const [newDef, setNewDef] = useState('');
  const [newAnalogy, setNewAnalogy] = useState('');
  const [newRel, setNewRel] = useState('');
  const [savingTerm, setSavingTerm] = useState(false);

  // Quiz state
  const [answers, setAnswers] = useState<Record<string, number>>({});

  const primary = endpoints[0] ?? null;

  // Dynamic living concepts bound to LIVE telemetry
  const builtInConcepts: ConceptItem[] = useMemo(() => {
    const hstsPresent = Boolean(primary?.securityHeaders.hsts);
    const dmarcPolicy = dnsAudit?.dmarc.policy ?? 'checking';
    const caaPresent = Boolean(dnsAudit?.caa.present);
    const rootDomain = dnsAudit?.rootDomain ?? 'domain utama';
    const primaryHost = primary?.hostname ?? 'portal utama';
    const kevCount = threatIntel?.cisaKev.totalCount ?? 0;
    const latestCve = threatIntel?.cisaKev.recent[0]?.cveID;
    const feodoEt =
      (threatIntel?.botnetC2.feodoTotal ?? 0) +
      (threatIntel?.botnetC2.etCompromisedTotal ?? 0);
    const openPhish = threatIntel?.openPhish.totalActiveUrls ?? 0;
    const ctTotal = threatIntel?.certTransparency.totalEntries ?? 0;
    const scaScore = localWazuh?.sca.scorePercent ?? null;
    const fimOk = localWazuh?.fim.okCount ?? 0;
    const fimTot = localWazuh?.fim.totalMonitored ?? 0;
    const fimMod = localWazuh?.fim.modifiedCount ?? 0;
    const ipClean =
      threatIntel?.ipReputation.every((r) => !r.listedInThreatFeeds) ?? true;

    return [
      {
        id: 'cti',
        term: 'Threat Intelligence (CTI)',
        acronym: 'Cyber Threat Intelligence',
        category: 'Threat Intelligence',
        definition:
          'Informasi terverifikasi mengenai ancaman siber yang sedang aktif (celah yang dieksploitasi, IP penyerang, domain phishing, kelompok ransomware) yang digunakan untuk pencegahan sebelum serangan terjadi.',
        analogy:
          'Seperti laporan cuaca meteorologi dan daftar buronan internasional — membantu tim bersiap sebelum badai menghantam.',
        orgRelevance:
          'Memberi peringatan dini bila muncul situs phishing tiruan atau celah kritis yang menyasar stack teknologi organisasi.',
        liveStatus: threatIntel
          ? `6/6 Feed Global Aktif · ${kevCount.toLocaleString('id-ID')} CISA KEV · ${openPhish} URL Phishing terpantau`
          : 'Menyinkronkan feed CTI global...',
        liveTone: 'ok',
      },
      {
        id: 'siem',
        term: 'SIEM & XDR (Wazuh)',
        acronym: 'Security Information & Event Management',
        category: 'SIEM & Wazuh',
        definition:
          'Sistem pusat yang mengumpulkan log server, memantau perubahan file, mengaudit konfigurasi OS, dan mendeteksi perilaku serangan di dalam infrastruktur lokal secara real-time.',
        analogy:
          'Seperti ruang kontrol CCTV dan sensor pintu di dalam gedung brankas bank.',
        orgRelevance:
          'Saat dipasang di server produksi lokal, SIEM menangkap percobaan login gagal, serangan SQL Injection, hingga perubahan file konfigurasi tanpa izin.',
        liveStatus: localWazuh
          ? `Agent ${localWazuh.config.agentName} AKTIF · SCA ${scaScore}% · ${localWazuh.alerts.length} rule alert`
          : 'Menunggu scan agent lokal...',
        liveTone: 'info',
      },
      {
        id: 'fim',
        term: 'FIM (File Integrity Monitoring)',
        acronym: 'SHA-256 Cryptographic Integrity',
        category: 'SIEM & Wazuh',
        definition:
          'Mekanisme pemantauan keutuhan file penting (seperti /etc/passwd, konfigurasi Nginx, atau .env aplikasi) menggunakan sidik jari kriptografi SHA-256 untuk mendeteksi perubahan ilegal.',
        analogy:
          'Seperti segel hologram bernomor seri pada brankas dokumen — jika segel berubah 1 karakter saja, alarm langsung berbunyi.',
        orgRelevance:
          'Mencegah web defacement, pencurian kredensial .env, atau penanaman backdoor (web shell) di server aplikasi.',
        liveStatus: localWazuh
          ? `${fimOk}/${fimTot} file sesuai baseline SHA-256 (${fimMod} perubahan)`
          : 'Memeriksa baseline FIM...',
        liveTone: fimMod > 0 ? 'warn' : 'ok',
      },
      {
        id: 'sca',
        term: 'SCA & CIS Benchmark',
        acronym: 'Security Configuration Assessment',
        category: 'SIEM & Wazuh',
        definition:
          'Audit otomatis terhadap pengaturan keamanan sistem operasi dan server berdasarkan standar internasional CIS Benchmark (izin file, hardening SSH, proteksi SYN Flood, prinsip non-root).',
        analogy:
          'Seperti daftar cek keselamatan pesawat (pre-flight checklist) sebelum lepas landas.',
        orgRelevance:
          'Memastikan server produksi lokal tidak memiliki celah salah konfigurasi (misconfiguration) yang mudah dimanfaatkan penyerang.',
        liveStatus:
          scaScore !== null
            ? `Skor CIS Host Lokal: ${scaScore}% (${localWazuh?.sca.passed} Pass · ${localWazuh?.sca.failed} Fail)`
            : 'Mengukur skor CIS...',
        liveTone: (scaScore ?? 0) >= 80 ? 'ok' : 'warn',
      },
      {
        id: 'cisa-kev',
        term: 'CVE & CISA KEV',
        acronym: 'Common Vulnerabilities & Exposures',
        category: 'Threat Intelligence',
        definition:
          'CVE adalah kode identitas unik untuk setiap celah keamanan perangkat lunak. CISA KEV adalah daftar khusus CVE yang terbukti SEDANG AKTIF dieksploitasi hacker di lapangan.',
        analogy:
          'CVE adalah daftar semua jenis penyakit yang diketahui; CISA KEV adalah daftar wabah yang sedang menular hari ini dan wajib segera divaksin (patch).',
        orgRelevance:
          'Membantu CTO & tim IT memprioritaskan pembaruan sistem (patching) berdasarkan risiko nyata, bukan tebakan.',
        liveStatus: latestCve
          ? `${kevCount.toLocaleString('id-ID')} CVE aktif · Terbaru: ${latestCve}`
          : 'Memuat katalog CISA KEV...',
        liveTone: 'info',
      },
      {
        id: 'mitre',
        term: 'MITRE ATT&CK Framework',
        acronym: 'Adversarial Tactics, Techniques & Common Knowledge',
        category: 'Serangan & MITRE',
        definition:
          'Peta taktik dan teknik standar internasional yang menjelaskan tahapan kerja penyerang siber—mulai dari masuk (Initial Access), mencuri akun (Credential Access), hingga merusak (Impact).',
        analogy:
          'Seperti buku taktik lawan dalam sepak bola sehingga tim pertahanan tahu pola serangan yang harus ditutup.',
        orgRelevance:
          'Setiap alert di halaman Local SIEM / XDR otomatis dipetakan ke kode MITRE (mis. T1110 Brute Force, T1190 Exploit Web) agar mudah dieskalasi ke CSIRT/Gov-CERT.',
        liveStatus: localWazuh
          ? `${localWazuh.mitreBreakdown.length} taktik MITRE terpetakan pada alert lokal saat ini`
          : 'Siap memetakan taktik',
        liveTone: 'info',
      },
      {
        id: 'hsts',
        term: 'HSTS (Strict-Transport-Security)',
        acronym: 'HTTP Security Header',
        category: 'Web & DNS Security',
        definition:
          'Header respons web yang memerintahkan browser agar SELALU menggunakan koneksi HTTPS terenkripsi dan menolak koneksi HTTP biasa.',
        analogy:
          'Seperti aturan wajib lewat jalur tol berlapis baja dan melarang kendaraan keluar ke jalan tikus yang rawan penyadapan.',
        orgRelevance:
          `Melindungi sesi login dan unggahan dokumen sensitif pengguna saat mengakses ${primaryHost} dari jaringan publik.`,
        liveStatus: primary
          ? hstsPresent
            ? `AKTIF pada ${primaryHost}`
            : `BELUM AKTIF pada ${primaryHost} (Prioritas P1)`
          : 'Memeriksa header...',
        liveTone: hstsPresent ? 'ok' : 'warn',
      },
      {
        id: 'csp',
        term: 'CSP (Content-Security-Policy)',
        acronym: 'Anti-XSS HTTP Header',
        category: 'Web & DNS Security',
        definition:
          'Aturan keamanan browser yang membatasi dari domain mana saja kode JavaScript, gambar, dan gaya halaman boleh dimuat untuk mencegah serangan XSS.',
        analogy:
          'Seperti daftar tamu VIP di gerbang resepsi—siapa pun di luar daftar tidak boleh masuk dan menjalankan perintah.',
        orgRelevance:
          'Mencegah pencurian token sesi pengguna atau injeksi form palsu ke halaman portal layanan.',
        liveStatus: primary
          ? primary.securityHeaders.csp
            ? `AKTIF pada ${primaryHost}`
            : `Belum terdeteksi di ${primaryHost}`
          : 'Memeriksa CSP...',
        liveTone: primary?.securityHeaders.csp ? 'ok' : 'warn',
      },
      {
        id: 'dmarc',
        term: 'SPF, DKIM & DMARC',
        acronym: 'Email Anti-Spoofing Protocol',
        category: 'Web & DNS Security',
        definition:
          `Tiga mekanisme DNS yang memastikan hanya server email resmi yang boleh mengirim email atas nama @${rootDomain}, serta menginstruksikan penerima menolak email palsu.`,
        analogy:
          'Seperti stempel resmi + tanda tangan digital + verifikasi identitas pengirim surat dinas.',
        orgRelevance:
          'Sangat krusial untuk mencegah penipuan email pengumuman resmi atau permintaan perubahan rekening transaksi.',
        liveStatus: dnsAudit
          ? `SPF: ${dnsAudit.spf.policy} · DMARC: p=${dmarcPolicy} (Skor DNS ${dnsAudit.score}/100)`
          : 'Mengaudit DNS...',
        liveTone: dmarcPolicy === 'reject' || dmarcPolicy === 'quarantine' ? 'ok' : 'warn',
      },
      {
        id: 'caa',
        term: 'DNS CAA Record',
        acronym: 'Certification Authority Authorization',
        category: 'Web & DNS Security',
        definition:
          'Catatan DNS yang membatasi lembaga sertifikat SSL (CA) mana saja yang secara sah diizinkan menerbitkan sertifikat HTTPS untuk domain organisasi.',
        analogy:
          'Seperti surat kuasa tertulis yang menyatakan hanya satu notaris resmi yang boleh menerbitkan akta atas nama lembaga.',
        orgRelevance:
          `Mencegah pihak tidak bertanggung jawab menerbitkan sertifikat SSL sah untuk subdomain tiruan *.${rootDomain}.`,
        liveStatus: dnsAudit
          ? caaPresent
            ? `CAA aktif (${dnsAudit.caa.records.length} record)`
            : `CAA belum dikonfigurasi pada ${rootDomain}`
          : 'Memeriksa CAA...',
        liveTone: caaPresent ? 'ok' : 'warn',
      },
      {
        id: 'ct-logs',
        term: 'Certificate Transparency (CT Log)',
        acronym: 'SSL Issuance Radar',
        category: 'Threat Intelligence',
        definition:
          'Buku besar publik global yang mencatat setiap sertifikat SSL/HTTPS yang diterbitkan di seluruh dunia secara transparan dan real-time.',
        analogy:
          'Seperti papan pengumuman publik setiap kali ada kartu identitas baru yang dicetak menggunakan nama domain Anda.',
        orgRelevance:
          `Memungkinkan tim SOC langsung mendeteksi subdomain baru atau penerbitan sertifikat tak dikenal pada *.${rootDomain}.`,
        liveStatus: threatIntel
          ? `${ctTotal} sertifikat live terpantau (${threatIntel.certTransparency.targetRelatedCount} terkait target/wildcard)`
          : 'Memantau CertSpotter CT...',
        liveTone: 'ok',
      },
      {
        id: 'botnet-c2',
        term: 'Botnet C2 & Threat Blocklist',
        acronym: 'Command & Control Infrastructure',
        category: 'Serangan & MITRE',
        definition:
          'Server pengendali (C2) yang digunakan hacker untuk mengomando ribuan komputer terinfeksi (botnet) guna melancarkan DDoS, pencurian kredensial, atau penyebaran ransomware.',
        analogy:
          'Seperti markas komando yang mengirim perintah ke pasukan drone penyerang.',
        orgRelevance:
          'Daftar IP C2 dari abuse.ch & EmergingThreats dapat langsung diimpor ke Firewall/WAF untuk memblokir koneksi berbahaya sekaligus memastikan IP organisasi bersih.',
        liveStatus: threatIntel
          ? `${feodoEt} IP berbahaya global dipantau · Seluruh IP Target: ${ipClean ? 'ALL CLEAN' : 'PERLU CEK'}`
          : 'Menyinkronkan feed botnet...',
        liveTone: ipClean ? 'ok' : 'warn',
      },
      {
        id: 'ransomware',
        term: 'Ransomware & Double Extortion',
        acronym: 'Malware Pemerasan Data',
        category: 'Serangan & MITRE',
        definition:
          'Serangan malware yang mengenkripsi seluruh data server hingga layanan lumpuh, sering disertai ancaman penyebaran data sensitif (double extortion) bila tebusan tidak dibayar.',
        analogy:
          'Seperti perampok yang menggembok seluruh ruang arsip sekaligus memotret dokumen untuk memeras pemiliknya.',
        orgRelevance:
          'Data pribadi pengguna (PII), rekening bank, dan operasional transaksi keuangan merupakan target bernilai tinggi sehingga memerlukan backup offline + SIEM + patching cepat.',
        liveStatus: threatIntel
          ? `${threatIntel.ransomware.totalRecent} klaim global terbaru (${threatIntel.ransomware.prioritySectorCount} sektor prioritas)`
          : 'Memantau Ransomware.live...',
        liveTone: 'info',
      },
      {
        id: 'tls13',
        term: 'TLS 1.3 & Sertifikat SSL',
        acronym: 'Transport Layer Security',
        category: 'Web & DNS Security',
        definition:
          'Protokol enkripsi modern terbaru yang mengamankan seluruh pertukaran data antara browser pengguna dan server agar tidak bisa disadap atau diubah di tengah jalan.',
        analogy:
          'Seperti amplop baja terkunci yang hanya bisa dibuka oleh pengirim dan penerima sah.',
        orgRelevance:
          'Portal layanan wajib mempertahankan TLS 1.3 dan memantau masa berlaku sertifikat agar tidak pernah kedaluwarsa saat beban trafik puncak.',
        liveStatus: primary?.tls
          ? `${primary.tls.protocol} aktif (${primary.tls.issuer}) · Sisa ${primary.tls.daysRemaining} hari`
          : 'Menginspeksi TLS...',
        liveTone:
          (primary?.tls?.daysRemaining ?? 99) > 30 ? 'ok' : 'warn',
      },
      {
        id: 'waf-soar',
        term: 'WAF & SOAR',
        acronym: 'Web Application Firewall & Automated Response',
        category: 'SIEM & Wazuh',
        definition:
          'WAF menyaring lalu lintas web berbahaya (SQLi, XSS, DDoS L7) sebelum mencapai server aplikasi; SOAR mengotomatisasi tindakan respons (blokir IP, notifikasi CSIRT, isolasi akun).',
        analogy:
          'WAF adalah satpam pemeriksa di lobi; SOAR adalah protokol darurat otomatis saat alarm berbunyi.',
        orgRelevance:
          'Mengurangi waktu respons insiden (MTTR) dari hitungan jam menjadi hitungan detik saat terjadi lonjakan serangan siber.',
        liveStatus: 'Siap terintegrasi via webhook POST /api/ingest/siem & Local Active Response',
        liveTone: 'info',
      },
      {
        id: 'bgp-asn',
        term: 'ASN, BGP & APNIC RDAP',
        acronym: 'Autonomous System & Internet Routing',
        category: 'Web & DNS Security',
        definition:
          'ASN adalah nomor identitas jaringan institusi di internet global; BGP mengatur rute lalu lintas ke IP resmi tersebut; RDAP adalah catatan kepemilikan blok IP resmi dari RIR (APNIC/ARIN/RIPE).',
        analogy:
          'Seperti kode pos resmi dan peta jalur logistik agar trafik pengguna selalu sampai ke server organisasi yang asli.',
        orgRelevance:
          'Verifikasi rutin memastikan IP portal organisasi tetap diumumkan melalui ASN resmi dan tidak mengalami BGP hijacking.',
        liveStatus: threatIntel?.ipReputation[0]
          ? `${threatIntel.ipReputation[0].ip} terverifikasi ${threatIntel.ipReputation[0].netName ?? 'NET'} (${threatIntel.ipReputation[0].asn ?? 'ASN'})`
          : 'Memverifikasi APNIC/BGP...',
        liveTone: 'ok',
      },
    ];
  }, [primary, dnsAudit, threatIntel, localWazuh]);

  const allConcepts: ConceptItem[] = useMemo(() => {
    const customMapped: ConceptItem[] = (knowledge?.customTerms ?? []).map(
      (c) => ({
        id: c.id,
        term: c.term,
        category: c.category,
        definition: c.definition,
        analogy: c.analogy,
        orgRelevance: c.orgRelevance,
        liveStatus: `Catatan internal SOC · Ditambahkan ${formatShortDateTime(c.addedAt)}`,
        liveTone: 'info',
        isCustom: true,
      })
    );
    return [...customMapped, ...builtInConcepts];
  }, [knowledge, builtInConcepts]);

  const filteredConcepts = useMemo(() => {
    const q = search.trim().toLowerCase();
    return allConcepts.filter((item) => {
      if (category !== 'ALL' && item.category !== category) return false;
      if (!q) return true;
      return (
        item.term.toLowerCase().includes(q) ||
        (item.acronym || '').toLowerCase().includes(q) ||
        item.definition.toLowerCase().includes(q) ||
        item.analogy.toLowerCase().includes(q) ||
        item.orgRelevance.toLowerCase().includes(q)
      );
    });
  }, [allConcepts, category, search]);

  const handleSaveCustomTerm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTerm.trim() || !newDef.trim()) return;
    setSavingTerm(true);
    try {
      await onAddCustomTerm({
        term: newTerm.trim(),
        category: newCat,
        definition: newDef.trim(),
        analogy: newAnalogy.trim() || 'Catatan kustom tim SOC.',
        orgRelevance:
          newRel.trim() || 'Referensi operasional keamanan siber organisasi.',
      });
      setNewTerm('');
      setNewDef('');
      setNewAnalogy('');
      setNewRel('');
      setShowAddForm(false);
    } finally {
      setSavingTerm(false);
    }
  };

  const quizScore = useMemo(() => {
    let correct = 0;
    for (const q of QUIZ_QUESTIONS) {
      if (answers[q.id] === q.answerIndex) correct += 1;
    }
    return correct;
  }, [answers]);

  const infocon = knowledge?.sansInfocon ?? 'unknown';
  const infoconTone =
    infocon === 'green'
      ? 'text-emerald-400'
      : infocon === 'yellow'
      ? 'text-amber-400'
      : infocon === 'orange'
      ? 'text-orange-400'
      : infocon === 'red'
      ? 'text-rose-400'
      : 'text-zinc-400';

  return (
    <div className="space-y-5">
      {/* Living Knowledge Hub Header with "Update Pengetahuan" */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <BookOpen className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100">
              Pusat Pengetahuan Hidup: Threat Intelligence, SIEM &amp; Cyber Security
            </h2>
            <span className="text-zinc-700">·</span>
            <span className="font-mono text-[11px] text-zinc-400">
              SANS Global InfoCon:{' '}
              <strong className={`uppercase ${infoconTone}`}>{infocon}</strong>
            </span>
          </div>
          {isDemo && (
            <p className="text-xs text-zinc-400">
              Setiap istilah terhubung langsung dengan status nyata sistem terpantau hari ini serta diperbarui dari advisory global (CISA, BleepingComputer, The Hacker News, SANS ISC).
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {knowledge?.lastUpdatedAt && (
            <span className="font-mono text-[11px] text-zinc-500 whitespace-nowrap">
              Updated {formatShortDateTime(knowledge.lastUpdatedAt)} WIB
            </span>
          )}
          <ActionTooltip
            label="Tambah Istilah Kamus"
            description="Tambahkan istilah atau catatan keamanan internal khusus tim SOC."
            scope={isDemo ? 'DEMO' : 'LIVE'}
          >
            <button
              type="button"
              onClick={() => {
                setActiveTab('glossary');
                setShowAddForm((prev) => !prev);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5 text-emerald-400" />
              Tambah Istilah
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Update Pengetahuan"
            description="Tarik advisory keamanan global terbaru (CISA, SANS InfoCon, berita siber) untuk memperbarui briefing."
            scope={isDemo ? 'DEMO' : 'LIVE'}
          >
            <button
              type="button"
              disabled={updating}
              onClick={onUpdateKnowledge}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${updating ? 'animate-spin' : ''}`} />
              {updating ? 'Memperbarui...' : 'Update Pengetahuan'}
            </button>
          </ActionTooltip>
        </div>
      </section>

      {/* Live Knowledge Sources Strip */}
      <section className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        {(knowledge?.sourcesStatus ?? []).map((s) => (
          <div
            key={s.name}
            className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg px-3.5 py-2.5 flex items-center justify-between gap-2"
          >
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span
                  className={`w-2 h-2 rounded-full shrink-0 ${
                    s.status === 'OK' ? 'bg-emerald-500' : 'bg-rose-500'
                  }`}
                />
                <span className="text-xs font-medium text-zinc-200 truncate">
                  {s.name}
                </span>
              </div>
              <p className="font-mono text-[10px] text-zinc-500 mt-0.5">
                {s.count} item · {s.latencyMs} ms
              </p>
            </div>
            <span className="font-mono text-[10px] text-emerald-400 shrink-0">
              {s.status}
            </span>
          </div>
        ))}
      </section>

      {/* Add Custom Term Inline Panel */}
      {showAddForm && (
        <form
          onSubmit={(e) => void handleSaveCustomTerm(e)}
          className="bg-zinc-900/60 border border-emerald-500/30 rounded-lg p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-emerald-400">
              Tambah Catatan / Istilah Keamanan Internal SOC
            </h3>
            <ActionTooltip
              label="Tutup Form Istilah"
              description="Tutup panel penambahan istilah tanpa menyimpan perubahan."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer whitespace-nowrap shrink-0"
              >
                Tutup
              </button>
            </ActionTooltip>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              type="text"
              required
              value={newTerm}
              onChange={(e) => setNewTerm(e.target.value)}
              placeholder="Nama Istilah (mis. Zero Trust / BOLA / MFA)"
              className="bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
            />
            <select
              value={newCat}
              onChange={(e) =>
                setNewCat(e.target.value as CustomGlossaryTerm['category'])
              }
              className="bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100"
            >
              <option value="Threat Intelligence">Threat Intelligence</option>
              <option value="SIEM & Wazuh">SIEM &amp; Wazuh</option>
              <option value="Web & DNS Security">Web &amp; DNS Security</option>
              <option value="Serangan & MITRE">Serangan &amp; MITRE</option>
            </select>
            <input
              type="text"
              value={newAnalogy}
              onChange={(e) => setNewAnalogy(e.target.value)}
              placeholder="Analogi Sederhana (opsional)"
              className="bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <textarea
              required
              rows={2}
              value={newDef}
              onChange={(e) => setNewDef(e.target.value)}
              placeholder="Penjelasan singkat dalam bahasa mudah dipahami..."
              className="bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
            />
            <textarea
              rows={2}
              value={newRel}
              onChange={(e) => setNewRel(e.target.value)}
              placeholder="Kenapa penting untuk sistem organisasi? (opsional)"
              className="bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
            />
          </div>
          <div className="flex justify-end">
            <ActionTooltip
              label="Simpan Istilah Baru"
              description="Simpan istilah keamanan baru ke kamus internal SOC."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="submit"
                disabled={savingTerm}
                className="px-4 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md cursor-pointer disabled:opacity-60 whitespace-nowrap shrink-0"
              >
                {savingTerm ? 'Menyimpan...' : 'Simpan ke Kamus SOC'}
              </button>
            </ActionTooltip>
          </div>
        </form>
      )}

      {/* Main Workspace Tabs */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center gap-1 overflow-x-auto">
            {[
              {
                id: 'glossary' as const,
                label: `Kamus & Konsep Hidup (${allConcepts.length})`,
                hint: 'Buka kamus konsep keamanan siber yang terhubung dengan status sistem terpantau.',
                icon: Compass,
              },
              {
                id: 'briefings' as const,
                label: `Berita & Advisory Live (${knowledge?.liveBriefings.length ?? 0})`,
                hint: 'Lihat berita dan advisory kerentanan terbaru dari sumber global.',
                icon: Newspaper,
              },
              {
                id: 'quiz' as const,
                label: `Uji Pemahaman (${quizScore}/${QUIZ_QUESTIONS.length})`,
                hint: 'Kerjakan kuis singkat untuk menguji pemahaman istilah keamanan siber.',
                icon: GraduationCap,
              },
            ].map((t) => {
              const Icon = t.icon;
              const active = activeTab === t.id;
              return (
                <ActionTooltip
                  key={t.id}
                  label={t.label}
                  description={t.hint}
                  scope={isDemo ? 'DEMO' : 'LIVE'}
                >
                  <button
                    type="button"
                    onClick={() => setActiveTab(t.id)}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                      active
                        ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                        : 'text-zinc-400 hover:text-zinc-200 border border-transparent'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    {t.label}
                  </button>
                </ActionTooltip>
              );
            })}
          </div>

          {activeTab === 'glossary' && (
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative w-full sm:w-56">
                <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Cari istilah (SIEM, DMARC, FIM...)"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                />
              </div>
              <ActionTooltip
                label="Filter Kategori Istilah"
                description="Saring kartu istilah berdasarkan topik Threat Intel, SIEM, Web/DNS, atau MITRE."
                scope={isDemo ? 'DEMO' : 'LIVE'}
              >
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value as CategoryFilter)}
                  className="bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-200 cursor-pointer"
                >
                  <option value="ALL">Semua Kategori</option>
                  <option value="Threat Intelligence">Threat Intelligence</option>
                  <option value="SIEM & Wazuh">SIEM &amp; Wazuh</option>
                  <option value="Web & DNS Security">Web &amp; DNS Security</option>
                  <option value="Serangan & MITRE">Serangan &amp; MITRE</option>
                </select>
              </ActionTooltip>
            </div>
          )}
        </div>

        {/* TAB 1: LIVING GLOSSARY */}
        {activeTab === 'glossary' && (
          <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
            {filteredConcepts.map((item) => (
              <article
                key={item.id}
                className="bg-zinc-950/70 border border-zinc-800/80 rounded-lg p-4 flex flex-col justify-between gap-3 hover:border-zinc-700 transition-colors"
              >
                <div className="space-y-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-semibold text-zinc-100">
                        {item.term}
                      </h3>
                      {item.acronym && (
                        <p className="font-mono text-[11px] text-zinc-500">
                          {item.acronym}
                        </p>
                      )}
                    </div>
                    <span className="font-mono text-[10px] text-zinc-400 uppercase shrink-0">
                      {item.isCustom ? 'CUSTOM · ' : ''}
                      {item.category}
                    </span>
                  </div>

                  <p className="text-xs text-zinc-200 leading-relaxed">
                    {item.definition}
                  </p>

                  <div className="space-y-1.5 text-xs border-t border-zinc-800/70 pt-2.5">
                    <p className="text-zinc-400">
                      <strong className="text-zinc-200">Analogi: </strong>
                      {item.analogy}
                    </p>
                    <p className="text-zinc-400">
                      <strong className="text-emerald-400">
                        Konteks Organisasi:{' '}
                      </strong>
                      {item.orgRelevance}
                    </p>
                  </div>
                </div>

                {item.liveStatus && (
                  <div
                    className={`rounded-md px-3 py-2 font-mono text-[11px] flex items-center gap-2 border ${
                      item.liveTone === 'warn'
                        ? 'bg-amber-500/5 border-amber-500/25 text-amber-300'
                        : item.liveTone === 'ok'
                        ? 'bg-emerald-500/5 border-emerald-500/25 text-emerald-300'
                        : 'bg-zinc-900 border-zinc-800 text-zinc-300'
                    }`}
                  >
                    <Activity className="w-3.5 h-3.5 shrink-0" />
                    <span className="truncate">Live Status: {item.liveStatus}</span>
                  </div>
                )}
              </article>
            ))}

            {filteredConcepts.length === 0 && (
              <div className="lg:col-span-2 py-10 text-center text-xs text-zinc-500 font-mono">
                Tidak ada istilah yang cocok dengan pencarian &ldquo;{search}&rdquo;.
              </div>
            )}
          </div>
        )}

        {/* TAB 2: LIVE GLOBAL ADVISORIES & BRIEFINGS */}
        {activeTab === 'briefings' && (
          <div className="divide-y divide-zinc-800/70">
            {(knowledge?.liveBriefings ?? []).length === 0 ? (
              <div className="p-10 text-center text-xs text-zinc-400 font-mono">
                {isDemo
                  ? 'Klik tombol "Update Pengetahuan" untuk menarik advisory keamanan terbaru secara live.'
                  : 'Belum ada advisory keamanan tersinkronisasi.'}
              </div>
            ) : (
              (knowledge?.liveBriefings ?? []).map((b) => (
                <div
                  key={b.id}
                  className="p-4 flex flex-col md:flex-row md:items-start justify-between gap-3 hover:bg-zinc-900/60"
                >
                  <div className="space-y-1.5 min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
                      <span
                        className={
                          b.source === 'CISA Advisory'
                            ? 'text-rose-400 font-semibold'
                            : b.source === 'BleepingComputer'
                            ? 'text-sky-400 font-semibold'
                            : 'text-emerald-400 font-semibold'
                        }
                      >
                        {b.source}
                      </span>
                      <span className="text-zinc-700">·</span>
                      <span className="text-zinc-500">
                        {formatShortDateTime(b.publishedAt)} WIB
                      </span>
                    </div>

                    <h3 className="text-sm font-semibold text-zinc-100 leading-snug">
                      {b.title}
                    </h3>

                    {b.summary && (
                      <p className="text-xs text-zinc-400 leading-relaxed">
                        {b.summary}
                      </p>
                    )}

                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      <span className="text-[11px] text-zinc-500 mr-1">
                        Istilah terkait:
                      </span>
                      {b.relatedConcepts.map((concept) => (
                        <ActionTooltip
                          key={concept}
                          label={`Cari "${concept}"`}
                          description={`Buka kamus dan cari penjelasan konsep ${concept}.`}
                          scope={isDemo ? 'DEMO' : 'LIVE'}
                        >
                          <button
                            type="button"
                            onClick={() => {
                              setActiveTab('glossary');
                              setCategory('ALL');
                              setSearch(concept.split(' ')[0]);
                            }}
                            className="font-mono text-[11px] text-emerald-400 hover:text-emerald-300 underline underline-offset-2 cursor-pointer"
                          >
                            {concept}
                          </button>
                        </ActionTooltip>
                      ))}
                    </div>
                  </div>

                  {b.link && (
                    <ActionTooltip
                      label={`Buka Sumber (${b.source})`}
                      description="Buka artikel advisory asli di tab baru browser."
                      scope={isDemo ? 'DEMO' : 'LIVE'}
                    >
                      <a
                        href={b.link}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md whitespace-nowrap shrink-0"
                      >
                        Sumber Asli
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </ActionTooltip>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {/* TAB 3: INTERACTIVE SELF-CHECK QUIZ */}
        {activeTab === 'quiz' && (
          <div className="p-5 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-zinc-800/80">
              <div>
                <h3 className="text-sm font-semibold text-zinc-100">
                  Cek Cepat Pemahaman Threat Intelligence &amp; SIEM
                </h3>
                {isDemo && (
                  <p className="text-xs text-zinc-400">
                    Uji pemahaman konsep kunci sebelum mempresentasikan laporan keamanan ke Direksi/CTO.
                  </p>
                )}
              </div>
              <div className="font-mono text-sm font-semibold text-emerald-400 tabular-nums">
                Skor: {quizScore} / {QUIZ_QUESTIONS.length}
              </div>
            </div>

            <div className="space-y-4">
              {QUIZ_QUESTIONS.map((q, idx) => {
                const chosen = answers[q.id];
                const answered = chosen !== undefined;
                const isRight = chosen === q.answerIndex;
                return (
                  <div
                    key={q.id}
                    className="bg-zinc-950/70 border border-zinc-800/80 rounded-lg p-4 space-y-3"
                  >
                    <p className="text-xs font-semibold text-zinc-100">
                      {idx + 1}. {q.question}
                    </p>
                    <div className="space-y-2">
                      {q.options.map((opt, optIdx) => {
                        const selected = chosen === optIdx;
                        const correctOpt = optIdx === q.answerIndex;
                        let style =
                          'bg-zinc-900/60 border-zinc-800 text-zinc-300 hover:border-zinc-700';
                        if (answered) {
                          if (correctOpt) {
                            style =
                              'bg-emerald-500/10 border-emerald-500/40 text-emerald-200';
                          } else if (selected && !correctOpt) {
                            style =
                              'bg-rose-500/10 border-rose-500/40 text-rose-200';
                          }
                        }
                        return (
                          <ActionTooltip
                            key={opt}
                            label={`Pilih Jawaban ${String.fromCharCode(65 + optIdx)}`}
                            description="Klik untuk memilih jawaban ini dan melihat penjelasannya."
                            scope={isDemo ? 'DEMO' : 'LIVE'}
                            className="block w-full"
                          >
                            <button
                              type="button"
                              onClick={() =>
                                setAnswers((prev) => ({ ...prev, [q.id]: optIdx }))
                              }
                              className={`w-full text-left px-3 py-2 rounded-md border text-xs transition-colors cursor-pointer ${style}`}
                            >
                              {opt}
                            </button>
                          </ActionTooltip>
                        );
                      })}
                    </div>

                    {answered && (
                      <div
                        className={`flex items-start gap-2 text-xs pt-1 ${
                          isRight ? 'text-emerald-400' : 'text-amber-300'
                        }`}
                      >
                        {isRight ? (
                          <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                        ) : (
                          <XCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
                        )}
                        <span>{q.explanation}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>
    </div>
  );
};
