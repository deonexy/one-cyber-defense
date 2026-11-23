import React, { useMemo, useState } from 'react';
import {
  Briefcase,
  FileDown,
  FileText,
  Printer,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  Table,
} from 'lucide-react';
import {
  ContentIntegrityScan,
  GlobalThreatIntelSnapshot,
  LocalWazuhSnapshot,
  ManualIncidentReport,
  RealDnsSecurityAudit,
  RealEndpointProbe,
  RealSecurityFinding,
} from '../types/soc';
import {
  exportToCSV,
  formatShortDateTime,
  getSeverityColor,
  triggerFileDownload,
} from '../utils/socFormatters';
import { ActionTooltip } from './ActionTooltip';
import { useSocMode } from '../context/SocModeContext';
import {
  CATEGORY_LABELS,
  SOURCE_LABELS,
  STATUS_LABELS,
} from './IncidentReportsView';

interface ExecutiveReportViewProps {
  endpoints: RealEndpointProbe[];
  dnsAudit: RealDnsSecurityAudit | null;
  threatIntel: GlobalThreatIntelSnapshot | null;
  localWazuh: LocalWazuhSnapshot | null;
  findings: RealSecurityFinding[];
  incidentReports: ManualIncidentReport[];
  contentScans: ContentIntegrityScan[];
  onOpenIncidentReports: () => void;
}

interface StrategicRecommendation {
  id: string;
  priority: 'P1 — Segera (0–7 Hari)' | 'P2 — Jangka Pendek (30 Hari)' | 'P3 — Strategis (90 Hari)';
  priorityCode: 'P1' | 'P2' | 'P3';
  domain: string;
  issuePlain: string;
  businessImpact: string;
  actionPlan: string;
  owner: string;
  evidenceLive: string;
}

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export const ExecutiveReportView: React.FC<ExecutiveReportViewProps> = ({
  endpoints,
  dnsAudit,
  threatIntel,
  localWazuh,
  findings,
  incidentReports,
  contentScans,
  onOpenIncidentReports,
}) => {
  const { isDemo } = useSocMode();
  const boardIncidents = useMemo(
    () => incidentReports.filter((r) => r.includeInBoardReport),
    [incidentReports]
  );
  const flaggedContentScans = useMemo(
    () => contentScans.filter((s) => s.riskLevel !== 'CLEAN'),
    [contentScans]
  );
  const todayIso = new Date().toISOString().slice(0, 10);
  const todayReadable = new Date().toLocaleDateString('id-ID', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
  });

  const [reportTitle, setReportTitle] = useState(
    'Laporan Eksekutif Threat Intelligence & Postur Keamanan Siber'
  );
  const [audience, setAudience] = useState(
    'Direksi (Board of Directors) & CTO Organisasi'
  );
  const [preparedBy, setPreparedBy] = useState(
    'Tim Cyber Defense & Security Operations (SOC)'
  );
  const [executiveNote, setExecutiveNote] = useState(
    'Seluruh layanan portal terpantau beroperasi normal dengan enkripsi TLS 1.3 dan reputasi IP publik bersih dari seluruh daftar hitam ancaman global. Fokus penguatan prioritas berada pada hardening HTTP header (HSTS & cookie sesi), peningkatan proteksi anti-phishing email (DMARC & CAA), serta aktivasi sensor SIEM lokal pada server produksi.'
  );
  const [exportFeedback, setExportFeedback] = useState<string | null>(null);

  const notifyExport = (msg: string) => {
    setExportFeedback(msg);
    setTimeout(() => setExportFeedback(null), 3000);
  };

  // Compute 4 real executive pillars (0-100)
  const scorecard = useMemo(() => {
    const upCount = endpoints.filter((e) => e.status === 'UP').length;
    const availBase =
      endpoints.length > 0 ? Math.round((upCount / endpoints.length) * 100) : 0;
    const primary = endpoints[0];
    const tlsBonus =
      primary?.tls?.protocol === 'TLSv1.3' &&
      (primary.tls.daysRemaining ?? 0) > 30
        ? 100
        : primary?.tls
        ? 70
        : 50;
    const availabilityTlsScore = Math.round(availBase * 0.6 + tlsBonus * 0.4);

    const avgHeaderScore =
      endpoints.length > 0
        ? Math.round(
            endpoints.reduce((sum, e) => sum + e.headerScore, 0) /
              endpoints.length
          )
        : 0;

    const dnsScore = dnsAudit?.score ?? 0;

    const ipAllClean =
      threatIntel && threatIntel.ipReputation.length > 0
        ? threatIntel.ipReputation.every((r) => !r.listedInThreatFeeds)
        : true;
    const brandPhishHits =
      threatIntel?.openPhish.brandOrIndonesiaMatches.length ?? 0;
    const scaScore = localWazuh?.sca.scorePercent ?? 70;
    const ctiHostScore = Math.round(
      (ipAllClean ? 100 : 25) * 0.45 +
        (brandPhishHits === 0 ? 100 : 30) * 0.25 +
        scaScore * 0.3
    );

    const overall = Math.round(
      availabilityTlsScore * 0.3 +
        avgHeaderScore * 0.25 +
        dnsScore * 0.25 +
        ctiHostScore * 0.2
    );

    const rating =
      overall >= 85
        ? 'STRONG (AMAN TERKENDALI)'
        : overall >= 70
        ? 'MODERATE (TERKENDALI — PERLU HARDENING)'
        : 'ELEVATED RISK (BUTUH AKSI PRIORITAS)';

    return {
      overall,
      rating,
      availabilityTlsScore,
      avgHeaderScore,
      dnsScore,
      ctiHostScore,
      ipAllClean,
      brandPhishHits,
      upCount,
    };
  }, [endpoints, dnsAudit, threatIntel, localWazuh]);

  // Easy-to-understand prioritized strategic recommendations from REAL live data
  const recommendations: StrategicRecommendation[] = useMemo(() => {
    const list: StrategicRecommendation[] = [];
    const primary = endpoints[0];

    const activeDefacementIncidents = boardIncidents.filter(
      (r) =>
        r.status !== 'CLOSED' &&
        (r.category === 'SEO_POISONING_JUDOL' ||
          r.category === 'WEB_DEFACEMENT' ||
          r.category === 'GOOGLE_CLOAKING')
    );
    if (activeDefacementIncidents.length > 0 || flaggedContentScans.length > 0) {
      const affectedList = Array.from(
        new Set([
          ...activeDefacementIncidents.map((r) => r.affectedUrl),
          ...flaggedContentScans.map((s) => s.hostname),
        ])
      ).join(', ');
      list.push({
        id: 'REC-P1-00',
        priority: 'P1 — Segera (0–7 Hari)',
        priorityCode: 'P1',
        domain: 'Penanganan Insiden SEO Poisoning / Web Defacement & Cloaking',
        issuePlain: `Tercatat ${activeDefacementIncidents.length} laporan insiden aktif dan ${flaggedContentScans.length} deteksi live scanner terkait penyusupan konten/SEO judol atau perubahan HTML pada: ${affectedList}.`,
        businessImpact:
          'Menurunkan kepercayaan publik terhadap institusi di hasil pencarian Google dan berisiko mengarahkan pengguna ke situs berbahaya.',
        actionPlan:
          'Koordinasi darurat dengan Tim Infra Ops & Internal CSIRT untuk audit file web/backdoor (.htaccess, webshell), pemulihan dari backup bersih, penguncian hak tulis direktori web (FIM SHA-256), serta pengajuan penghapusan cache & re-indexing di Google Search Console.',
        owner: 'CTO, Tim Infra Ops & Internal CSIRT',
        evidenceLive:
          activeDefacementIncidents[0]?.evidenceSnippet ||
          activeDefacementIncidents[0]?.title ||
          `Live Content Scanner mendeteksi anomali pada ${flaggedContentScans[0]?.hostname ?? '-'}`,
      });
    }

    const missingHstsCount = endpoints.filter(
      (e) => e.status !== 'DOWN' && !e.securityHeaders.hsts
    ).length;
    if (missingHstsCount > 0) {
      list.push({
        id: 'REC-P1-01',
        priority: 'P1 — Segera (0–7 Hari)',
        priorityCode: 'P1',
        domain: 'Keamanan Portal Web (HTTPS Enforcement)',
        issuePlain: `Header keamanan HSTS belum aktif pada ${missingHstsCount} dari ${endpoints.length} portal yang dipantau.`,
        businessImpact:
          'Pengguna yang mengakses portal lewat Wi-Fi publik berisiko terkena serangan penyadapan (downgrade HTTPS ke HTTP).',
        actionPlan:
          'Aktifkan header Strict-Transport-Security (max-age=31536000; includeSubDomains) pada reverse proxy / WAF portal utama dan portal pendamping.',
        owner: 'Tim Infrastruktur Web & WAF',
        evidenceLive: `Live HTTPS probe mendeteksi HSTS=null pada ${primary?.hostname ?? 'portal utama'}.`,
      });
    }

    const weakCookies = endpoints.filter(
      (e) =>
        e.cookies.count > 0 && (!e.cookies.allSecure || !e.cookies.allHttpOnly)
    );
    if (weakCookies.length > 0) {
      list.push({
        id: 'REC-P1-02',
        priority: 'P1 — Segera (0–7 Hari)',
        priorityCode: 'P1',
        domain: 'Perlindungan Sesi Login Pengguna',
        issuePlain: `Cookie sesi pada ${weakCookies.length} endpoint belum seluruhnya dikunci dengan atribut Secure & HttpOnly.`,
        businessImpact:
          'Meningkatkan risiko pembajakan sesi akun (session hijacking) pengguna atau admin apabila terjadi celah script di sisi browser.',
        actionPlan:
          'Wajibkan flag Secure, HttpOnly, dan SameSite=Lax/Strict pada seluruh cookie sesi autentikasi di aplikasi dan load balancer.',
        owner: 'Tim Pengembangan Aplikasi',
        evidenceLive: `Set-Cookie terdeteksi pada ${weakCookies.map((w) => w.hostname).join(', ')}.`,
      });
    }

    if (dnsAudit && (dnsAudit.dmarc.policy === 'none' || dnsAudit.dmarc.policy === 'MISSING')) {
      list.push({
        id: 'REC-P2-01',
        priority: 'P2 — Jangka Pendek (30 Hari)',
        priorityCode: 'P2',
        domain: 'Anti-Phishing & Keaslian Email Resmi',
        issuePlain: `Kebijakan DMARC pada ${dnsAudit.rootDomain} masih bersifat pemantauan saja (p=${dnsAudit.dmarc.policy}), belum memblokir email palsu.`,
        businessImpact:
          'Pelaku penipuan lebih mudah mengirim email phishing mengatasnamakan organisasi (mis. surat palsu kelulusan atau perubahan rekening pencairan dana).',
        actionPlan:
          'Koordinasi dengan pengelola DNS organisasi untuk menaikkan kebijakan DMARC secara bertahap dari p=none → p=quarantine → p=reject setelah audit laporan RUA.',
        owner: 'Divisi Keamanan Informasi & Pengelola DNS',
        evidenceLive: `Live DNS TXT _dmarc.${dnsAudit.rootDomain}: ${dnsAudit.dmarc.record ?? 'MISSING'}`,
      });
    }

    if (dnsAudit && !dnsAudit.caa.present) {
      list.push({
        id: 'REC-P2-02',
        priority: 'P2 — Jangka Pendek (30 Hari)',
        priorityCode: 'P2',
        domain: 'Kontrol Penerbitan Sertifikat SSL/TLS',
        issuePlain: `Record DNS CAA belum dikonfigurasi pada domain induk ${dnsAudit.rootDomain}.`,
        businessImpact:
          'Tanpa CAA, secara teknis Certificate Authority mana pun di dunia dapat menerbitkan sertifikat SSL untuk subdomain organisasi jika terjadi kesalahan verifikasi.',
        actionPlan:
          'Tambahkan DNS CAA record resmi (mis. 0 issue "sectigo.com" atau CA rekanan) agar hanya CA resmi yang diizinkan menerbitkan sertifikat.',
        owner: 'Pengelola DNS Organisasi',
        evidenceLive: `Live DNS CAA lookup pada ${dnsAudit.rootDomain} mengembalikan 0 record.`,
      });
    }

    const lowHeaderSites = endpoints.filter((e) => e.headerScore < 60);
    if (lowHeaderSites.length > 0) {
      list.push({
        id: 'REC-P2-03',
        priority: 'P2 — Jangka Pendek (30 Hari)',
        priorityCode: 'P2',
        domain: 'Standardisasi Keamanan Multi-Portal',
        issuePlain: `Terdapat kesenjangan hardening: ${lowHeaderSites
          .map((s) => `${s.hostname} (${s.headerScore}%)`)
          .join(', ')} jauh lebih rendah dibanding portal utama (${primary?.headerScore ?? 83}%).`,
        businessImpact:
          'Penyerang biasanya menyasar situs pendamping/informasi yang proteksinya lebih lemah sebagai pintu masuk defacement atau distribusi tautan palsu.',
        actionPlan:
          'Terapkan template security headers seragam (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy) di seluruh web server dan sembunyikan header X-Powered-By.',
        owner: 'Tim DevOps & Web Security',
        evidenceLive: `Skor header: ${endpoints.map((e) => `${e.hostname}=${e.headerScore}%`).join(' | ')}`,
      });
    }

    list.push({
      id: 'REC-P3-01',
      priority: 'P3 — Strategis (90 Hari)',
      priorityCode: 'P3',
      domain: 'Visibilitas Internal Server (Local SIEM / Wazuh)',
      issuePlain:
        'Pemantauan eksternal tidak dapat melihat percobaan login brute-force, SQL Injection, atau perubahan file di dalam jaringan internal server produksi.',
      businessImpact:
        'Tanpa sensor SIEM internal, insiden intrusi atau penyalahgunaan hak akses internal berisiko terlambat terdeteksi (MTTD tinggi).',
      actionPlan:
        'Deploy aplikasi SOC ini atau agent Wazuh pada server produksi, aktifkan File Integrity Monitoring (FIM SHA-256), audit CIS Benchmark, serta hubungkan log WAF/Nginx ke endpoint POST /api/ingest/siem.',
      owner: 'CTO, Tim SOC & Infrastruktur Server',
      evidenceLive: localWazuh
        ? `Local SIEM engine teruji aktif (SCA ${localWazuh.sca.scorePercent}%, FIM ${localWazuh.fim.okCount}/${localWazuh.fim.totalMonitored} OK).`
        : 'Modul Local SIEM/XDR siap dikonfigurasi di server lokal.',
    });

    list.push({
      id: 'REC-P3-02',
      priority: 'P3 — Strategis (90 Hari)',
      priorityCode: 'P3',
      domain: 'Patch Management Berbasis CISA KEV & Monitoring Sertifikat',
      issuePlain: `Terdapat ${threatIntel?.cisaKev.totalCount.toLocaleString('id-ID') ?? '0'} celah keamanan yang aktif dieksploitasi secara global (CISA KEV) serta sertifikat TLS portal yang tersisa ${primary?.tls?.daysRemaining ?? '-'} hari.`,
      businessImpact:
        'Keterlambatan patching celah aktif menjadi jalur utama serangan ransomware; sertifikat SSL yang habis masa berlaku dapat menghentikan operasional layanan publik.',
      actionPlan:
        'Tetapkan SLA patching < 72 jam untuk CVE yang masuk CISA KEV jika berdampak pada stack aplikasi, serta otomatisasi perpanjangan sertifikat TLS minimal H-30 sebelum kedaluwarsa.',
      owner: 'CTO & Tim Operasi TI',
      evidenceLive: `TLS ${primary?.tls?.protocol ?? 'TLSv1.3'} valid hingga ${primary?.tls?.validTo ?? '-'} · CISA KEV latest: ${threatIntel?.cisaKev.recent[0]?.cveID ?? '-'}.`,
    });

    return list;
  }, [endpoints, dnsAudit, threatIntel, localWazuh, boardIncidents, flaggedContentScans]);

  const buildExecutiveHtmlDocument = (): string => {
    const endpointRows = endpoints
      .map(
        (ep) => `
        <tr>
          <td><strong>${escapeHtml(ep.label)}</strong><br/><span class="mono">${escapeHtml(ep.hostname)}</span></td>
          <td class="mono">${ep.httpStatus ? `HTTP ${ep.httpStatus}` : ep.status}</td>
          <td class="mono">${ep.latencyMs !== null ? `${ep.latencyMs} ms` : '-'}</td>
          <td class="mono">${ep.headerScore}%</td>
          <td class="mono">${escapeHtml(ep.tls?.protocol ?? '-')} (${ep.tls?.daysRemaining ?? '-'} hari)</td>
          <td class="mono">${escapeHtml(ep.dns.ipv4[0] ?? '-')}</td>
        </tr>`
      )
      .join('');

    const recRows = recommendations
      .map(
        (r) => `
        <tr>
          <td><span class="badge badge-${r.priorityCode.toLowerCase()}">${escapeHtml(r.priorityCode)}</span><br/><span class="small">${escapeHtml(r.priority.replace(/^P\d\s—\s/, ''))}</span></td>
          <td><strong>${escapeHtml(r.domain)}</strong><br/>${escapeHtml(r.issuePlain)}</td>
          <td>${escapeHtml(r.businessImpact)}</td>
          <td>${escapeHtml(r.actionPlan)}</td>
          <td>${escapeHtml(r.owner)}</td>
        </tr>`
      )
      .join('');

    const topKevRows = (threatIntel?.cisaKev.recent ?? [])
      .slice(0, 6)
      .map(
        (k) => `
        <tr>
          <td class="mono"><strong>${escapeHtml(k.cveID)}</strong></td>
          <td>${escapeHtml(k.vendorProject)} — ${escapeHtml(k.product)}</td>
          <td>${escapeHtml(k.vulnerabilityName)}</td>
          <td class="mono">${escapeHtml(k.dateAdded)}</td>
          <td class="mono">${escapeHtml(k.knownRansomwareCampaignUse)}</td>
        </tr>`
      )
      .join('');

    const boardIncidentRows = boardIncidents
      .map(
        (r) => `
        <tr>
          <td class="mono"><strong>${escapeHtml(r.id)}</strong><br/><span class="small">${escapeHtml(formatShortDateTime(r.occurredAt))} WIB</span></td>
          <td><span class="badge ${r.severity === 'CRITICAL' || r.severity === 'HIGH' ? 'badge-p1' : r.severity === 'MEDIUM' ? 'badge-p2' : 'badge-p3'}">${escapeHtml(r.severity)}</span><br/><span class="small">${escapeHtml(STATUS_LABELS[r.status])}</span></td>
          <td><strong>${escapeHtml(r.title)}</strong><br/><span class="mono">${escapeHtml(r.affectedUrl)}</span><br/><span class="small">${escapeHtml(CATEGORY_LABELS[r.category])} · Sumber: ${escapeHtml(SOURCE_LABELS[r.source])}</span></td>
          <td>${escapeHtml(r.description || '-')}${r.evidenceSnippet ? `<br/><span class="mono small">Bukti: ${escapeHtml(r.evidenceSnippet)}</span>` : ''}</td>
          <td><strong>Koordinasi:</strong> ${escapeHtml(r.coordinationNotes || '-')}<br/><strong>Mitigasi:</strong> ${escapeHtml(r.actionTaken || '-')}</td>
        </tr>`
      )
      .join('');

    const demoTag = isDemo ? '[SIMULASI DEMO] ' : '';
    const effectiveTitle = `${demoTag}${reportTitle}`;
    return `<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(effectiveTitle)}</title>
<style>
  @page { size: A4; margin: 16mm; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; line-height: 1.5; margin: 0; padding: 28px; background: #ffffff; }
  .demo-banner { background: #fef3c7; border: 1px solid #f59e0b; color: #92400e; padding: 10px 14px; border-radius: 4px; font-size: 12px; font-weight: 700; margin-bottom: 16px; }
  .header { border-bottom: 3px solid #047857; padding-bottom: 14px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
  .header h1 { margin: 4px 0 0; font-size: 20px; color: #0f172a; }
  .eyebrow { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; color: #047857; font-weight: 700; }
  .meta { font-size: 11px; color: #475569; text-align: right; }
  .summary-box { background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #047857; padding: 14px 16px; border-radius: 4px; margin-bottom: 20px; font-size: 13px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 22px; }
  .kpi { border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px; background: #ffffff; }
  .kpi-label { font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: 600; }
  .kpi-val { font-size: 22px; font-weight: 700; margin-top: 4px; color: #0f172a; font-family: ui-monospace, Menlo, monospace; }
  .kpi-sub { font-size: 11px; color: #475569; margin-top: 2px; }
  h2 { font-size: 15px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin: 24px 0 10px; }
  table { width: 100%; border-collapse: collapse; font-size: 11.5px; margin-bottom: 14px; }
  th { background: #f1f5f9; color: #334155; text-align: left; padding: 8px; border: 1px solid #cbd5e1; font-weight: 600; }
  td { padding: 8px; border: 1px solid #e2e8f0; vertical-align: top; }
  .mono { font-family: ui-monospace, Menlo, monospace; font-size: 11px; }
  .small { font-size: 10px; color: #64748b; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 3px; font-weight: 700; font-size: 10px; font-family: ui-monospace, monospace; }
  .badge-p1 { background: #fee2e2; color: #b91c1c; }
  .badge-p2 { background: #fef3c7; color: #b45309; }
  .badge-p3 { background: #e0f2fe; color: #0369a1; }
  .footer { margin-top: 28px; padding-top: 10px; border-top: 1px solid #e2e8f0; font-size: 10.5px; color: #64748b; display: flex; justify-content: space-between; }
</style>
</head>
<body>
  ${isDemo ? '<div class="demo-banner">[SIMULASI DEMO] Dokumen ini dihasilkan dari data latihan Demo Sandbox, bukan laporan insiden operasional Live.</div>' : ''}
  <div class="header">
    <div>
      <div class="eyebrow">Enterprise Security Operations · Cyber Defense Executive Brief</div>
      <h1>${escapeHtml(effectiveTitle)}</h1>
    </div>
    <div class="meta">
      <div><strong>Tanggal:</strong> ${escapeHtml(todayReadable)}</div>
      <div><strong>Audiens:</strong> ${escapeHtml(audience)}</div>
      <div><strong>Disiapkan oleh:</strong> ${escapeHtml(preparedBy)}</div>
    </div>
  </div>

  <div class="summary-box">
    <strong>Ringkasan Eksekutif (${escapeHtml(scorecard.rating)} — Skor ${scorecard.overall}/100):</strong><br/>
    ${escapeHtml(executiveNote)}
  </div>

  <div class="kpi-grid">
    <div class="kpi">
      <div class="kpi-label">Skor Postur Gabungan</div>
      <div class="kpi-val">${scorecard.overall}/100</div>
      <div class="kpi-sub">${isDemo ? 'Demo Sandbox Telemetry [SIMULASI DEMO]' : '100% Real Live Telemetry'}</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Ketersediaan &amp; TLS</div>
      <div class="kpi-val">${scorecard.upCount}/${endpoints.length} UP</div>
      <div class="kpi-sub">TLSv1.3 · Skor ${scorecard.availabilityTlsScore}/100</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Hardening Web &amp; DNS</div>
      <div class="kpi-val">${scorecard.avgHeaderScore}% / ${scorecard.dnsScore}%</div>
      <div class="kpi-sub">Avg Header / DNS Anti-Spoof</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Reputasi IP &amp; CTI</div>
      <div class="kpi-val">${scorecard.ipAllClean ? 'ALL CLEAN' : 'ALERT'}</div>
      <div class="kpi-sub">Phish Match: ${scorecard.brandPhishHits} · CISA KEV: ${threatIntel?.cisaKev.totalCount ?? 0}</div>
    </div>
  </div>

  <h2>1. Rangkuman Masukan &amp; Peta Jalan Penguatan Keamanan (Prioritas P1–P3)</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 11%">Prioritas</th>
        <th style="width: 24%">Area &amp; Temuan Utama</th>
        <th style="width: 22%">Dampak Bisnis / Risiko</th>
        <th style="width: 28%">Rekomendasi Aksi Penguatan</th>
        <th style="width: 15%">PIC Disarankan</th>
      </tr>
    </thead>
    <tbody>${recRows}</tbody>
  </table>

  <h2>2. Status Live Layanan Portal &amp; Endpoint Terpantau</h2>
  <table>
    <thead>
      <tr>
        <th>Portal / Endpoint</th>
        <th>Status HTTP</th>
        <th>Latensi</th>
        <th>Skor Header</th>
        <th>TLS / Sisa Hari</th>
        <th>IPv4 Resmi</th>
      </tr>
    </thead>
    <tbody>${endpointRows}</tbody>
  </table>

  <h2>3. Ringkasan Global Threat Intelligence (Sumber Publik Terverifikasi)</h2>
  <p style="font-size:12px; color:#334155; margin-top:0;">
    Data ditarik langsung dari 6 sumber CTI global: <strong>CISA KEV</strong> (${threatIntel?.cisaKev.totalCount ?? 0} CVE aktif),
    <strong>abuse.ch Feodo + EmergingThreats</strong> (${(threatIntel?.botnetC2.feodoTotal ?? 0) + (threatIntel?.botnetC2.etCompromisedTotal ?? 0)} IP botnet/berbahaya),
    <strong>CertSpotter CT</strong> (${threatIntel?.certTransparency.totalEntries ?? 0} sertifikat *.${escapeHtml(dnsAudit?.rootDomain ?? 'domain target')}),
    <strong>OpenPhish</strong> (${threatIntel?.openPhish.totalActiveUrls ?? 0} URL aktif, ${scorecard.brandPhishHits} kecocokan kata kunci target),
    <strong>Ransomware.live</strong> (${threatIntel?.ransomware.totalRecent ?? 0} klaim terbaru), dan <strong>APNIC RDAP / RIPEstat BGP</strong> (reputasi blok IP target terverifikasi).
  </p>
  <table>
    <thead>
      <tr>
        <th>CVE ID</th>
        <th>Vendor / Produk</th>
        <th>Nama Kerentanan Aktif (CISA KEV Terbaru)</th>
        <th>Ditambahkan</th>
        <th>Ransomware</th>
      </tr>
    </thead>
    <tbody>${topKevRows}</tbody>
  </table>

  <h2>4. Daftar Insiden Tercatat &amp; Laporan Eksternal (Infra Ops / CSIRT / SEO Poisoning / Defacement)</h2>
  ${
    boardIncidents.length > 0
      ? `<table>
    <thead>
      <tr>
        <th style="width: 14%">ID &amp; Waktu</th>
        <th style="width: 11%">Severity / Status</th>
        <th style="width: 26%">Insiden &amp; Sistem Terdampak</th>
        <th style="width: 25%">Kronologi &amp; Bukti</th>
        <th style="width: 24%">Koordinasi Infra &amp; Mitigasi</th>
      </tr>
    </thead>
    <tbody>${boardIncidentRows}</tbody>
  </table>`
      : `<p style="font-size:12px; color:#475569;">Tidak ada insiden manual/eksternal (defacement, SEO poisoning, atau eskalasi Infra Ops) yang dilampirkan pada periode laporan ini.</p>`
  }

  <div class="footer">
    <span>Dokumen Rahasia Terbatas — Untuk Keperluan Rapat Manajemen / Direksi / CTO</span>
    <span>Dihasilkan otomatis pada ${escapeHtml(formatShortDateTime(new Date().toISOString()))} WIB</span>
  </div>
</body>
</html>`;
  };

  const handleExportHtmlPdfReady = () => {
    const html = buildExecutiveHtmlDocument();
    triggerFileDownload(
      html,
      `SOC-Board-Threat-Intel-Report-${todayIso}.html`,
      'text/html;charset=utf-8'
    );
    notifyExport('Laporan HTML siap cetak/PDF berhasil diunduh.');
  };

  const handleExportWordDoc = () => {
    const html = buildExecutiveHtmlDocument();
    triggerFileDownload(
      html,
      `SOC-Board-Threat-Intel-Report-${todayIso}.doc`,
      'application/msword;charset=utf-8'
    );
    notifyExport('Dokumen Word (.doc) untuk Rapat Direksi/CTO berhasil diunduh.');
  };

  const handleExportMarkdown = () => {
    const demoPrefix = isDemo ? '[SIMULASI DEMO] ' : '';
    const md = [
      `# ${demoPrefix}${reportTitle}`,
      ...(isDemo
        ? [
            ``,
            `> **[SIMULASI DEMO]** Dokumen ini dihasilkan dari data latihan Demo Sandbox, bukan laporan operasional Live.`,
          ]
        : []),
      ``,
      `- **Tanggal:** ${todayReadable}`,
      `- **Audiens:** ${audience}`,
      `- **Disiapkan oleh:** ${preparedBy}`,
      `- **Skor Postur Keamanan:** **${scorecard.overall}/100 (${scorecard.rating})**`,
      ``,
      `## Ringkasan Eksekutif`,
      executiveNote,
      ``,
      `## 1. Skor 4 Pilar Keamanan (${isDemo ? 'Demo Sandbox Telemetry' : '100% Live Data'})`,
      `| Pilar | Skor / Status | Keterangan |`,
      `|---|---|---|`,
      `| Ketersediaan Portal & Enkripsi TLS | ${scorecard.availabilityTlsScore}/100 | ${scorecard.upCount}/${endpoints.length} endpoint UP, TLSv1.3 |`,
      `| Hardening Aplikasi Web (Headers & Cookie) | ${scorecard.avgHeaderScore}/100 | Rata-rata 6 security headers |`,
      `| Perlindungan Domain & Email (SPF/DMARC/CAA) | ${scorecard.dnsScore}/100 | SPF ${dnsAudit?.spf.policy ?? '-'}, DMARC p=${dnsAudit?.dmarc.policy ?? '-'} |`,
      `| Reputasi IP, Open CTI & Host Readiness | ${scorecard.ctiHostScore}/100 | IP Target ${scorecard.ipAllClean ? 'ALL CLEAN' : 'ALERT'}, Phishing Match: ${scorecard.brandPhishHits} |`,
      ``,
      `## 2. Rangkuman Masukan & Prioritas Penguatan Sistem`,
      ...recommendations.map(
        (r) =>
          `### [${r.priorityCode}] ${r.domain} (${r.priority})\n- **Masalah:** ${r.issuePlain}\n- **Dampak Bisnis:** ${r.businessImpact}\n- **Langkah Penguatan:** ${r.actionPlan}\n- **PIC:** ${r.owner}\n- **Bukti Live:** \`${r.evidenceLive}\`\n`
      ),
      `## 3. Sorotan Threat Intelligence Global Terkini`,
      `- **CISA KEV:** ${threatIntel?.cisaKev.totalCount ?? 0} CVE aktif dieksploitasi (Terbaru: ${threatIntel?.cisaKev.recent[0]?.cveID ?? '-'})`,
      `- **Botnet & Compromised IPs:** ${(threatIntel?.botnetC2.feodoTotal ?? 0) + (threatIntel?.botnetC2.etCompromisedTotal ?? 0)} IP dipantau (abuse.ch Feodo + EmergingThreats)`,
      `- **OpenPhish Live Radar:** ${threatIntel?.openPhish.totalActiveUrls ?? 0} URL aktif dipindai (${scorecard.brandPhishHits} kecocokan kata kunci target)`,
      `- **Verifikasi APNIC/BGP:** ${threatIntel?.ipReputation.map((i) => `${i.ip} (${i.netName}/${i.asn}: ${i.listedInThreatFeeds ? 'LISTED' : 'CLEAN'})`).join(', ') || '-'}`,
      ``,
      `## 4. Insiden Tercatat & Laporan Eksternal (Infra Ops / CSIRT / SEO Poisoning / Defacement)`,
      ...(boardIncidents.length > 0
        ? boardIncidents.map(
            (r) =>
              `### [${r.severity}] ${r.title} (${r.id} — ${STATUS_LABELS[r.status]})\n- **URL Terdampak:** ${r.affectedUrl}\n- **Kategori & Sumber:** ${CATEGORY_LABELS[r.category]} · ${SOURCE_LABELS[r.source]} (${r.reporterName})\n- **Waktu Kejadian:** ${formatShortDateTime(r.occurredAt)} WIB\n- **Kronologi:** ${r.description || '-'}\n- **Bukti:** ${r.evidenceSnippet || '-'}\n- **Koordinasi Infra / Server:** ${r.coordinationNotes || '-'}\n- **Tindakan Mitigasi:** ${r.actionTaken || '-'}\n`
          )
        : [`Tidak ada insiden manual/eksternal yang dilampirkan pada laporan ini.`]),
    ].join('\n');

    triggerFileDownload(
      md,
      `SOC-CTO-Threat-Intel-Brief-${todayIso}.md`,
      'text/markdown;charset=utf-8'
    );
    notifyExport('Executive Brief format Markdown (.md) berhasil diunduh.');
  };

  const handleExportRoadmapCsv = () => {
    exportToCSV(
      recommendations.map((r) => ({
        id: r.id,
        priority: r.priority,
        domain: r.domain,
        issue_plain: r.issuePlain,
        business_impact: r.businessImpact,
        action_plan: r.actionPlan,
        owner: r.owner,
        live_evidence: r.evidenceLive,
      })),
      `SOC-Security-Strengthening-Roadmap-${todayIso}.csv`
    );
    notifyExport('Roadmap penguatan keamanan (.csv) berhasil diunduh.');
  };

  return (
    <div className="space-y-5">
      {isDemo && (
        <div className="bg-amber-500/10 border border-amber-500/35 rounded-lg px-4 py-2.5 text-xs text-amber-200 flex items-center justify-between gap-2 print:hidden">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              <strong className="font-mono">[SIMULASI DEMO]</strong> Pratinjau Laporan Eksekutif menggunakan paket latihan Demo Sandbox. Semua file ekspor dari mode ini otomatis ditandai <span className="font-mono">[SIMULASI DEMO]</span>.
            </span>
          </div>
        </div>
      )}

      {/* Executive Report Export Bar */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-4 print:hidden">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100">
              Executive Brief &amp; Laporan Threat Intelligence (Board / Direksi / CTO)
            </h2>
          </div>
          {isDemo && (
            <p className="text-xs text-zinc-400">
              Rangkuman masukan berbahasa manajemen yang dihitung otomatis dari data SOC, siap diekspor ke format rapi untuk rapat Direksi atau CTO.
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ActionTooltip
            label="Unduh Word (.doc)"
            description="Ekspor laporan eksekutif lengkap ke dokumen Microsoft Word siap edit."
          >
            <button
              type="button"
              onClick={handleExportWordDoc}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <FileDown className="w-3.5 h-3.5" />
              Export Word (.doc)
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Unduh HTML Siap PDF"
            description="Ekspor dokumen HTML dengan tata letak cetak A4 untuk dikonversi ke PDF."
          >
            <button
              type="button"
              onClick={handleExportHtmlPdfReady}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5 text-emerald-400" />
              Export HTML / PDF
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Unduh Brief Markdown"
            description="Ekspor ringkasan eksekutif ke format teks terstruktur .md."
          >
            <button
              type="button"
              onClick={handleExportMarkdown}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <ClipboardCheck className="w-3.5 h-3.5 text-zinc-400" />
              Brief (.md)
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Unduh Roadmap CSV"
            description="Ekspor daftar rekomendasi prioritas P1-P3 ke format spreadsheet CSV."
          >
            <button
              type="button"
              onClick={handleExportRoadmapCsv}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Table className="w-3.5 h-3.5 text-zinc-400" />
              Roadmap CSV
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Cetak / Simpan PDF"
            description="Buka dialog cetak browser untuk langsung mencetak atau Save as PDF."
          >
            <button
              type="button"
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5 text-zinc-400" />
              Print / PDF
            </button>
          </ActionTooltip>
        </div>
      </section>

      {exportFeedback && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg px-4 py-2.5 text-xs text-emerald-300 flex items-center gap-2 print:hidden">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{exportFeedback}</span>
        </div>
      )}

      {/* Customizable Board Metadata */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 space-y-3 print:hidden">
        <p className="text-xs font-semibold text-zinc-200">
          Kustomisasi Identitas &amp; Catatan Pengantar Rapat
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <label className="block space-y-1">
            <span className="text-[11px] text-zinc-400">Judul Laporan</span>
            <input
              type="text"
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            />
          </label>
          <label className="block space-y-1">
            <span className="text-[11px] text-zinc-400">Audiens Rapat</span>
            <select
              value={audience}
              onChange={(e) => setAudience(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100"
            >
              <option value="Direksi (Board of Directors) & CTO Organisasi">
                Direksi (Board of Directors) &amp; CTO Organisasi
              </option>
              <option value="Chief Technology Officer (CTO) & Divisi TI">
                Chief Technology Officer (CTO) &amp; Divisi TI
              </option>
              <option value="Komite Manajemen Risiko & Audit Internal">
                Komite Manajemen Risiko &amp; Audit Internal
              </option>
            </select>
          </label>
          <label className="block space-y-1">
            <span className="text-[11px] text-zinc-400">Disiapkan Oleh</span>
            <input
              type="text"
              value={preparedBy}
              onChange={(e) => setPreparedBy(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            />
          </label>
        </div>
        <label className="block space-y-1">
          <span className="text-[11px] text-zinc-400">
            Ringkasan Eksekutif (Bahasa Manajemen — Otomatis masuk ke dokumen ekspor)
          </span>
          <textarea
            rows={2}
            value={executiveNote}
            onChange={(e) => setExecutiveNote(e.target.value)}
            className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
          />
        </label>
      </section>

      {/* Executive Posture Scorecard (4 Pillars + Overall Rating) */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-zinc-800/80 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <p className="font-mono text-[11px] uppercase text-emerald-400">
              ENTERPRISE CYBER POSTURE SCORECARD · {todayReadable}
            </p>
            <h3 className="text-base font-semibold text-zinc-100 mt-0.5">
              {reportTitle}
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Audiens: {audience} · Disiapkan oleh: {preparedBy}
            </p>
          </div>

          <div className="bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-2.5 text-right shrink-0">
            <p className="text-[10px] font-mono uppercase text-zinc-500">
              Skor Postur Gabungan
            </p>
            <p
              className={`font-mono text-2xl font-bold tabular-nums ${
                scorecard.overall >= 85
                  ? 'text-emerald-400'
                  : scorecard.overall >= 70
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {scorecard.overall} / 100
            </p>
            <p className="font-mono text-[10px] text-zinc-400">
              {scorecard.rating}
            </p>
          </div>
        </div>

        <div className="px-5 py-3.5 bg-zinc-950/50 border-b border-zinc-800/80 text-xs text-zinc-200 leading-relaxed">
          <strong className="text-emerald-400">Pesan Utama untuk Pimpinan: </strong>
          {executiveNote}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-zinc-800/80">
          <div className="p-4">
            <p className="text-[11px] text-zinc-400">
              1. Ketersediaan &amp; Enkripsi TLS
            </p>
            <p className="mt-1 font-mono text-xl font-semibold text-emerald-400 tabular-nums">
              {scorecard.availabilityTlsScore}/100
            </p>
            <p className="mt-1 text-[11px] text-zinc-400">
              {scorecard.upCount}/{endpoints.length} portal UP · TLSv1.3 aktif (sisa{' '}
              {endpoints[0]?.tls?.daysRemaining ?? '-'} hari)
            </p>
          </div>

          <div className="p-4">
            <p className="text-[11px] text-zinc-400">
              2. Hardening Aplikasi Web
            </p>
            <p
              className={`mt-1 font-mono text-xl font-semibold tabular-nums ${
                scorecard.avgHeaderScore >= 75 ? 'text-emerald-400' : 'text-amber-400'
              }`}
            >
              {scorecard.avgHeaderScore}/100
            </p>
            <p className="mt-1 text-[11px] text-zinc-400">
              Rata-rata kepatuhan 6 header keamanan lintas portal terpantau
            </p>
          </div>

          <div className="p-4">
            <p className="text-[11px] text-zinc-400">
              3. Anti-Phishing Domain &amp; Email
            </p>
            <p
              className={`mt-1 font-mono text-xl font-semibold tabular-nums ${
                scorecard.dnsScore >= 75 ? 'text-emerald-400' : 'text-amber-400'
              }`}
            >
              {scorecard.dnsScore}/100
            </p>
            <p className="mt-1 text-[11px] text-zinc-400">
              SPF {dnsAudit?.spf.policy ?? '-'} · DMARC p=
              {dnsAudit?.dmarc.policy ?? '-'} · CAA{' '}
              {dnsAudit?.caa.present ? 'Aktif' : 'Belum Ada'}
            </p>
          </div>

          <div className="p-4">
            <p className="text-[11px] text-zinc-400">
              4. Threat Intel &amp; Reputasi IP
            </p>
            <p className="mt-1 font-mono text-xl font-semibold text-emerald-400 tabular-nums">
              {scorecard.ctiHostScore}/100
            </p>
            <p className="mt-1 text-[11px] text-zinc-400">
              IP Target {scorecard.ipAllClean ? 'ALL CLEAN' : 'ALERT'} ·{' '}
              {scorecard.brandPhishHits} phishing match ·{' '}
              {findings.filter((f) => f.status === 'OPEN').length} temuan terbuka
            </p>
          </div>
        </div>
      </section>

      {/* Easy-to-Understand Strengthening Roadmap (P1 / P2 / P3) */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-zinc-800/80 flex items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">
              Rangkuman Masukan Penguatan Keamanan Sistem ({recommendations.length} Prioritas)
            </h3>
            {isDemo && (
              <p className="text-xs text-zinc-400 mt-0.5">
                Disusun dalam bahasa non-teknis agar cepat diputuskan oleh Direksi &amp; langsung dapat dieksekusi oleh tim CTO/TI.
              </p>
            )}
          </div>
        </div>

        <div className="divide-y divide-zinc-800/70">
          {recommendations.map((rec) => {
            const tone =
              rec.priorityCode === 'P1'
                ? 'text-rose-400'
                : rec.priorityCode === 'P2'
                ? 'text-amber-400'
                : 'text-sky-400';
            return (
              <div key={rec.id} className="p-5 space-y-2.5 hover:bg-zinc-900/50">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                    <span className={`font-semibold ${tone}`}>
                      {rec.priority}
                    </span>
                    <span className="text-zinc-700">·</span>
                    <span className="text-zinc-300 font-semibold font-sans text-sm">
                      {rec.domain}
                    </span>
                  </div>
                  <span className="font-mono text-[11px] text-zinc-400">
                    PIC: {rec.owner}
                  </span>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 text-xs pt-1">
                  <div className="bg-zinc-950/70 border border-zinc-800/80 rounded-md p-3">
                    <p className="font-mono text-[10px] uppercase text-zinc-500 mb-1">
                      Apa yang Ditemukan (Bahasa Sederhana)
                    </p>
                    <p className="text-zinc-200 leading-relaxed">{rec.issuePlain}</p>
                  </div>

                  <div className="bg-zinc-950/70 border border-zinc-800/80 rounded-md p-3">
                    <p className="font-mono text-[10px] uppercase text-amber-400/90 mb-1 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Dampak ke Bisnis &amp; Pengguna
                    </p>
                    <p className="text-zinc-300 leading-relaxed">
                      {rec.businessImpact}
                    </p>
                  </div>

                  <div className="bg-zinc-950/70 border border-emerald-500/20 rounded-md p-3">
                    <p className="font-mono text-[10px] uppercase text-emerald-400 mb-1 flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" />
                      Rekomendasi Aksi Penguatan
                    </p>
                    <p className="text-zinc-200 leading-relaxed">{rec.actionPlan}</p>
                  </div>
                </div>

                <p className="font-mono text-[11px] text-zinc-500">
                  Bukti Pengukuran Live: {rec.evidenceLive}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Recorded Manual / Infra Ops / Defacement / SEO Poisoning Incidents for Board & CTO */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">
              Lampiran Insiden Tercatat &amp; Laporan Eksternal Infra Ops / CSIRT ({boardIncidents.length})
            </h3>
            {isDemo && (
              <p className="text-xs text-zinc-400 mt-0.5">
                Seluruh kasus defacement, SEO poisoning/judol, Google cloaking, maupun laporan dari Tim Infra Ops yang ditandai masuk laporan CTO &amp; BoD otomatis terlampir saat ekspor Word, HTML/PDF, dan Markdown.
              </p>
            )}
          </div>
          <ActionTooltip
            label="Buka Incident Reports"
            description="Kelola daftar insiden atau ubah centang lampiran CTO & BoD."
          >
            <button
              type="button"
              onClick={onOpenIncidentReports}
              className="text-xs font-medium text-emerald-400 hover:text-emerald-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer print:hidden"
            >
              Kelola / Catat Insiden →
            </button>
          </ActionTooltip>
        </div>

        {boardIncidents.length === 0 ? (
          <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-zinc-400">
            <span>
              Belum ada laporan insiden eksternal yang dilampirkan pada periode ini.
            </span>
            <ActionTooltip
              label="Catat Insiden Baru"
              description="Navigasi ke halaman Incident Reports untuk mencatat atau menandai insiden ke laporan Direksi."
            >
              <button
                type="button"
                onClick={onOpenIncidentReports}
                className="px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md whitespace-nowrap shrink-0 cursor-pointer print:hidden"
              >
                Catat Insiden di Halaman Incident Reports
              </button>
            </ActionTooltip>
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/70">
            {boardIncidents.map((inc) => {
              const sev = getSeverityColor(inc.severity);
              return (
                <div key={inc.id} className="p-5 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`font-semibold ${sev.text}`}>
                        {sev.label}
                      </span>
                      <span className="text-zinc-700">·</span>
                      <span className="text-zinc-300">{inc.id}</span>
                      <span className="text-zinc-700">·</span>
                      <span className="text-zinc-400">
                        {CATEGORY_LABELS[inc.category]}
                      </span>
                      <span className="text-zinc-700">·</span>
                      <span className="text-zinc-400">
                        {SOURCE_LABELS[inc.source]}
                      </span>
                    </div>
                    <span className="text-zinc-400">
                      Status: <strong className="text-zinc-200">{STATUS_LABELS[inc.status]}</strong> · {formatShortDateTime(inc.occurredAt)} WIB
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-zinc-100">
                    {inc.title}
                  </h4>
                  <p className="font-mono text-[11px] text-emerald-400 break-all">
                    {inc.affectedUrl}
                  </p>
                  {inc.description && (
                    <p className="text-xs text-zinc-300 leading-relaxed">
                      {inc.description}
                    </p>
                  )}
                  {inc.evidenceSnippet && (
                    <p className="font-mono text-[11px] text-zinc-400">
                      Bukti: {inc.evidenceSnippet}
                    </p>
                  )}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-1 text-zinc-300">
                    <div>
                      <span className="text-zinc-500 font-mono text-[11px]">
                        Koordinasi Infra Ops / Server:{' '}
                      </span>
                      {inc.coordinationNotes || '—'}
                    </div>
                    <div>
                      <span className="text-zinc-500 font-mono text-[11px]">
                        Tindakan Mitigasi:{' '}
                      </span>
                      {inc.actionTaken || '—'}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
};
