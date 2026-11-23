import React, { useMemo, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Copy,
  Check,
  RefreshCw,
  Headphones,
  ArrowUpRight,
  PhoneCall,
  Layers,
  MessageSquare,
  Edit3,
  Save,
  X,
} from 'lucide-react';
import {
  ContentIntegrityScan,
  LiveAttackEvent,
  LocalWazuhSnapshot,
  ManualIncidentReport,
  RealEndpointProbe,
  RealSecurityFinding,
  RealSocView,
  Severity,
} from '../types/soc';
import { SeverityBadge } from './IncidentReportsView';
import { ActionTooltip } from './ActionTooltip';
import { useSocMode } from '../context/SocModeContext';
import { formatShortDateTime } from '../utils/socFormatters';

interface ServiceHealthSupportViewProps {
  endpoints: RealEndpointProbe[];
  contentScans: ContentIntegrityScan[];
  findings: RealSecurityFinding[];
  incidentReports: ManualIncidentReport[];
  localWazuh: LocalWazuhSnapshot | null;
  ingestedSiemEvents: LiveAttackEvent[];
  scanningNow: boolean;
  onRunLiveScan: () => Promise<void>;
  onNavigateView: (view: RealSocView) => void;
}

type TrafficLight = 'GREEN' | 'YELLOW' | 'RED';

interface EvaluatedServiceHealth {
  endpoint: RealEndpointProbe;
  light: TrafficLight;
  statusLabel: string;
  userImpactMessage: string;
  reasons: string[];
  scan: ContentIntegrityScan | null;
  activeIncidentsCount: number;
}

interface GroupedAlertDigest {
  id: string;
  title: string;
  source: string;
  severity: Severity;
  count: number;
  plainSummary: string;
  latestAt: string;
  targetView: RealSocView;
}

interface SupportScenario {
  id: string;
  title: string;
  triggerExample: string;
  defaultSeverity: Severity;
  firstChecks: string[];
  whenToEscalate: string;
  helpdeskReplyTemplate: string;
  escalateTarget: RealSocView;
}

interface EscalationRow {
  id: string;
  incidentType: string;
  severity: Severity;
  primaryUnit: string;
  supportUnits: string;
  slaResponse: string;
  defaultChannelHint: string;
}

const PIC_STORAGE_KEY = 'soc_support_pic_contacts_v1';

const SUPPORT_SCENARIOS: SupportScenario[] = [
  {
    id: 'sc-portal-down',
    title: 'Pengguna melapor portal layanan lambat atau tidak bisa dibuka',
    triggerExample: 'Contoh keluhan: "Web portal error 502 / muter terus saat submit formulir."',
    defaultSeverity: 'HIGH',
    firstChecks: [
      'Cek warna status layanan pada papan Lampu Lalu Lintas di atas (Hijau = server pusat normal; Merah/Kuning = gangguan pusat).',
      'Jika status Hijau, minta user mencoba mode Incognito, membersihkan cache browser, atau ganti koneksi internet.',
      'Jika status Merah/Kuning di luar jadwal maintenance resmi, segera catat jam mulai gangguan dan jumlah laporan masuk.',
    ],
    whenToEscalate:
      'Eskalasi segera ke Tim Infra / Server Ops jika status layanan Merah > 5 menit atau latensi > 3.000 ms pada jam sibuk.',
    helpdeskReplyTemplate:
      'Halo Bapak/Ibu, terima kasih atas laporannya. Saat ini tim teknis kami sedang melakukan pengecekan pada akses portal layanan. Mohon berkenan menunggu sekitar 15–30 menit dan mencoba kembali melalui browser terbaru (Chrome/Edge). Kami akan segera menginformasikan pembaruan apabila layanan telah kembali normal sepenuhnya.',
    escalateTarget: 'action-advisor',
  },
  {
    id: 'sc-defacement-judol',
    title: 'Ditemukan tampilan aneh / link iklan judi online di Google atau halaman web',
    triggerExample: 'Contoh laporan: "Cari portal resmi di Google muncul deskripsi SLOT777 / gacor."',
    defaultSeverity: 'CRITICAL',
    firstChecks: [
      'Ambil tangkapan layar (screenshot) penuh termasuk alamat URL dan jam kejadian sebagai bukti awal.',
      'Cek tampilan langsung di browser Incognito dan jalankan "Scan HTML & Cloaking" pada menu Incident Reports.',
      'Jangan menyebarkan tautan bermasalah secara luas; segera catat melalui Incident Triage Wizard (kategori Defacement).',
    ],
    whenToEscalate:
      'WAJIB eskalasi segera (< 15 menit) ke Tim Infra Ops, Internal CSIRT, dan pimpinan TI/CTO untuk audit server & pembersihan indeks Google.',
    helpdeskReplyTemplate:
      'Halo Bapak/Ibu, terima kasih atas informasi yang disampaikan. Tim keamanan TI kami bersama pengelola infrastruktur telah menerima laporan tersebut dan sedang menindaklanjuti penanganannya. Untuk keamanan bersama, mohon selalu mengakses layanan hanya melalui domain resmi organisasi.',
    escalateTarget: 'incident-reports',
  },
  {
    id: 'sc-phishing-brand',
    title: 'Pengguna menerima email / situs palsu mengatasnamakan organisasi',
    triggerExample: 'Contoh laporan: "Ada link portal-verify-account.example minta isi data KTP & rekening."',
    defaultSeverity: 'HIGH',
    firstChecks: [
      'Verifikasi alamat domain pengirim/tautan—layanan resmi organisasi hanya menggunakan domain resmi yang terdaftar.',
      'Minta pelapor tidak mengklik tautan, tidak memasukkan kata sandi, dan meneruskan salinan URL/screenshot ke Support IT.',
      'Catat domain palsu di Incident Triage Wizard (kategori Phishing) untuk pengajuan pemblokiran (takedown).',
    ],
    whenToEscalate:
      'Eskalasi ke Internal CSIRT, Gov-CERT/Registrar untuk takedown domain, dan koordinasi dengan tim komunikasi untuk imbauan publik.',
    helpdeskReplyTemplate:
      'Halo Bapak/Ibu, tautan/email tersebut BUKAN merupakan kanal resmi organisasi kami. Seluruh informasi dan layanan resmi hanya dilakukan melalui portal resmi kami dan tidak dipungut biaya tambahan. Mohon abaikan tautan tersebut dan jangan memasukkan data pribadi atau kode OTP apa pun.',
    escalateTarget: 'incident-reports',
  },
  {
    id: 'sc-account-takeover',
    title: 'Pengguna / Pegawai melapor akun dibobol atau ada perubahan data tidak dikenal',
    triggerExample: 'Contoh laporan: "Ada login dari lokasi tidak dikenal atau data rekening/profil berubah sendiri."',
    defaultSeverity: 'CRITICAL',
    firstChecks: [
      'Verifikasi identitas pelapor sesuai SOP Helpdesk sebelum melakukan tindakan pada akun.',
      'Catat alamat email/ID akun, waktu kejadian, serta detail perubahan data yang dilaporkan.',
      'Minta pengguna segera mengganti password akun email pribadi yang terhubung dan aktifkan 2FA/MFA.',
    ],
    whenToEscalate:
      'Eskalasi segera (< 30 menit) ke Tim IAM/Development & Tim Infra untuk penguncian sementara akun, pencabutan sesi aktif, dan audit log login.',
    helpdeskReplyTemplate:
      'Halo Bapak/Ibu, laporan terkait keamanan akun Anda telah kami terima dengan prioritas tinggi. Tim teknis kami sedang melakukan pengamanan akun dan pengecekan riwayat aktivitas login. Mohon segera mengganti kata sandi email pribadi Anda dan tidak membagikan kode verifikasi kepada siapa pun.',
    escalateTarget: 'incident-reports',
  },
];

const ESCALATION_MATRIX: EscalationRow[] = [
  {
    id: 'esc-defacement',
    incidentType: 'Web Defacement / SEO Judol / Cloaking',
    severity: 'CRITICAL',
    primaryUnit: 'Tim Infra / Server Ops + Tim Development',
    supportUnits: 'Internal CSIRT · Komunikasi Publik · CTO',
    slaResponse: '< 1 Jam',
    defaultChannelHint: 'Tiket Prioritas Infra + Hotline CSIRT',
  },
  {
    id: 'esc-outage',
    incidentType: 'Portal Down / Gangguan Ketersediaan (DDoS)',
    severity: 'CRITICAL',
    primaryUnit: 'Tim Infra / Server Ops (Network & WAF)',
    supportUnits: 'Support IT · Helpdesk Layanan',
    slaResponse: '< 30 Menit',
    defaultChannelHint: 'Service Desk Infra + Grup Ops TI',
  },
  {
    id: 'esc-account',
    incidentType: 'Akses Tidak Sah / Kebocoran Akun & Data',
    severity: 'CRITICAL',
    primaryUnit: 'Tim IAM/Dev + Internal CSIRT',
    supportUnits: 'Tim Infra Ops · Pimpinan / Manajemen',
    slaResponse: '< 30 Menit',
    defaultChannelHint: 'Eskalasi Langsung CSIRT & CTO',
  },
  {
    id: 'esc-phishing',
    incidentType: 'Situs / Email Phishing Mengatasnamakan Organisasi',
    severity: 'HIGH',
    primaryUnit: 'Internal CSIRT + Gov-CERT / Registrar',
    supportUnits: 'Support IT · Komunikasi Publik',
    slaResponse: '< 4 Jam',
    defaultChannelHint: 'Email CSIRT + Laporan Takedown',
  },
  {
    id: 'esc-hardening',
    incidentType: 'Kelemahan Header / TLS / DNS / CVE Non-Aktif',
    severity: 'MEDIUM',
    primaryUnit: 'Tim Development + Tim Infra Ops',
    supportUnits: 'Tim Keamanan Informasi (SOC)',
    slaResponse: '3–7 Hari Kerja',
    defaultChannelHint: 'Tiket Change Request / Sprint Dev',
  },
];

function loadSavedContacts(): Record<string, string> {
  try {
    const raw = localStorage.getItem(PIC_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === 'object'
      ? (parsed as Record<string, string>)
      : {};
  } catch {
    return {};
  }
}

export const ServiceHealthSupportView: React.FC<
  ServiceHealthSupportViewProps
> = ({
  endpoints,
  contentScans,
  findings,
  incidentReports,
  localWazuh,
  ingestedSiemEvents,
  scanningNow,
  onRunLiveScan,
  onNavigateView,
}) => {
  const { isDemo } = useSocMode();
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(
    SUPPORT_SCENARIOS[0].id
  );
  const [checkedSteps, setCheckedSteps] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Editable internal PIC contacts (stored locally in browser localStorage)
  const [picContacts, setPicContacts] = useState<Record<string, string>>(() =>
    loadSavedContacts()
  );
  const [editingContacts, setEditingContacts] = useState(false);
  const [draftContacts, setDraftContacts] = useState<Record<string, string>>(
    {}
  );

  // 1. Evaluate Traffic-Light Status for each real monitored endpoint
  const evaluatedServices = useMemo<EvaluatedServiceHealth[]>(() => {
    return endpoints.map((ep) => {
      const scan =
        contentScans.find(
          (s) => s.endpointId === ep.id || s.url === ep.url
        ) ?? null;
      const relatedOpenIncidents = incidentReports.filter(
        (r) =>
          r.status !== 'CLOSED' &&
          r.status !== 'MITIGATED' &&
          (r.affectedUrl.toLowerCase().includes(ep.hostname.toLowerCase()) ||
            ep.url.toLowerCase().includes(r.affectedUrl.toLowerCase()))
      );
      const hasCriticalIncident = relatedOpenIncidents.some(
        (r) => r.severity === 'CRITICAL'
      );

      const reasons: string[] = [];
      let light: TrafficLight = 'GREEN';

      if (ep.status === 'DOWN' || (ep.httpStatus !== null && ep.httpStatus >= 500)) {
        light = 'RED';
        reasons.push(
          ep.httpStatus
            ? `Server merespons HTTP ${ep.httpStatus}`
            : 'Endpoint tidak dapat dijangkau dari luar'
        );
      }
      if (scan && scan.riskLevel === 'CRITICAL') {
        light = 'RED';
        reasons.push('Terdeteksi indikasi defacement / kata kunci ilegal pada HTML');
      }
      if (hasCriticalIncident) {
        light = 'RED';
        reasons.push(
          `${relatedOpenIncidents.length} insiden aktif (termasuk Critical)`
        );
      }

      if (light !== 'RED') {
        if (ep.status === 'DEGRADED' || (ep.latencyMs !== null && ep.latencyMs >= 1500)) {
          light = 'YELLOW';
          reasons.push(
            `Respon melambat (${ep.latencyMs ?? '-'} ms)`
          );
        }
        if (scan && scan.riskLevel === 'SUSPICIOUS') {
          light = 'YELLOW';
          reasons.push('Perubahan hash HTML / indikasi cloaking perlu diverifikasi');
        }
        if (
          ep.tls?.daysRemaining !== null &&
          ep.tls?.daysRemaining !== undefined &&
          ep.tls.daysRemaining <= 30
        ) {
          light = 'YELLOW';
          reasons.push(`Sertifikat TLS tersisa ${ep.tls.daysRemaining} hari`);
        }
        if (relatedOpenIncidents.length > 0) {
          light = 'YELLOW';
          reasons.push(
            `${relatedOpenIncidents.length} laporan insiden aktif sedang ditangani`
          );
        }
        if (ep.headerScore < 50 && ep.status === 'UP') {
          light = 'YELLOW';
          reasons.push(`Skor security header masih rendah (${ep.headerScore}%)`);
        }
      }

      if (reasons.length === 0) {
        reasons.push('Portal online, konten bersih, dan TLS aktif');
      }

      const statusLabel =
        light === 'RED'
          ? 'GANGGUAN / INSIDEN'
          : light === 'YELLOW'
          ? 'WASPADA / PERLU CEK'
          : 'NORMAL (SEHAT)';

      const userImpactMessage =
        light === 'RED'
          ? 'Berpotensi langsung dirasakan pengguna/publik. Segera beri tahu tim Helpdesk dan eskalasikan ke Tim Infra/CSIRT.'
          : light === 'YELLOW'
          ? 'Layanan tetap dapat diakses, namun ada anomali atau peringatan teknis yang perlu dipantau bersama Tim Infra/Tim Dev.'
          : 'Layanan berjalan normal dari jaringan publik. Jika ada komplain user, arahkan cek browser/jaringan lokal terlebih dahulu.';

      return {
        endpoint: ep,
        light,
        statusLabel,
        userImpactMessage,
        reasons,
        scan,
        activeIncidentsCount: relatedOpenIncidents.length,
      };
    });
  }, [endpoints, contentScans, incidentReports]);

  const trafficCounts = useMemo(() => {
    return {
      green: evaluatedServices.filter((s) => s.light === 'GREEN').length,
      yellow: evaluatedServices.filter((s) => s.light === 'YELLOW').length,
      red: evaluatedServices.filter((s) => s.light === 'RED').length,
    };
  }, [evaluatedServices]);

  // 2. Anti-Fatigue Grouped Alert Digest (consolidates repetitive alerts/findings into clean 1-line summaries)
  const groupedDigests = useMemo<GroupedAlertDigest[]>(() => {
    const groups = new Map<string, GroupedAlertDigest>();
    const sevRank: Record<Severity, number> = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
    };

    const upsert = (
      key: string,
      entry: Omit<GroupedAlertDigest, 'id' | 'count'>,
      increment = 1
    ) => {
      const existing = groups.get(key);
      if (!existing) {
        groups.set(key, { id: key, ...entry, count: increment });
      } else {
        existing.count += increment;
        if (sevRank[entry.severity] > sevRank[existing.severity]) {
          existing.severity = entry.severity;
        }
        if (new Date(entry.latestAt).getTime() > new Date(existing.latestAt).getTime()) {
          existing.latestAt = entry.latestAt;
        }
      }
    };

    // Group open findings by category
    for (const f of findings) {
      if (f.status === 'RESOLVED') continue;
      if (f.category === 'HTTP_HEADER' || f.category === 'INFO_DISCLOSURE') {
        upsert('grp-http-headers', {
          title: 'Konfigurasi HTTP Security Headers & Info Server Belum Optimal',
          source: 'Live HTTP Audit',
          severity: f.severity,
          plainSummary:
            'Beberapa header pelindung browser (CSP/HSTS/X-Frame-Options) belum lengkap. Tidak menyebabkan downtime, namun perlu diperkuat oleh Tim Dev/Infra.',
          latestAt: f.detected_at,
          targetView: 'action-advisor',
        });
      } else if (f.category === 'DNS_EMAIL') {
        upsert('grp-dns-email', {
          title: 'Penguatan Kebijakan DNS & Anti-Spoofing Email (SPF/DMARC/CAA)',
          source: 'DNS Audit',
          severity: f.severity,
          plainSummary:
            'Pengaturan proteksi pemalsuan email domain masih perlu diperketat bersama pengelola DNS / Tim Infra.',
          latestAt: f.detected_at,
          targetView: 'dns-audit',
        });
      } else if (f.category === 'TLS_CERT') {
        upsert('grp-tls', {
          title: 'Peringatan Sertifikat HTTPS / TLS',
          source: 'TLS Audit',
          severity: f.severity,
          plainSummary:
            'Ada sertifikat SSL/TLS yang mendekati kedaluwarsa atau perlu pembaruan konfigurasi.',
          latestAt: f.detected_at,
          targetView: 'headers-tls',
        });
      } else if (f.category === 'AVAILABILITY') {
        upsert('grp-avail', {
          title: 'Gangguan Ketersediaan / Latensi Tinggi Endpoint Layanan',
          source: 'Availability Probe',
          severity: f.severity,
          plainSummary:
            'Satu atau lebih URL terpantau gagal merespons atau melambat secara signifikan.',
          latestAt: f.detected_at,
          targetView: 'overview',
        });
      }
    }

    // Group non-clean content scans
    for (const scan of contentScans) {
      if (scan.riskLevel === 'CLEAN') continue;
      upsert('grp-content-scan', {
        title: 'Anomali Konten HTML / Indikasi Defacement atau Googlebot Cloaking',
        source: 'Live Content Scanner',
        severity: scan.riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        plainSummary:
          'Ditemukan perbedaan konten atau kata kunci mencurigakan pada halaman publik. Segera verifikasi & eskalasikan ke Tim Infra.',
        latestAt: scan.scannedAt,
        targetView: 'incident-reports',
      });
    }

    // Group Local SIEM / Wazuh alerts by rule source
    if (localWazuh) {
      for (const al of localWazuh.alerts) {
        upsert(`grp-wazuh-${al.source}`, {
          title:
            al.source === 'FIM'
              ? 'Perubahan Integritas File Host (Wazuh FIM)'
              : al.source === 'NET_SENSOR'
              ? 'Port Jaringan Tidak Terdaftar Terbuka (Wazuh Network)'
              : al.source === 'LOGCOLLECTOR'
              ? 'Pola Serangan / Login Gagal pada Log Server (Wazuh Log)'
              : 'Temuan Pengerasan Konfigurasi Host (Wazuh SCA)',
          source: `Local SIEM (${al.source})`,
          severity: al.severity,
          plainSummary:
            'Ringkasan alert dari sensor host lokal agar Support IT tidak kebanjiran log baris per baris.',
          latestAt: al.timestamp,
          targetView: 'wazuh-dashboard',
        });
      }
    }

    // Group ingested external SIEM events by attack vector
    for (const ev of ingestedSiemEvents) {
      upsert(`grp-siem-${ev.attack_vector}`, {
        title: `Event SIEM Eksternal: ${ev.attack_vector}`,
        source: 'External SIEM Ingest',
        severity: ev.severity,
        plainSummary: `Aktivitas serangan ${ev.attack_vector} menuju ${ev.target_asset} (${ev.action_taken}).`,
        latestAt: ev.timestamp,
        targetView: 'findings',
      });
    }

    return Array.from(groups.values()).sort(
      (a, b) => sevRank[b.severity] - sevRank[a.severity] || b.count - a.count
    );
  }, [findings, contentScans, localWazuh, ingestedSiemEvents]);

  const activeScenario =
    SUPPORT_SCENARIOS.find((s) => s.id === selectedScenarioId) ??
    SUPPORT_SCENARIOS[0];

  const handleCopy = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
      }, 2200);
    } catch {
      // Ignore clipboard failures gracefully
    }
  };

  const buildHelpdeskStatusSummary = (svc: EvaluatedServiceHealth) => {
    return `[Info Status Layanan]
Layanan : ${svc.endpoint.label} (${svc.endpoint.url})
Status  : ${svc.statusLabel}
Latensi : ${svc.endpoint.latencyMs !== null ? `${svc.endpoint.latencyMs} ms` : '-'} | Uptime: ${svc.endpoint.uptimePercent.toFixed(1)}%
Catatan : ${svc.reasons.join('; ')}.
Panduan : ${svc.userImpactMessage}`;
  };

  const startEditContacts = () => {
    setDraftContacts({ ...picContacts });
    setEditingContacts(true);
  };

  const saveContacts = () => {
    setPicContacts(draftContacts);
    try {
      localStorage.setItem(PIC_STORAGE_KEY, JSON.stringify(draftContacts));
    } catch {
      // Ignore storage quota errors
    }
    setEditingContacts(false);
  };

  return (
    <div className="space-y-5">
      {/* Header Control Bar */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Headphones className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100">
              Service Health Board &amp; Escalation Matrix (Support IT Hub)
            </h2>
          </div>
          {isDemo && (
            <p className="text-xs text-zinc-400 max-w-3xl leading-relaxed">
              Tampilan status layanan bergaya <strong className="text-zinc-200">Lampu Lalu Lintas</strong>, peringkas alert anti-spam, panduan respon keluhan Helpdesk, dan matriks eskalasi PIC agar Tim Support IT dapat bertindak cepat tanpa membaca log mentah server.
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ActionTooltip
            label="Periksa Status Layanan"
            description="Uji ulang ketersediaan HTTP, latensi, sertifikat TLS, dan integritas konten seluruh portal."
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
              {scanningNow ? 'Memeriksa...' : 'Cek Status Layanan'}
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Buka Action Advisor"
            description="Lihat panduan teknis detail untuk Support IT, tim Developer, dan Pimpinan."
          >
            <button
              type="button"
              onClick={() => onNavigateView('action-advisor')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Buka Action Advisor
              <ArrowUpRight className="w-3.5 h-3.5 text-zinc-400" />
            </button>
          </ActionTooltip>
        </div>
      </section>

      {/* Traffic-Light Overview Strip */}
      <section
        aria-label="Ringkasan Status Lampu Lalu Lintas"
        className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-zinc-800/80 bg-zinc-900/40 border border-zinc-800/80 rounded-lg"
      >
        <div className="p-4 flex items-center justify-between gap-3">
          <div>
            <p className="text-xs text-zinc-400">Hijau · Layanan Normal</p>
            <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-emerald-400">
              {trafficCounts.green}
            </p>
            {isDemo && (
              <p className="text-[11px] text-zinc-500 mt-0.5">
                Portal online, konten bersih, siap diakses
              </p>
            )}
          </div>
          <CheckCircle2 className="w-6 h-6 text-emerald-400/80 shrink-0" />
        </div>

        <div className="p-4 flex items-center justify-between gap-3">
          <div>
            <p className="text-xs text-zinc-400">Kuning · Waspada / Cek</p>
            <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-amber-400">
              {trafficCounts.yellow}
            </p>
            {isDemo && (
              <p className="text-[11px] text-zinc-500 mt-0.5">
                Latensi tinggi, header lemah, atau insiden sedang
              </p>
            )}
          </div>
          <AlertTriangle className="w-6 h-6 text-amber-400/80 shrink-0" />
        </div>

        <div className="p-4 flex items-center justify-between gap-3">
          <div>
            <p className="text-xs text-zinc-400">Merah · Gangguan / Insiden</p>
            <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-rose-400">
              {trafficCounts.red}
            </p>
            {isDemo && (
              <p className="text-[11px] text-zinc-500 mt-0.5">
                Portal down, defacement, atau insiden kritis
              </p>
            )}
          </div>
          <ShieldAlert className="w-6 h-6 text-rose-400/80 shrink-0" />
        </div>
      </section>

      {/* 1. Traffic-Light Service Health Board */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400 shrink-0" />
            <h3 className="text-xs font-semibold text-zinc-100">
              Papan Kesehatan Layanan (Status Publik Real-Time)
            </h3>
          </div>
          <span className="text-[11px] font-mono tabular-nums text-zinc-400">
            {evaluatedServices.length} layanan terpantau
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:gap-px bg-zinc-800/60">
          {evaluatedServices.map((svc) => {
            const lightBadgeClass =
              svc.light === 'RED'
                ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
                : svc.light === 'YELLOW'
                ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40';
            const LightIcon =
              svc.light === 'RED'
                ? ShieldAlert
                : svc.light === 'YELLOW'
                ? AlertTriangle
                : CheckCircle2;
            const copyId = `svc-${svc.endpoint.id}`;

            return (
              <div
                key={svc.endpoint.id}
                className="bg-zinc-950/90 p-4 space-y-3 flex flex-col justify-between"
              >
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h4 className="text-sm font-semibold text-zinc-100 truncate">
                        {svc.endpoint.label}
                      </h4>
                      <p className="font-mono text-[11px] text-zinc-400 truncate">
                        {svc.endpoint.url}
                      </p>
                    </div>
                    <span
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] font-mono font-semibold whitespace-nowrap shrink-0 ${lightBadgeClass}`}
                    >
                      <LightIcon className="w-3.5 h-3.5 shrink-0" />
                      {svc.statusLabel}
                    </span>
                  </div>

                  {/* Plain Metrics Row */}
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] font-mono tabular-nums text-zinc-400">
                    <span>
                      HTTP:{' '}
                      <strong className="text-zinc-200">
                        {svc.endpoint.httpStatus ?? svc.endpoint.status}
                      </strong>
                    </span>
                    <span className="text-zinc-700">·</span>
                    <span>
                      Kecepatan:{' '}
                      <strong className="text-zinc-200">
                        {svc.endpoint.latencyMs !== null
                          ? `${svc.endpoint.latencyMs} ms`
                          : '—'}
                      </strong>
                    </span>
                    <span className="text-zinc-700">·</span>
                    <span>
                      Uptime:{' '}
                      <strong className="text-zinc-200">
                        {svc.endpoint.uptimePercent.toFixed(1)}%
                      </strong>
                    </span>
                    <span className="text-zinc-700">·</span>
                    <span>
                      TLS:{' '}
                      <strong className="text-zinc-200">
                        {svc.endpoint.tls?.daysRemaining !== null &&
                        svc.endpoint.tls?.daysRemaining !== undefined
                          ? `${svc.endpoint.tls.daysRemaining}h`
                          : '—'}
                      </strong>
                    </span>
                    <span className="text-zinc-700">·</span>
                    <span>
                      Konten:{' '}
                      <strong
                        className={
                          svc.scan?.riskLevel === 'CRITICAL'
                            ? 'text-rose-400'
                            : svc.scan?.riskLevel === 'SUSPICIOUS'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }
                      >
                        {svc.scan ? svc.scan.riskLevel : 'Menunggu Scan'}
                      </strong>
                    </span>
                  </div>

                  {isDemo && (
                    <p className="text-xs text-zinc-300 leading-relaxed">
                      {svc.userImpactMessage}
                    </p>
                  )}
                  <p className="text-[11px] text-zinc-500">
                    Indikator: {svc.reasons.join(' · ')}
                  </p>
                </div>

                <div className="pt-2 border-t border-zinc-800/70 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[10px] font-mono text-zinc-500 tabular-nums">
                    Cek terakhir:{' '}
                    {svc.endpoint.lastCheckedAt
                      ? `${formatShortDateTime(svc.endpoint.lastCheckedAt)} WIB`
                      : 'Sedang memindai...'}
                  </span>
                  <ActionTooltip
                    label="Salin Ringkasan Helpdesk"
                    description={svc.userImpactMessage}
                  >
                    <button
                      type="button"
                      onClick={() =>
                        void handleCopy(buildHelpdeskStatusSummary(svc), copyId)
                      }
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded transition-colors cursor-pointer"
                    >
                      {copiedKey === copyId ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          Tersalin
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3 text-zinc-400" />
                          Salin Info Helpdesk
                        </>
                      )}
                    </button>
                  </ActionTooltip>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* 2. Split: Anti-Fatigue Grouped Alert Digest (5 cols) + Helpdesk Interactive Decision Guide (7 cols) */}
      <section className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        {/* Left: Anti-Fatigue Alert Grouping */}
        <div className="xl:col-span-5 bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-emerald-400 shrink-0" />
              <div>
                <h3 className="text-xs font-semibold text-zinc-100">
                  Peringkas Alert Anti-Spam (Grouped Digest)
                </h3>
                {isDemo && (
                  <p className="text-[11px] text-zinc-500">
                    Alert berulang dikelompokkan jadi 1 ringkasan yang mudah dibaca
                  </p>
                )}
              </div>
            </div>
            <span className="font-mono text-[11px] tabular-nums text-zinc-400">
              {groupedDigests.length} grup
            </span>
          </div>

          {groupedDigests.length === 0 ? (
            <div className="p-6 text-center space-y-1.5">
              <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto" />
              <p className="text-xs font-medium text-zinc-200">
                Tidak ada kelompok alert aktif saat ini
              </p>
              {isDemo && (
                <p className="text-[11px] text-zinc-500">
                  Semua sensor eksternal dan lokal melaporkan kondisi tenang.
                </p>
              )}
            </div>
          ) : (
            <div className="divide-y divide-zinc-800/70">
              {groupedDigests.map((grp) => (
                <div
                  key={grp.id}
                  className="p-3.5 space-y-2 hover:bg-zinc-900/40 transition-colors"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={grp.severity} />
                      <span className="font-mono text-[11px] tabular-nums px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-200">
                        ×{grp.count}
                      </span>
                      <span className="text-[11px] text-zinc-500">
                        {grp.source}
                      </span>
                    </div>
                    <ActionTooltip
                      label="Tindak Lanjut Alert"
                      description="Buka modul terkait untuk menyelidiki atau memitigasi kelompok alert ini."
                    >
                      <button
                        type="button"
                        onClick={() => onNavigateView(grp.targetView)}
                        className="text-[11px] text-emerald-400 hover:text-emerald-300 whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Tindak Lanjut →
                      </button>
                    </ActionTooltip>
                  </div>
                  <p className="text-xs font-semibold text-zinc-100 leading-snug">
                    {grp.title}
                  </p>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">
                    {grp.plainSummary}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Helpdesk Interactive Decision Guide & Safe Reply Templates */}
        <div className="xl:col-span-7 bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center gap-2">
            <MessageSquare className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <h3 className="text-xs font-semibold text-zinc-100">
                Panduan Cepat Support IT &amp; Template Jawaban Helpdesk
              </h3>
              {isDemo && (
                <p className="text-[11px] text-zinc-500">
                  Pilih skenario keluhan yang masuk untuk melihat langkah verifikasi &amp; jawaban aman ke pendaftar
                </p>
              )}
            </div>
          </div>

          <div className="p-4 space-y-4">
            {/* Scenario Tabs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {SUPPORT_SCENARIOS.map((sc) => {
                const active = sc.id === activeScenario.id;
                return (
                  <ActionTooltip
                    key={sc.id}
                    label="Pilih Skenario Helpdesk"
                    description={sc.triggerExample}
                    className="block w-full"
                  >
                    <button
                      type="button"
                      onClick={() => setSelectedScenarioId(sc.id)}
                      className={`w-full h-full p-3 rounded-md border text-left transition-colors cursor-pointer space-y-1 ${
                        active
                          ? 'bg-emerald-600/15 border-emerald-500/40 text-zinc-100'
                          : 'bg-zinc-950/60 border-zinc-800 text-zinc-300 hover:border-zinc-700'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <SeverityBadge severity={sc.defaultSeverity} />
                      </div>
                      <p className="text-xs font-semibold leading-snug pt-1">
                        {sc.title}
                      </p>
                    </button>
                  </ActionTooltip>
                );
              })}
            </div>

            {/* Active Scenario Details */}
            <div className="bg-zinc-950/70 border border-zinc-800/80 rounded-md p-4 space-y-4">
              <div className="space-y-1">
                <p className="text-xs font-semibold text-zinc-100">
                  {activeScenario.title}
                </p>
                <p className="text-[11px] text-zinc-400">
                  {activeScenario.triggerExample}
                </p>
              </div>

              {/* Interactive Verification Steps */}
              <div className="space-y-2">
                <span className="text-[11px] font-mono text-zinc-500 block">
                  Langkah Verifikasi Awal Support IT (Centang saat selesai):
                </span>
                <div className="space-y-1.5">
                  {activeScenario.firstChecks.map((step, idx) => {
                    const key = `${activeScenario.id}-${idx}`;
                    const done = Boolean(checkedSteps[key]);
                    return (
                      <label
                        key={key}
                        className="flex items-start gap-2.5 p-2 rounded bg-zinc-900/60 border border-zinc-800/70 cursor-pointer text-xs"
                      >
                        <input
                          type="checkbox"
                          checked={done}
                          onChange={() =>
                            setCheckedSteps((prev) => ({
                              ...prev,
                              [key]: !prev[key],
                            }))
                          }
                          className="mt-0.5 accent-emerald-500 shrink-0"
                        />
                        <span
                          className={
                            done
                              ? 'text-zinc-500 line-through'
                              : 'text-zinc-200 leading-relaxed'
                          }
                        >
                          {step}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* Escalation Trigger Rule */}
              <div className="bg-zinc-900/80 border border-amber-500/30 rounded-md p-3 text-xs space-y-1">
                <span className="text-[11px] font-mono font-semibold text-amber-300 block">
                  Kapan Harus Eskalasi?
                </span>
                <p className="text-zinc-200 leading-relaxed">
                  {activeScenario.whenToEscalate}
                </p>
              </div>

              {/* Safe Helpdesk Reply Template */}
              <div className="space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] font-mono text-zinc-500">
                    Template Jawaban Aman ke Pengguna / Pelapor:
                  </span>
                  <div className="flex items-center gap-2">
                    <ActionTooltip
                      label="Salin Template Jawaban"
                      description="Salin kalimat respon aman Helpdesk ini ke clipboard."
                    >
                      <button
                        type="button"
                        onClick={() =>
                          void handleCopy(
                            activeScenario.helpdeskReplyTemplate,
                            `reply-${activeScenario.id}`
                          )
                        }
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium bg-zinc-900 hover:bg-zinc-800 text-emerald-300 border border-zinc-700 rounded cursor-pointer"
                      >
                        {copiedKey === `reply-${activeScenario.id}` ? (
                          <>
                            <Check className="w-3 h-3" />
                            Tersalin
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            Salin Jawaban
                          </>
                        )}
                      </button>
                    </ActionTooltip>
                    <ActionTooltip
                      label="Eskalasi Insiden"
                      description="Buka modul tujuan untuk mencatat atau memitigasi skenario ini."
                    >
                      <button
                        type="button"
                        onClick={() =>
                          onNavigateView(activeScenario.escalateTarget)
                        }
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded cursor-pointer"
                      >
                        Eskalasi Sekarang
                        <ArrowUpRight className="w-3 h-3" />
                      </button>
                    </ActionTooltip>
                  </div>
                </div>
                <div className="bg-zinc-900/70 border border-zinc-800 rounded p-3 text-xs text-zinc-200 leading-relaxed">
                  {activeScenario.helpdeskReplyTemplate}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 3. Escalation Matrix & Local PIC Directory */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <PhoneCall className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <h3 className="text-xs font-semibold text-zinc-100">
                Matriks Eskalasi &amp; Direktori PIC (Who-to-Call Matrix)
              </h3>
              {isDemo && (
                <p className="text-[11px] text-zinc-500">
                  Panduan siapa yang dihubungi berdasarkan jenis insiden. Anda dapat mengisi nama/kanal PIC internal organisasi &amp; Tim Infra (tersimpan aman di browser lokal).
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            {!editingContacts ? (
              <ActionTooltip
                label="Edit Direktori PIC Internal"
                description="Sesuaikan nama atau kanal kontak PIC internal organisasi & Tim Infra (disimpan di browser lokal)."
              >
                <button
                  type="button"
                  onClick={startEditContacts}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors cursor-pointer"
                >
                  <Edit3 className="w-3.5 h-3.5 text-emerald-400" />
                  Isi / Edit Kontak PIC Internal
                </button>
              </ActionTooltip>
            ) : (
              <>
                <ActionTooltip label="Batalkan Edit" description="Tutup mode edit tanpa menyimpan perubahan kontak.">
                  <button
                    type="button"
                    onClick={() => setEditingContacts(false)}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer"
                  >
                    <X className="w-3.5 h-3.5" />
                    Batal
                  </button>
                </ActionTooltip>
                <ActionTooltip
                  label="Simpan Kontak Lokal"
                  description="Simpan daftar kontak PIC ke penyimpanan browser lokal."
                >
                  <button
                    type="button"
                    onClick={saveContacts}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md cursor-pointer"
                  >
                    <Save className="w-3.5 h-3.5" />
                    Simpan Kontak Lokal
                  </button>
                </ActionTooltip>
              </>
            )}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-zinc-800/80 bg-zinc-950/60 text-[11px] font-mono text-zinc-400 uppercase tracking-wider">
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Jenis Kejadian</th>
                <th className="py-2.5 px-4">PIC Utama &amp; Pendukung</th>
                <th className="py-2.5 px-4 whitespace-nowrap">SLA Respon</th>
                <th className="py-2.5 px-4">Kanal / Kontak PIC Internal</th>
                <th className="py-2.5 px-4 text-right whitespace-nowrap">Aksi</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/70 text-xs">
              {ESCALATION_MATRIX.map((row) => (
                <tr key={row.id} className="hover:bg-zinc-900/40">
                  <td className="py-3 px-4 align-top whitespace-nowrap">
                    <SeverityBadge severity={row.severity} />
                  </td>
                  <td className="py-3 px-4 align-top font-semibold text-zinc-100">
                    {row.incidentType}
                  </td>
                  <td className="py-3 px-4 align-top">
                    <div className="text-zinc-200">{row.primaryUnit}</div>
                    <div className="text-[11px] text-zinc-500 mt-0.5">
                      Pendukung: {row.supportUnits}
                    </div>
                  </td>
                  <td className="py-3 px-4 align-top whitespace-nowrap font-mono text-amber-300 tabular-nums">
                    {row.slaResponse}
                  </td>
                  <td className="py-3 px-4 align-top min-w-[220px]">
                    {editingContacts ? (
                      <input
                        type="text"
                        value={draftContacts[row.id] ?? ''}
                        onChange={(e) =>
                          setDraftContacts((prev) => ({
                            ...prev,
                            [row.id]: e.target.value,
                          }))
                        }
                        placeholder={row.defaultChannelHint}
                        className="w-full bg-zinc-950 border border-zinc-700 rounded px-2.5 py-1 text-xs text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-500/60"
                      />
                    ) : (
                      <span
                        className={
                          picContacts[row.id]
                            ? 'text-emerald-300 font-medium'
                            : 'text-zinc-400'
                        }
                      >
                        {picContacts[row.id] || row.defaultChannelHint}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 align-top text-right whitespace-nowrap">
                    <ActionTooltip
                      label="Buka Incident Triage"
                      description="Catat atau eskalasikan insiden kategori ini di halaman Incident Reports."
                    >
                      <button
                        type="button"
                        onClick={() => onNavigateView('incident-reports')}
                        className="px-2.5 py-1 text-[11px] font-medium bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded transition-colors cursor-pointer"
                      >
                        Buka Triage →
                      </button>
                    </ActionTooltip>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
