import React, { useMemo, useState } from 'react';
import {
  CheckCircle2,
  Circle,
  ChevronRight,
  ChevronLeft,
  ShieldAlert,
  Globe,
  KeyRound,
  Save,
  RotateCcw,
  ClipboardCheck,
  ListChecks,
} from 'lucide-react';
import { ActionTooltip } from './ActionTooltip';
import { useSocMode } from '../context/SocModeContext';
import {
  IncidentReportCategory,
  IncidentReportSource,
  IncidentReportStatus,
  ManualIncidentReport,
  RealEndpointProbe,
  Severity,
} from '../types/soc';
import { formatTimeWIB } from '../utils/socFormatters';

export type TriageCategoryKey = 'phishing' | 'defacement' | 'unauthorized_access';

interface ChecklistStep {
  id: string;
  phase: 'Containment' | 'Eradication' | 'Recovery & Governance';
  title: string;
  guidance: string;
  owner: string;
}

interface TriagePlaybook {
  key: TriageCategoryKey;
  name: string;
  subtitle: string;
  slaTarget: string;
  defaultSeverity: Severity;
  reportCategory: IncidentReportCategory;
  defaultSource: IncidentReportSource;
  defaultTitle: string;
  defaultDescription: string;
  defaultCoordination: string;
  icon: React.ComponentType<{ className?: string }>;
  accentText: string;
  steps: ChecklistStep[];
}

const TRIAGE_PLAYBOOKS: Record<TriageCategoryKey, TriagePlaybook> = {
  phishing: {
    key: 'phishing',
    name: 'Phishing',
    subtitle: 'Impersonasi domain resmi organisasi, portal login tiruan, atau spoofing email institusi.',
    slaTarget: 'SLA Containment: < 4 Jam',
    defaultSeverity: 'HIGH',
    reportCategory: 'PHISHING_IMPERSONATION',
    defaultSource: 'EXTERNAL_REPORTER',
    defaultTitle: 'Insiden Phishing / Impersonasi Portal Layanan Organisasi',
    defaultDescription:
      'Teridentifikasi tautan atau email phishing yang mencatut identitas organisasi untuk mencuri kredensial pengguna atau data sensitif rekening.',
    defaultCoordination:
      'Koordinasi takedown domain bersama Internal CSIRT, Gov-CERT / National CSIRT, serta registrar/hosting provider terkait.',
    icon: ShieldAlert,
    accentText: 'text-amber-400',
    steps: [
      {
        id: 'phish-1',
        phase: 'Containment',
        title: 'Amankan bukti forensik awal (URL penuh, screenshot, header email .eml, WHOIS/IP)',
        guidance:
          'Dokumentasikan URL lengkap, IP hosting, sertifikat SSL, serta header SMTP sebelum situs dihapus pelaku.',
        owner: 'SOC Analyst',
      },
      {
        id: 'phish-2',
        phase: 'Containment',
        title: 'Verifikasi lintas feed OpenPhish & Certificate Transparency Log domain resmi',
        guidance:
          'Pastikan tidak ada sertifikat subdomain resmi yang disalahgunakan dan cek apakah URL sudah masuk radar OpenPhish.',
        owner: 'SOC Analyst',
      },
      {
        id: 'phish-3',
        phase: 'Containment',
        title: 'Blokir domain/URL berbahaya pada DNS internal, Email Gateway, dan Proxy/Firewall',
        guidance:
          'Cegah pegawai internal maupun jaringan kantor mengakses domain phishing yang dilaporkan.',
        owner: 'Tim Jaringan & Keamanan TI',
      },
      {
        id: 'phish-4',
        phase: 'Eradication',
        title: 'Ajukan laporan takedown ke Registrar, Hosting Provider, Internal CSIRT & otoritas terkait',
        guidance:
          'Lampirkan bukti penyalahgunaan merek resmi organisasi serta bukti tangkapan layar.',
        owner: 'Internal CSIRT / Divisi Hukum',
      },
      {
        id: 'phish-5',
        phase: 'Eradication',
        title: 'Audit kebijakan SPF, DKIM, dan DMARC domain resmi untuk mencegah spoofing lanjutan',
        guidance:
          'Periksa laporan DMARC RUA dan dorong peningkatan kebijakan ke p=quarantine / p=reject.',
        owner: 'Pengelola DNS Organisasi',
      },
      {
        id: 'phish-6',
        phase: 'Recovery & Governance',
        title: 'Terbitkan imbauan resmi anti-penipuan kepada seluruh pengguna layanan',
        guidance:
          'Informasikan alamat portal resmi melalui kanal terverifikasi agar masyarakat tidak tertipu.',
        owner: 'Humas & Layanan Pengguna',
      },
      {
        id: 'phish-7',
        phase: 'Recovery & Governance',
        title: 'Catat indikator IOC & lampirkan ringkasan insiden pada Laporan CTO & Direksi',
        guidance:
          'Pastikan insiden terekam sebagai bahan evaluasi keamanan periode berjalan.',
        owner: 'Tim SOC',
      },
    ],
  },
  defacement: {
    key: 'defacement',
    name: 'Defacement',
    subtitle: 'Perubahan tampilan HTML, injeksi konten judi online (SLOT/SEO Poisoning), atau Googlebot Cloaking.',
    slaTarget: 'SLA Containment: < 1 Jam',
    defaultSeverity: 'CRITICAL',
    reportCategory: 'WEB_DEFACEMENT',
    defaultSource: 'GOOGLE_SEARCH_OSINT',
    defaultTitle: 'Insiden Web Defacement / SEO Poisoning & Cloaking pada Portal Layanan',
    defaultDescription:
      'Terdeteksi perubahan isi halaman HTML tidak sah, penyusupan konten promosi judi online, atau manipulasi respons khusus Googlebot pada subdomain layanan.',
    defaultCoordination:
      'Eskalasi darurat ke Tim Infra / Server Ops, Internal CSIRT, dan tim pengelola server aplikasi untuk isolasi & pembersihan.',
    icon: Globe,
    accentText: 'text-rose-400',
    steps: [
      {
        id: 'def-1',
        phase: 'Containment',
        title: 'Simpan bukti visual & teknis (snippet Google, source HTML Browser vs Googlebot, access log)',
        guidance:
          'Ambil bukti lengkap sebelum perubahan dibersihkan agar akar celah (entry point) tetap bisa ditelusuri.',
        owner: 'SOC Analyst',
      },
      {
        id: 'def-2',
        phase: 'Containment',
        title: 'Koordinasi darurat dengan Tim Infra Ops untuk isolasi / mode maintenance halaman terdampak',
        guidance:
          'Hentikan paparan konten ilegal kepada publik dan cegah mesin pencari terus mengindeks halaman terinjeksi.',
        owner: 'Tim Infra Ops & Pengelola Server',
      },
      {
        id: 'def-3',
        phase: 'Eradication',
        title: 'Audit integritas file web (FIM SHA-256), .htaccess, konfigurasi Nginx/Apache, dan plugin CMS',
        guidance:
          'Bandingkan hash file produksi dengan repositori/baseline resmi untuk menemukan file yang diubah atau disisipkan.',
        owner: 'Tim Aplikasi & Infra Ops',
      },
      {
        id: 'def-4',
        phase: 'Eradication',
        title: 'Bersihkan webshell, skrip cloaking User-Agent/IP Googlebot, cronjob ilegal & akun admin liar',
        guidance:
          'Pastikan tidak ada backdoor persisten yang memungkinkan penyerang menginjeksi ulang halaman.',
        owner: 'Internal CSIRT & SysAdmin',
      },
      {
        id: 'def-5',
        phase: 'Recovery & Governance',
        title: 'Pulihkan aplikasi dari backup bersih terverifikasi & rotasi seluruh kredensial server/DB/FTP',
        guidance:
          'Ganti seluruh password admin, kunci SSH, API token, dan pastikan patch celah keamanan sudah diterapkan.',
        owner: 'Tim Infra Ops & DevOps',
      },
      {
        id: 'def-6',
        phase: 'Recovery & Governance',
        title: 'Verifikasi ulang lewat Dual-UA Scanner (Browser vs Googlebot) & ajukan pembersihan cache Google Search Console',
        guidance:
          'Minta re-indexing / penghapusan cache lama di Google Search Console agar snippet ilegal segera hilang dari hasil pencarian.',
        owner: 'Tim Web & SOC',
      },
      {
        id: 'def-7',
        phase: 'Recovery & Governance',
        title: 'Kunci izin tulis (read-only) direktori web, aktifkan WAF & masukkan laporan ke Rapat CTO & BoD',
        guidance:
          'Dokumentasikan akar masalah dan rencana pencegahan berulang bagi pimpinan.',
        owner: 'CTO & Tim SOC',
      },
    ],
  },
  unauthorized_access: {
    key: 'unauthorized_access',
    name: 'Unauthorized Access',
    subtitle: 'Pengambilalihan akun admin/pengguna, login mencurigakan, eskalasi hak akses, atau intrusi server.',
    slaTarget: 'SLA Containment: < 30 Menit',
    defaultSeverity: 'CRITICAL',
    reportCategory: 'CREDENTIAL_LEAK',
    defaultSource: 'INFRA_OPS',
    defaultTitle: 'Insiden Akses Tidak Sah (Unauthorized Access) pada Sistem Produksi',
    defaultDescription:
      'Terdeteksi percobaan atau keberhasilan akses tidak sah terhadap akun istimewa, server aplikasi, atau data sensitif organisasi.',
    defaultCoordination:
      'Eskalasi prioritas ke CTO, Tim Infra Ops, Internal CSIRT, serta evaluasi notifikasi kepatuhan perlindungan data (UU PDP / Gov-CERT).',
    icon: KeyRound,
    accentText: 'text-orange-400',
    steps: [
      {
        id: 'ua-1',
        phase: 'Containment',
        title: 'Cabut seluruh sesi aktif, nonaktifkan akun terdampak & paksa reset password serta MFA',
        guidance:
          'Hentikan akses pelaku segera dengan invalidasi token sesi, cookie, dan kredensial akun terkait.',
        owner: 'Tim IAM / Admin Aplikasi',
      },
      {
        id: 'ua-2',
        phase: 'Containment',
        title: 'Isolasi host terdampak & blokir IP/ASN penyerang pada Firewall / WAF perimeter',
        guidance:
          'Putus jalur komunikasi C2 atau akses remote SSH/RDP/Admin Panel dari IP sumber mencurigakan.',
        owner: 'Tim Infra Ops & Jaringan',
      },
      {
        id: 'ua-3',
        phase: 'Containment',
        title: 'Amankan log autentikasi, log aplikasi, SSH (/var/log/auth.log), dan audit trail database',
        guidance:
          'Ekspor dan lindungi log secara read-only untuk investigasi forensik serta penentuan waktu awal intrusi.',
        owner: 'Tim SOC & Internal CSIRT',
      },
      {
        id: 'ua-4',
        phase: 'Eradication',
        title: 'Audit eskalasi hak akses, SSH authorized_keys, API key baru, dan perubahan role/sudoers',
        guidance:
          'Hapus seluruh akun bayangan, token API tak dikenal, atau izin istimewa yang dibuat selama insiden.',
        owner: 'SysAdmin & Internal CSIRT',
      },
      {
        id: 'ua-5',
        phase: 'Eradication',
        title: 'Periksa potensi pergerakan lateral & dampak terhadap data sensitif / modul pencairan dana',
        guidance:
          'Verifikasi integritas tabel rekening penerima manfaat, transaksi keuangan, dan data pribadi (PII).',
        owner: 'Tim Aplikasi, Data & Audit Internal',
      },
      {
        id: 'ua-6',
        phase: 'Recovery & Governance',
        title: 'Tambal celah keamanan yang dieksploitasi (cek CISA KEV) & perketat konfigurasi CIS Benchmark',
        guidance:
          'Terapkan prinsip least-privilege, MFA wajib untuk seluruh admin, dan pembatasan IP akses manajemen.',
        owner: 'Tim Infrastruktur & DevOps',
      },
      {
        id: 'ua-7',
        phase: 'Recovery & Governance',
        title: 'Evaluasi kewajiban pelaporan insiden data pribadi (UU PDP 3×24 jam) & sampaikan ke CTO & BoD',
        guidance:
          'Koordinasikan pelaporan formal ke Gov-CERT / CSIRT dan lengkapi laporan manajemen.',
        owner: 'CTO, DPO / Hukum & Tim SOC',
      },
    ],
  },
};

const PHASES: Array<ChecklistStep['phase']> = [
  'Containment',
  'Eradication',
  'Recovery & Governance',
];

interface IncidentTriageWizardProps {
  endpoints: RealEndpointProbe[];
  onSaveTriagedIncident: (
    payload: Omit<ManualIncidentReport, 'id' | 'reportedAt' | 'updatedAt'>
  ) => Promise<void>;
}

export const IncidentTriageWizard: React.FC<IncidentTriageWizardProps> = ({
  endpoints,
  onSaveTriagedIncident,
}) => {
  const { isDemo } = useSocMode();
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [selectedCategory, setSelectedCategory] =
    useState<TriageCategoryKey | null>(null);

  // Step 2: Scope & Context
  const [affectedUrl, setAffectedUrl] = useState<string>(
    endpoints[0]?.url ?? 'https://portal.example.org/'
  );
  const [title, setTitle] = useState<string>('');
  const [severity, setSeverity] = useState<Severity>('HIGH');
  const [source, setSource] = useState<IncidentReportSource>('INFRA_OPS');
  const [reporterName, setReporterName] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [evidenceSnippet, setEvidenceSnippet] = useState<string>('');
  const [coordinationNotes, setCoordinationNotes] = useState<string>('');
  const [includeInBoardReport, setIncludeInBoardReport] = useState<boolean>(true);

  // Step 3: Checklist completion map (stepId -> ISO timestamp completed)
  const [checkedSteps, setCheckedSteps] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const playbook = selectedCategory ? TRIAGE_PLAYBOOKS[selectedCategory] : null;

  const handleSelectCategory = (key: TriageCategoryKey) => {
    const pb = TRIAGE_PLAYBOOKS[key];
    setSelectedCategory(key);
    setTitle(pb.defaultTitle);
    setSeverity(pb.defaultSeverity);
    setSource(pb.defaultSource);
    setDescription(pb.defaultDescription);
    setCoordinationNotes(pb.defaultCoordination);
    setCheckedSteps({});
    setErrorMsg(null);
    setStep(2);
  };

  const toggleStep = (stepId: string) => {
    setCheckedSteps((prev) => {
      if (prev[stepId]) {
        const next = { ...prev };
        delete next[stepId];
        return next;
      }
      return { ...prev, [stepId]: new Date().toISOString() };
    });
  };

  const checkPhaseSteps = (phase: ChecklistStep['phase']) => {
    if (!playbook) return;
    const nowIso = new Date().toISOString();
    setCheckedSteps((prev) => {
      const next = { ...prev };
      for (const s of playbook.steps) {
        if (s.phase === phase && !next[s.id]) {
          next[s.id] = nowIso;
        }
      }
      return next;
    });
  };

  const completedCount = useMemo(() => {
    if (!playbook) return 0;
    return playbook.steps.filter((s) => Boolean(checkedSteps[s.id])).length;
  }, [playbook, checkedSteps]);

  const totalSteps = playbook?.steps.length ?? 0;
  const progressPct =
    totalSteps > 0 ? Math.round((completedCount / totalSteps) * 100) : 0;

  const handleProceedToChecklist = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (!title.trim() || !affectedUrl.trim()) {
      setErrorMsg('Judul insiden dan URL / aset terdampak wajib diisi sebelum melanjutkan.');
      return;
    }
    setStep(3);
  };

  const handleResetWizard = () => {
    setStep(1);
    setSelectedCategory(null);
    setCheckedSteps({});
    setEvidenceSnippet('');
    setReporterName('');
    setErrorMsg(null);
  };

  const handleSaveToReports = async () => {
    if (!playbook) return;
    setErrorMsg(null);
    setSaving(true);
    try {
      const checklistSummary = playbook.steps
        .map((s) => {
          const doneAt = checkedSteps[s.id];
          return doneAt
            ? `[DONE ${formatTimeWIB(doneAt)}] ${s.title}`
            : `[PENDING] ${s.title}`;
        })
        .join(' | ');

      const computedStatus: IncidentReportStatus =
        completedCount === totalSteps && totalSteps > 0
          ? 'MITIGATED'
          : selectedCategory === 'defacement' && Boolean(checkedSteps['def-2'])
          ? 'ESCALATED_INFRA'
          : 'INVESTIGATING';

      await onSaveTriagedIncident({
        title: title.trim(),
        affectedUrl: affectedUrl.trim(),
        category: playbook.reportCategory,
        severity,
        source,
        reporterName: reporterName.trim() || 'Incident Triage Wizard (Tim SOC)',
        occurredAt: new Date().toISOString(),
        description: description.trim(),
        evidenceSnippet: evidenceSnippet.trim(),
        coordinationNotes: coordinationNotes.trim(),
        actionTaken: `Triage Playbook (${playbook.name} · ${completedCount}/${totalSteps} langkah selesai): ${checklistSummary}`,
        status: computedStatus,
        includeInBoardReport,
      });
      handleResetWizard();
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Gagal menyimpan hasil triage ke laporan'
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="divide-y divide-zinc-800/80">
      {/* Wizard Step Indicator Header */}
      <div className="px-5 py-3.5 bg-zinc-950/60 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ListChecks className="w-4 h-4 text-emerald-400 shrink-0" />
          <div>
            <h3 className="text-xs font-semibold text-zinc-100">
              Automated Incident Triage Wizard
            </h3>
            {isDemo && (
              <p className="text-[11px] text-zinc-400">
                Pilih kategori insiden untuk memicu daftar periksa mitigasi terstandar dan merekamnya otomatis ke Laporan CTO &amp; BoD.
              </p>
            )}
          </div>
        </div>

        <ol
          aria-label="Triage wizard steps"
          className="flex items-center gap-2 text-[11px] font-mono tabular-nums shrink-0"
        >
          {[
            {
              num: 1 as const,
              label: '1. Category',
              desc: 'Pilih jenis insiden (Phishing, Defacement, atau Unauthorized Access).',
            },
            {
              num: 2 as const,
              label: '2. Scope',
              desc: 'Lengkapi detail aset terdampak, severity, dan pelapor.',
            },
            {
              num: 3 as const,
              label: '3. Mitigation Checklist',
              desc: 'Jalankan langkah Containment, Eradication, dan Recovery.',
            },
          ].map((s, idx) => {
            const active = step === s.num;
            const done = step > s.num;
            const clickable =
              s.num === 1 || (s.num === 2 && selectedCategory !== null);
            return (
              <React.Fragment key={s.num}>
                <ActionTooltip label={s.label} description={s.desc}>
                  <button
                    type="button"
                    disabled={!clickable && !active}
                    onClick={() => {
                      if (clickable) setStep(s.num);
                    }}
                    className={`whitespace-nowrap transition-colors ${
                      active
                        ? 'text-emerald-400 font-semibold'
                        : done
                        ? 'text-zinc-200 hover:text-emerald-300 cursor-pointer'
                        : 'text-zinc-500 cursor-default'
                    }`}
                  >
                    {s.label}
                  </button>
                </ActionTooltip>
                {idx < 2 && (
                  <ChevronRight className="w-3 h-3 text-zinc-700 shrink-0" />
                )}
              </React.Fragment>
            );
          })}
        </ol>
      </div>

      {/* STEP 1: SELECT INCIDENT CATEGORY */}
      {step === 1 && (
        <div className="p-5 space-y-4">
          <div>
            <p className="text-xs font-medium text-zinc-200">
              Langkah 1: Pilih Kategori Insiden Keamanan
            </p>
            {isDemo && (
              <p className="text-[11px] text-zinc-400 mt-0.5">
                Setiap kategori otomatis memuat standar eskalasi, target SLA, dan checklist mitigasi operasional organisasi.
              </p>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {(
              ['phishing', 'defacement', 'unauthorized_access'] as TriageCategoryKey[]
            ).map((key) => {
              const pb = TRIAGE_PLAYBOOKS[key];
              const Icon = pb.icon;
              return (
                <ActionTooltip
                  key={key}
                  label={`Playbook ${pb.name}`}
                  description={pb.subtitle}
                  className="block w-full"
                >
                  <button
                    type="button"
                    onClick={() => handleSelectCategory(key)}
                    className="w-full h-full group text-left bg-zinc-950/80 hover:bg-zinc-900 border border-zinc-800 hover:border-emerald-500/60 rounded-lg p-4 flex flex-col justify-between gap-4 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500"
                  >
                    <div className="space-y-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <Icon className={`w-5 h-5 ${pb.accentText} shrink-0`} />
                        <span className="font-mono text-[10px] text-zinc-400 tabular-nums">
                          {pb.steps.length} langkah · {pb.defaultSeverity}
                        </span>
                      </div>
                      <div>
                        <h4 className="text-sm font-semibold text-zinc-100 group-hover:text-emerald-300 transition-colors">
                          {pb.name}
                        </h4>
                        {isDemo && (
                          <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                            {pb.subtitle}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-[11px] font-mono">
                      <span className="text-zinc-500">{pb.slaTarget}</span>
                      <span className="text-emerald-400 inline-flex items-center gap-0.5 font-sans font-medium">
                        Pilih <ChevronRight className="w-3.5 h-3.5" />
                      </span>
                    </div>
                  </button>
                </ActionTooltip>
              );
            })}
          </div>
        </div>
      )}

      {/* STEP 2: INCIDENT SCOPE & ASSESSMENT */}
      {step === 2 && playbook && (
        <form onSubmit={handleProceedToChecklist} className="p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-xs font-medium text-zinc-200">
                Langkah 2: Lengkapi Ruang Lingkup Insiden —{' '}
                <span className={playbook.accentText}>{playbook.name}</span>
              </p>
              {isDemo && (
                <p className="text-[11px] text-zinc-400 mt-0.5 font-mono">
                  {playbook.slaTarget} · Playbook berisi {playbook.steps.length} langkah mitigasi siap pakai
                </p>
              )}
            </div>
            <ActionTooltip
              label="Kembali ke Pilihan Kategori"
              description="Ubah jenis insiden sebelum menjalankan checklist mitigasi."
            >
              <button
                type="button"
                onClick={() => setStep(1)}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] text-zinc-300 bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 rounded transition-colors cursor-pointer"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                Ganti Kategori
              </button>
            </ActionTooltip>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 text-xs">
            <label className="md:col-span-2 block space-y-1">
              <span className="text-[11px] text-zinc-400">Judul Insiden *</span>
              <input
                type="text"
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
              />
            </label>

            <label className="md:col-span-2 block space-y-1">
              <span className="text-[11px] text-zinc-400">
                URL / Sistem / Akun Terdampak *
              </span>
              <input
                type="text"
                required
                list="triage-monitored-urls"
                value={affectedUrl}
                onChange={(e) => setAffectedUrl(e.target.value)}
                placeholder="https://portal.example.org"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-1.5 font-mono text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
              />
              <datalist id="triage-monitored-urls">
                {endpoints.map((ep) => (
                  <option key={ep.id} value={ep.url} />
                ))}
                <option value="https://portal.example.org" />
              </datalist>
            </label>

            <label className="block space-y-1">
              <span className="text-[11px] text-zinc-400">Severity</span>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-100"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </label>

            <label className="block space-y-1">
              <span className="text-[11px] text-zinc-400">Sumber Deteksi / Pelapor</span>
              <select
                value={source}
                onChange={(e) =>
                  setSource(e.target.value as IncidentReportSource)
                }
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-100"
              >
                <option value="INFRA_OPS">Tim Infra / Server Ops</option>
                <option value="ORG_CSIRT">Internal CSIRT</option>
                <option value="GOV_CERT">Gov-CERT / National CSIRT</option>
                <option value="INTERNAL_STAFF">Pegawai / User Internal</option>
                <option value="GOOGLE_SEARCH_OSINT">Google Search / OSINT</option>
                <option value="AUTO_SCANNER">Auto Content Scanner</option>
                <option value="EXTERNAL_REPORTER">Pelapor Eksternal</option>
              </select>
            </label>

            <label className="md:col-span-2 block space-y-1">
              <span className="text-[11px] text-zinc-400">Nama Pelapor / PIC Awal</span>
              <input
                type="text"
                value={reporterName}
                onChange={(e) => setReporterName(e.target.value)}
                placeholder="Contoh: Tim Infra Ops / Pegawai Internal / Analis SOC"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
            <label className="block space-y-1">
              <span className="text-[11px] text-zinc-400">Ringkasan Insiden</span>
              <textarea
                rows={2}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-[11px] text-zinc-400">
                Bukti Awal / IOC (Domain Phishing, Snippet Slot, IP / Username)
              </span>
              <textarea
                rows={2}
                value={evidenceSnippet}
                onChange={(e) => setEvidenceSnippet(e.target.value)}
                placeholder="Tempelkan cuplikan bukti awal di sini (opsional)..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 font-mono text-[11px] text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
              />
            </label>
          </div>

          {errorMsg && (
            <p className="text-xs font-mono text-rose-400">{errorMsg}</p>
          )}

          <div className="flex items-center justify-between pt-1">
            <ActionTooltip
              label="Reset Wizard"
              description="Bersihkan pilihan dan mulai ulang proses triage dari Langkah 1."
            >
              <button
                type="button"
                onClick={handleResetWizard}
                className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer"
              >
                Reset Wizard
              </button>
            </ActionTooltip>
            <ActionTooltip
              label="Lanjut ke Checklist Mitigasi"
              description="Validasi scope lalu buka daftar langkah Containment, Eradication, dan Recovery."
            >
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <ClipboardCheck className="w-3.5 h-3.5" />
                Buka Mitigation Checklist ({playbook.steps.length} Langkah) →
              </button>
            </ActionTooltip>
          </div>
        </form>
      )}

      {/* STEP 3: TRIGGERED MITIGATION PLAYBOOK CHECKLIST */}
      {step === 3 && playbook && (
        <div className="p-5 space-y-4">
          {/* Playbook Summary & Live Progress Bar */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="space-y-1 min-w-0">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs font-mono">
                <span className={`font-semibold ${playbook.accentText}`}>
                  PLAYBOOK: {playbook.name.toUpperCase()}
                </span>
                <span className="text-zinc-700">·</span>
                <span className="text-zinc-300">{severity}</span>
                <span className="text-zinc-700">·</span>
                <span className="text-zinc-400">{playbook.slaTarget}</span>
              </div>
              <h4 className="text-sm font-semibold text-zinc-100 truncate">
                {title}
              </h4>
              <p className="font-mono text-[11px] text-emerald-400 truncate">
                Target: {affectedUrl}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <ActionTooltip
                label="Centang Fase Containment"
                description="Tandai seluruh langkah fase Containment sebagai selesai sekaligus."
              >
                <button
                  type="button"
                  onClick={() => checkPhaseSteps('Containment')}
                  className="px-2.5 py-1.5 text-[11px] font-medium bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap cursor-pointer"
                >
                  Tandai Containment Selesai
                </button>
              </ActionTooltip>
              <ActionTooltip
                label="Reset Checklist"
                description="Hapus seluruh tanda centang progres pada playbook ini."
              >
                <button
                  type="button"
                  onClick={() => setCheckedSteps({})}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-medium bg-zinc-950 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap cursor-pointer"
                >
                  <RotateCcw className="w-3 h-3" />
                  Reset Centang
                </button>
              </ActionTooltip>
              <ActionTooltip
                label="Kembali ke Langkah 2"
                description="Ubah judul, URL target, severity, atau pelapor."
              >
                <button
                  type="button"
                  onClick={() => setStep(2)}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-medium bg-zinc-950 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md transition-colors whitespace-nowrap cursor-pointer"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  Edit Detail
                </button>
              </ActionTooltip>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] font-mono tabular-nums">
              <span className="text-zinc-400">
                Progres Mitigasi Checklist ({completedCount}/{totalSteps} langkah)
              </span>
              <span
                className={
                  progressPct === 100
                    ? 'text-emerald-400 font-semibold'
                    : 'text-zinc-200'
                }
              >
                {progressPct}%
              </span>
            </div>
            <div className="h-1.5 w-full bg-zinc-950 border border-zinc-800/80 rounded-full overflow-hidden">
              <div
                style={{ width: `${progressPct}%` }}
                className="h-full bg-emerald-500 transition-all duration-200"
              />
            </div>
          </div>

          {/* Phase-Grouped Interactive Checklist */}
          <div className="space-y-4">
            {PHASES.map((phase) => {
              const phaseSteps = playbook.steps.filter((s) => s.phase === phase);
              const phaseDone = phaseSteps.filter((s) =>
                Boolean(checkedSteps[s.id])
              ).length;
              return (
                <div
                  key={phase}
                  className="bg-zinc-950/70 border border-zinc-800/80 rounded-lg overflow-hidden"
                >
                  <div className="px-4 py-2 bg-zinc-900/60 border-b border-zinc-800/80 flex items-center justify-between text-[11px] font-mono">
                    <span className="font-semibold text-zinc-200">{phase}</span>
                    <span className="text-zinc-400 tabular-nums">
                      {phaseDone}/{phaseSteps.length} selesai
                    </span>
                  </div>
                  <div className="divide-y divide-zinc-800/60">
                    {phaseSteps.map((item) => {
                      const doneAt = checkedSteps[item.id];
                      return (
                        <ActionTooltip
                          key={item.id}
                          label={doneAt ? 'Batalkan Centang Langkah' : 'Tandai Langkah Selesai'}
                          description={item.guidance}
                          className="block w-full"
                        >
                          <button
                            type="button"
                            onClick={() => toggleStep(item.id)}
                            aria-pressed={Boolean(doneAt)}
                            className={`w-full px-4 py-3 text-left flex items-start gap-3 transition-colors cursor-pointer ${
                              doneAt
                                ? 'bg-emerald-500/5 hover:bg-emerald-500/10'
                                : 'hover:bg-zinc-900/60'
                            }`}
                          >
                            {doneAt ? (
                              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                            ) : (
                              <Circle className="w-4 h-4 text-zinc-600 shrink-0 mt-0.5" />
                            )}
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-baseline justify-between gap-2">
                                <span
                                  className={`text-xs font-medium ${
                                    doneAt
                                      ? 'text-zinc-400 line-through'
                                      : 'text-zinc-100'
                                  }`}
                                >
                                  {item.title}
                                </span>
                                <span className="font-mono text-[10px] text-zinc-500 shrink-0 tabular-nums">
                                  {doneAt
                                    ? `Selesai ${formatTimeWIB(doneAt)}`
                                    : `PIC: ${item.owner}`}
                                </span>
                              </div>
                              {isDemo && (
                                <p className="text-[11px] text-zinc-400 mt-0.5 leading-relaxed">
                                  {item.guidance}
                                </p>
                              )}
                            </div>
                          </button>
                        </ActionTooltip>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Coordination Note + Save Action Footer */}
          <div className="pt-2 border-t border-zinc-800/80 space-y-3">
            <label className="block space-y-1 text-xs">
              <span className="text-[11px] text-zinc-400">
                Catatan Koordinasi Eskalasi (Tim Infra Ops / CSIRT / CTO)
              </span>
              <textarea
                rows={2}
                value={coordinationNotes}
                onChange={(e) => setCoordinationNotes(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
              />
            </label>

            {errorMsg && (
              <p className="text-xs font-mono text-rose-400">{errorMsg}</p>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3">
              <label className="inline-flex items-center gap-2 text-xs text-zinc-200 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={includeInBoardReport}
                  onChange={(e) => setIncludeInBoardReport(e.target.checked)}
                  className="accent-emerald-500"
                />
                Lampirkan otomatis ke Laporan Eksekutif CTO &amp; BoD
              </label>

              <div className="flex items-center gap-2">
                <ActionTooltip
                  label="Batalkan Triage"
                  description="Reset wizard kembali ke Langkah 1 tanpa menyimpan laporan."
                >
                  <button
                    type="button"
                    onClick={handleResetWizard}
                    className="px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer"
                  >
                    Batal
                  </button>
                </ActionTooltip>
                <ActionTooltip
                  label="Simpan Hasil Triage"
                  description={
                    isDemo
                      ? 'Catat hasil triage dan progres checklist ke Incident Reports Demo.'
                      : 'Simpan permanen hasil triage ke Laporan Insiden & lampiran CTO/BoD.'
                  }
                >
                  <button
                    type="button"
                    disabled={saving}
                    onClick={() => void handleSaveToReports()}
                    className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
                  >
                    <Save className="w-3.5 h-3.5" />
                    {saving
                      ? 'Menyimpan...'
                      : 'Simpan Hasil Triage ke Laporan Insiden'}
                  </button>
                </ActionTooltip>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
