import React, { useMemo, useState } from 'react';
import {
  ClipboardList,
  Plus,
  RefreshCw,
  Download,
  Trash2,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  Search,
  CheckCircle2,
  Briefcase,
  Globe,
  FileWarning,
  Save,
  X,
  ListChecks,
  ChevronDown,
  ChevronUp,
  ArrowUpRight,
} from 'lucide-react';
import { IncidentTriageWizard } from './IncidentTriageWizard';
import { ActionTooltip } from './ActionTooltip';
import { CopyToLiveDraft } from './CopyToLiveModal';
import { useSocMode } from '../context/SocModeContext';
import {
  ContentIntegrityScan,
  IncidentReportCategory,
  IncidentReportSource,
  IncidentReportStatus,
  ManualIncidentReport,
  RealEndpointProbe,
  Severity,
} from '../types/soc';
import {
  exportToCSV,
  formatShortDateTime,
} from '../utils/socFormatters';

interface IncidentReportsViewProps {
  incidentReports: ManualIncidentReport[];
  contentScans: ContentIntegrityScan[];
  endpoints: RealEndpointProbe[];
  scanningContent: boolean;
  onScanContent: () => Promise<void>;
  onAcceptContentBaseline: () => Promise<void>;
  onCreateIncident: (
    payload: Omit<ManualIncidentReport, 'id' | 'reportedAt' | 'updatedAt'>
  ) => Promise<void>;
  onUpdateIncident: (
    id: string,
    patch: Partial<
      Pick<
        ManualIncidentReport,
        | 'status'
        | 'severity'
        | 'coordinationNotes'
        | 'actionTaken'
        | 'includeInBoardReport'
        | 'description'
        | 'evidenceSnippet'
      >
    >
  ) => Promise<void>;
  onDeleteIncident: (id: string) => Promise<void>;
  onOpenBoardReport: () => void;
  onCopyToLive?: (draft: CopyToLiveDraft) => void;
}

export const CATEGORY_LABELS: Record<IncidentReportCategory, string> = {
  SEO_POISONING_JUDOL: 'SEO Poisoning / Judol',
  WEB_DEFACEMENT: 'Web Defacement / HTML',
  GOOGLE_CLOAKING: 'Googlebot Cloaking',
  PHISHING_IMPERSONATION: 'Phishing / Brand Abuse',
  CREDENTIAL_LEAK: 'Kebocoran Kredensial',
  VULNERABILITY_REPORT: 'Laporan Kerentanan',
  OTHER: 'Insiden Lainnya',
};

export const SOURCE_LABELS: Record<IncidentReportSource, string> = {
  INFRA_OPS: 'Tim Infra / Server Ops',
  ORG_CSIRT: 'Internal CSIRT',
  GOV_CERT: 'Gov-CERT / National CSIRT',
  INTERNAL_STAFF: 'Pegawai / User Internal',
  GOOGLE_SEARCH_OSINT: 'Google Search / OSINT',
  AUTO_SCANNER: 'Auto Content Scanner',
  EXTERNAL_REPORTER: 'Pelapor Eksternal',
};

export const STATUS_LABELS: Record<IncidentReportStatus, string> = {
  OPEN: 'Open',
  INVESTIGATING: 'Investigasi',
  ESCALATED_INFRA: 'Eskalasi Infra Ops',
  MITIGATED: 'Termitigasi',
  CLOSED: 'Selesai (Closed)',
};

const STATUS_TONE: Record<IncidentReportStatus, string> = {
  OPEN: 'text-rose-400',
  INVESTIGATING: 'text-orange-400',
  ESCALATED_INFRA: 'text-amber-400',
  MITIGATED: 'text-sky-400',
  CLOSED: 'text-emerald-400',
};

const SEVERITY_BADGE_CONFIG: Record<
  Severity,
  {
    label: string;
    badgeClass: string;
    Icon: React.FC<{ className?: string }>;
  }
> = {
  CRITICAL: {
    label: 'Critical',
    badgeClass: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
    Icon: ShieldAlert,
  },
  HIGH: {
    label: 'High',
    badgeClass: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
    Icon: AlertTriangle,
  },
  MEDIUM: {
    label: 'Medium',
    badgeClass: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
    Icon: AlertCircle,
  },
  LOW: {
    label: 'Low',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
    Icon: Info,
  },
};

export const SeverityBadge: React.FC<{ severity: Severity }> = ({ severity }) => {
  const cfg = SEVERITY_BADGE_CONFIG[severity] ?? SEVERITY_BADGE_CONFIG.LOW;
  const Icon = cfg.Icon;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border text-[11px] font-mono font-semibold tracking-wide whitespace-nowrap shrink-0 ${cfg.badgeClass}`}
      title={`Severity: ${cfg.label}`}
    >
      <Icon className="w-3 h-3 shrink-0" aria-hidden="true" />
      <span>{cfg.label}</span>
    </span>
  );
};

type WorkspaceTab = 'reports' | 'triage-wizard' | 'content-scanner';

export const IncidentReportsView: React.FC<IncidentReportsViewProps> = ({
  incidentReports,
  contentScans,
  endpoints,
  scanningContent,
  onScanContent,
  onAcceptContentBaseline,
  onCreateIncident,
  onUpdateIncident,
  onDeleteIncident,
  onOpenBoardReport,
  onCopyToLive,
}) => {
  const { isDemo } = useSocMode();
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('reports');
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | IncidentReportStatus>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Form fields
  const [title, setTitle] = useState('');
  const [affectedUrl, setAffectedUrl] = useState('');
  const [category, setCategory] = useState<IncidentReportCategory>('SEO_POISONING_JUDOL');
  const [severity, setSeverity] = useState<Severity>('HIGH');
  const [source, setSource] = useState<IncidentReportSource>('INFRA_OPS');
  const [reporterName, setReporterName] = useState('');
  const [occurredAtLocal, setOccurredAtLocal] = useState(() =>
    new Date(Date.now() - new Date().getTimezoneOffset() * 60000)
      .toISOString()
      .slice(0, 16)
  );
  const [description, setDescription] = useState('');
  const [evidenceSnippet, setEvidenceSnippet] = useState('');
  const [coordinationNotes, setCoordinationNotes] = useState('');
  const [actionTaken, setActionTaken] = useState('');
  const [status, setStatus] = useState<IncidentReportStatus>('OPEN');
  const [includeInBoardReport, setIncludeInBoardReport] = useState(true);

  // Expandable row & inline note/severity editing state per incident
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editSeverity, setEditSeverity] = useState<Severity>('HIGH');
  const [editCoordination, setEditCoordination] = useState('');
  const [editActionTaken, setEditActionTaken] = useState('');
  const [savingEdit, setSavingEdit] = useState(false);

  const openCount = useMemo(
    () =>
      incidentReports.filter(
        (r) => r.status !== 'CLOSED' && r.status !== 'MITIGATED'
      ).length,
    [incidentReports]
  );

  const boardCount = useMemo(
    () => incidentReports.filter((r) => r.includeInBoardReport).length,
    [incidentReports]
  );

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    incidentReports.forEach((r) => {
      counts[r.severity] = (counts[r.severity] ?? 0) + 1;
    });
    return counts;
  }, [incidentReports]);

  const flaggedScanCount = useMemo(
    () => contentScans.filter((s) => s.riskLevel !== 'CLEAN').length,
    [contentScans]
  );

  const filteredReports = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return incidentReports.filter((r) => {
      if (severityFilter !== 'ALL' && r.severity !== severityFilter) return false;
      if (statusFilter !== 'ALL' && r.status !== statusFilter) return false;
      if (!q) return true;
      return (
        r.id.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.affectedUrl.toLowerCase().includes(q) ||
        r.reporterName.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.evidenceSnippet.toLowerCase().includes(q)
      );
    });
  }, [incidentReports, severityFilter, statusFilter, searchQuery]);

  const applyTemplate = (preset: 'seo-judol' | 'defacement' | 'infra-alert') => {
    setShowForm(true);
    setFormError(null);
    const defaultTarget = endpoints[0]?.url ?? 'https://portal.example.org/';
    if (preset === 'seo-judol') {
      setCategory('SEO_POISONING_JUDOL');
      setSeverity('CRITICAL');
      setSource('GOOGLE_SEARCH_OSINT');
      setTitle('Indikasi SEO Poisoning / Injeksi Konten Slot Online pada Indeks Google');
      setAffectedUrl(defaultTarget);
      setDescription(
        'Ditemukan cuplikan hasil pencarian Google pada subdomain layanan yang menampilkan teks promosi judi online (indikasi Googlebot cloaking / injeksi konten).'
      );
      setEvidenceSnippet(
        'Snippet Google: "Debut eksklusif SLOT777 merupakan pengenalan konsep platform game slot online..."'
      );
      setCoordinationNotes(
        'Perlu koordinasi dengan Tim Infra / Server Ops & pengelola aplikasi untuk audit file server, .htaccess, webshell, dan pembersihan indeks Google Search Console.'
      );
      setStatus('ESCALATED_INFRA');
      setIncludeInBoardReport(true);
    } else if (preset === 'defacement') {
      setCategory('WEB_DEFACEMENT');
      setSeverity('CRITICAL');
      setSource('INTERNAL_STAFF');
      setTitle('Perubahan Tampilan / Konten HTML Tidak Sah (Web Defacement)');
      setAffectedUrl(defaultTarget);
      setDescription(
        'Terdeteksi perubahan isi halaman web atau penambahan konten/tautan tidak sah yang tidak sesuai dengan rilis resmi aplikasi.'
      );
      setEvidenceSnippet('');
      setCoordinationNotes('Koordinasi isolasi halaman terdampak dan pemulihan dari backup terverifikasi bersama Tim Infra / Server Ops.');
      setStatus('OPEN');
      setIncludeInBoardReport(true);
    } else {
      setCategory('VULNERABILITY_REPORT');
      setSeverity('HIGH');
      setSource('INFRA_OPS');
      setTitle('Notifikasi Insiden / Temuan Keamanan dari Infra Ops / Internal CSIRT');
      setAffectedUrl(defaultTarget);
      setDescription('');
      setEvidenceSnippet('');
      setCoordinationNotes('Diterima dari Tim Infra Ops / CSIRT untuk ditindaklanjuti dan dilaporkan ke CTO & Direksi.');
      setStatus('INVESTIGATING');
      setIncludeInBoardReport(true);
    }
  };

  const promoteScanToIncident = (scan: ContentIntegrityScan) => {
    setActiveTab('reports');
    setShowForm(true);
    setFormError(null);
    const kws = Array.from(
      new Set([...scan.browserKeywordsFound, ...scan.googlebotKeywordsFound])
    );
    setCategory(
      scan.cloakingSuspected
        ? 'GOOGLE_CLOAKING'
        : kws.length > 0
        ? 'SEO_POISONING_JUDOL'
        : 'WEB_DEFACEMENT'
    );
    setSeverity(scan.riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH');
    setSource('AUTO_SCANNER');
    setReporterName('SOC Live Content & Cloaking Scanner');
    setAffectedUrl(scan.url);
    setTitle(
      scan.defacementSuspected
        ? `Temuan Live Scanner: Signature Defacement/Judol pada ${scan.hostname}`
        : scan.cloakingSuspected
        ? `Temuan Live Scanner: Indikasi Googlebot Cloaking pada ${scan.hostname}`
        : `Perubahan Baseline HTML pada ${scan.hostname}`
    );
    setDescription(
      scan.cloakingReason ||
        (kws.length > 0
          ? `Scanner mendeteksi signature mencurigakan (${kws.join(', ')}) pada respons HTML ${scan.url}.`
          : `Hash SHA-256 konten HTML berubah dari baseline yang disetujui.`)
    );
    setEvidenceSnippet(
      `Browser Title: "${scan.browserTitle ?? '-'}" | Googlebot Title: "${
        scan.googlebotTitle ?? '-'
      }" | Keywords: ${kws.join(', ') || 'None'} | Hash: ${
        scan.browserHashSha256?.slice(0, 16) ?? '-'
      }`
    );
    setCoordinationNotes(
      'Eskalasi ke pengelola server / Tim Infra Ops untuk verifikasi file aplikasi dan log akses web server.'
    );
    setStatus('OPEN');
    setIncludeInBoardReport(true);
  };

  const resetForm = () => {
    setTitle('');
    setAffectedUrl('');
    setReporterName('');
    setDescription('');
    setEvidenceSnippet('');
    setCoordinationNotes('');
    setActionTaken('');
    setStatus('OPEN');
    setIncludeInBoardReport(true);
    setFormError(null);
  };

  const handleSubmitForm = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!title.trim() || !affectedUrl.trim()) {
      setFormError('Judul insiden dan URL / sistem terdampak wajib diisi.');
      return;
    }

    setSubmitting(true);
    try {
      const occurredIso = occurredAtLocal
        ? new Date(occurredAtLocal).toISOString()
        : new Date().toISOString();
      await onCreateIncident({
        title: title.trim(),
        affectedUrl: affectedUrl.trim(),
        category,
        severity,
        source,
        reporterName: reporterName.trim() || 'Tim SOC / Pengelola Layanan',
        occurredAt: occurredIso,
        description: description.trim(),
        evidenceSnippet: evidenceSnippet.trim(),
        coordinationNotes: coordinationNotes.trim(),
        actionTaken: actionTaken.trim(),
        status,
        includeInBoardReport,
      });
      resetForm();
      setShowForm(false);
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : 'Gagal menyimpan laporan insiden'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const startInlineEdit = (rep: ManualIncidentReport) => {
    setExpandedId(rep.id);
    setEditingId(rep.id);
    setEditSeverity(rep.severity);
    setEditCoordination(rep.coordinationNotes);
    setEditActionTaken(rep.actionTaken);
  };

  const saveInlineEdit = async (id: string) => {
    setSavingEdit(true);
    try {
      await onUpdateIncident(id, {
        severity: editSeverity,
        coordinationNotes: editCoordination,
        actionTaken: editActionTaken,
      });
      setEditingId(null);
    } finally {
      setSavingEdit(false);
    }
  };

  const handleExportCsv = () => {
    exportToCSV(
      incidentReports.map((r) => ({
        incident_id: r.id,
        occurred_at: r.occurredAt,
        reported_at: r.reportedAt,
        severity: r.severity,
        status: r.status,
        category: CATEGORY_LABELS[r.category],
        source: SOURCE_LABELS[r.source],
        reporter: r.reporterName,
        affected_url: r.affectedUrl,
        title: r.title,
        description: r.description,
        evidence_snippet: r.evidenceSnippet,
        coordination_notes: r.coordinationNotes,
        action_taken: r.actionTaken,
        include_in_cto_bod_report: r.includeInBoardReport ? 'YES' : 'NO',
      })),
      `soc-incident-reports-${new Date().toISOString().slice(0, 10)}.csv`
    );
  };

  return (
    <div className="space-y-5">
      {/* Header Control Bar */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <ClipboardList className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100">
              Incident Reports &amp; Web Defacement / Cloaking Monitor
            </h2>
          </div>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs font-mono tabular-nums text-zinc-400">
            <span className="text-zinc-200">
              {incidentReports.length} laporan tercatat
            </span>
            <span className="text-zinc-700">·</span>
            <span className={openCount > 0 ? 'text-amber-400' : 'text-emerald-400'}>
              {openCount} aktif ditangani
            </span>
            <span className="text-zinc-700">·</span>
            <span className="text-emerald-400">
              {boardCount} masuk Laporan CTO &amp; BoD
            </span>
            <span className="text-zinc-700">·</span>
            <span className={flaggedScanCount > 0 ? 'text-rose-400' : 'text-zinc-400'}>
              Live Content Scan: {flaggedScanCount > 0 ? `${flaggedScanCount} alert` : `${contentScans.length} URL bersih`}
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ActionTooltip
            label="Buka Triage Wizard"
            description="Panduan 3 langkah untuk klasifikasi insiden dan checklist mitigasi."
          >
            <button
              type="button"
              onClick={() => setActiveTab('triage-wizard')}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <ListChecks className="w-3.5 h-3.5" />
              Incident Triage Wizard
            </button>
          </ActionTooltip>

          <ActionTooltip
            label="Catat Insiden Manual"
            description="Buka atau tutup form pencatatan laporan insiden Infra Ops / CSIRT / OSINT."
          >
            <button
              type="button"
              onClick={() => {
                setActiveTab('reports');
                setShowForm((prev) => !prev);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5 text-emerald-400" />
              Catat Manual
            </button>
          </ActionTooltip>

          <ActionTooltip
            label="Pindai HTML & Cloaking"
            description="Jalankan pemeriksaan Dual-UA (Browser vs Googlebot) dan hash SHA-256 pada seluruh portal."
          >
            <button
              type="button"
              disabled={scanningContent}
              onClick={() => void onScanContent()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 text-emerald-400 ${
                  scanningContent ? 'animate-spin' : ''
                }`}
              />
              {scanningContent ? 'Scanning...' : 'Scan HTML & Cloaking'}
            </button>
          </ActionTooltip>

          <ActionTooltip
            label="Buka Laporan CTO & BoD"
            description="Lihat ringkasan eksekutif beserta daftar insiden yang ditandai untuk Direksi."
          >
            <button
              type="button"
              onClick={onOpenBoardReport}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Briefcase className="w-3.5 h-3.5 text-zinc-400" />
              Lihat Laporan CTO &amp; BoD →
            </button>
          </ActionTooltip>

          {incidentReports.length > 0 && (
            <ActionTooltip
              label="Ekspor CSV Insiden"
              description="Unduh seluruh daftar laporan insiden beserta catatan koordinasi dalam format CSV."
            >
              <button
                type="button"
                onClick={handleExportCsv}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5 text-zinc-400" />
                Export CSV
              </button>
            </ActionTooltip>
          )}
        </div>
      </section>

      {/* Main Workspace Tabs */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center gap-1 overflow-x-auto pb-1 lg:pb-0">
            <ActionTooltip
              label="Tab Laporan Insiden"
              description="Tampilkan daftar laporan insiden manual, Infra Ops, CSIRT, dan hasil triage."
            >
              <button
                type="button"
                onClick={() => setActiveTab('reports')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  activeTab === 'reports'
                    ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                    : 'text-zinc-400 hover:text-zinc-200 border border-transparent'
                }`}
              >
                <FileWarning className="w-3.5 h-3.5" />
                Laporan Insiden / Manual ({incidentReports.length})
              </button>
            </ActionTooltip>
            <ActionTooltip
              label="Tab Triage Wizard"
              description="Alur klasifikasi cepat dan checklist mitigasi terstandar."
            >
              <button
                type="button"
                onClick={() => setActiveTab('triage-wizard')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  activeTab === 'triage-wizard'
                    ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                    : 'text-zinc-400 hover:text-zinc-200 border border-transparent'
                }`}
              >
                <ListChecks className="w-3.5 h-3.5 text-emerald-400" />
                Incident Triage Wizard
              </button>
            </ActionTooltip>
            <ActionTooltip
              label="Tab Pemindai Defacement & Cloaking"
              description="Perbandingan respons HTML Browser vs Googlebot serta verifikasi integritas SHA-256."
            >
              <button
                type="button"
                onClick={() => setActiveTab('content-scanner')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  activeTab === 'content-scanner'
                    ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                    : 'text-zinc-400 hover:text-zinc-200 border border-transparent'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                Live HTML Defacement &amp; Googlebot Cloaking ({contentScans.length})
              </button>
            </ActionTooltip>
          </div>

          {activeTab === 'reports' && (
            <div className="flex flex-wrap items-center gap-2">
              <ActionTooltip
                label="Filter Severity"
                description="Saring laporan berdasarkan tingkat dampak (Critical hingga Low)."
              >
                <select
                  value={severityFilter}
                  onChange={(e) =>
                    setSeverityFilter(e.target.value as 'ALL' | Severity)
                  }
                  aria-label="Filter severity laporan"
                  className="bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-200 font-mono tabular-nums"
                >
                  <option value="ALL">Semua Severity ({incidentReports.length})</option>
                  <option value="CRITICAL">Critical ({severityCounts.CRITICAL})</option>
                  <option value="HIGH">High ({severityCounts.HIGH})</option>
                  <option value="MEDIUM">Medium ({severityCounts.MEDIUM})</option>
                  <option value="LOW">Low ({severityCounts.LOW})</option>
                </select>
              </ActionTooltip>

              <ActionTooltip
                label="Filter Status"
                description="Saring laporan berdasarkan progres penanganan saat ini."
              >
                <select
                  value={statusFilter}
                  onChange={(e) =>
                    setStatusFilter(e.target.value as 'ALL' | IncidentReportStatus)
                  }
                  aria-label="Filter status laporan"
                  className="bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-200"
                >
                  <option value="ALL">Semua Status</option>
                  <option value="OPEN">Open</option>
                  <option value="INVESTIGATING">Investigasi</option>
                  <option value="ESCALATED_INFRA">Eskalasi Infra Ops</option>
                  <option value="MITIGATED">Termitigasi</option>
                  <option value="CLOSED">Selesai (Closed)</option>
                </select>
              </ActionTooltip>

              <div className="relative w-56">
                <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Cari insiden, URL, pelapor..."
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                />
              </div>
            </div>
          )}
        </div>

        {/* TAB 0: AUTOMATED INCIDENT TRIAGE WIZARD */}
        {activeTab === 'triage-wizard' && (
          <IncidentTriageWizard
            endpoints={endpoints}
            onSaveTriagedIncident={async (payload) => {
              await onCreateIncident(payload);
              setActiveTab('reports');
            }}
          />
        )}

        {/* TAB 1: MANUAL / INFRA OPS / CSIRT INCIDENT REPORTS */}
        {activeTab === 'reports' && (
          <div>
            {/* Record New Incident Form */}
            {showForm && (
              <form
                onSubmit={handleSubmitForm}
                className="p-5 bg-zinc-950/80 border-b border-zinc-800/80 space-y-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-xs font-semibold text-zinc-100">
                      Form Pencatatan Insiden Manual / Laporan Infra Ops &amp; CSIRT
                    </h3>
                    {isDemo && (
                      <p className="text-[11px] text-zinc-400 mt-0.5">
                        Insiden yang dicatat tersimpan di sandbox latihan atau permanen di server pada Live Mode serta otomatis masuk ke 24h Timeline dan Laporan CTO &amp; BoD.
                      </p>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <ActionTooltip
                      label="Preset SEO Poisoning"
                      description="Isi otomatis form dengan template insiden SEO Poisoning / Judol."
                    >
                      <button
                        type="button"
                        onClick={() => applyTemplate('seo-judol')}
                        className="px-2.5 py-1 text-[11px] bg-zinc-900 hover:bg-zinc-800 text-amber-300 border border-zinc-800 rounded transition-colors cursor-pointer"
                      >
                        Isi Cepat: SEO Judol / Cloaking
                      </button>
                    </ActionTooltip>
                    <ActionTooltip
                      label="Preset Defacement HTML"
                      description="Isi otomatis form dengan template perubahan tampilan/HTML tidak sah."
                    >
                      <button
                        type="button"
                        onClick={() => applyTemplate('defacement')}
                        className="px-2.5 py-1 text-[11px] bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded transition-colors cursor-pointer"
                      >
                        Isi Cepat: Defacement HTML
                      </button>
                    </ActionTooltip>
                    <ActionTooltip
                      label="Preset Notifikasi Infra Ops"
                      description="Isi otomatis form untuk temuan atau eskalasi dari Tim Infra Ops / CSIRT."
                    >
                      <button
                        type="button"
                        onClick={() => applyTemplate('infra-alert')}
                        className="px-2.5 py-1 text-[11px] bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded transition-colors cursor-pointer"
                      >
                        Isi Cepat: Notifikasi Infra Ops
                      </button>
                    </ActionTooltip>
                    <ActionTooltip label="Tutup Form" description="Sembunyikan form pencatatan insiden.">
                      <button
                        type="button"
                        onClick={() => setShowForm(false)}
                        aria-label="Tutup form"
                        className="p-1 text-zinc-500 hover:text-zinc-200 cursor-pointer"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </ActionTooltip>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 text-xs">
                  <label className="md:col-span-2 block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Judul Insiden *
                    </span>
                    <input
                      type="text"
                      required
                      value={title}
                      onChange={(e) => setTitle(e.target.value)}
                      placeholder="Contoh: SEO Poisoning SLOT777 pada portal.example.org"
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                    />
                  </label>

                  <label className="md:col-span-2 block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      URL / Subdomain / Sistem Terdampak *
                    </span>
                    <input
                      type="text"
                      required
                      value={affectedUrl}
                      onChange={(e) => setAffectedUrl(e.target.value)}
                      placeholder="https://portal.example.org"
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 font-mono text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                    />
                  </label>

                  <label className="block space-y-1">
                    <span className="text-[11px] text-zinc-400">Kategori</span>
                    <select
                      value={category}
                      onChange={(e) =>
                        setCategory(e.target.value as IncidentReportCategory)
                      }
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-100"
                    >
                      {Object.entries(CATEGORY_LABELS).map(([k, v]) => (
                        <option key={k} value={k}>
                          {v}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="block space-y-1">
                    <span className="text-[11px] text-zinc-400">Severity</span>
                    <select
                      value={severity}
                      onChange={(e) => setSeverity(e.target.value as Severity)}
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-100"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </label>

                  <label className="block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Sumber Laporan
                    </span>
                    <select
                      value={source}
                      onChange={(e) =>
                        setSource(e.target.value as IncidentReportSource)
                      }
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-100"
                    >
                      {Object.entries(SOURCE_LABELS).map(([k, v]) => (
                        <option key={k} value={k}>
                          {v}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Status Penanganan
                    </span>
                    <select
                      value={status}
                      onChange={(e) =>
                        setStatus(e.target.value as IncidentReportStatus)
                      }
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-100"
                    >
                      {Object.entries(STATUS_LABELS).map(([k, v]) => (
                        <option key={k} value={k}>
                          {v}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="md:col-span-2 block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Nama Pelapor / Unit (mis. Infra Ops, WhatsApp Internal, CSIRT)
                    </span>
                    <input
                      type="text"
                      value={reporterName}
                      onChange={(e) => setReporterName(e.target.value)}
                      placeholder="Contoh: Laporan Internal / Tim Infra Ops"
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                    />
                  </label>

                  <label className="md:col-span-2 block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Waktu Kejadian / Ditemukan
                    </span>
                    <input
                      type="datetime-local"
                      value={occurredAtLocal}
                      onChange={(e) => setOccurredAtLocal(e.target.value)}
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 font-mono text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
                    />
                  </label>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
                  <label className="block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Kronologi &amp; Dampak Insiden
                    </span>
                    <textarea
                      rows={3}
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Jelaskan apa yang terjadi, bagaimana ditemukan, dan dampaknya terhadap reputasi/layanan organisasi..."
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                    />
                  </label>

                  <label className="block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Bukti / Cuplikan Konten (Snippet Google, URL, Log, Screenshot Ref)
                    </span>
                    <textarea
                      rows={3}
                      value={evidenceSnippet}
                      onChange={(e) => setEvidenceSnippet(e.target.value)}
                      placeholder='Contoh: Cuplikan Google "Debut eksklusif SLOT777..." pada tanggal 19 Nov 22:24 WIB'
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 font-mono text-[11px] text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                    />
                  </label>

                  <label className="block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Catatan Koordinasi (Infra Ops / Pengelola Server / CSIRT)
                    </span>
                    <textarea
                      rows={2}
                      value={coordinationNotes}
                      onChange={(e) => setCoordinationNotes(e.target.value)}
                      placeholder="Nomor tiket Infra Ops, PIC pengelola server, status koordinasi..."
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                    />
                  </label>

                  <label className="block space-y-1">
                    <span className="text-[11px] text-zinc-400">
                      Tindakan Mitigasi / Pemulihan
                    </span>
                    <textarea
                      rows={2}
                      value={actionTaken}
                      onChange={(e) => setActionTaken(e.target.value)}
                      placeholder="Pembersihan file terinjeksi, audit .htaccess, permintaan re-index Google Search Console..."
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                    />
                  </label>
                </div>

                {formError && (
                  <p className="text-xs font-mono text-rose-400">{formError}</p>
                )}

                <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                  <label className="inline-flex items-center gap-2 text-xs text-zinc-200 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={includeInBoardReport}
                      onChange={(e) => setIncludeInBoardReport(e.target.checked)}
                      className="accent-emerald-500"
                    />
                    Sertakan insiden ini secara otomatis di Laporan Eksekutif CTO &amp; BoD (Word / PDF / Markdown)
                  </label>

                  <div className="flex items-center gap-2">
                    <ActionTooltip label="Batalkan Pencatatan" description="Kosongkan input dan tutup form pencatatan.">
                      <button
                        type="button"
                        onClick={() => {
                          resetForm();
                          setShowForm(false);
                        }}
                        className="px-3 py-1.5 text-xs font-medium text-zinc-400 hover:text-zinc-200 cursor-pointer"
                      >
                        Batal
                      </button>
                    </ActionTooltip>
                    <ActionTooltip
                      label="Simpan Laporan Insiden"
                      description={
                        isDemo
                          ? 'Simpan laporan ke sandbox Demo (tidak mengubah data Live).'
                          : 'Simpan laporan permanen ke database insiden server.'
                      }
                    >
                      <button
                        type="submit"
                        disabled={submitting}
                        className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors cursor-pointer disabled:opacity-60"
                      >
                        <Save className="w-3.5 h-3.5" />
                        {submitting ? 'Menyimpan...' : 'Simpan Laporan Insiden'}
                      </button>
                    </ActionTooltip>
                  </div>
                </div>
              </form>
            )}

            {/* Recorded Incident Reports Table */}
            {filteredReports.length === 0 ? (
              <div className="p-8 text-center space-y-3">
                <p className="text-sm font-medium text-zinc-200">
                  {incidentReports.length === 0
                    ? 'Belum ada laporan insiden manual / eksternal yang dicatat'
                    : 'Tidak ada laporan insiden yang cocok dengan filter aktif'}
                </p>
                {isDemo && (
                  <p className="text-xs text-zinc-400 max-w-xl mx-auto leading-relaxed">
                    {incidentReports.length === 0 ? (
                      <>
                        Gunakan halaman ini untuk merekam insiden yang tidak terlihat oleh pemindaian pasif biasa—seperti laporan dari <strong className="text-zinc-200">Tim Infra Ops</strong>, <strong className="text-zinc-200">CSIRT</strong>, maupun temuan <strong className="text-zinc-200">SEO Poisoning / Google Cloaking (SLOT777)</strong>—agar tercatat rapi dan otomatis terlampir pada laporan rapat <strong className="text-zinc-200">CTO &amp; Direksi (BoD)</strong>.
                      </>
                    ) : (
                      'Ubah filter severity, status, atau kata kunci pencarian untuk melihat laporan lainnya.'
                    )}
                  </p>
                )}
                <div className="flex flex-wrap items-center justify-center gap-2 pt-1">
                  {incidentReports.length === 0 ? (
                    <>
                      <ActionTooltip
                        label="Mulai Triage Wizard"
                        description="Panduan klasifikasi insiden dan checklist mitigasi."
                      >
                        <button
                          type="button"
                          onClick={() => setActiveTab('triage-wizard')}
                          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors cursor-pointer"
                        >
                          <ListChecks className="w-3.5 h-3.5" />
                          Mulai Incident Triage Wizard
                        </button>
                      </ActionTooltip>
                      <ActionTooltip
                        label="Template SEO Judol / Cloaking"
                        description="Buka form pencatatan dengan preset kasus SEO Poisoning."
                      >
                        <button
                          type="button"
                          onClick={() => applyTemplate('seo-judol')}
                          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors cursor-pointer"
                        >
                          <Plus className="w-3.5 h-3.5 text-emerald-400" />
                          Catat Kasus SEO Judol / Cloaking
                        </button>
                      </ActionTooltip>
                      <ActionTooltip
                        label="Form Laporan Kosong"
                        description="Catat insiden keamanan baru secara manual."
                      >
                        <button
                          type="button"
                          onClick={() => setShowForm(true)}
                          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors cursor-pointer"
                        >
                          Catat Laporan Baru
                        </button>
                      </ActionTooltip>
                    </>
                  ) : (
                    <ActionTooltip
                      label="Reset Semua Filter"
                      description="Kembalikan filter severity, status, dan pencarian ke kondisi semula."
                    >
                      <button
                        type="button"
                        onClick={() => {
                          setSeverityFilter('ALL');
                          setStatusFilter('ALL');
                          setSearchQuery('');
                        }}
                        className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors cursor-pointer"
                      >
                        Reset Filter
                      </button>
                    </ActionTooltip>
                  )}
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-zinc-800/80 bg-zinc-950/60 text-[11px] font-mono text-zinc-400 uppercase tracking-wider">
                      <th className="py-2.5 px-4 whitespace-nowrap">Severity</th>
                      <th className="py-2.5 px-4">Incident &amp; Target System</th>
                      <th className="py-2.5 px-4 whitespace-nowrap">Category &amp; Source</th>
                      <th className="py-2.5 px-4 whitespace-nowrap">Occurred (WIB)</th>
                      <th className="py-2.5 px-4 whitespace-nowrap">Status &amp; BoD</th>
                      <th className="py-2.5 px-4 text-right whitespace-nowrap">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/70 text-xs">
                    {filteredReports.map((rep) => {
                      const isExpanded = expandedId === rep.id || editingId === rep.id;
                      const isEditing = editingId === rep.id;
                      return (
                        <React.Fragment key={rep.id}>
                          <tr className="hover:bg-zinc-900/50 transition-colors">
                            {/* Severity Visual Badge + ID */}
                            <td className="py-3.5 px-4 align-top whitespace-nowrap">
                              <div className="flex flex-col items-start gap-1.5">
                                <SeverityBadge severity={rep.severity} />
                                <span className="font-mono text-[10px] tabular-nums text-zinc-500">
                                  {rep.id}
                                </span>
                              </div>
                            </td>

                            {/* Title, Affected URL & Summary Preview */}
                            <td className="py-3.5 px-4 align-top min-w-[260px] max-w-md">
                              <ActionTooltip
                                label={isExpanded ? 'Tutup Detail Insiden' : 'Buka Detail Insiden'}
                                description="Lihat kronologi lengkap, bukti, dan editor catatan koordinasi."
                              >
                                <button
                                  type="button"
                                  onClick={() =>
                                    setExpandedId((prev) =>
                                      prev === rep.id ? null : rep.id
                                    )
                                  }
                                  className="text-left group cursor-pointer"
                                >
                                  <div className="text-xs font-semibold text-zinc-100 group-hover:text-emerald-300 transition-colors leading-snug">
                                    {rep.title}
                                  </div>
                                </button>
                              </ActionTooltip>
                              <div className="font-mono text-[11px] text-emerald-400 break-all mt-0.5">
                                {rep.affectedUrl}
                              </div>
                              {rep.description && !isExpanded && (
                                <p className="text-[11px] text-zinc-400 mt-1 line-clamp-1">
                                  {rep.description}
                                </p>
                              )}
                            </td>

                            {/* Category & Source */}
                            <td className="py-3.5 px-4 align-top whitespace-nowrap">
                              <div className="text-xs font-medium text-zinc-200">
                                {CATEGORY_LABELS[rep.category]}
                              </div>
                              <div className="text-[11px] text-zinc-400 mt-0.5">
                                {SOURCE_LABELS[rep.source]}
                              </div>
                              <div className="text-[10px] text-zinc-500 mt-0.5 truncate max-w-[180px]">
                                {rep.reporterName}
                              </div>
                            </td>

                            {/* Occurred Timestamp */}
                            <td className="py-3.5 px-4 align-top whitespace-nowrap font-mono text-[11px] tabular-nums text-zinc-400">
                              {formatShortDateTime(rep.occurredAt)}
                            </td>

                            {/* Status Selector & CTO/BoD Inclusion */}
                            <td className="py-3.5 px-4 align-top whitespace-nowrap">
                              <div className="flex flex-col items-start gap-1.5">
                                <ActionTooltip
                                  label="Ubah Status Insiden"
                                  description="Perbarui progres penanganan (Open, Investigasi, Eskalasi Infra, Termitigasi, Closed)."
                                >
                                  <select
                                    value={rep.status}
                                    aria-label={`Ubah status ${rep.id}`}
                                    onChange={(e) =>
                                      void onUpdateIncident(rep.id, {
                                        status: e.target.value as IncidentReportStatus,
                                      })
                                    }
                                    className={`bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-[11px] font-mono font-medium ${STATUS_TONE[rep.status]}`}
                                  >
                                    {Object.entries(STATUS_LABELS).map(([k, v]) => (
                                      <option key={k} value={k} className="text-zinc-100">
                                        {v}
                                      </option>
                                    ))}
                                  </select>
                                </ActionTooltip>

                                <ActionTooltip
                                  label="Lampiran CTO & BoD"
                                  description="Sertakan atau kecualikan insiden ini dari dokumen ekspor Laporan Direksi."
                                >
                                  <label className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400 hover:text-zinc-200 cursor-pointer select-none">
                                    <input
                                      type="checkbox"
                                      checked={rep.includeInBoardReport}
                                      onChange={(e) =>
                                        void onUpdateIncident(rep.id, {
                                          includeInBoardReport: e.target.checked,
                                        })
                                      }
                                      className="accent-emerald-500"
                                    />
                                    <span>CTO/BoD Report</span>
                                  </label>
                                </ActionTooltip>
                              </div>
                            </td>

                            {/* Row Actions */}
                            <td className="py-3.5 px-4 align-top text-right whitespace-nowrap">
                              <div className="inline-flex items-center gap-1.5">
                                {isDemo && onCopyToLive && (
                                  <ActionTooltip
                                    label="Salin ke Live Report"
                                    description="Promosikan hasil latihan insiden ini menjadi laporan Live permanen (ditandai Salinan Latihan Demo)."
                                  >
                                    <button
                                      type="button"
                                      onClick={() =>
                                        onCopyToLive({
                                          sourceLabel: 'Incident Report Demo',
                                          sourceId: rep.id,
                                          payload: {
                                            title: rep.title,
                                            affectedUrl: rep.affectedUrl,
                                            category: rep.category,
                                            severity: rep.severity,
                                            source: rep.source,
                                            reporterName: rep.reporterName,
                                            occurredAt: rep.occurredAt,
                                            description: rep.description,
                                            evidenceSnippet: rep.evidenceSnippet,
                                            coordinationNotes: rep.coordinationNotes,
                                            actionTaken: rep.actionTaken,
                                            status: rep.status,
                                            includeInBoardReport: false,
                                          },
                                        })
                                      }
                                      className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/40 rounded transition-colors cursor-pointer"
                                    >
                                      <ArrowUpRight className="w-3 h-3" />
                                      Salin ke Live
                                    </button>
                                  </ActionTooltip>
                                )}

                                <ActionTooltip
                                  label={isExpanded ? 'Tutup Detail' : 'Lihat Detail'}
                                  description="Tampilkan atau sembunyikan kronologi, bukti, dan form edit triage."
                                >
                                  <button
                                    type="button"
                                    onClick={() =>
                                      setExpandedId((prev) =>
                                        prev === rep.id ? null : rep.id
                                      )
                                    }
                                    aria-expanded={isExpanded}
                                    aria-label={`Toggle details for ${rep.id}`}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] bg-zinc-950 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded transition-colors cursor-pointer"
                                  >
                                    {isExpanded ? (
                                      <>
                                        <span>Tutup</span>
                                        <ChevronUp className="w-3 h-3" />
                                      </>
                                    ) : (
                                      <>
                                        <span>Detail</span>
                                        <ChevronDown className="w-3 h-3" />
                                      </>
                                    )}
                                  </button>
                                </ActionTooltip>

                                <ActionTooltip
                                  label="Hapus Laporan Insiden"
                                  description="Hapus permanen baris laporan ini dari daftar insiden."
                                >
                                  <button
                                    type="button"
                                    onClick={() => void onDeleteIncident(rep.id)}
                                    aria-label={`Hapus laporan ${rep.id}`}
                                    className="p-1.5 text-zinc-500 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors cursor-pointer"
                                  >
                                    <Trash2 className="w-3.5 h-3.5" />
                                  </button>
                                </ActionTooltip>
                              </div>
                            </td>
                          </tr>

                          {/* Expandable Evidence, Coordination Notes & Inline Triage Editor */}
                          {isExpanded && (
                            <tr className="bg-zinc-950/70">
                              <td colSpan={6} className="px-5 py-4 space-y-3">
                                {rep.description && (
                                  <div className="space-y-1">
                                    <span className="text-[11px] font-mono text-zinc-500 block">
                                      Kronologi &amp; Dampak Insiden
                                    </span>
                                    <p className="text-xs text-zinc-200 leading-relaxed">
                                      {rep.description}
                                    </p>
                                  </div>
                                )}

                                {rep.evidenceSnippet && (
                                  <div className="bg-zinc-900/70 border border-zinc-800/80 rounded-md px-3 py-2 font-mono text-[11px] text-zinc-300">
                                    <span className="text-zinc-500 mr-2">Bukti:</span>
                                    {rep.evidenceSnippet}
                                  </div>
                                )}

                                {!isEditing ? (
                                  <div className="space-y-3 pt-2 border-t border-zinc-800/60">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                                      <div>
                                        <span className="text-[11px] font-mono text-zinc-500 block">
                                          Koordinasi Infra Ops / Pengelola Server
                                        </span>
                                        <p className="text-zinc-300 mt-0.5 whitespace-pre-line">
                                          {rep.coordinationNotes || 'Belum ada catatan koordinasi.'}
                                        </p>
                                      </div>
                                      <div>
                                        <span className="text-[11px] font-mono text-zinc-500 block">
                                          Tindakan Mitigasi / Pemulihan
                                        </span>
                                        <p className="text-zinc-300 mt-0.5 whitespace-pre-line">
                                          {rep.actionTaken || 'Belum ada catatan mitigasi.'}
                                        </p>
                                      </div>
                                    </div>
                                    <div className="flex justify-end">
                                      <ActionTooltip
                                        label="Edit Catatan Triage"
                                        description="Ubah severity, catatan koordinasi Infra Ops, atau tindakan pemulihan."
                                      >
                                        <button
                                          type="button"
                                          onClick={() => startInlineEdit(rep)}
                                          className="px-3 py-1 text-[11px] font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded transition-colors cursor-pointer"
                                        >
                                          Edit Severity &amp; Catatan Triage
                                        </button>
                                      </ActionTooltip>
                                    </div>
                                  </div>
                                ) : (
                                  <div className="pt-2 border-t border-zinc-800/80 space-y-3 text-xs">
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                      <label className="block space-y-1">
                                        <span className="text-[11px] text-zinc-400">
                                          Tingkat Severity
                                        </span>
                                        <select
                                          value={editSeverity}
                                          onChange={(e) =>
                                            setEditSeverity(e.target.value as Severity)
                                          }
                                          className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs font-mono text-zinc-100"
                                        >
                                          <option value="CRITICAL">Critical</option>
                                          <option value="HIGH">High</option>
                                          <option value="MEDIUM">Medium</option>
                                          <option value="LOW">Low</option>
                                        </select>
                                      </label>
                                      <label className="block space-y-1">
                                        <span className="text-[11px] text-zinc-400">
                                          Catatan Koordinasi Infra Ops / Pengelola Server
                                        </span>
                                        <textarea
                                          rows={2}
                                          value={editCoordination}
                                          onChange={(e) => setEditCoordination(e.target.value)}
                                          className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100"
                                        />
                                      </label>
                                      <label className="block space-y-1">
                                        <span className="text-[11px] text-zinc-400">
                                          Tindakan Mitigasi / Pemulihan
                                        </span>
                                        <textarea
                                          rows={2}
                                          value={editActionTaken}
                                          onChange={(e) => setEditActionTaken(e.target.value)}
                                          className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100"
                                        />
                                      </label>
                                    </div>
                                    <div className="flex justify-end gap-2">
                                      <button
                                        type="button"
                                        onClick={() => setEditingId(null)}
                                        className="px-3 py-1 text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer"
                                      >
                                        Batal
                                      </button>
                                      <button
                                        type="button"
                                        disabled={savingEdit}
                                        onClick={() => void saveInlineEdit(rep.id)}
                                        className="px-3 py-1 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded cursor-pointer disabled:opacity-60"
                                      >
                                        {savingEdit ? 'Menyimpan...' : 'Simpan Perubahan'}
                                      </button>
                                    </div>
                                  </div>
                                )}
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: LIVE AUTOMATED HTML DEFACEMENT & GOOGLEBOT CLOAKING SCANNER */}
        {activeTab === 'content-scanner' && (
          <div className="divide-y divide-zinc-800/80">
            <div className="px-4 py-3 bg-zinc-950/60 flex flex-col lg:flex-row lg:items-center justify-between gap-3 text-xs">
              <div className="space-y-1 max-w-3xl">
                <p className="text-zinc-200 font-medium">
                  Pemindai Otomatis Konten HTML (Browser Biasa vs Googlebot User-Agent) + Hash SHA-256
                </p>
                {isDemo && (
                  <p className="text-[11px] text-zinc-400 leading-relaxed">
                    Scanner ini mengambil respons HTML secara langsung dari setiap URL terpantau memakai 2 identitas (<span className="font-mono text-zinc-300">Chrome Browser</span> dan <span className="font-mono text-zinc-300">Googlebot/2.1</span>) untuk mendeteksi injeksi kata kunci judi online (<span className="font-mono">SLOT777, gacor, maxwin, togel</span>), perbedaan judul/meta (*cloaking*), serta perubahan baseline HTML.{' '}
                    <span className="text-amber-300">
                      Catatan jujur:
                    </span>{' '}
                    jika penyerang memakai *IP-verified Reverse-DNS Googlebot cloaking* atau menaruh file di sub-path rahasia yang hanya muncul di indeks Google, tetap perlu dicatat melalui tab <strong>Laporan Insiden / Manual</strong>.
                  </p>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <ActionTooltip
                  label="Setujui Baseline SHA-256"
                  description="Simpan hash HTML saat ini sebagai baseline resmi agar perubahan rilis sah tidak memicu alert palsu."
                >
                  <button
                    type="button"
                    onClick={() => void onAcceptContentBaseline()}
                    disabled={contentScans.length === 0}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap cursor-pointer disabled:opacity-50"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    Accept Baseline SHA-256
                  </button>
                </ActionTooltip>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400 uppercase">
                    <th className="py-2.5 px-4">Endpoint &amp; Status</th>
                    <th className="py-2.5 px-4">Browser UA Response</th>
                    <th className="py-2.5 px-4">Googlebot UA Response</th>
                    <th className="py-2.5 px-4">Integritas &amp; Cloaking</th>
                    <th className="py-2.5 px-4 text-right">Aksi</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 text-xs">
                  {contentScans.map((scan) => {
                    const riskColor =
                      scan.riskLevel === 'CRITICAL'
                        ? 'text-rose-400'
                        : scan.riskLevel === 'SUSPICIOUS'
                        ? 'text-amber-400'
                        : 'text-emerald-400';
                    const allKw = Array.from(
                      new Set([
                        ...scan.browserKeywordsFound,
                        ...scan.googlebotKeywordsFound,
                      ])
                    );

                    return (
                      <tr key={scan.endpointId} className="hover:bg-zinc-900/50">
                        <td className="py-3 px-4 align-top">
                          <div className="font-medium text-zinc-100">
                            {scan.label}
                          </div>
                          <div className="font-mono text-[11px] text-zinc-400 break-all">
                            {scan.url}
                          </div>
                          <div className="font-mono text-[10px] text-zinc-500 mt-1">
                            Scan: {formatShortDateTime(scan.scannedAt)} WIB
                          </div>
                        </td>

                        <td className="py-3 px-4 align-top max-w-xs">
                          <div className="font-mono text-[11px] text-zinc-300">
                            HTTP {scan.browserStatus ?? 'ERR'} ·{' '}
                            <span className="text-zinc-500">
                              SHA256:{scan.browserHashSha256?.slice(0, 10) ?? '-'}
                            </span>
                          </div>
                          <div className="text-zinc-200 text-[11px] mt-0.5 truncate">
                            Title: {scan.browserTitle || '—'}
                          </div>
                          {scan.browserMetaDesc && (
                            <div className="text-zinc-500 text-[10px] mt-0.5 line-clamp-2">
                              Meta: {scan.browserMetaDesc}
                            </div>
                          )}
                        </td>

                        <td className="py-3 px-4 align-top max-w-xs">
                          <div className="font-mono text-[11px] text-zinc-300">
                            HTTP {scan.googlebotStatus ?? 'ERR'} ·{' '}
                            <span className="text-zinc-500">
                              SHA256:{scan.googlebotHashSha256?.slice(0, 10) ?? '-'}
                            </span>
                          </div>
                          <div className="text-zinc-200 text-[11px] mt-0.5 truncate">
                            Title: {scan.googlebotTitle || '—'}
                          </div>
                          {scan.googlebotMetaDesc && (
                            <div className="text-zinc-500 text-[10px] mt-0.5 line-clamp-2">
                              Meta: {scan.googlebotMetaDesc}
                            </div>
                          )}
                        </td>

                        <td className="py-3 px-4 align-top">
                          <div
                            className={`inline-flex items-center gap-1 font-mono text-[11px] font-semibold ${riskColor}`}
                          >
                            {scan.riskLevel === 'CLEAN' ? (
                              <ShieldCheck className="w-3.5 h-3.5" />
                            ) : (
                              <AlertTriangle className="w-3.5 h-3.5" />
                            )}
                            {scan.riskLevel}
                          </div>
                          {allKw.length > 0 && (
                            <div className="text-[11px] font-mono text-rose-400 mt-1">
                              Match: {allKw.join(', ')}
                            </div>
                          )}
                          {scan.cloakingSuspected && scan.cloakingReason && (
                            <div className="text-[11px] text-amber-300 mt-1 leading-snug">
                              {scan.cloakingReason}
                            </div>
                          )}
                          {!scan.defacementSuspected &&
                            !scan.cloakingSuspected &&
                            scan.contentChangedFromBaseline && (
                              <div className="text-[11px] text-amber-400 mt-1">
                                Hash HTML berubah dari baseline
                              </div>
                            )}
                          {scan.riskLevel === 'CLEAN' && (
                            <div className="text-[11px] text-zinc-500 mt-0.5">
                              0 keyword judol/deface · Browser = Googlebot
                            </div>
                          )}
                        </td>

                        <td className="py-3 px-4 align-top text-right whitespace-nowrap">
                          <ActionTooltip
                            label="Catat ke Incident Report"
                            description="Buka form laporan insiden dengan bukti Dual-UA dan hash SHA-256 dari baris scan ini."
                          >
                            <button
                              type="button"
                              onClick={() => promoteScanToIncident(scan)}
                              className="px-2.5 py-1 text-[11px] font-medium bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded transition-colors cursor-pointer"
                            >
                              Catat Insiden →
                            </button>
                          </ActionTooltip>
                        </td>
                      </tr>
                    );
                  })}

                  {contentScans.length === 0 && (
                    <tr>
                      <td
                        colSpan={5}
                        className="py-8 text-center text-xs font-mono text-zinc-500"
                      >
                        {isDemo
                          ? 'Menjalankan pemindaian HTML & Googlebot Cloaking pertama... Klik "Scan HTML & Cloaking" untuk memicu segera.'
                          : 'Belum ada hasil scan HTML & Googlebot Cloaking.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};
