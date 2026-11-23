import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Play,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Search,
  Terminal,
  Radio,
  RotateCcw,
  X,
  Clock,
  Activity,
  Ban,
  CopyCheck,
} from 'lucide-react';
import {
  AttackAction,
  AttackVector,
  LiveAttackEvent,
  Severity,
  ThreatIntelAlert,
  ThreatIntelCategory,
  ThreatIntelStatus,
} from '../types/soc';
import {
  formatShortDateTime,
  getActionColor,
  getIntelCategoryLabel,
  getIntelStatusMeta,
  getSeverityColor,
} from '../utils/socFormatters';
import { useSocMode } from '../context/SocModeContext';
import { ActionTooltip } from './ActionTooltip';
import { CopyToLiveDraft } from './CopyToLiveModal';

interface PlaybookIntegrationViewProps {
  threatIntelAlerts: ThreatIntelAlert[];
  ingestedSiemEvents: LiveAttackEvent[];
  onRunPlaybook: (intelId: string, nextStatus: ThreatIntelStatus) => Promise<void>;
  onMitigateAttackEvent: (
    eventId: string,
    mitigatedBy: string,
    mitigatedAt: string
  ) => Promise<void>;
  onPushSiemTestEvent: (payload: Partial<LiveAttackEvent>) => Promise<void>;
  onCopyToLive?: (draft: CopyToLiveDraft) => void;
}

interface PlaybookExecutionRun {
  intelId: string;
  playbookName: string;
  affectedEntity: string;
  category: ThreatIntelCategory;
  startedAt: string;
  completedAt?: string;
  status: 'RUNNING' | 'COMPLETED' | 'ERROR';
  errorMessage?: string;
  steps: Array<{
    label: string;
    detail: string;
    state: 'PENDING' | 'RUNNING' | 'DONE';
    timestamp?: string;
  }>;
}

function buildPlaybookSteps(alert: ThreatIntelAlert): Array<{
  label: string;
  detail: string;
}> {
  switch (alert.category) {
    case 'ZERO_DAY_CVE':
      return [
        {
          label: 'Asset Inventory & Exposure Check',
          detail: `Memeriksa eksposur ${alert.affected_entity} pada endpoint layanan & infrastruktur organisasi.`,
        },
        {
          label: 'Apply WAF Virtual Patch Signature',
          detail: `Mengaktifkan aturan deteksi & blokir eksploitasi ${alert.intel_id} di edge WAF.`,
        },
        {
          label: 'Dispatch Patch Ticket to Infra Ops / Dev',
          detail: `Mengirim rekomendasi patch darurat ke pengelola server & tim Development.`,
        },
        {
          label: 'Verify Posture & Record Audit Trail',
          detail: `Menyelesaikan eksekusi ${alert.recommended_playbook} dan mencatat log kepatuhan.`,
        },
      ];
    case 'PHISHING_DOMAIN':
      return [
        {
          label: 'IOC Enrichment & DNS Resolution',
          detail: `Mengumpulkan WHOIS, IP hosting, dan DNS record dari ${alert.affected_entity}.`,
        },
        {
          label: 'Internal Proxy & DNS Sinkhole Block',
          detail: `Memblokir akses ke ${alert.affected_entity} pada DNS resolver & proxy internal organisasi.`,
        },
        {
          label: 'Submit Takedown & CSIRT Notification',
          detail: `Menyiapkan laporan takedown ke Internal CSIRT / Gov-CERT & memverifikasi DMARC.`,
        },
        {
          label: 'Close & Archive Playbook Evidence',
          detail: `Menyelesaikan eksekusi ${alert.recommended_playbook} ke log insiden.`,
        },
      ];
    case 'CREDENTIAL_LEAK':
    default:
      return [
        {
          label: 'Scope Compromised Accounts & Sessions',
          detail: `Mengidentifikasi kredensial/token aktif terkait ${alert.affected_entity}.`,
        },
        {
          label: 'Revoke Active Tokens & Force Reset',
          detail: `Mencabut sesi login aktif dan memicu rotasi kredensial / kunci akses.`,
        },
        {
          label: 'Enforce MFA & Egress Anomaly Check',
          detail: `Memastikan verifikasi MFA aktif serta mengaudit log akses 7 hari terakhir.`,
        },
        {
          label: 'Finalize Playbook & Update Alert Status',
          detail: `Menyelesaikan eksekusi ${alert.recommended_playbook} dan menyimpan jejak audit.`,
        },
      ];
  }
}

function getActionBadgeStyle(action: AttackAction): string {
  switch (action) {
    case 'DETECTED':
      return 'bg-rose-500/15 text-rose-300 border-rose-500/40';
    case 'CHALLENGED':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
    case 'BLOCKED_BY_WAF':
      return 'bg-sky-500/15 text-sky-300 border-sky-500/40';
    case 'MITIGATED':
    default:
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40';
  }
}

function getSeverityBadgeStyle(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return 'bg-rose-500/15 text-rose-300 border-rose-500/40';
    case 'HIGH':
      return 'bg-orange-500/15 text-orange-300 border-orange-500/40';
    case 'MEDIUM':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
    case 'LOW':
    default:
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40';
  }
}

export interface AttackEventMitigationModalProps {
  event: LiveAttackEvent | null;
  submitting: boolean;
  onCancel: () => void;
  onConfirm: (event: LiveAttackEvent, mitigatedBy: string, mitigatedAt: string) => void;
}

export const AttackEventMitigationModal: React.FC<
  AttackEventMitigationModalProps
> = ({ event, submitting, onCancel, onConfirm }) => {
  if (!event) return null;
  const sevColor = getSeverityColor(event.severity);
  const actionMeta = getActionColor(event.action_taken);
  const previewIso = new Date().toISOString();

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="mitigate-modal-title"
      onClick={onCancel}
    >
      <div
        className="w-full max-w-lg bg-zinc-950 border border-zinc-800 rounded-lg overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-5 py-3.5 border-b border-zinc-800 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <h3
              id="mitigate-modal-title"
              className="text-sm font-semibold text-zinc-100"
            >
              Confirm Attack Event Mitigation
            </h3>
          </div>
          <button
            type="button"
            onClick={onCancel}
            aria-label="Close confirmation dialog"
            className="p-1 text-zinc-500 hover:text-zinc-200 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4 text-xs">
          <p className="text-zinc-300 leading-relaxed">
            Are you sure you want to mitigate this live attack event? Confirming will transition its status to{' '}
            <strong className="text-emerald-400 font-mono">MITIGATED</strong> and record attribution metadata.
          </p>

          <div className="bg-zinc-900/70 border border-zinc-800 rounded-md p-3.5 space-y-2 font-mono text-[11px]">
            <div className="flex items-center justify-between gap-2">
              <span className="text-zinc-500">Event ID</span>
              <span className="text-zinc-100 font-semibold">{event.event_id}</span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-zinc-500">Attack Vector / Severity</span>
              <span className={sevColor.text}>
                {event.attack_vector} · {sevColor.label}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-zinc-500">Source IP → Target</span>
              <span className="text-zinc-200 truncate max-w-[260px]">
                {event.source_ip} ({event.source_country}) → {event.target_asset}
              </span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-zinc-500">Current Action</span>
              <span className={actionMeta.text}>{event.action_taken}</span>
            </div>
          </div>

          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-md p-3.5 space-y-1.5 font-mono text-[11px]">
            <div className="text-emerald-300 font-semibold font-sans text-xs">
              Updates to apply (LiveAttackEvent):
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-zinc-400">action_taken</span>
              <span className="text-emerald-300 font-semibold">MITIGATED</span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-zinc-400">mitigated_by</span>
              <span className="text-zinc-100">SOC-Analyst-Auto</span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-zinc-400">mitigated_at</span>
              <span className="text-zinc-300 tabular-nums">{previewIso}</span>
            </div>
          </div>
        </div>

        <div className="px-5 py-3.5 border-t border-zinc-800 flex items-center justify-end gap-2 bg-zinc-900/40">
          <button
            type="button"
            disabled={submitting}
            onClick={onCancel}
            className="px-3.5 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md transition-colors cursor-pointer disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={submitting}
            onClick={() =>
              onConfirm(event, 'SOC-Analyst-Auto', new Date().toISOString())
            }
            className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors cursor-pointer disabled:opacity-60"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            {submitting ? 'Mitigating...' : 'Confirm Mitigate'}
          </button>
        </div>
      </div>
    </div>
  );
};

export const PlaybookIntegrationView: React.FC<
  PlaybookIntegrationViewProps
> = ({
  threatIntelAlerts,
  ingestedSiemEvents,
  onRunPlaybook,
  onMitigateAttackEvent,
  onPushSiemTestEvent,
  onCopyToLive,
}) => {
  const { isDemo, setMode } = useSocMode();
  const [statusFilter, setStatusFilter] = useState<'ALL' | ThreatIntelStatus>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<'ALL' | ThreatIntelCategory>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Playbook simulation state
  const [activeRun, setActiveRun] = useState<PlaybookExecutionRun | null>(null);
  const [runHistory, setRunHistory] = useState<Record<string, PlaybookExecutionRun>>({});
  const timersRef = useRef<Array<ReturnType<typeof setTimeout>>>([]);

  // Attack event mitigation confirmation modal state
  const [pendingMitigateEvent, setPendingMitigateEvent] =
    useState<LiveAttackEvent | null>(null);
  const [mitigating, setMitigating] = useState(false);
  const [pushingWebhook, setPushingWebhook] = useState(false);

  useEffect(() => {
    return () => {
      timersRef.current.forEach((t) => clearTimeout(t));
      timersRef.current = [];
    };
  }, []);

  const clearRunTimers = () => {
    timersRef.current.forEach((t) => clearTimeout(t));
    timersRef.current = [];
  };

  const openAlertsCount = useMemo(
    () => threatIntelAlerts.filter((a) => a.status === 'OPEN').length,
    [threatIntelAlerts]
  );
  const mitigatedAlertsCount = useMemo(
    () => threatIntelAlerts.filter((a) => a.status === 'MITIGATED').length,
    [threatIntelAlerts]
  );
  const unmitigatedAttacksCount = useMemo(
    () =>
      ingestedSiemEvents.filter(
        (e) => e.action_taken === 'DETECTED' || e.action_taken === 'CHALLENGED'
      ).length,
    [ingestedSiemEvents]
  );
  const mitigatedAttacksCount = useMemo(
    () => ingestedSiemEvents.filter((e) => e.action_taken === 'MITIGATED').length,
    [ingestedSiemEvents]
  );

  const filteredAlerts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return threatIntelAlerts.filter((a) => {
      if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
      if (categoryFilter !== 'ALL' && a.category !== categoryFilter) return false;
      if (!q) return true;
      return (
        a.intel_id.toLowerCase().includes(q) ||
        a.affected_entity.toLowerCase().includes(q) ||
        a.recommended_playbook.toLowerCase().includes(q) ||
        a.source.toLowerCase().includes(q)
      );
    });
  }, [threatIntelAlerts, statusFilter, categoryFilter, searchQuery]);

  const handleInitiatePlaybook = (alert: ThreatIntelAlert) => {
    clearRunTimers();
    const stepDefs = buildPlaybookSteps(alert);
    const initialRun: PlaybookExecutionRun = {
      intelId: alert.intel_id,
      playbookName: alert.recommended_playbook,
      affectedEntity: alert.affected_entity,
      category: alert.category,
      startedAt: new Date().toISOString(),
      status: 'RUNNING',
      steps: stepDefs.map((s, idx) => ({
        ...s,
        state: idx === 0 ? 'RUNNING' : 'PENDING',
        timestamp: idx === 0 ? new Date().toISOString() : undefined,
      })),
    };
    setActiveRun(initialRun);

    stepDefs.forEach((_, idx) => {
      if (idx === 0) return;
      const t = setTimeout(() => {
        setActiveRun((prev) => {
          if (!prev || prev.intelId !== alert.intel_id) return prev;
          return {
            ...prev,
            steps: prev.steps.map((st, sIdx) => {
              if (sIdx < idx) {
                return {
                  ...st,
                  state: 'DONE',
                  timestamp: st.timestamp ?? new Date().toISOString(),
                };
              }
              if (sIdx === idx) {
                return {
                  ...st,
                  state: 'RUNNING',
                  timestamp: new Date().toISOString(),
                };
              }
              return st;
            }),
          };
        });
      }, idx * 550);
      timersRef.current.push(t);
    });

    const finishTimer = setTimeout(() => {
      void (async () => {
        try {
          await onRunPlaybook(alert.intel_id, 'MITIGATED');
          const completedAt = new Date().toISOString();
          setActiveRun((prev) => {
            if (!prev || prev.intelId !== alert.intel_id) return prev;
            const finalized: PlaybookExecutionRun = {
              ...prev,
              status: 'COMPLETED',
              completedAt,
              steps: prev.steps.map((st) => ({
                ...st,
                state: 'DONE',
                timestamp: st.timestamp ?? completedAt,
              })),
            };
            setRunHistory((hist) => ({
              ...hist,
              [alert.intel_id]: finalized,
            }));
            return finalized;
          });
        } catch (err) {
          setActiveRun((prev) =>
            prev && prev.intelId === alert.intel_id
              ? {
                  ...prev,
                  status: 'ERROR',
                  errorMessage:
                    err instanceof Error ? err.message : 'Playbook execution failed',
                }
              : prev
          );
        }
      })();
    }, stepDefs.length * 550);
    timersRef.current.push(finishTimer);
  };

  const handleConfirmMitigate = async (
    evt: LiveAttackEvent,
    mitigatedBy: string,
    mitigatedAt: string
  ) => {
    setMitigating(true);
    try {
      await onMitigateAttackEvent(evt.event_id, mitigatedBy, mitigatedAt);
      setPendingMitigateEvent(null);
    } finally {
      setMitigating(false);
    }
  };

  const handleSimulateSiemWebhook = async (
    actionTaken: 'DETECTED' | 'CHALLENGED',
    vector: AttackVector,
    severity: Severity
  ) => {
    setPushingWebhook(true);
    try {
      await onPushSiemTestEvent({
        source_ip: actionTaken === 'DETECTED' ? '185.220.101.44' : '45.146.164.110',
        source_country: actionTaken === 'DETECTED' ? 'RU' : 'NL',
        target_asset: 'portal.example-corp.test',
        attack_vector: vector,
        severity,
        action_taken: actionTaken,
        payload_snippet:
          vector === 'SQLi'
            ? "GET /api/v1/beneficiary?id=1' OR '1'='1 HTTP/1.1"
            : 'POST /auth/login (excessive credential attempts)',
      });
    } finally {
      setPushingWebhook(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header Control Bar */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100">
              Incident Response Playbook Integration &amp; Attack Mitigation Console
            </h2>
          </div>
          {isDemo && (
            <p className="text-xs text-zinc-400 max-w-3xl leading-relaxed">
              Jalankan playbook respons otomatis pada <strong className="text-zinc-200">ThreatIntelAlert</strong> berstatus <span className="font-mono text-rose-400">OPEN</span> dan eksekusi mitigasi terkonfirmasi pada <strong className="text-zinc-200">LiveAttackEvent</strong> (<span className="font-mono text-rose-400">DETECTED</span> / <span className="font-mono text-amber-400">CHALLENGED</span>).
            </p>
          )}
        </div>

        {isDemo && (
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <ActionTooltip
              label="Simulasi Webhook SIEM: DETECTED"
              description="Menambahkan event serangan SQLi sintetis ke sandbox Demo untuk melatih alur konfirmasi Mitigate."
              scope="DEMO ONLY"
            >
              <button
                type="button"
                disabled={pushingWebhook}
                onClick={() =>
                  void handleSimulateSiemWebhook('DETECTED', 'SQLi', 'CRITICAL')
                }
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-rose-300 border border-rose-500/30 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
              >
                <Radio className="w-3.5 h-3.5" />
                Push SIEM: DETECTED
              </button>
            </ActionTooltip>
            <ActionTooltip
              label="Simulasi Webhook SIEM: CHALLENGED"
              description="Menambahkan event Credential Stuffing berstatus CHALLENGED ke sandbox Demo."
              scope="DEMO ONLY"
            >
              <button
                type="button"
                disabled={pushingWebhook}
                onClick={() =>
                  void handleSimulateSiemWebhook(
                    'CHALLENGED',
                    'Credential Stuffing',
                    'HIGH'
                  )
                }
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-amber-300 border border-amber-500/30 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
              >
                <Radio className="w-3.5 h-3.5" />
                Push SIEM: CHALLENGED
              </button>
            </ActionTooltip>
          </div>
        )}
      </section>

      {/* 4-Column Semantic Threat KPI Strip */}
      <section
        aria-label="Playbook and Mitigation Metrics"
        className="grid grid-cols-2 xl:grid-cols-4 divide-y xl:divide-y-0 xl:divide-x divide-zinc-800/80 bg-zinc-900/40 border border-zinc-800/80 rounded-lg"
      >
        <div className="p-4">
          <p className="text-xs text-zinc-400">Open Threat Intel Alerts</p>
          <p
            className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${
              openAlertsCount > 0 ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {openAlertsCount}
          </p>
          {isDemo && (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Menunggu eksekusi recommended playbook
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">Playbook Mitigated Alerts</p>
          <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-emerald-400">
            {mitigatedAlertsCount}
          </p>
          {isDemo && (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Dari total {threatIntelAlerts.length} ThreatIntelAlert aktif
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">Attacks Needing Mitigation</p>
          <p
            className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${
              unmitigatedAttacksCount > 0 ? 'text-amber-400' : 'text-emerald-400'
            }`}
          >
            {unmitigatedAttacksCount}
          </p>
          {isDemo && (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Status DETECTED atau CHALLENGED
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">Mitigated Live Attack Events</p>
          <p className="mt-1 font-mono text-2xl font-semibold tabular-nums text-emerald-400">
            {mitigatedAttacksCount}
          </p>
          {isDemo && (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              Tercatat dengan timestamp &amp; SOC-Analyst-Auto
            </p>
          )}
        </div>
      </section>

      {/* Active / Recent Playbook Execution Console */}
      {activeRun && (
        <section
          aria-label="Playbook Execution Console"
          className="bg-zinc-950 border border-emerald-500/40 rounded-lg overflow-hidden"
        >
          <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-2 bg-zinc-900/60">
            <div className="flex items-center gap-2 min-w-0">
              <Activity
                className={`w-4 h-4 shrink-0 ${
                  activeRun.status === 'RUNNING'
                    ? 'text-amber-400 animate-pulse'
                    : activeRun.status === 'ERROR'
                    ? 'text-rose-400'
                    : 'text-emerald-400'
                }`}
              />
              <div className="min-w-0">
                <h3 className="text-xs font-semibold text-zinc-100 truncate">
                  Playbook Execution: {activeRun.playbookName}
                </h3>
                <p className="font-mono text-[11px] text-zinc-400 truncate">
                  Target: {activeRun.intelId} · {activeRun.affectedEntity}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border text-[11px] font-mono font-semibold ${
                  activeRun.status === 'RUNNING'
                    ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                    : activeRun.status === 'ERROR'
                    ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
                    : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                }`}
              >
                {activeRun.status === 'RUNNING'
                  ? 'INITIATING PLAYBOOK...'
                  : activeRun.status === 'ERROR'
                  ? 'EXECUTION FAILED'
                  : 'PLAYBOOK COMPLETED · MITIGATED'}
              </span>
              <button
                type="button"
                onClick={() => setActiveRun(null)}
                aria-label="Close playbook console"
                className="p-1 text-zinc-500 hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="p-4 space-y-2.5">
            {activeRun.steps.map((step, idx) => (
              <div
                key={idx}
                className="flex items-start justify-between gap-3 p-2.5 rounded-md bg-zinc-900/50 border border-zinc-800/70 text-xs"
              >
                <div className="flex items-start gap-2.5 min-w-0">
                  {step.state === 'DONE' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : step.state === 'RUNNING' ? (
                    <Clock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5 animate-spin" />
                  ) : (
                    <Clock className="w-4 h-4 text-zinc-600 shrink-0 mt-0.5" />
                  )}
                  <div className="min-w-0">
                    <p
                      className={`font-medium ${
                        step.state === 'PENDING' ? 'text-zinc-500' : 'text-zinc-100'
                      }`}
                    >
                      Step {idx + 1}: {step.label}
                    </p>
                    <p className="text-[11px] text-zinc-400 mt-0.5">
                      {step.detail}
                    </p>
                  </div>
                </div>
                <span className="font-mono text-[10px] tabular-nums text-zinc-500 whitespace-nowrap shrink-0">
                  {step.timestamp ? `${formatShortDateTime(step.timestamp)} WIB` : 'Queued'}
                </span>
              </div>
            ))}

            {activeRun.errorMessage && (
              <p className="text-xs font-mono text-rose-400">
                {activeRun.errorMessage}
              </p>
            )}
          </div>
        </section>
      )}

      {/* SECTION 1: ThreatIntelAlert Playbook Orchestration */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">
              Threat Intelligence Alerts &amp; Automated Playbooks ({filteredAlerts.length})
            </h3>
            {isDemo && (
              <p className="text-xs text-zinc-400 mt-0.5">
                Setiap ThreatIntelAlert berstatus <span className="font-mono text-rose-400">OPEN</span> dengan <span className="font-mono text-zinc-300">recommended_playbook</span> menampilkan tombol aksi <strong className="text-zinc-200">Run Playbook</strong>.
              </p>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <ActionTooltip
              label="Filter Status Alert"
              description="Saring alert berdasarkan status OPEN, MITIGATED, atau FALSE POSITIVE."
            >
              <select
                value={statusFilter}
                onChange={(e) =>
                  setStatusFilter(e.target.value as 'ALL' | ThreatIntelStatus)
                }
                aria-label="Filter ThreatIntelAlert status"
                className="bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs font-mono text-zinc-200"
              >
                <option value="ALL">All Status ({threatIntelAlerts.length})</option>
                <option value="OPEN">OPEN ({openAlertsCount})</option>
                <option value="MITIGATED">MITIGATED ({mitigatedAlertsCount})</option>
                <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
              </select>
            </ActionTooltip>

            <ActionTooltip
              label="Filter Kategori CTI"
              description="Saring berdasarkan Zero-Day CVE, Phishing Domain, atau Credential Leak."
            >
              <select
                value={categoryFilter}
                onChange={(e) =>
                  setCategoryFilter(e.target.value as 'ALL' | ThreatIntelCategory)
                }
                aria-label="Filter ThreatIntelAlert category"
                className="bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs text-zinc-200"
              >
                <option value="ALL">All Categories</option>
                <option value="ZERO_DAY_CVE">Zero-Day CVE</option>
                <option value="PHISHING_DOMAIN">Phishing Domain</option>
                <option value="CREDENTIAL_LEAK">Credential Leak</option>
              </select>
            </ActionTooltip>

            <div className="relative w-52">
              <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search entity, CVE, playbook..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
              />
            </div>
          </div>
        </div>

        {filteredAlerts.length === 0 ? (
          <div className="p-8 text-center text-xs text-zinc-400">
            {threatIntelAlerts.length === 0
              ? 'Synchronizing live Global Open CTI feeds to populate ThreatIntelAlerts...'
              : 'No ThreatIntelAlert entries match your active filters.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-zinc-800/80 bg-zinc-950/60 text-[11px] font-mono text-zinc-400 uppercase tracking-wider">
                  <th className="py-2.5 px-4 whitespace-nowrap">Status</th>
                  <th className="py-2.5 px-4">Threat Alert &amp; Affected Entity</th>
                  <th className="py-2.5 px-4 whitespace-nowrap">Source &amp; Confidence</th>
                  <th className="py-2.5 px-4">Recommended Playbook</th>
                  <th className="py-2.5 px-4 text-right whitespace-nowrap">Playbook Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/70 text-xs">
                {filteredAlerts.map((alert) => {
                  const statusMeta = getIntelStatusMeta(alert.status);
                  const isRunningThis =
                    activeRun?.intelId === alert.intel_id &&
                    activeRun.status === 'RUNNING';
                  const hasPlaybook = Boolean(alert.recommended_playbook?.trim());
                  const lastRun = runHistory[alert.intel_id];

                  return (
                    <tr
                      key={alert.intel_id}
                      className="hover:bg-zinc-900/50 transition-colors"
                    >
                      {/* Semantic Status Badge */}
                      <td className="py-3.5 px-4 align-top whitespace-nowrap">
                        <div className="flex flex-col items-start gap-1">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border text-[11px] font-mono font-semibold ${
                              alert.status === 'OPEN'
                                ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
                                : alert.status === 'MITIGATED'
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                                : 'bg-zinc-800 text-zinc-400 border-zinc-700'
                            }`}
                          >
                            {alert.status === 'OPEN' ? (
                              <ShieldAlert className="w-3 h-3 shrink-0" />
                            ) : alert.status === 'MITIGATED' ? (
                              <CheckCircle2 className="w-3 h-3 shrink-0" />
                            ) : (
                              <Ban className="w-3 h-3 shrink-0" />
                            )}
                            {statusMeta.label}
                          </span>
                          <span className="font-mono text-[10px] text-zinc-500 tabular-nums">
                            {alert.intel_id}
                          </span>
                        </div>
                      </td>

                      {/* Category, Affected Entity & Timestamp */}
                      <td className="py-3.5 px-4 align-top min-w-[240px] max-w-md">
                        <div className="text-[11px] font-mono text-zinc-400">
                          {getIntelCategoryLabel(alert.category)} ·{' '}
                          <span className="tabular-nums">
                            {formatShortDateTime(alert.detected_at)} WIB
                          </span>
                        </div>
                        <div className="text-xs font-semibold text-zinc-100 mt-0.5 break-all">
                          {alert.affected_entity}
                        </div>
                      </td>

                      {/* Source & Confidence */}
                      <td className="py-3.5 px-4 align-top whitespace-nowrap">
                        <div className="text-xs text-zinc-200">{alert.source}</div>
                        <div className="font-mono text-[11px] tabular-nums mt-0.5">
                          Confidence:{' '}
                          <span
                            className={
                              alert.confidence_score >= 90
                                ? 'text-rose-400 font-semibold'
                                : 'text-amber-400 font-semibold'
                            }
                          >
                            {alert.confidence_score}%
                          </span>
                        </div>
                      </td>

                      {/* Recommended Playbook */}
                      <td className="py-3.5 px-4 align-top min-w-[220px] max-w-sm">
                        <div className="font-mono text-[11px] text-emerald-300 leading-snug">
                          {alert.recommended_playbook || '—'}
                        </div>
                        {lastRun?.completedAt && (
                          <div className="text-[10px] font-mono text-zinc-500 mt-1 tabular-nums">
                            Executed {formatShortDateTime(lastRun.completedAt)} WIB
                          </div>
                        )}
                      </td>

                      {/* Run Playbook / Lifecycle Action */}
                      <td className="py-3.5 px-4 align-top text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5">
                          {alert.status === 'OPEN' && hasPlaybook && (
                            <ActionTooltip
                              label="Jalankan Playbook Respons"
                              description={`Memulai simulasi tahapan playbook "${alert.recommended_playbook}" dan mengubah status alert menjadi MITIGATED.`}
                            >
                              <button
                                type="button"
                                disabled={isRunningThis}
                                onClick={() => handleInitiatePlaybook(alert)}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
                              >
                                <Play
                                  className={`w-3.5 h-3.5 ${
                                    isRunningThis ? 'animate-pulse' : ''
                                  }`}
                                />
                                {isRunningThis ? 'Running Playbook...' : 'Run Playbook'}
                              </button>
                            </ActionTooltip>
                          )}

                          {alert.status === 'OPEN' && (
                            <ActionTooltip
                              label="Tandai False Positive"
                              description="Menutup alert ini sebagai temuan tidak berbahaya agar tidak mengganggu antrean OPEN."
                            >
                              <button
                                type="button"
                                onClick={() =>
                                  void onRunPlaybook(alert.intel_id, 'FALSE_POSITIVE')
                                }
                                className="px-2.5 py-1.5 text-[11px] bg-zinc-950 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-800 rounded-md transition-colors cursor-pointer"
                              >
                                False Positive
                              </button>
                            </ActionTooltip>
                          )}

                          {isDemo && onCopyToLive && alert.status === 'MITIGATED' && (
                            <ActionTooltip
                              label="Salin ke Laporan Live"
                              description="Mempromosikan hasil eksekusi playbook Demo ini menjadi catatan insiden di Live Mode."
                              scope="DEMO -> LIVE"
                            >
                              <button
                                type="button"
                                onClick={() =>
                                  onCopyToLive({
                                    sourceLabel: 'Playbook Run',
                                    sourceId: alert.intel_id,
                                    payload: {
                                      title: `Eksekusi Playbook: ${alert.recommended_playbook}`,
                                      affectedUrl: alert.affected_entity,
                                      category:
                                        alert.category === 'PHISHING_DOMAIN'
                                          ? 'PHISHING_IMPERSONATION'
                                          : alert.category === 'CREDENTIAL_LEAK'
                                          ? 'CREDENTIAL_LEAK'
                                          : 'VULNERABILITY_REPORT',
                                      severity:
                                        alert.confidence_score >= 90 ? 'CRITICAL' : 'HIGH',
                                      source: 'INTERNAL_STAFF',
                                      reporterName: 'SOC Analyst (Playbook Practice)',
                                      occurredAt: alert.detected_at,
                                      description: `Hasil latihan eksekusi playbook otomatis untuk alert ${alert.intel_id} (${alert.source}, confidence ${alert.confidence_score}%).`,
                                      evidenceSnippet: `Entity: ${alert.affected_entity} · Playbook: ${alert.recommended_playbook}`,
                                      coordinationNotes: '',
                                      actionTaken: `Playbook ${alert.recommended_playbook} diselesaikan (status MITIGATED).`,
                                      status: 'MITIGATED',
                                      includeInBoardReport: false,
                                    },
                                  })
                                }
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-md transition-colors cursor-pointer"
                              >
                                <CopyCheck className="w-3 h-3" />
                                Salin ke Live
                              </button>
                            </ActionTooltip>
                          )}

                          {alert.status !== 'OPEN' && (
                            <ActionTooltip
                              label="Buka Kembali Alert"
                              description="Mengembalikan status alert ke OPEN untuk investigasi atau eksekusi ulang."
                            >
                              <button
                                type="button"
                                onClick={() => void onRunPlaybook(alert.intel_id, 'OPEN')}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] bg-zinc-950 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md transition-colors cursor-pointer"
                              >
                                <RotateCcw className="w-3 h-3" />
                                Reopen
                              </button>
                            </ActionTooltip>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* SECTION 2: LiveAttackEvent Mitigation Queue */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">
              Live Attack Events &amp; Confirmed Mitigation Queue ({ingestedSiemEvents.length})
            </h3>
            {isDemo && (
              <p className="text-xs text-zinc-400 mt-0.5">
                Event dengan <span className="font-mono text-rose-400">DETECTED</span> atau <span className="font-mono text-amber-400">CHALLENGED</span> menampilkan tombol <strong className="text-zinc-200">Mitigate</strong> dengan konfirmasi sebelum memperbarui status menjadi <span className="font-mono text-emerald-400">MITIGATED</span>.
              </p>
            )}
          </div>
        </div>

        {ingestedSiemEvents.length === 0 ? (
          <div className="p-8 text-center space-y-3">
            <p className="text-xs font-medium text-zinc-200">
              {isDemo
                ? 'Belum ada LiveAttackEvent di antrean Demo'
                : 'Belum ada event masuk dari webhook SIEM eksternal (POST /api/ingest/siem)'}
            </p>
            {isDemo ? (
              <p className="text-xs text-zinc-400 max-w-xl mx-auto leading-relaxed">
                Gunakan tombol <strong className="text-zinc-200">Push SIEM: DETECTED</strong> atau <strong className="text-zinc-200">CHALLENGED</strong> di atas untuk melatih alur konfirmasi <strong className="text-zinc-200">Mitigate</strong>.
              </p>
            ) : (
              <div>
                <ActionTooltip
                  label="Buka Sandbox Demo"
                  description="Pindah ke Demo Mode untuk mencoba alur simulasi webhook SIEM & mitigasi serangan tanpa menyentuh data Live."
                >
                  <button
                    type="button"
                    onClick={() => setMode('DEMO')}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-md transition-colors cursor-pointer"
                  >
                    <Radio className="w-3.5 h-3.5" />
                    Coba di Demo Mode
                  </button>
                </ActionTooltip>
              </div>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-zinc-800/80 bg-zinc-950/60 text-[11px] font-mono text-zinc-400 uppercase tracking-wider">
                  <th className="py-2.5 px-4 whitespace-nowrap">Severity</th>
                  <th className="py-2.5 px-4 whitespace-nowrap">Action Status</th>
                  <th className="py-2.5 px-4">Attack Vector &amp; Payload</th>
                  <th className="py-2.5 px-4 whitespace-nowrap">Source → Target</th>
                  <th className="py-2.5 px-4 whitespace-nowrap">Mitigation Audit</th>
                  <th className="py-2.5 px-4 text-right whitespace-nowrap">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/70 text-xs">
                {ingestedSiemEvents.map((evt) => {
                  const actionMeta = getActionColor(evt.action_taken);
                  const canMitigate =
                    evt.action_taken === 'DETECTED' ||
                    evt.action_taken === 'CHALLENGED';

                  return (
                    <tr
                      key={evt.event_id}
                      className="hover:bg-zinc-900/50 transition-colors"
                    >
                      <td className="py-3.5 px-4 align-top whitespace-nowrap">
                        <div className="flex flex-col items-start gap-1">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border text-[11px] font-mono font-semibold ${getSeverityBadgeStyle(
                              evt.severity
                            )}`}
                          >
                            {evt.severity === 'CRITICAL' ? (
                              <ShieldAlert className="w-3 h-3" />
                            ) : (
                              <AlertTriangle className="w-3 h-3" />
                            )}
                            {evt.severity}
                          </span>
                          <span className="font-mono text-[10px] text-zinc-500 tabular-nums">
                            {evt.event_id}
                          </span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border text-[11px] font-mono font-semibold ${getActionBadgeStyle(
                            evt.action_taken
                          )}`}
                        >
                          {evt.action_taken === 'MITIGATED' ||
                          evt.action_taken === 'BLOCKED_BY_WAF' ? (
                            <CheckCircle2 className="w-3 h-3" />
                          ) : (
                            <AlertTriangle className="w-3 h-3" />
                          )}
                          {actionMeta.label}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 align-top min-w-[220px] max-w-md">
                        <div className="text-xs font-semibold text-zinc-100">
                          {evt.attack_vector}
                        </div>
                        <div className="font-mono text-[11px] text-zinc-400 mt-0.5 break-all">
                          {evt.payload_snippet}
                        </div>
                        <div className="font-mono text-[10px] text-zinc-500 mt-1 tabular-nums">
                          Detected: {formatShortDateTime(evt.timestamp)} WIB
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top whitespace-nowrap font-mono text-[11px]">
                        <div className="text-zinc-200">
                          {evt.source_ip}{' '}
                          <span className="text-zinc-500">({evt.source_country})</span>
                        </div>
                        <div className="text-emerald-400 mt-0.5 truncate max-w-[220px]">
                          → {evt.target_asset}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top whitespace-nowrap font-mono text-[11px]">
                        {evt.action_taken === 'MITIGATED' && evt.mitigated_by ? (
                          <div className="space-y-0.5">
                            <div className="text-emerald-300 font-semibold">
                              {evt.mitigated_by}
                            </div>
                            {evt.mitigated_at && (
                              <div
                                className="text-zinc-400 tabular-nums"
                                title={evt.mitigated_at}
                              >
                                {formatShortDateTime(evt.mitigated_at)} WIB
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-zinc-500">Pending analyst review</span>
                        )}
                      </td>

                      <td className="py-3.5 px-4 align-top text-right whitespace-nowrap">
                        {canMitigate ? (
                          <ActionTooltip
                            label="Mitigasi Attack Event"
                            description="Membuka dialog konfirmasi untuk mengubah action_taken menjadi MITIGATED dengan timestamp & SOC-Analyst-Auto."
                          >
                            <button
                              type="button"
                              onClick={() => setPendingMitigateEvent(evt)}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-rose-600 hover:bg-rose-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                            >
                              <ShieldCheck className="w-3.5 h-3.5" />
                              Mitigate
                            </button>
                          </ActionTooltip>
                        ) : (
                          <div className="inline-flex items-center gap-2">
                            <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              Mitigated
                            </span>
                            {isDemo && onCopyToLive && evt.action_taken === 'MITIGATED' && (
                              <ActionTooltip
                                label="Salin ke Laporan Live"
                                description="Salin hasil mitigasi event serangan Demo ini menjadi laporan insiden di Live Mode."
                                scope="DEMO -> LIVE"
                              >
                                <button
                                  type="button"
                                  onClick={() =>
                                    onCopyToLive({
                                      sourceLabel: 'Attack Mitigation',
                                      sourceId: evt.event_id,
                                      payload: {
                                        title: `Mitigasi ${evt.attack_vector} (${evt.source_ip})`,
                                        affectedUrl: `https://${evt.target_asset}`,
                                        category: 'VULNERABILITY_REPORT',
                                        severity: evt.severity,
                                        source: 'INTERNAL_STAFF',
                                        reporterName: evt.mitigated_by || 'SOC-Analyst-Auto',
                                        occurredAt: evt.timestamp,
                                        description: `Latihan mitigasi event ${evt.attack_vector} dari ${evt.source_ip} (${evt.source_country}) terhadap ${evt.target_asset}.`,
                                        evidenceSnippet: evt.payload_snippet,
                                        coordinationNotes: '',
                                        actionTaken: `Event ${evt.event_id} dimitigasi oleh ${evt.mitigated_by ?? 'SOC-Analyst-Auto'} pada ${evt.mitigated_at ?? evt.timestamp}.`,
                                        status: 'MITIGATED',
                                        includeInBoardReport: false,
                                      },
                                    })
                                  }
                                  className="inline-flex items-center gap-1 px-2 py-1 text-[11px] bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded transition-colors cursor-pointer"
                                >
                                  <CopyCheck className="w-3 h-3" />
                                  Salin ke Live
                                </button>
                              </ActionTooltip>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Confirmation Modal */}
      <AttackEventMitigationModal
        event={pendingMitigateEvent}
        submitting={mitigating}
        onCancel={() => setPendingMitigateEvent(null)}
        onConfirm={(evt, by, at) => void handleConfirmMitigate(evt, by, at)}
      />
    </div>
  );
};
