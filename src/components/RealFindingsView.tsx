import React, { useMemo, useState } from 'react';
import { CheckCircle2, RotateCcw, Radio, ShieldCheck } from 'lucide-react';
import {
  LiveAttackEvent,
  RealFindingStatus,
  RealSecurityFinding,
  Severity,
} from '../types/soc';
import {
  formatShortDateTime,
  getActionColor,
  getSeverityColor,
} from '../utils/socFormatters';
import { AttackEventMitigationModal } from './PlaybookIntegrationView';
import { ActionTooltip } from './ActionTooltip';
import { useSocMode } from '../context/SocModeContext';

interface RealFindingsViewProps {
  findings: RealSecurityFinding[];
  ingestedSiemEvents: LiveAttackEvent[];
  compact?: boolean;
  onUpdateStatus: (findingId: string, status: RealFindingStatus) => void;
  onMitigateEvent?: (
    eventId: string,
    mitigatedBy: string,
    mitigatedAt: string
  ) => Promise<void>;
  onViewAll?: () => void;
}

export const RealFindingsView: React.FC<RealFindingsViewProps> = ({
  findings,
  ingestedSiemEvents,
  compact = false,
  onUpdateStatus,
  onMitigateEvent,
  onViewAll,
}) => {
  const { isDemo, setMode } = useSocMode();
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');
  const [pendingMitigateEvent, setPendingMitigateEvent] =
    useState<LiveAttackEvent | null>(null);
  const [mitigating, setMitigating] = useState(false);

  const filtered = useMemo(() => {
    const list =
      severityFilter === 'ALL'
        ? findings
        : findings.filter((f) => f.severity === severityFilter);
    return compact ? list.slice(0, 5) : list;
  }, [findings, severityFilter, compact]);

  if (compact) {
    return (
      <div className="flex flex-col h-full bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-zinc-800/80">
          <div>
            <h2 className="text-sm font-semibold text-zinc-100">
              Verified Live Security Findings
            </h2>
            {isDemo && (
              <p className="text-xs text-zinc-400 mt-0.5">
                Automatically detected from HTTP, TLS &amp; DNS probes
              </p>
            )}
          </div>
          {onViewAll && (
            <ActionTooltip
              label="Lihat Semua Temuan"
              description="Buka halaman daftar lengkap security findings & SIEM webhook receiver."
            >
              <button
                type="button"
                onClick={onViewAll}
                className="text-xs font-medium text-emerald-400 hover:text-emerald-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                All Findings ({findings.length}) →
              </button>
            </ActionTooltip>
          )}
        </div>

        <div className="flex-1 divide-y divide-zinc-800/70 overflow-y-auto">
          {filtered.length === 0 ? (
            <div className="p-8 text-center text-xs text-emerald-400">
              No active security findings detected across monitored endpoints.
            </div>
          ) : (
            filtered.map((item) => {
              const sev = getSeverityColor(item.severity);
              return (
                <div
                  key={item.finding_id}
                  className="px-4 py-3 flex items-start justify-between gap-3 hover:bg-zinc-900/60 transition-colors"
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className={`font-mono font-semibold ${sev.text}`}>
                        {sev.label}
                      </span>
                      <span className="text-zinc-600">·</span>
                      <span className="font-mono text-[11px] text-zinc-400">
                        {item.category}
                      </span>
                      <span className="text-zinc-600">·</span>
                      <span
                        className={`font-mono text-[11px] ${
                          item.status === 'ACKNOWLEDGED'
                            ? 'text-emerald-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {item.status}
                      </span>
                    </div>
                    <p className="text-xs font-medium text-zinc-100">
                      {item.title}
                    </p>
                    <p className="font-mono text-[11px] text-zinc-400 truncate">
                      {item.target}
                    </p>
                  </div>

                  {item.status === 'OPEN' && (
                    <ActionTooltip
                      label="Acknowledge Finding"
                      description="Tandai temuan ini sudah diketahui dan sedang ditangani tim TI."
                    >
                      <button
                        type="button"
                        onClick={() =>
                          onUpdateStatus(item.finding_id, 'ACKNOWLEDGED')
                        }
                        className="px-2.5 py-1 text-[11px] font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Acknowledge
                      </button>
                    </ActionTooltip>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Filter Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-zinc-900/40 border border-zinc-800/80 rounded-lg">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">
            Verified Passive Security Findings ({findings.length})
          </h2>
          {isDemo && (
            <p className="text-xs text-zinc-400 mt-0.5">
              Every finding below is derived from HTTP headers, TLS handshakes, and DNS lookups
            </p>
          )}
        </div>

        <div
          className="flex items-center gap-1 p-0.5 bg-zinc-950 border border-zinc-800 rounded-md"
          role="group"
          aria-label="Filter findings by severity"
        >
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((lvl) => (
            <ActionTooltip
              key={lvl}
              label={`Filter ${lvl}`}
              description={
                lvl === 'ALL'
                  ? 'Tampilkan seluruh tingkat severity.'
                  : `Tampilkan hanya temuan dengan tingkat ${lvl}.`
              }
            >
              <button
                type="button"
                onClick={() => setSeverityFilter(lvl)}
                className={`px-2.5 py-1.5 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  severityFilter === lvl
                    ? 'bg-zinc-800 text-zinc-100'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {lvl === 'ALL' ? 'All' : lvl}
              </button>
            </ActionTooltip>
          ))}
        </div>
      </div>

      {/* Findings List */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg divide-y divide-zinc-800/80">
        {filtered.length === 0 ? (
          <div className="p-10 text-center text-xs text-zinc-400">
            No findings matching the selected severity filter.
          </div>
        ) : (
          filtered.map((item) => {
            const sev = getSeverityColor(item.severity);
            return (
              <div
                key={item.finding_id}
                className="p-5 flex flex-col lg:flex-row lg:items-start justify-between gap-4 hover:bg-zinc-900/60 transition-colors"
              >
                <div className="space-y-2 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs">
                    <span className={`font-mono font-semibold ${sev.text}`}>
                      {sev.label}
                    </span>
                    <span className="text-zinc-600">·</span>
                    <span className="font-mono text-zinc-300">
                      {item.finding_id}
                    </span>
                    <span className="text-zinc-600">·</span>
                    <span className="font-mono text-zinc-400">
                      {item.category}
                    </span>
                    <span className="text-zinc-600">·</span>
                    <span
                      className={`font-mono font-semibold ${
                        item.status === 'ACKNOWLEDGED'
                          ? 'text-emerald-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {item.status}
                    </span>
                    <span className="text-zinc-600">·</span>
                    <span className="font-mono text-zinc-500 tabular-nums">
                      {formatShortDateTime(item.detected_at)} WIB
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-zinc-100">
                    {item.title}
                  </h3>

                  <p className="font-mono text-xs text-emerald-300/90 break-all">
                    Target: {item.target}
                  </p>

                  <div className="p-3 bg-zinc-950 border border-zinc-800/80 rounded-md text-xs space-y-1">
                    <p className="font-mono text-[11px] text-amber-200/90 break-all">
                      Evidence: {item.evidence}
                    </p>
                    <p className="text-zinc-400">
                      <span className="text-zinc-300 font-medium">Remediation: </span>
                      {item.remediation}
                    </p>
                  </div>
                </div>

                <div className="shrink-0">
                  {item.status === 'OPEN' ? (
                    <ActionTooltip
                      label="Acknowledge Finding"
                      description="Ubah status temuan dari OPEN menjadi ACKNOWLEDGED."
                    >
                      <button
                        type="button"
                        onClick={() =>
                          onUpdateStatus(item.finding_id, 'ACKNOWLEDGED')
                        }
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Acknowledge Finding
                      </button>
                    </ActionTooltip>
                  ) : (
                    <ActionTooltip
                      label="Buka Kembali Temuan"
                      description="Kembalikan status temuan ini menjadi OPEN untuk tindak lanjut ulang."
                    >
                      <button
                        type="button"
                        onClick={() => onUpdateStatus(item.finding_id, 'OPEN')}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        Reopen
                      </button>
                    </ActionTooltip>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Real External SIEM / WAF Webhook Inbox (Zero Simulated Data) */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-emerald-400" />
            <div>
              <h2 className="text-sm font-semibold text-zinc-100">
                External SIEM / WAF Webhook Receiver (Real Push Only)
              </h2>
              <p className="text-xs text-zinc-400 mt-0.5 font-mono">
                Endpoint: POST /api/ingest/siem
              </p>
            </div>
          </div>
          <span className="font-mono text-xs text-zinc-400 tabular-nums">
            {ingestedSiemEvents.length} real event(s)
          </span>
        </div>

        {ingestedSiemEvents.length === 0 ? (
          <div className="p-8 text-center space-y-2.5">
            <p className="text-xs font-medium text-zinc-300">
              0 External SIEM/WAF Events Received
            </p>
            {isDemo ? (
              <p className="text-xs text-zinc-500 max-w-xl mx-auto">
                When internal IT connects Wazuh, Cloudflare Logpush, or Imperva WAF webhooks to{' '}
                <span className="font-mono text-zinc-300">POST /api/ingest/siem</span>, real intrusion alerts will stream here automatically.
              </p>
            ) : (
              <div>
                <ActionTooltip
                  label="Latihan di Demo Mode"
                  description="Buka Demo Mode untuk melihat simulasi alert SIEM/WAF dan alur mitigasi."
                >
                  <button
                    type="button"
                    onClick={() => setMode('DEMO')}
                    className="px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-amber-300 border border-amber-500/40 rounded-md transition-colors cursor-pointer"
                  >
                    Coba di Demo Mode
                  </button>
                </ActionTooltip>
              </div>
            )}
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/70 text-xs">
            {ingestedSiemEvents.map((evt) => {
              const actionMeta = getActionColor(evt.action_taken);
              const canMitigate =
                evt.action_taken === 'DETECTED' ||
                evt.action_taken === 'CHALLENGED';
              return (
                <div
                  key={evt.event_id}
                  className="px-4 py-3 flex flex-wrap items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="font-mono flex flex-wrap items-center gap-x-2 gap-y-0.5">
                      <span
                        className={
                          getSeverityColor(evt.severity).text + ' font-semibold'
                        }
                      >
                        {evt.severity}
                      </span>
                      <span className="text-zinc-200">{evt.event_id}</span>
                      <span className="text-zinc-400">{evt.source_ip}</span>
                      <span className="text-zinc-300">{evt.attack_vector}</span>
                      <span className="text-zinc-600">·</span>
                      <span className={`font-semibold ${actionMeta.text}`}>
                        {actionMeta.label}
                      </span>
                    </div>
                    {evt.action_taken === 'MITIGATED' && evt.mitigated_by && (
                      <div className="font-mono text-[11px] text-emerald-400">
                        Mitigated by {evt.mitigated_by}
                        {evt.mitigated_at
                          ? ` · ${formatShortDateTime(evt.mitigated_at)} WIB`
                          : ''}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2.5 shrink-0">
                    <span className="font-mono text-[11px] text-zinc-500">
                      {formatShortDateTime(evt.timestamp)} WIB
                    </span>
                    {canMitigate && onMitigateEvent && (
                      <ActionTooltip
                        label="Mitigasi Attack Event"
                        description="Konfirmasi mitigasi event SIEM ini dan catat timestamp serta operator."
                      >
                        <button
                          type="button"
                          onClick={() => setPendingMitigateEvent(evt)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium bg-rose-600 hover:bg-rose-500 text-white rounded transition-colors cursor-pointer"
                        >
                          <ShieldCheck className="w-3 h-3" />
                          Mitigate
                        </button>
                      </ActionTooltip>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {onMitigateEvent && (
        <AttackEventMitigationModal
          event={pendingMitigateEvent}
          submitting={mitigating}
          onCancel={() => setPendingMitigateEvent(null)}
          onConfirm={(evt, by, at) => {
            setMitigating(true);
            void onMitigateEvent(evt.event_id, by, at).finally(() => {
              setMitigating(false);
              setPendingMitigateEvent(null);
            });
          }}
        />
      )}
    </div>
  );
};
