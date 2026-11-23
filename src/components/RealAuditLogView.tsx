import React, { useMemo, useState } from 'react';
import { Download, Search, Clock, Check } from 'lucide-react';
import {
  RealProbeLogEntry,
  RealSecurityFinding,
} from '../types/soc';
import { exportToCSV, formatShortDateTime } from '../utils/socFormatters';
import { useSocMode } from '../context/SocModeContext';
import { ActionTooltip } from './ActionTooltip';

interface RealAuditLogViewProps {
  probeLogs: RealProbeLogEntry[];
  findings: RealSecurityFinding[];
  probeIntervalMs: number;
  connectedAnalysts: number;
  onUpdateInterval: (ms: number) => void;
  onExportComplianceJson: () => void;
}

export const RealAuditLogView: React.FC<RealAuditLogViewProps> = ({
  probeLogs,
  findings,
  probeIntervalMs,
  connectedAnalysts,
  onUpdateInterval,
  onExportComplianceJson,
}) => {
  const { isDemo } = useSocMode();
  const [search, setSearch] = useState('');
  const [exportedAudit, setExportedAudit] = useState(false);

  const filteredLogs = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return probeLogs;
    return probeLogs.filter(
      (l) =>
        l.id.toLowerCase().includes(q) ||
        l.actor.toLowerCase().includes(q) ||
        l.check_type.toLowerCase().includes(q) ||
        l.target.toLowerCase().includes(q) ||
        l.result.toLowerCase().includes(q)
    );
  }, [probeLogs, search]);

  const handleExportAuditCsv = () => {
    exportToCSV(
      probeLogs,
      `soc-real-audit-log-${new Date().toISOString().slice(0, 10)}.csv`
    );
    setExportedAudit(true);
    setTimeout(() => setExportedAudit(false), 2200);
  };

  const handleExportFindingsCsv = () => {
    exportToCSV(
      findings,
      `soc-real-security-findings-${new Date().toISOString().slice(0, 10)}.csv`
    );
  };

  return (
    <div className="space-y-5">
      {/* Dedicated Header with Export Audit CSV */}
      <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4 bg-zinc-900/40 border border-zinc-800/80 rounded-lg">
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-zinc-100">
            Real Telemetry Audit Log &amp; Compliance Export
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5 font-mono tabular-nums">
            {probeLogs.length} probe &amp; analyst records · {connectedAnalysts}{' '}
            connected session{connectedAnalysts === 1 ? '' : 's'} ·{' '}
            {isDemo ? 'Demo Sandbox Mode' : 'Live Mode'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ActionTooltip
            label="Export Audit CSV"
            description="Unduh seluruh log probe & aktivitas analis dalam format CSV untuk arsip audit."
            scope={isDemo ? 'DEMO' : 'LIVE'}
          >
            <button
              type="button"
              onClick={handleExportAuditCsv}
              disabled={probeLogs.length === 0}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              {exportedAudit ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  Audit CSV Exported
                </>
              ) : (
                <>
                  <Download className="w-3.5 h-3.5" />
                  Export Audit CSV
                </>
              )}
            </button>
          </ActionTooltip>

          <ActionTooltip
            label="Export Findings CSV"
            description="Unduh daftar temuan keamanan saat ini ke berkas CSV."
            scope={isDemo ? 'DEMO' : 'LIVE'}
          >
            <button
              type="button"
              onClick={handleExportFindingsCsv}
              disabled={findings.length === 0}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              Findings CSV
            </button>
          </ActionTooltip>

          <ActionTooltip
            label="Export Compliance JSON"
            description="Unduh snapshot kepatuhan & telemetri terstruktur dalam format JSON."
            scope={isDemo ? 'DEMO' : 'LIVE'}
          >
            <button
              type="button"
              onClick={onExportComplianceJson}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              Compliance JSON
            </button>
          </ActionTooltip>
        </div>
      </div>

      {/* Probe Cadence & Search Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-zinc-900/40 border border-zinc-800/80 rounded-lg">
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter real probe logs by target, status, or result..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-zinc-950 border border-zinc-800 rounded-md text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
          />
        </div>

        <div className="flex items-center gap-2 text-xs">
          <Clock className="w-3.5 h-3.5 text-zinc-400" />
          <span className="text-zinc-400">Live Probe Cadence:</span>
          <div className="flex items-center gap-1 p-0.5 bg-zinc-950 border border-zinc-800 rounded-md">
            {[10000, 15000, 30000, 60000].map((ms) => (
              <ActionTooltip
                key={ms}
                label={`Interval Probe ${ms / 1000} detik`}
                description={`Atur frekuensi pemeriksaan HTTP/TLS otomatis menjadi setiap ${ms / 1000} detik.`}
                scope={isDemo ? 'DEMO' : 'LIVE'}
              >
                <button
                  type="button"
                  onClick={() => onUpdateInterval(ms)}
                  className={`px-2.5 py-1 font-mono text-[11px] rounded transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                    probeIntervalMs === ms
                      ? 'bg-zinc-800 text-zinc-100'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  {ms / 1000}s
                </button>
              </ActionTooltip>
            ))}
          </div>
        </div>
      </div>

      {/* Chronological Real Probe Ledger */}
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-950/60 text-[11px] font-medium text-zinc-400">
                <th className="py-2.5 px-4 whitespace-nowrap">Log ID</th>
                <th className="py-2.5 px-4 whitespace-nowrap">Timestamp (WIB)</th>
                <th className="py-2.5 px-4 whitespace-nowrap">Type</th>
                <th className="py-2.5 px-4 whitespace-nowrap">Target</th>
                <th className="py-2.5 px-4 whitespace-nowrap">Status / Latency</th>
                <th className="py-2.5 px-4">Verified Observation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/70 text-xs">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-zinc-500">
                    Waiting for real probe log entries...
                  </td>
                </tr>
              ) : (
                filteredLogs.map((entry) => (
                  <tr
                    key={entry.id}
                    className="hover:bg-zinc-900/60 transition-colors"
                  >
                    <td className="py-2.5 px-4 font-mono text-zinc-300 whitespace-nowrap">
                      {entry.id}
                    </td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-zinc-400 whitespace-nowrap">
                      {formatShortDateTime(entry.timestamp)}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[11px] text-emerald-400 whitespace-nowrap">
                      {entry.check_type}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[11px] text-zinc-300 max-w-[260px] truncate">
                      {entry.target}
                    </td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-zinc-200 whitespace-nowrap">
                      {entry.http_status}
                      {entry.latency_ms !== '-' ? ` · ${entry.latency_ms}` : ''}
                    </td>
                    <td className="py-2.5 px-4 text-zinc-300">{entry.result}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
