import React, { useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell,
} from 'recharts';
import {
  Cpu,
  HardDrive,
  RefreshCw,
  Download,
  Settings,
  ShieldCheck,
  ShieldAlert,
  FileSearch,
  Network,
  CheckCircle2,
  AlertTriangle,
  Search,
  Terminal,
} from 'lucide-react';
import { LocalWazuhSnapshot } from '../types/soc';
import { ActionTooltip } from './ActionTooltip';
import { useSocMode } from '../context/SocModeContext';
import {
  exportToCSV,
  formatShortDateTime,
  getSeverityColor,
} from '../utils/socFormatters';

interface LocalWazuhDashboardViewProps {
  localWazuh: LocalWazuhSnapshot | null;
  scanning: boolean;
  onRunScan: () => void;
  onAcceptBaseline: () => void;
  onOpenConfig: () => void;
}

type WazuhTab = 'events' | 'fim' | 'sca' | 'ports-logs';

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const LocalWazuhDashboardView: React.FC<LocalWazuhDashboardViewProps> = ({
  localWazuh,
  scanning,
  onRunScan,
  onAcceptBaseline,
  onOpenConfig,
}) => {
  const { isDemo } = useSocMode();
  const [activeTab, setActiveTab] = useState<WazuhTab>('events');
  const [search, setSearch] = useState('');

  const q = search.trim().toLowerCase();

  const filteredAlerts = useMemo(() => {
    const list = localWazuh?.alerts ?? [];
    if (!q) return list;
    return list.filter(
      (a) =>
        a.rule_id.toLowerCase().includes(q) ||
        a.title.toLowerCase().includes(q) ||
        a.mitre_id.toLowerCase().includes(q) ||
        a.mitre_tactic.toLowerCase().includes(q) ||
        a.source.toLowerCase().includes(q) ||
        a.target.toLowerCase().includes(q)
    );
  }, [localWazuh, q]);

  const handleExportWazuhCsv = () => {
    if (!localWazuh) return;
    const dateStamp = new Date().toISOString().slice(0, 10);
    if (activeTab === 'fim') {
      exportToCSV(
        localWazuh.fim.entries.map((e) => ({
          path: e.path,
          status: e.status,
          sha256: e.sha256 ?? '',
          baseline_sha256: e.baselineSha256 ?? '',
          permissions: e.permissions ?? '',
          size_bytes: e.sizeBytes ?? '',
          modified_at: e.modifiedAt ?? '',
          note: e.note ?? '',
        })),
        `soc-local-fim-${dateStamp}.csv`
      );
    } else if (activeTab === 'sca') {
      exportToCSV(
        localWazuh.sca.checks.map((c) => ({
          id: c.id,
          cis_control: c.cisControl,
          category: c.category,
          status: c.status,
          severity: c.severity,
          title: c.title,
          evidence: c.evidence,
          remediation: c.remediation,
        })),
        `soc-local-sca-cis-${dateStamp}.csv`
      );
    } else {
      exportToCSV(
        localWazuh.alerts.map((a) => ({
          alert_id: a.alert_id,
          timestamp: a.timestamp,
          agent: a.agent_name,
          rule_id: a.rule_id,
          rule_level: a.rule_level,
          severity: a.severity,
          mitre_id: a.mitre_id,
          mitre_tactic: a.mitre_tactic,
          source: a.source,
          title: a.title,
          target: a.target,
          detail: a.detail,
        })),
        `soc-local-siem-alerts-${dateStamp}.csv`
      );
    }
  };

  if (!localWazuh || !localWazuh.host) {
    return (
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-10 text-center text-xs font-mono text-zinc-400">
        Menginisialisasi Local Host SIEM / XDR Sensor...
      </div>
    );
  }

  const { host, config, fim, sca, network, logSourcesStatus, alerts } =
    localWazuh;

  const primaryLocalIp =
    host.interfaces.find((i) => i.family === 'IPv4' && i.address !== '127.0.0.1')
      ?.address ?? '127.0.0.1';

  const histogramColors = ['#10b981', '#f59e0b', '#f97316', '#f43f5e'];

  return (
    <div className="space-y-5">
      {/* Wazuh-Style Active Agent Header */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div className="space-y-1.5 min-w-0">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-semibold text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              AGENT ACTIVE
            </span>
            <span className="text-zinc-700">·</span>
            <h2 className="text-sm font-semibold text-zinc-100 font-mono">
              {config.agentName}
            </h2>
            <span className="text-zinc-700">·</span>
            <span className="text-xs font-mono text-zinc-400">
              Group: {config.clusterGroup}
            </span>
            <span className="text-zinc-700">·</span>
            <span className="text-xs font-mono text-zinc-400">
              Env: {config.environment}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-zinc-400">
            <span>
              OS: <strong className="text-zinc-200">{host.platform} {host.osRelease} ({host.arch})</strong>
            </span>
            <span>
              IP: <strong className="text-zinc-200">{primaryLocalIp}</strong>
            </span>
            <span>
              CPU: <strong className="text-zinc-200">{host.cpuCores} cores · Load {host.loadAvg1m}</strong>
            </span>
            <span>
              RAM: <strong className="text-zinc-200">{host.memUsedMb}/{host.memTotalMb} MB ({host.memUsagePercent}%)</strong>
            </span>
            <span>
              Uptime: <strong className="text-zinc-200">{formatUptime(host.uptimeSeconds)}</strong>
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ActionTooltip
            label="Konfigurasi Local Agent"
            description="Atur path log Nginx/Linux, daftar file FIM SHA-256, whitelist port, dan ambang batas alert."
          >
            <button
              type="button"
              onClick={onOpenConfig}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Settings className="w-3.5 h-3.5 text-zinc-400" />
              Local Agent Config
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Ekspor CSV Tab Aktif"
            description="Unduh data Security Events, FIM, atau SCA CIS dalam format CSV."
          >
            <button
              type="button"
              onClick={handleExportWazuhCsv}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-zinc-400" />
              Export CSV
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Jalankan Full Host Scan"
            description="Pindai ulang FIM SHA-256, audit CIS Linux, port jaringan, dan kolektor log lokal."
          >
            <button
              type="button"
              disabled={scanning}
              onClick={onRunScan}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
              {scanning ? 'Scanning Host...' : 'Run Full Host Scan'}
            </button>
          </ActionTooltip>
        </div>
      </section>

      {/* 4-Column Wazuh XDR KPI Strip */}
      <section className="grid grid-cols-2 xl:grid-cols-4 divide-y xl:divide-y-0 xl:divide-x divide-zinc-800/80 bg-zinc-900/40 border border-zinc-800/80 rounded-lg">
        <div className="p-4">
          <p className="text-xs text-zinc-400">SCA (CIS Linux Compliance)</p>
          <div className="mt-1.5 flex items-baseline gap-2.5 font-mono tabular-nums">
            <span
              className={`text-2xl font-semibold ${
                sca.scorePercent >= 80
                  ? 'text-emerald-400'
                  : sca.scorePercent >= 60
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {sca.scorePercent}%
            </span>
            <span className="text-xs text-zinc-400">
              {sca.passed} Pass · {sca.failed} Fail
            </span>
          </div>
          {isDemo && (
            <p className="mt-1 text-[11px] text-zinc-500">
              OS permissions, sysctl &amp; SSH audit
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">FIM (File Integrity SHA-256)</p>
          <div className="mt-1.5 flex items-baseline gap-2.5 font-mono tabular-nums">
            <span
              className={`text-2xl font-semibold ${
                fim.modifiedCount > 0 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {fim.okCount}/{fim.totalMonitored}
            </span>
            <span className="text-xs text-zinc-400">
              {fim.modifiedCount} modified
            </span>
          </div>
          {isDemo && (
            <p className="mt-1 text-[11px] text-zinc-500">
              Cryptographic baseline verification
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">
            Active Rule Alerts (Level ≥ {config.alertLevelThreshold})
          </p>
          <div className="mt-1.5 flex items-baseline gap-2.5 font-mono tabular-nums">
            <span
              className={`text-2xl font-semibold ${
                alerts.some((a) => a.rule_level >= 12)
                  ? 'text-rose-400'
                  : alerts.length > 0
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {alerts.length}
            </span>
            <span className="text-xs text-zinc-400">
              {localWazuh.mitreBreakdown.length} MITRE tactic(s)
            </span>
          </div>
          {isDemo && (
            <p className="mt-1 text-[11px] text-zinc-500">
              FIM + SCA + Logcollector + HTTP Sensor
            </p>
          )}
        </div>

        <div className="p-4">
          <p className="text-xs text-zinc-400">Host Network (/proc/net/tcp)</p>
          <div className="mt-1.5 flex items-baseline gap-2.5 font-mono tabular-nums">
            <span
              className={`text-2xl font-semibold ${
                network.unexpectedPortCount > 0
                  ? 'text-amber-400'
                  : 'text-zinc-100'
              }`}
            >
              {network.listeningPorts.length} Ports
            </span>
            <span className="text-xs text-zinc-400">
              {network.establishedCount} Estab
            </span>
          </div>
          {isDemo && (
            <p className="mt-1 text-[11px] text-zinc-500">
              {network.unexpectedPortCount === 0
                ? 'All open ports match local whitelist'
                : `${network.unexpectedPortCount} port(s) outside whitelist`}
            </p>
          )}
        </div>
      </section>

      {/* Wazuh Analytics Split: Rule Level Distribution (7 cols) + MITRE & Host Telemetry (5 cols) */}
      <section className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch">
        <div className="xl:col-span-7 bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col">
          <div className="flex items-center justify-between gap-2 mb-3">
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">
                Wazuh Rule Severity Distribution (Level 1–15)
              </h3>
              {isDemo && (
                <p className="text-xs text-zinc-400">
                  Count of local host security alerts grouped by Wazuh rule level
                </p>
              )}
            </div>
            {localWazuh.lastScannedAt && (
              <span className="font-mono text-[11px] text-zinc-500">
                Scan: {formatShortDateTime(localWazuh.lastScannedAt)} ({localWazuh.scanDurationMs} ms)
              </span>
            )}
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={localWazuh.ruleLevelHistogram}
                margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                <XAxis
                  dataKey="level"
                  tick={{ fill: '#a1a1aa', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                  axisLine={{ stroke: '#3f3f46' }}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: '#71717a', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  contentStyle={{
                    backgroundColor: '#09090b',
                    borderColor: '#27272a',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontFamily: 'IBM Plex Mono',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={54}>
                  {localWazuh.ruleLevelHistogram.map((entry, idx) => (
                    <Cell
                      key={entry.level}
                      fill={histogramColors[idx % histogramColors.length]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="xl:col-span-5 bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">
              MITRE ATT&amp;CK Tactics &amp; Local Host Telemetry
            </h3>
            {isDemo && (
              <p className="text-xs text-zinc-400 mt-0.5">
                Host resource pressure &amp; active rule tactic mapping
              </p>
            )}
          </div>

          {/* Real RAM & Load Bars */}
          <div className="space-y-3">
            <div>
              <div className="flex items-center justify-between text-[11px] font-mono mb-1">
                <span className="flex items-center gap-1.5 text-zinc-300">
                  <HardDrive className="w-3.5 h-3.5 text-zinc-400" />
                  Memory Utilization
                </span>
                <span className="text-zinc-200 tabular-nums">
                  {host.memUsedMb} / {host.memTotalMb} MB ({host.memUsagePercent}%)
                </span>
              </div>
              <div className="h-2 bg-zinc-950 border border-zinc-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all ${
                    host.memUsagePercent > 85
                      ? 'bg-rose-500'
                      : host.memUsagePercent > 70
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(100, host.memUsagePercent)}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between text-[11px] font-mono mb-1">
                <span className="flex items-center gap-1.5 text-zinc-300">
                  <Cpu className="w-3.5 h-3.5 text-zinc-400" />
                  CPU Load Average (1m / 5m / 15m)
                </span>
                <span className="text-zinc-200 tabular-nums">
                  {host.loadAvg1m} · {host.loadAvg5m} · {host.loadAvg15m}
                </span>
              </div>
              <div className="h-2 bg-zinc-950 border border-zinc-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-sky-500 transition-all"
                  style={{
                    width: `${Math.min(
                      100,
                      Math.round((host.loadAvg1m / Math.max(1, host.cpuCores)) * 100)
                    )}%`,
                  }}
                />
              </div>
            </div>
          </div>

          {/* MITRE Tactics Breakdown */}
          <div className="border-t border-zinc-800/80 pt-3">
            <p className="text-[11px] font-mono uppercase text-zinc-500 mb-2">
              Detected MITRE ATT&amp;CK Tactics
            </p>
            {localWazuh.mitreBreakdown.length === 0 ? (
              <p className="text-xs text-emerald-400 font-mono">
                0 active rule alerts — host posture nominal
              </p>
            ) : (
              <div className="space-y-1.5">
                {localWazuh.mitreBreakdown.slice(0, 4).map((m) => (
                  <div
                    key={m.tactic}
                    className="flex items-center justify-between text-xs"
                  >
                    <span className="text-zinc-300">{m.tactic}</span>
                    <span className="font-mono text-amber-400 font-semibold tabular-nums">
                      {m.count}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Main Wazuh Module Workspace Tabs */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center gap-1 overflow-x-auto pb-1 lg:pb-0">
            {[
              {
                id: 'events' as const,
                label: `Security Events (${alerts.length})`,
                desc: 'Daftar alert rule lokal beserta pemetaan MITRE ATT&CK.',
                icon: ShieldAlert,
              },
              {
                id: 'fim' as const,
                label: `FIM Integrity (${fim.totalMonitored})`,
                desc: 'Status hash SHA-256 berkas sistem & aplikasi terpantau.',
                icon: FileSearch,
              },
              {
                id: 'sca' as const,
                label: `SCA Benchmark (${sca.scorePercent}%)`,
                desc: 'Hasil audit konfigurasi keamanan OS berbasis CIS Linux.',
                icon: ShieldCheck,
              },
              {
                id: 'ports-logs' as const,
                label: `Ports & Log Collectors (${network.listeningPorts.length})`,
                desc: 'Daftar port TCP listening aktif dan status akses file log lokal.',
                icon: Network,
              },
            ].map((tab) => {
              const Icon = tab.icon;
              const active = activeTab === tab.id;
              return (
                <ActionTooltip key={tab.id} label={tab.label} description={tab.desc}>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveTab(tab.id);
                      setSearch('');
                    }}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                      active
                        ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                        : 'text-zinc-400 hover:text-zinc-200 border border-transparent'
                    }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    {tab.label}
                  </button>
                </ActionTooltip>
              );
            })}
          </div>

          {activeTab === 'events' && (
            <div className="relative w-full lg:w-64 shrink-0">
              <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter Rule ID, MITRE, source..."
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
              />
            </div>
          )}

          {activeTab === 'fim' && (
            <ActionTooltip
              label="Accept Baseline SHA-256"
              description="Tetapkan hash file saat ini sebagai baseline resmi agar perubahan yang disetujui tidak memicu alert FIM."
            >
              <button
                type="button"
                onClick={onAcceptBaseline}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-emerald-400 border border-emerald-500/30 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                Accept Current SHA-256 Baseline
              </button>
            </ActionTooltip>
          )}
        </div>

        {/* TAB 1: SECURITY EVENTS */}
        {activeTab === 'events' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400 uppercase bg-zinc-950/60">
                  <th className="py-2.5 px-4">Rule / Level</th>
                  <th className="py-2.5 px-4">MITRE ATT&amp;CK</th>
                  <th className="py-2.5 px-4">Module</th>
                  <th className="py-2.5 px-4">Description &amp; Evidence</th>
                  <th className="py-2.5 px-4">Target</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 text-xs">
                {filteredAlerts.map((a) => {
                  const sev = getSeverityColor(a.severity);
                  return (
                    <tr
                      key={a.alert_id}
                      className="hover:bg-zinc-900/60 transition-colors"
                    >
                      <td className="py-3 px-4 font-mono whitespace-nowrap align-top">
                        <div className={`font-semibold ${sev.text}`}>
                          Rule {a.rule_id} · L{a.rule_level}
                        </div>
                        <div className="text-[10px] text-zinc-500 mt-0.5">
                          {formatShortDateTime(a.timestamp)}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] whitespace-nowrap align-top">
                        <div className="text-zinc-200">{a.mitre_id}</div>
                        <div className="text-zinc-500">{a.mitre_tactic}</div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-zinc-300 whitespace-nowrap align-top">
                        {a.source}
                      </td>
                      <td className="py-3 px-4 align-top max-w-xl">
                        <div className="font-medium text-zinc-100">{a.title}</div>
                        <p className="text-[11px] font-mono text-zinc-400 mt-0.5 break-all">
                          {a.detail}
                        </p>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-emerald-300/90 align-top max-w-[200px] truncate">
                        {a.target}
                      </td>
                    </tr>
                  );
                })}
                {filteredAlerts.length === 0 && (
                  <tr>
                    <td
                      colSpan={5}
                      className="py-10 text-center text-xs text-emerald-400 font-mono"
                    >
                      0 active local rule alerts matching threshold Level ≥{' '}
                      {config.alertLevelThreshold}.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB 2: FIM (FILE INTEGRITY MONITORING) */}
        {activeTab === 'fim' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400 uppercase bg-zinc-950/60">
                  <th className="py-2.5 px-4">Monitored File Path</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Mode / Size</th>
                  <th className="py-2.5 px-4">Live SHA-256 Digest</th>
                  <th className="py-2.5 px-4">Modified</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60 text-xs">
                {fim.entries.map((entry) => {
                  const tone =
                    entry.status === 'BASELINE_OK'
                      ? 'text-emerald-400'
                      : entry.status === 'MODIFIED' || entry.status === 'DELETED'
                      ? 'text-rose-400 font-semibold'
                      : entry.status === 'ADDED'
                      ? 'text-sky-400'
                      : 'text-zinc-500';
                  return (
                    <tr
                      key={entry.path}
                      className="hover:bg-zinc-900/60 transition-colors"
                    >
                      <td className="py-2.5 px-4 font-mono text-zinc-100">
                        <div>{entry.path}</div>
                        {entry.note && (
                          <div className="text-[11px] text-amber-400 mt-0.5">
                            {entry.note}
                          </div>
                        )}
                      </td>
                      <td className={`py-2.5 px-4 font-mono text-[11px] whitespace-nowrap ${tone}`}>
                        {entry.status}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-[11px] text-zinc-300 whitespace-nowrap">
                        {entry.permissions ?? '—'} · {formatBytes(entry.sizeBytes)}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-[11px] text-zinc-400">
                        {entry.sha256 ? `${entry.sha256.slice(0, 24)}…` : '—'}
                      </td>
                      <td className="py-2.5 px-4 font-mono text-[11px] text-zinc-400 whitespace-nowrap">
                        {entry.modifiedAt
                          ? formatShortDateTime(entry.modifiedAt)
                          : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB 3: SCA (SECURITY CONFIGURATION ASSESSMENT) */}
        {activeTab === 'sca' && (
          <div className="divide-y divide-zinc-800/70">
            {sca.checks.map((chk) => {
              const statusTone =
                chk.status === 'PASS'
                  ? 'text-emerald-400'
                  : chk.status === 'FAIL'
                  ? 'text-rose-400'
                  : 'text-zinc-500';
              return (
                <div
                  key={chk.id}
                  className="p-4 flex flex-col lg:flex-row lg:items-start justify-between gap-3 hover:bg-zinc-900/60"
                >
                  <div className="space-y-1.5 min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                      <span className={`font-semibold ${statusTone}`}>
                        {chk.status}
                      </span>
                      <span className="text-zinc-700">·</span>
                      <span className="text-zinc-300">{chk.cisControl}</span>
                      <span className="text-zinc-700">·</span>
                      <span className="text-zinc-500">{chk.category}</span>
                      <span className="text-zinc-700">·</span>
                      <span className={getSeverityColor(chk.severity).text}>
                        {chk.severity}
                      </span>
                    </div>
                    <p className="text-xs font-semibold text-zinc-100">
                      {chk.title}
                    </p>
                    <p className="font-mono text-[11px] text-zinc-400">
                      Evidence: {chk.evidence}
                    </p>
                    {chk.status === 'FAIL' && (
                      <p className="text-[11px] text-amber-300/90 bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 font-mono">
                        Remediation: {chk.remediation}
                      </p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* TAB 4: LISTENING PORTS & LOG COLLECTOR SOURCES */}
        {activeTab === 'ports-logs' && (
          <div className="grid grid-cols-1 xl:grid-cols-12 divide-y xl:divide-y-0 xl:divide-x divide-zinc-800/80">
            <div className="xl:col-span-6">
              <div className="px-4 py-2.5 bg-zinc-950/60 border-b border-zinc-800/60 flex items-center justify-between text-xs">
                <span className="font-medium text-zinc-200">
                  Real Listening TCP Ports (/proc/net/tcp)
                </span>
                <span className="font-mono text-[11px] text-zinc-400">
                  Allowed: {config.allowedListeningPorts.join(', ')}
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400 uppercase">
                      <th className="py-2 px-4">Proto</th>
                      <th className="py-2 px-4">Local Bind</th>
                      <th className="py-2 px-4">Port</th>
                      <th className="py-2 px-4">Policy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60 text-xs font-mono">
                    {network.listeningPorts.map((p) => (
                      <tr
                        key={`${p.protocol}-${p.localAddress}-${p.port}`}
                        className="hover:bg-zinc-900/60"
                      >
                        <td className="py-2.5 px-4 text-zinc-400">{p.protocol}</td>
                        <td className="py-2.5 px-4 text-zinc-200">
                          {p.localAddress}
                        </td>
                        <td className="py-2.5 px-4 text-zinc-100 font-semibold">
                          :{p.port}
                        </td>
                        <td className="py-2.5 px-4">
                          {p.isAllowed ? (
                            <span className="text-emerald-400">WHITELISTED</span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-amber-400 font-semibold">
                              <AlertTriangle className="w-3 h-3" />
                              UNEXPECTED
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="xl:col-span-6">
              <div className="px-4 py-2.5 bg-zinc-950/60 border-b border-zinc-800/60 flex items-center justify-between text-xs">
                <span className="font-medium text-zinc-200 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  Local Log Collector Sources
                </span>
                <ActionTooltip
                  label="Ubah Path Log Lokal"
                  description="Buka konfigurasi Local Agent untuk menambah, menghapus, atau memverifikasi file log."
                >
                  <button
                    type="button"
                    onClick={onOpenConfig}
                    className="text-[11px] text-emerald-400 hover:text-emerald-300 cursor-pointer"
                  >
                    Edit Log Paths →
                  </button>
                </ActionTooltip>
              </div>
              <div className="divide-y divide-zinc-800/60">
                {logSourcesStatus.map((src) => {
                  const statusTone =
                    src.accessStatus === 'READABLE'
                      ? 'text-emerald-400'
                      : src.accessStatus === 'DISABLED'
                      ? 'text-zinc-500'
                      : 'text-amber-400';
                  return (
                    <div
                      key={src.id}
                      className="px-4 py-3 flex items-start justify-between gap-3"
                    >
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-zinc-100">
                          {src.label}
                        </p>
                        <p className="font-mono text-[11px] text-zinc-400 truncate mt-0.5">
                          {src.path} ({src.format})
                        </p>
                      </div>
                      <div className="text-right font-mono text-[11px] shrink-0">
                        <div className={`font-semibold ${statusTone}`}>
                          {src.accessStatus}
                        </div>
                        <div className="text-zinc-500">
                          {src.linesScanned} lines · {src.alertsMatched} match
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};
