import React, { useEffect, useState } from 'react';
import {
  Save,
  Plus,
  Trash2,
  CheckCircle2,
  AlertCircle,
  Download,
  Sliders,
  FileSearch,
  Terminal,
  Shield,
  ArrowLeft,
} from 'lucide-react';
import { LocalAgentConfig, LogSourceFormat } from '../types/soc';
import { triggerFileDownload } from '../utils/socFormatters';
import { ActionTooltip } from './ActionTooltip';
import { useSocMode } from '../context/SocModeContext';

interface LocalConfigViewProps {
  config: LocalAgentConfig | null;
  saving: boolean;
  onSaveConfig: (next: LocalAgentConfig) => Promise<void>;
  onVerifyPath: (path: string) => Promise<{
    path: string;
    status: 'READABLE' | 'NOT_FOUND' | 'PERMISSION_DENIED';
    sizeBytes: number | null;
    permissions: string | null;
  }>;
  onBackToWazuh: () => void;
}

export const LocalConfigView: React.FC<LocalConfigViewProps> = ({
  config,
  saving,
  onSaveConfig,
  onVerifyPath,
  onBackToWazuh,
}) => {
  const { isDemo } = useSocMode();
  const [draft, setDraft] = useState<LocalAgentConfig | null>(config);
  const [portsInput, setPortsInput] = useState(
    config ? config.allowedListeningPorts.join(', ') : '80, 443, 3000'
  );
  const [newFimPath, setNewFimPath] = useState('');
  const [newLogLabel, setNewLogLabel] = useState('');
  const [newLogPath, setNewLogPath] = useState('');
  const [newLogFormat, setNewLogFormat] = useState<LogSourceFormat>('nginx');
  const [pathChecks, setPathChecks] = useState<
    Record<
      string,
      {
        status: 'READABLE' | 'NOT_FOUND' | 'PERMISSION_DENIED' | 'CHECKING';
        detail: string;
      }
    >
  >({});

  useEffect(() => {
    if (config && !draft) {
      setDraft(config);
      setPortsInput(config.allowedListeningPorts.join(', '));
    }
  }, [config, draft]);

  if (!draft) {
    return (
      <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-10 text-center text-xs font-mono text-zinc-400">
        Memuat konfigurasi Local Agent...
      </div>
    );
  }

  const handleVerify = async (targetPath: string) => {
    const clean = targetPath.trim();
    if (!clean) return;
    setPathChecks((prev) => ({
      ...prev,
      [clean]: { status: 'CHECKING', detail: 'Checking...' },
    }));
    try {
      const res = await onVerifyPath(clean);
      setPathChecks((prev) => ({
        ...prev,
        [clean]: {
          status: res.status,
          detail:
            res.status === 'READABLE'
              ? `READABLE (${res.permissions ?? ''} · ${res.sizeBytes ?? 0} B)`
              : res.status,
        },
      }));
    } catch {
      setPathChecks((prev) => ({
        ...prev,
        [clean]: { status: 'NOT_FOUND', detail: 'Check failed' },
      }));
    }
  };

  const handleAddFimPath = () => {
    const clean = newFimPath.trim();
    if (!clean || draft.fimPaths.includes(clean)) return;
    setDraft({ ...draft, fimPaths: [...draft.fimPaths, clean] });
    setNewFimPath('');
  };

  const handleRemoveFimPath = (target: string) => {
    setDraft({
      ...draft,
      fimPaths: draft.fimPaths.filter((p) => p !== target),
    });
  };

  const handleAddLogSource = () => {
    const cleanPath = newLogPath.trim();
    if (!cleanPath) return;
    const nextSource = {
      id: `log-custom-${Date.now().toString(36)}`,
      label: newLogLabel.trim() || cleanPath,
      path: cleanPath,
      format: newLogFormat,
      enabled: true,
    };
    setDraft({
      ...draft,
      logSources: [...draft.logSources, nextSource],
    });
    setNewLogLabel('');
    setNewLogPath('');
  };

  const handleRemoveLogSource = (id: string) => {
    setDraft({
      ...draft,
      logSources: draft.logSources.filter((s) => s.id !== id),
    });
  };

  const handleToggleLogSource = (id: string) => {
    setDraft({
      ...draft,
      logSources: draft.logSources.map((s) =>
        s.id === id ? { ...s, enabled: !s.enabled } : s
      ),
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const parsedPorts = portsInput
      .split(/[\s,]+/)
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);

    const payload: LocalAgentConfig = {
      ...draft,
      allowedListeningPorts:
        parsedPorts.length > 0 ? Array.from(new Set(parsedPorts)) : [80, 443, 3000],
    };
    setDraft(payload);
    await onSaveConfig(payload);
  };

  const handleExportJson = () => {
    triggerFileDownload(
      JSON.stringify(draft, null, 2),
      `soc-local-agent-config-${new Date().toISOString().slice(0, 10)}.json`,
      'application/json'
    );
  };

  return (
    <form onSubmit={(e) => void handleSubmit(e)} className="space-y-5">
      {/* Header Bar */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-semibold text-zinc-100">
              Konfigurasi Parameter Server Lokal (Wazuh-Style Local Agent)
            </h2>
          </div>
          {isDemo && (
            <p className="text-xs text-zinc-400">
              Atur identitas node, path log Nginx/Linux/aplikasi, daftar file FIM SHA-256, whitelist port, dan ambang batas deteksi lokal. Tersimpan otomatis ke <span className="font-mono text-zinc-300">soc-local-config.json</span>.
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ActionTooltip
            label="Kembali ke Dashboard SIEM"
            description="Lihat kembali ringkasan alert lokal, FIM, dan SCA CIS."
          >
            <button
              type="button"
              onClick={onBackToWazuh}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Local SIEM Dashboard
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Ekspor Konfigurasi JSON"
            description="Unduh cadangan file konfigurasi agent saat ini."
          >
            <button
              type="button"
              onClick={handleExportJson}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              Export JSON
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Simpan & Terapkan Konfigurasi"
            description={
              isDemo
                ? 'Terapkan perubahan konfigurasi pada sesi Demo Sandbox.'
                : 'Simpan ke soc-local-config.json dan jalankan ulang sensor lokal.'
            }
          >
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? 'Saving & Scanning...' : 'Save & Apply Config'}
            </button>
          </ActionTooltip>
        </div>
      </section>

      {/* Section 1: Server Identity & Thresholds */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-5 space-y-4">
        <div className="flex items-center gap-2 border-b border-zinc-800/80 pb-3">
          <Shield className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-zinc-100">
            1. Identitas Node Lokal, Whitelist Port &amp; Threshold Deteksi
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">Agent Name (Nama Server)</span>
            <input
              type="text"
              value={draft.agentName}
              onChange={(e) => setDraft({ ...draft, agentName: e.target.value })}
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
              placeholder="soc-prod-portal-01"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">Cluster / Unit Group</span>
            <input
              type="text"
              value={draft.clusterGroup}
              onChange={(e) => setDraft({ ...draft, clusterGroup: e.target.value })}
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
              placeholder="SOC-Core-Cluster"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">Deployment Environment</span>
            <select
              value={draft.environment}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  environment: e.target.value as LocalAgentConfig['environment'],
                })
              }
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            >
              <option value="PRODUCTION">PRODUCTION (Server Utama)</option>
              <option value="STAGING">STAGING / UAT</option>
              <option value="LOCAL_DEV">LOCAL_DEV / SANDBOX</option>
            </select>
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">
              Auto-Scan Interval (Detik · 10–300s)
            </span>
            <input
              type="number"
              min={10}
              max={300}
              value={draft.scanIntervalSec}
              onChange={(e) =>
                setDraft({ ...draft, scanIntervalSec: Number(e.target.value) || 30 })
              }
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">
              Wazuh Alert Level Threshold (1–15)
            </span>
            <input
              type="number"
              min={1}
              max={15}
              value={draft.alertLevelThreshold}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  alertLevelThreshold: Number(e.target.value) || 5,
                })
              }
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">
              Allowed Listening Ports (pisahkan koma)
            </span>
            <input
              type="text"
              value={portsInput}
              onChange={(e) => setPortsInput(e.target.value)}
              placeholder="22, 80, 443, 3000, 5432"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">
              SSH / Login Brute-Force Threshold (gagal)
            </span>
            <input
              type="number"
              min={2}
              max={100}
              value={draft.bruteForceThreshold}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  bruteForceThreshold: Number(e.target.value) || 5,
                })
              }
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            />
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">Active Response Mode</span>
            <select
              value={draft.activeResponseMode}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  activeResponseMode: e.target
                    .value as LocalAgentConfig['activeResponseMode'],
                })
              }
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            >
              <option value="MONITOR_ONLY">MONITOR_ONLY (Audit &amp; Alert)</option>
              <option value="WEBHOOK_NOTIFY">WEBHOOK_NOTIFY (Forward to SOAR/Chat)</option>
            </select>
          </label>

          <label className="block space-y-1.5">
            <span className="text-xs text-zinc-300">
              Local SOAR / Telegram / Slack Webhook (Opsional)
            </span>
            <input
              type="url"
              value={draft.webhookUrl}
              onChange={(e) => setDraft({ ...draft, webhookUrl: e.target.value })}
              placeholder="https://internal-soar.local/webhook"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 focus:outline-none focus:border-emerald-500/60"
            />
          </label>
        </div>

        {/* Built-in Wazuh Rule Toggles */}
        <div className="pt-2 border-t border-zinc-800/80">
          <p className="text-xs font-medium text-zinc-300 mb-2.5">
            Active Detection Rules (Analysisd Local Engine)
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
            {(
              [
                ['sshBruteForce', 'Rule 5710 · SSH Brute Force'],
                ['webSqlInjection', 'Rule 31103 · Web SQL Injection'],
                ['webXssAndTraversal', 'Rule 31104 · XSS & Traversal'],
                ['fimIntegrityChange', 'Rule 550 · FIM SHA-256 Drift'],
                ['unexpectedOpenPort', 'Rule 19102 · Unexpected Port'],
              ] as const
            ).map(([key, label]) => (
              <label
                key={key}
                className="flex items-center gap-2 bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-200 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={draft.enabledRules[key]}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      enabledRules: {
                        ...draft.enabledRules,
                        [key]: e.target.checked,
                      },
                    })
                  }
                  className="accent-emerald-500"
                />
                <span className="truncate">{label}</span>
              </label>
            ))}
          </div>
        </div>
      </section>

      {/* Section 2: Log Collector Sources */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between gap-2 border-b border-zinc-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-zinc-100">
              2. Local Log Collector Sources (Pengganti Wazuh Logcollector)
            </h3>
          </div>
          <span className="font-mono text-[11px] text-zinc-400">
            {draft.logSources.length} / 15 sources
          </span>
        </div>

        <div className="divide-y divide-zinc-800/70 border border-zinc-800/80 rounded-md bg-zinc-950/60">
          {draft.logSources.map((src) => {
            const chk = pathChecks[src.path];
            return (
              <div
                key={src.id}
                className="px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <input
                    type="checkbox"
                    checked={src.enabled}
                    onChange={() => handleToggleLogSource(src.id)}
                    className="accent-emerald-500 mt-1"
                  />
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-zinc-100">
                      {src.label}
                    </p>
                    <p className="font-mono text-[11px] text-zinc-400 break-all">
                      {src.path} · format:{src.format}
                    </p>
                    {chk && (
                      <p
                        className={`font-mono text-[11px] mt-1 flex items-center gap-1 ${
                          chk.status === 'READABLE'
                            ? 'text-emerald-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {chk.status === 'READABLE' ? (
                          <CheckCircle2 className="w-3 h-3" />
                        ) : (
                          <AlertCircle className="w-3 h-3" />
                        )}
                        {chk.detail}
                      </p>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <ActionTooltip
                    label="Verifikasi Izin Baca Path"
                    description="Periksa apakah file log dapat diakses dan dibaca oleh proses agent."
                  >
                    <button
                      type="button"
                      onClick={() => void handleVerify(src.path)}
                      className="px-2.5 py-1 text-[11px] font-mono bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded cursor-pointer"
                    >
                      Verify Path
                    </button>
                  </ActionTooltip>
                  <ActionTooltip
                    label="Hapus Sumber Log"
                    description="Keluarkan path log ini dari daftar pengumpul lokal."
                  >
                    <button
                      type="button"
                      onClick={() => handleRemoveLogSource(src.id)}
                      aria-label={`Remove ${src.label}`}
                      className="p-1.5 text-zinc-500 hover:text-rose-400 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </ActionTooltip>
                </div>
              </div>
            );
          })}
        </div>

        {/* Add Log Source Form */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-2.5">
          <input
            type="text"
            value={newLogLabel}
            onChange={(e) => setNewLogLabel(e.target.value)}
            placeholder="Label (mis. Portal Disbursement API Log)"
            className="md:col-span-4 bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
          />
          <input
            type="text"
            value={newLogPath}
            onChange={(e) => setNewLogPath(e.target.value)}
            placeholder="Path absolut (mis. /var/log/app/portal.log)"
            className="md:col-span-5 bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
          />
          <select
            value={newLogFormat}
            onChange={(e) => setNewLogFormat(e.target.value as LogSourceFormat)}
            className="md:col-span-2 bg-zinc-950 border border-zinc-800 rounded-md px-2.5 py-2 text-xs font-mono text-zinc-100"
          >
            <option value="nginx">nginx</option>
            <option value="auth">auth</option>
            <option value="syslog">syslog</option>
            <option value="app-json">app-json</option>
          </select>
          <ActionTooltip
            label="Tambah Sumber Log"
            description="Tambahkan path log baru ke daftar Log Collector lokal."
            className="md:col-span-1 flex"
          >
            <button
              type="button"
              onClick={handleAddLogSource}
              className="w-full inline-flex items-center justify-center gap-1 px-3 py-2 text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-100 rounded-md cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              Add
            </button>
          </ActionTooltip>
        </div>
      </section>

      {/* Section 3: File Integrity Monitoring (FIM) Paths */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between gap-2 border-b border-zinc-800/80 pb-3">
          <div className="flex items-center gap-2">
            <FileSearch className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-semibold text-zinc-100">
              3. File Integrity Monitoring (FIM SHA-256 Monitored Paths)
            </h3>
          </div>
          <span className="font-mono text-[11px] text-zinc-400">
            {draft.fimPaths.length} / 30 files
          </span>
        </div>

        <div className="divide-y divide-zinc-800/70 border border-zinc-800/80 rounded-md bg-zinc-950/60">
          {draft.fimPaths.map((fp) => {
            const chk = pathChecks[fp];
            return (
              <div
                key={fp}
                className="px-4 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div className="min-w-0">
                  <p className="font-mono text-xs text-zinc-200 break-all">{fp}</p>
                  {chk && (
                    <p
                      className={`font-mono text-[11px] mt-0.5 ${
                        chk.status === 'READABLE'
                          ? 'text-emerald-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {chk.detail}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <ActionTooltip
                    label="Verifikasi File FIM"
                    description="Periksa keterbacaan, izin file, dan ukuran path ini."
                  >
                    <button
                      type="button"
                      onClick={() => void handleVerify(fp)}
                      className="px-2.5 py-1 text-[11px] font-mono bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded cursor-pointer"
                    >
                      Verify Path
                    </button>
                  </ActionTooltip>
                  <ActionTooltip
                    label="Hapus Path FIM"
                    description="Hentikan pemantauan hash SHA-256 pada file ini."
                  >
                    <button
                      type="button"
                      onClick={() => handleRemoveFimPath(fp)}
                      aria-label={`Remove ${fp}`}
                      className="p-1.5 text-zinc-500 hover:text-rose-400 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </ActionTooltip>
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex flex-col sm:flex-row gap-2.5">
          <input
            type="text"
            value={newFimPath}
            onChange={(e) => setNewFimPath(e.target.value)}
            placeholder="Tambah file kritis (mis. /etc/nginx/sites-enabled/portal.conf atau /var/www/portal/.env)"
            className="flex-1 bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
          />
          <ActionTooltip
            label="Tambah Path FIM"
            description="Tambahkan berkas baru ke daftar pemantauan integritas SHA-256."
          >
            <button
              type="button"
              onClick={handleAddFimPath}
              className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-100 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              Add FIM Path
            </button>
          </ActionTooltip>
        </div>
      </section>
    </form>
  );
};
