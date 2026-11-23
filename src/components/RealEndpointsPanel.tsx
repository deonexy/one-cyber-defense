import React, { useRef, useState } from 'react';
import { Plus, Trash2, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';
import { RealEndpointProbe } from '../types/soc';
import { formatTimeWIB } from '../utils/socFormatters';
import { useSocMode } from '../context/SocModeContext';
import { ActionTooltip } from './ActionTooltip';

interface RealEndpointsPanelProps {
  endpoints: RealEndpointProbe[];
  onAddEndpoint: (url: string, label: string) => Promise<void>;
  onRemoveEndpoint: (id: string) => Promise<void>;
  onInspectHeaders: () => void;
}

function normalizeInputUrl(raw: string): string {
  let cleaned = raw.trim();
  cleaned = cleaned.replace(/^(https?:\/\/)+(https?:\/\/)/i, '$2');
  if (cleaned && !/^https?:\/\//i.test(cleaned)) {
    cleaned = `https://${cleaned}`;
  }
  return cleaned;
}

export const RealEndpointsPanel: React.FC<RealEndpointsPanelProps> = ({
  endpoints,
  onAddEndpoint,
  onRemoveEndpoint,
  onInspectHeaders,
}) => {
  const { isDemo } = useSocMode();
  const [showAddForm, setShowAddForm] = useState(false);
  const [newUrl, setNewUrl] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [adding, setAdding] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);

  const upCount = endpoints.filter((e) => e.status === 'UP').length;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    const normalized = normalizeInputUrl(newUrl);
    try {
      new URL(normalized);
    } catch {
      setFormError('Format URL tidak valid (contoh: portal.example.org)');
      return;
    }

    setAdding(true);
    try {
      await onAddEndpoint(normalized, newLabel.trim());
      setNewUrl('');
      setNewLabel('');
      setShowAddForm(false);
      listRef.current?.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Gagal menambahkan URL');
    } finally {
      setAdding(false);
    }
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    try {
      await onRemoveEndpoint(id);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="flex flex-col h-full bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-zinc-800/80">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">
            Monitored Live Endpoints
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5 font-mono tabular-nums">
            {upCount}/{endpoints.length} UP · Direct HTTP/TLS Telemetry
          </p>
        </div>

        <ActionTooltip
          label="Tambah URL Target"
          description="Tambahkan endpoint HTTPS baru untuk dipantau uptime, latensi, header, dan sertifikat TLS-nya."
          scope={isDemo ? 'DEMO' : 'LIVE'}
        >
          <button
            type="button"
            onClick={() => {
              setFormError(null);
              setShowAddForm((v) => !v);
            }}
            className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3 h-3" />
            Add URL
          </button>
        </ActionTooltip>
      </div>

      {showAddForm && (
        <form
          onSubmit={handleSubmit}
          className="p-3.5 border-b border-zinc-800 bg-zinc-950/80 space-y-2.5 text-xs"
        >
          <input
            type="text"
            required
            autoComplete="off"
            spellCheck={false}
            value={newUrl}
            onChange={(e) => setNewUrl(e.target.value)}
            placeholder="https://portal.example.org/"
            className="w-full px-2.5 py-1.5 font-mono text-[11px] bg-zinc-900 border border-zinc-800 rounded text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
          />
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="Label (opsional)"
              className="flex-1 px-2.5 py-1.5 text-[11px] bg-zinc-900 border border-zinc-800 rounded text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
            />
            <ActionTooltip
              label="Probe & Tambah Endpoint"
              description="Jalankan pemeriksaan HTTP/TLS langsung dan simpan target ke daftar pantau."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="submit"
                disabled={adding}
                className="px-3 py-1.5 text-[11px] font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
              >
                {adding ? 'Probing...' : 'Probe & Add'}
              </button>
            </ActionTooltip>
          </div>
          {formError && (
            <p className="text-[11px] text-rose-400 font-mono">{formError}</p>
          )}
        </form>
      )}

      <div
        ref={listRef}
        className="flex-1 max-h-[420px] divide-y divide-zinc-800/70 overflow-y-auto"
      >
        {endpoints.map((ep) => {
          const statusColor =
            ep.status === 'UP'
              ? 'text-emerald-400'
              : ep.status === 'DEGRADED'
              ? 'text-amber-400'
              : ep.status === 'DOWN'
              ? 'text-rose-400'
              : 'text-zinc-400';
          const canDelete = ep.id !== 'ep-primary';

          return (
            <div
              key={ep.id}
              className="px-4 py-3 space-y-1.5 hover:bg-zinc-900/60 transition-colors"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-xs font-medium text-zinc-100 truncate">
                    {ep.label}
                  </p>
                  <p className="font-mono text-[10px] text-zinc-400 truncate mt-0.5">
                    {ep.url}
                  </p>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <span
                    className={`inline-flex items-center gap-1 font-mono text-[11px] font-semibold ${statusColor}`}
                  >
                    {ep.status === 'UP' && <CheckCircle2 className="w-3.5 h-3.5" />}
                    {ep.status === 'DEGRADED' && (
                      <AlertTriangle className="w-3.5 h-3.5" />
                    )}
                    {ep.status === 'DOWN' && <XCircle className="w-3.5 h-3.5" />}
                    {ep.httpStatus ? `HTTP ${ep.httpStatus}` : ep.status}
                  </span>
                  {canDelete && (
                    <ActionTooltip
                      label={`Hapus ${ep.label}`}
                      description={`Keluarkan ${ep.hostname} dari daftar target pemantauan.`}
                      scope={isDemo ? 'DEMO' : 'LIVE'}
                    >
                      <button
                        type="button"
                        disabled={deletingId === ep.id}
                        onClick={() => void handleDelete(ep.id)}
                        aria-label={`Hapus ${ep.label}`}
                        className="p-1 text-zinc-400 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors cursor-pointer disabled:opacity-40"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </ActionTooltip>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-0.5 font-mono text-[11px] tabular-nums text-zinc-400">
                <span className="text-zinc-200">
                  {ep.latencyMs !== null ? `${ep.latencyMs} ms` : '—'}
                </span>
                <span className="text-zinc-600">·</span>
                <span>Uptime {ep.uptimePercent.toFixed(1)}%</span>
                <span className="text-zinc-600">·</span>
                <span
                  className={
                    ep.headerScore >= 80
                      ? 'text-emerald-400'
                      : ep.headerScore >= 50
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }
                >
                  Hdr {ep.headerScore}%
                </span>
                {ep.tls?.daysRemaining !== null &&
                  ep.tls?.daysRemaining !== undefined && (
                    <>
                      <span className="text-zinc-600">·</span>
                      <span>TLS {ep.tls.daysRemaining}d</span>
                    </>
                  )}
              </div>

              <div className="flex items-center justify-between text-[10px] font-mono text-zinc-500">
                <span>IPv4: {ep.dns.ipv4[0] ?? 'resolving...'}</span>
                <span>
                  {ep.lastCheckedAt ? formatTimeWIB(ep.lastCheckedAt) : 'pending'}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="px-4 py-2 border-t border-zinc-800/80 bg-zinc-950/60 flex items-center justify-between text-xs">
        <span className="text-zinc-500 text-[11px]">
          {isDemo ? 'Demo Sandbox Endpoints' : 'Live HTTP/TLS Telemetry'}
        </span>
        <ActionTooltip
          label="Inspeksi Header & TLS"
          description="Buka rincian HTTP security headers dan sertifikat SSL/TLS setiap endpoint."
          scope={isDemo ? 'DEMO' : 'LIVE'}
        >
          <button
            type="button"
            onClick={onInspectHeaders}
            className="text-emerald-400 hover:text-emerald-300 font-medium text-[11px] cursor-pointer whitespace-nowrap shrink-0"
          >
            Inspect Headers &amp; TLS →
          </button>
        </ActionTooltip>
      </div>
    </div>
  );
};
