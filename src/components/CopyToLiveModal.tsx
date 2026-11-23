import React, { useEffect, useState } from 'react';
import { CopyCheck, ShieldAlert, X } from 'lucide-react';
import { ManualIncidentReport, Severity } from '../types/soc';
import { CATEGORY_LABELS, SeverityBadge } from './IncidentReportsView';

export interface CopyToLiveDraft {
  sourceLabel: string;
  sourceId: string;
  payload: Omit<ManualIncidentReport, 'id' | 'reportedAt' | 'updatedAt'>;
}

interface CopyToLiveModalProps {
  draft: CopyToLiveDraft | null;
  submitting: boolean;
  onCancel: () => void;
  onConfirm: (
    payload: Omit<ManualIncidentReport, 'id' | 'reportedAt' | 'updatedAt'>
  ) => Promise<void>;
}

export const CopyToLiveModal: React.FC<CopyToLiveModalProps> = ({
  draft,
  submitting,
  onCancel,
  onConfirm,
}) => {
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<Severity>('HIGH');
  const [coordinationNotes, setCoordinationNotes] = useState('');
  const [actionTaken, setActionTaken] = useState('');
  const [includeInBoardReport, setIncludeInBoardReport] = useState(false);

  useEffect(() => {
    if (!draft) return;
    setTitle(draft.payload.title);
    setSeverity(draft.payload.severity);
    const originTag = `[Salinan Latihan Demo · Sumber: ${draft.sourceId}]`;
    const baseCoord = draft.payload.coordinationNotes?.trim();
    setCoordinationNotes(
      baseCoord && !baseCoord.includes('[Salinan Latihan Demo')
        ? `${originTag}\n${baseCoord}`
        : baseCoord || originTag
    );
    setActionTaken(draft.payload.actionTaken);
    setIncludeInBoardReport(false);
  }, [draft]);

  if (!draft) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onConfirm({
      ...draft.payload,
      title: title.trim() || draft.payload.title,
      severity,
      coordinationNotes: coordinationNotes.trim(),
      actionTaken: actionTaken.trim(),
      includeInBoardReport,
    });
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="copy-to-live-title"
      onClick={onCancel}
    >
      <div
        className="w-full max-w-xl bg-zinc-950 border border-zinc-800 rounded-lg overflow-hidden shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-5 py-3.5 border-b border-zinc-800 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <CopyCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <h3
              id="copy-to-live-title"
              className="text-sm font-semibold text-zinc-100"
            >
              Salin Hasil Latihan Demo ke Laporan Live
            </h3>
          </div>
          <button
            type="button"
            onClick={onCancel}
            aria-label="Tutup dialog salin ke Live"
            className="p-1 text-zinc-500 hover:text-zinc-200 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={(e) => void handleSubmit(e)} className="p-5 space-y-4 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 bg-amber-500/10 border border-amber-500/30 rounded-md px-3 py-2 text-[11px] text-amber-200">
            <span className="inline-flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              Data akan disimpan ke <strong>Incident Reports (Live Server)</strong> dengan penanda asal latihan Demo.
            </span>
            <span className="font-mono text-amber-300">{draft.sourceId}</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="sm:col-span-2 block space-y-1">
              <span className="text-[11px] text-zinc-400">Judul Laporan Live</span>
              <input
                type="text"
                required
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-emerald-500/60"
              />
            </label>

            <label className="block space-y-1">
              <span className="text-[11px] text-zinc-400">Severity</span>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-2.5 py-1.5 text-xs font-mono text-zinc-100"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </label>

            <div className="flex items-end justify-between gap-2 bg-zinc-900/50 border border-zinc-800 rounded-md px-3 py-1.5">
              <div className="space-y-0.5">
                <span className="text-[10px] font-mono text-zinc-500 block">
                  Kategori
                </span>
                <span className="text-[11px] text-zinc-200">
                  {CATEGORY_LABELS[draft.payload.category]}
                </span>
              </div>
              <SeverityBadge severity={severity} />
            </div>

            <label className="sm:col-span-2 block space-y-1">
              <span className="text-[11px] text-zinc-400">
                Catatan Koordinasi &amp; Provenance (Otomatis ditandai Latihan Demo)
              </span>
              <textarea
                rows={2}
                value={coordinationNotes}
                onChange={(e) => setCoordinationNotes(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100"
              />
            </label>

            <label className="sm:col-span-2 block space-y-1">
              <span className="text-[11px] text-zinc-400">
                Ringkasan Tindakan / Playbook yang Dijalankan
              </span>
              <textarea
                rows={2}
                value={actionTaken}
                onChange={(e) => setActionTaken(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded-md px-3 py-1.5 text-xs text-zinc-100"
              />
            </label>
          </div>

          <label className="flex items-start gap-2.5 p-3 rounded-md bg-zinc-900/60 border border-zinc-800 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeInBoardReport}
              onChange={(e) => setIncludeInBoardReport(e.target.checked)}
              className="mt-0.5 accent-emerald-500"
            />
            <span className="text-[11px] text-zinc-300 leading-snug">
              Sertakan juga pada <strong className="text-zinc-100">Laporan CTO &amp; Direksi (BoD)</strong> di Live Mode{' '}
              <span className="text-zinc-500">(default nonaktif agar laporan eksekutif tetap murni insiden nyata)</span>
            </span>
          </label>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-zinc-800">
            <button
              type="button"
              onClick={onCancel}
              className="px-3.5 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 border border-zinc-800 rounded-md cursor-pointer"
            >
              Batal
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors cursor-pointer disabled:opacity-60"
            >
              <CopyCheck className="w-3.5 h-3.5" />
              {submitting ? 'Menyimpan ke Live...' : 'Simpan ke Laporan Live'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
