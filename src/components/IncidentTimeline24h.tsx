import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  Clock,
  Pause,
  Play,
  RotateCcw,
  ArrowUpRight,
} from 'lucide-react';
import {
  GlobalThreatIntelSnapshot,
  LiveAttackEvent,
  LocalWazuhSnapshot,
  ManualIncidentReport,
  RealProbeLogEntry,
  RealSecurityFinding,
  RealSocView,
  Severity,
} from '../types/soc';
import { formatShortDateTime, getSeverityColor } from '../utils/socFormatters';
import { useSocMode } from '../context/SocModeContext';
import { ActionTooltip } from './ActionTooltip';

export interface TimelineIncident {
  id: string;
  timestampMs: number;
  isoTimestamp: string;
  severity: Severity;
  sourceLabel: string;
  target: string;
  title: string;
  detail: string;
  destinationView: RealSocView;
  destinationLabel: string;
}

interface IncidentTimeline24hProps {
  findings: RealSecurityFinding[];
  localWazuh: LocalWazuhSnapshot | null;
  ingestedSiemEvents: LiveAttackEvent[];
  probeLogs: RealProbeLogEntry[];
  threatIntel: GlobalThreatIntelSnapshot | null;
  incidentReports: ManualIncidentReport[];
  onNavigateView: (view: RealSocView) => void;
}

const WINDOW_MS = 24 * 60 * 60 * 1000;
const BUCKET_COUNT = 24;
const BUCKET_MS = WINDOW_MS / BUCKET_COUNT;
const SCRUB_WINDOW_MS = 45 * 60 * 1000; // ±45 min highlight around playhead

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const SEVERITY_STYLES: Record<
  Severity,
  { bg: string; border: string; text: string; bar: string }
> = {
  CRITICAL: {
    bg: 'bg-rose-500',
    border: 'border-rose-400',
    text: 'text-rose-400',
    bar: 'bg-rose-500/85',
  },
  HIGH: {
    bg: 'bg-orange-500',
    border: 'border-orange-400',
    text: 'text-orange-400',
    bar: 'bg-orange-500/85',
  },
  MEDIUM: {
    bg: 'bg-amber-500',
    border: 'border-amber-400',
    text: 'text-amber-400',
    bar: 'bg-amber-500/80',
  },
  LOW: {
    bg: 'bg-emerald-500',
    border: 'border-emerald-400',
    text: 'text-emerald-400',
    bar: 'bg-emerald-500/75',
  },
};

function parseTimestampMs(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed === '-') return null;
  // Handle ISO or space-separated UTC timestamps (e.g. Ransomware.live "YYYY-MM-DD HH:MM:SS")
  let normalized = trimmed;
  if (/^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}/.test(normalized)) {
    normalized = normalized.replace(' ', 'T');
    if (!/[zZ]|[+-]\d{2}:?\d{2}$/.test(normalized)) {
      normalized += 'Z';
    }
  }
  const ms = Date.parse(normalized);
  return Number.isFinite(ms) ? ms : null;
}

function formatHourTickWIB(ms: number): string {
  try {
    return new Date(ms).toLocaleTimeString('id-ID', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
  } catch {
    return '--:--';
  }
}

export const IncidentTimeline24h: React.FC<IncidentTimeline24hProps> = ({
  findings,
  localWazuh,
  ingestedSiemEvents,
  probeLogs,
  threatIntel,
  incidentReports,
  onNavigateView,
}) => {
  const { isDemo } = useSocMode();
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');
  // Scrub progress from 0 (24h ago) to 1000 (Now), default pinned to live edge (1000)
  const [scrubPermille, setScrubPermille] = useState<number>(1000);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);

  const trackRef = useRef<HTMLDivElement | null>(null);
  const isDraggingRef = useRef<boolean>(false);

  // Refresh the 24h anchor clock every 30s so live events stay aligned
  useEffect(() => {
    const timer = setInterval(() => {
      setNowMs(Date.now());
    }, 30_000);
    return () => clearInterval(timer);
  }, []);

  const windowStartMs = nowMs - WINDOW_MS;

  // Aggregate 100% real security incidents across the last 24 hours
  const allIncidents24h = useMemo<TimelineIncident[]>(() => {
    const items: TimelineIncident[] = [];
    const seenIds = new Set<string>();

    const pushIfInWindow = (item: TimelineIncident) => {
      if (seenIds.has(item.id)) return;
      // Allow slight positive clock skew up to 5 min, clamp to nowMs
      if (item.timestampMs < windowStartMs || item.timestampMs > nowMs + 5 * 60_000) {
        return;
      }
      seenIds.add(item.id);
      items.push({
        ...item,
        timestampMs: Math.min(item.timestampMs, nowMs),
      });
    };

    // 1. Verified Portal Security Findings (HTTP/TLS/DNS/Availability/CTI)
    for (const f of findings) {
      const ms = parseTimestampMs(f.detected_at);
      if (ms === null) continue;
      pushIfInWindow({
        id: `finding:${f.finding_id}`,
        timestampMs: ms,
        isoTimestamp: f.detected_at,
        severity: f.severity,
        sourceLabel: `Portal Audit · ${f.category.replace('_', ' ')}`,
        target: f.target,
        title: f.title,
        detail: f.evidence,
        destinationView: 'findings',
        destinationLabel: 'Open Findings',
      });
    }

    // 2. Local Host SIEM / XDR Alerts (Wazuh-Style FIM / SCA / Net / Logcollector)
    for (const a of localWazuh?.alerts ?? []) {
      const ms = parseTimestampMs(a.timestamp);
      if (ms === null) continue;
      pushIfInWindow({
        id: `wazuh:${a.alert_id}`,
        timestampMs: ms,
        isoTimestamp: a.timestamp,
        severity: a.severity,
        sourceLabel: `Local SIEM · ${a.source} (Lvl ${a.rule_level})`,
        target: a.target,
        title: a.title,
        detail: `${a.detail}${a.mitre_id ? ` · MITRE ${a.mitre_id}` : ''}`,
        destinationView: 'wazuh-dashboard',
        destinationLabel: 'Open Local SIEM',
      });
    }

    // 3. External Ingested SIEM Events (if any pushed via webhook)
    for (const e of ingestedSiemEvents) {
      const ms = parseTimestampMs(e.timestamp);
      if (ms === null) continue;
      pushIfInWindow({
        id: `siem:${e.event_id}`,
        timestampMs: ms,
        isoTimestamp: e.timestamp,
        severity: e.severity,
        sourceLabel: `SIEM Ingest · ${e.attack_vector}`,
        target: e.target_asset,
        title: `${e.attack_vector} from ${e.source_ip} (${e.source_country})`,
        detail: e.payload_snippet || `Action: ${e.action_taken}`,
        destinationView: 'findings',
        destinationLabel: 'Open Findings',
      });
    }

    // 4. Degraded / Failed Live Portal Probe Events
    for (const log of probeLogs) {
      const ms = parseTimestampMs(log.timestamp);
      if (ms === null) continue;
      const isFailure =
        /DOWN|FAIL|ERR|TIMEOUT|5\d\d|4\d\d/i.test(log.http_status) ||
        /FAIL|ERROR|DEGRADED|DOWN/i.test(log.result);
      if (!isFailure) continue;
      pushIfInWindow({
        id: `probe:${log.id}`,
        timestampMs: ms,
        isoTimestamp: log.timestamp,
        severity: /DOWN|5\d\d|TIMEOUT/i.test(log.http_status + log.result)
          ? 'HIGH'
          : 'MEDIUM',
        sourceLabel: `Live Probe · ${log.check_type.replace('_', ' ')}`,
        target: log.target,
        title: `${log.target} returned ${log.http_status}`,
        detail: `${log.result} (${log.latency_ms})`,
        destinationView: 'audit',
        destinationLabel: 'Open Audit Log',
      });
    }

    // 5. Global Open CTI — Live Ransomware.live Victim Claims Discovered in Last 24h
    for (const r of threatIntel?.ransomware.recent ?? []) {
      const ms = parseTimestampMs(r.discovered);
      if (ms === null) continue;
      const severity: Severity =
        r.country === 'ID'
          ? 'CRITICAL'
          : r.isPrioritySector
          ? 'HIGH'
          : 'MEDIUM';
      pushIfInWindow({
        id: `ransom:${r.group}:${r.victim}:${r.discovered}`,
        timestampMs: ms,
        isoTimestamp: new Date(ms).toISOString(),
        severity,
        sourceLabel: `Global CTI · Ransomware (${r.group})`,
        target: `${r.victim} (${r.country})`,
        title: `${r.group} ransomware claim targeting ${r.activity}`,
        detail:
          r.description && r.description !== 'Not Found'
            ? r.description.slice(0, 180)
            : `Sector: ${r.activity} · Country: ${r.country} · Live Ransomware.live feed`,
        destinationView: 'threat-intel',
        destinationLabel: 'Open Threat Intel',
      });
    }

    // 6. Recorded Manual / Infra Ops / CSIRT Incident Reports (SEO Poisoning, Defacement, etc.)
    for (const rep of incidentReports) {
      const ms = parseTimestampMs(rep.occurredAt) ?? parseTimestampMs(rep.reportedAt);
      if (ms === null) continue;
      pushIfInWindow({
        id: `manual-inc:${rep.id}`,
        timestampMs: ms,
        isoTimestamp: rep.occurredAt || rep.reportedAt,
        severity: rep.severity,
        sourceLabel: `Incident Report · ${rep.source.replace(/_/g, ' ')}`,
        target: rep.affectedUrl,
        title: rep.title,
        detail:
          rep.evidenceSnippet ||
          rep.description ||
          `Status: ${rep.status} · Pelapor: ${rep.reporterName}`,
        destinationView: 'incident-reports',
        destinationLabel: 'Open Incident Reports',
      });
    }

    // Sort chronologically ascending (oldest -> newest)
    items.sort((a, b) => a.timestampMs - b.timestampMs);
    return items;
  }, [
    findings,
    localWazuh,
    ingestedSiemEvents,
    probeLogs,
    threatIntel,
    incidentReports,
    windowStartMs,
    nowMs,
  ]);

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    for (const inc of allIncidents24h) {
      counts[inc.severity] += 1;
    }
    return counts;
  }, [allIncidents24h]);

  const filteredIncidents = useMemo(() => {
    if (severityFilter === 'ALL') return allIncidents24h;
    return allIncidents24h.filter((i) => i.severity === severityFilter);
  }, [allIncidents24h, severityFilter]);

  // Build 24 hourly stacked severity buckets
  const hourlyBuckets = useMemo(() => {
    const buckets = Array.from({ length: BUCKET_COUNT }, (_, idx) => ({
      index: idx,
      startMs: windowStartMs + idx * BUCKET_MS,
      endMs: windowStartMs + (idx + 1) * BUCKET_MS,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      total: 0,
    }));

    for (const inc of filteredIncidents) {
      const rawIdx = Math.floor((inc.timestampMs - windowStartMs) / BUCKET_MS);
      const idx = Math.max(0, Math.min(BUCKET_COUNT - 1, rawIdx));
      buckets[idx][inc.severity] += 1;
      buckets[idx].total += 1;
    }

    const maxCount = Math.max(1, ...buckets.map((b) => b.total));
    return { buckets, maxCount };
  }, [filteredIncidents, windowStartMs]);

  const playheadMs = windowStartMs + (scrubPermille / 1000) * WINDOW_MS;
  const playheadPct = (scrubPermille / 1000) * 100;

  // Smooth replay scrubber when Play is active
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      setScrubPermille((prev) => {
        const next = prev + 8;
        if (next >= 1000) {
          setIsPlaying(false);
          return 1000;
        }
        return next;
      });
    }, 90);
    return () => clearInterval(interval);
  }, [isPlaying]);

  // Events inside ±45 min of playhead
  const nearbyIncidents = useMemo(() => {
    const inSlice = filteredIncidents.filter(
      (i) => Math.abs(i.timestampMs - playheadMs) <= SCRUB_WINDOW_MS
    );
    return [...inSlice].sort((a, b) => {
      const distA = Math.abs(a.timestampMs - playheadMs);
      const distB = Math.abs(b.timestampMs - playheadMs);
      if (distA !== distB) return distA - distB;
      return SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    });
  }, [filteredIncidents, playheadMs]);

  // Active focused incident: explicit user selection if still in filtered list & close, otherwise closest in slice
  const activeIncident = useMemo<TimelineIncident | null>(() => {
    if (selectedId) {
      const found = filteredIncidents.find((i) => i.id === selectedId);
      if (found && Math.abs(found.timestampMs - playheadMs) <= SCRUB_WINDOW_MS * 1.5) {
        return found;
      }
    }
    if (nearbyIncidents.length > 0) {
      return nearbyIncidents[0];
    }
    return null;
  }, [selectedId, filteredIncidents, nearbyIncidents, playheadMs]);

  const updateScrubFromClientX = (clientX: number) => {
    const el = trackRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0) return;
    const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    setIsPlaying(false);
    setSelectedId(null);
    setScrubPermille(Math.round(ratio * 1000));
  };

  const handleTrackPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    // Ignore if user clicked directly on an event marker button
    if ((e.target as HTMLElement).closest('button[data-timeline-marker="true"]')) {
      return;
    }
    isDraggingRef.current = true;
    e.currentTarget.setPointerCapture(e.pointerId);
    updateScrubFromClientX(e.clientX);
  };

  const handleTrackPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDraggingRef.current) return;
    updateScrubFromClientX(e.clientX);
  };

  const handleTrackPointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDraggingRef.current) return;
    isDraggingRef.current = false;
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {
      // ignore if capture already released
    }
  };

  const jumpToIncident = (inc: TimelineIncident) => {
    setIsPlaying(false);
    setSelectedId(inc.id);
    const ratio = Math.max(
      0,
      Math.min(1, (inc.timestampMs - windowStartMs) / WINDOW_MS)
    );
    setScrubPermille(Math.round(ratio * 1000));
  };

  const stepIncident = (direction: -1 | 1) => {
    if (filteredIncidents.length === 0) return;
    setIsPlaying(false);

    if (activeIncident) {
      const idx = filteredIncidents.findIndex((i) => i.id === activeIncident.id);
      if (idx !== -1) {
        const targetIdx = Math.max(
          0,
          Math.min(filteredIncidents.length - 1, idx + direction)
        );
        jumpToIncident(filteredIncidents[targetIdx]);
        return;
      }
    }

    if (direction === -1) {
      const earlier = [...filteredIncidents]
        .reverse()
        .find((i) => i.timestampMs < playheadMs);
      jumpToIncident(earlier ?? filteredIncidents[0]);
    } else {
      const later = filteredIncidents.find((i) => i.timestampMs > playheadMs);
      jumpToIncident(later ?? filteredIncidents[filteredIncidents.length - 1]);
    }
  };

  const handleTogglePlay = () => {
    if (isPlaying) {
      setIsPlaying(false);
      return;
    }
    if (scrubPermille >= 995) {
      setScrubPermille(0);
    }
    setSelectedId(null);
    setIsPlaying(true);
  };

  const handleResetToLive = () => {
    setIsPlaying(false);
    setSelectedId(null);
    setNowMs(Date.now());
    setScrubPermille(1000);
  };

  // Generate 7 evenly spaced axis labels (-24h to Now, every 4 hours)
  const axisTicks = useMemo(() => {
    return [0, 4, 8, 12, 16, 20, 24].map((hourOffset) => {
      const ms = windowStartMs + hourOffset * 60 * 60 * 1000;
      return {
        pct: (hourOffset / 24) * 100,
        clock: hourOffset === 24 ? 'Now' : formatHourTickWIB(ms),
        relative: hourOffset === 24 ? 'LIVE' : `-${24 - hourOffset}h`,
      };
    });
  }, [windowStartMs]);

  const activeSevMeta = activeIncident
    ? getSeverityColor(activeIncident.severity)
    : null;

  return (
    <section
      aria-label="24-Hour Security Incident Timeline"
      className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden"
    >
      {/* Header Toolbar */}
      <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100 truncate">
              24-Hour Security Incident Timeline
            </h2>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs font-mono tabular-nums text-zinc-400">
            <span className="text-zinc-200 font-medium">
              {allIncidents24h.length} incidents (24h)
            </span>
            <span aria-hidden="true" className="text-zinc-700">
              ·
            </span>
            <span className="text-rose-400">
              Critical {severityCounts.CRITICAL}
            </span>
            <span aria-hidden="true" className="text-zinc-700">
              ·
            </span>
            <span className="text-orange-400">High {severityCounts.HIGH}</span>
            <span aria-hidden="true" className="text-zinc-700">
              ·
            </span>
            <span className="text-amber-400">Medium {severityCounts.MEDIUM}</span>
            <span aria-hidden="true" className="text-zinc-700">
              ·
            </span>
            <span className="text-emerald-400">Low {severityCounts.LOW}</span>
          </div>
        </div>

        {/* Interactive Filter & Scrub Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div
            role="group"
            aria-label="Filter incidents by severity"
            className="inline-flex items-center bg-zinc-950 border border-zinc-800 rounded-md p-0.5"
          >
            {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(
              (level) => {
                const active = severityFilter === level;
                const label =
                  level === 'ALL'
                    ? 'All'
                    : level.charAt(0) + level.slice(1).toLowerCase();
                return (
                  <ActionTooltip
                    key={level}
                    label={`Filter ${label}`}
                    description={`Tampilkan hanya event berlevel ${label} pada linimasa 24 jam.`}
                    scope={isDemo ? 'DEMO' : 'LIVE'}
                  >
                    <button
                      type="button"
                      onClick={() => {
                        setSeverityFilter(level);
                        setSelectedId(null);
                      }}
                      className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500 ${
                        active
                          ? 'bg-zinc-800 text-zinc-100'
                          : 'text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      {label}
                    </button>
                  </ActionTooltip>
                );
              }
            )}
          </div>

          <div className="inline-flex items-center gap-1">
            <ActionTooltip
              label="Insiden Sebelumnya"
              description="Geser penanda ke insiden lebih lama sebelumnya."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={() => stepIncident(-1)}
                disabled={filteredIncidents.length === 0}
                aria-label="Previous security incident"
                className="p-1.5 bg-zinc-950 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md transition-colors cursor-pointer disabled:opacity-40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
            </ActionTooltip>
            <ActionTooltip
              label={isPlaying ? 'Jeda Replay' : 'Putar Replay 24 Jam'}
              description={
                isPlaying
                  ? 'Hentikan pemutaran ulang linimasa.'
                  : 'Putar ulang kronologi kejadian keamanan selama 24 jam terakhir.'
              }
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={handleTogglePlay}
                disabled={filteredIncidents.length === 0}
                aria-label={isPlaying ? 'Pause timeline replay' : 'Play 24h timeline replay'}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] font-medium bg-zinc-950 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500"
              >
                {isPlaying ? (
                  <>
                    <Pause className="w-3 h-3 text-amber-400" />
                    <span>Pause</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3 h-3 text-emerald-400" />
                    <span>Replay</span>
                  </>
                )}
              </button>
            </ActionTooltip>
            <ActionTooltip
              label="Insiden Berikutnya"
              description="Geser penanda ke insiden berikutnya yang lebih baru."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={() => stepIncident(1)}
                disabled={filteredIncidents.length === 0}
                aria-label="Next security incident"
                className="p-1.5 bg-zinc-950 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md transition-colors cursor-pointer disabled:opacity-40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </ActionTooltip>
            <ActionTooltip
              label="Lompat ke Sekarang"
              description="Kembalikan playhead linimasa ke waktu terkini (LIVE)."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={handleResetToLive}
                aria-label="Jump to current time"
                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-medium bg-zinc-950 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500"
              >
                <RotateCcw className="w-3 h-3 text-zinc-400" />
                <span>Now</span>
              </button>
            </ActionTooltip>
          </div>
        </div>
      </div>

      {/* Interactive Horizontal Scrubbing Rail & 24-Hour Severity Histogram */}
      <div className="px-4 pt-4 pb-3 bg-zinc-950/60 select-none">
        <div className="flex items-center justify-between text-[11px] font-mono tabular-nums text-zinc-400 mb-2">
          <span>
            Scrubbed Time:{' '}
            <strong className="text-zinc-100">
              {formatShortDateTime(new Date(playheadMs).toISOString())} WIB
            </strong>
            <span className="text-zinc-500 ml-2">
              (±45m window · {nearbyIncidents.length} event
              {nearbyIncidents.length === 1 ? '' : 's'})
            </span>
          </span>
          {isDemo && (
            <span className="hidden sm:inline text-zinc-500">
              Drag track or click any marker to inspect past events
            </span>
          )}
        </div>

        {/* Interactive Scrub Area */}
        <div
          ref={trackRef}
          onPointerDown={handleTrackPointerDown}
          onPointerMove={handleTrackPointerMove}
          onPointerUp={handleTrackPointerUp}
          onPointerCancel={handleTrackPointerUp}
          className="relative h-24 w-full bg-zinc-950 border border-zinc-800/90 rounded-md overflow-hidden cursor-ew-resize touch-none"
        >
          {/* Subtle vertical 4-hour grid guidelines */}
          {axisTicks.slice(1, -1).map((tick) => (
            <div
              key={tick.relative}
              style={{ left: `${tick.pct}%` }}
              className="absolute top-0 bottom-0 w-px bg-zinc-800/50 pointer-events-none"
            />
          ))}

          {/* Active ±45m Inspection Band around Playhead */}
          <div
            style={{
              left: `${Math.max(0, playheadPct - (SCRUB_WINDOW_MS / WINDOW_MS) * 100)}%`,
              width: `${Math.min(
                100,
                ((SCRUB_WINDOW_MS * 2) / WINDOW_MS) * 100
              )}%`,
            }}
            className="absolute top-0 bottom-0 bg-emerald-500/8 border-x border-emerald-500/20 pointer-events-none"
          />

          {/* 24 Hourly Stacked Severity Bars */}
          <div className="absolute inset-x-0 bottom-6 top-3 px-1 flex items-end gap-[2px] pointer-events-none">
            {hourlyBuckets.buckets.map((bucket) => {
              const heightPct =
                bucket.total > 0
                  ? Math.max(14, (bucket.total / hourlyBuckets.maxCount) * 100)
                  : 0;
              return (
                <div
                  key={bucket.index}
                  className="flex-1 h-full flex flex-col justify-end"
                >
                  {bucket.total > 0 ? (
                    <div
                      style={{ height: `${heightPct}%` }}
                      className="w-full flex flex-col-reverse overflow-hidden rounded-t-[2px]"
                    >
                      {bucket.LOW > 0 && (
                        <div
                          style={{
                            flexGrow: bucket.LOW,
                          }}
                          className={SEVERITY_STYLES.LOW.bar}
                        />
                      )}
                      {bucket.MEDIUM > 0 && (
                        <div
                          style={{
                            flexGrow: bucket.MEDIUM,
                          }}
                          className={SEVERITY_STYLES.MEDIUM.bar}
                        />
                      )}
                      {bucket.HIGH > 0 && (
                        <div
                          style={{
                            flexGrow: bucket.HIGH,
                          }}
                          className={SEVERITY_STYLES.HIGH.bar}
                        />
                      )}
                      {bucket.CRITICAL > 0 && (
                        <div
                          style={{
                            flexGrow: bucket.CRITICAL,
                          }}
                          className={SEVERITY_STYLES.CRITICAL.bar}
                        />
                      )}
                    </div>
                  ) : (
                    <div className="w-full h-[2px] bg-zinc-900" />
                  )}
                </div>
              );
            })}
          </div>

          {/* Horizontal Baseline Rail + Clickable Color-Coded Event Markers */}
          <div className="absolute inset-x-0 bottom-0 h-6 bg-zinc-900/80 border-t border-zinc-800/80">
            {filteredIncidents.map((inc) => {
              const pct = Math.max(
                0.5,
                Math.min(
                  99.5,
                  ((inc.timestampMs - windowStartMs) / WINDOW_MS) * 100
                )
              );
              const isSelected = activeIncident?.id === inc.id;
              const style = SEVERITY_STYLES[inc.severity];
              return (
                <button
                  key={inc.id}
                  type="button"
                  data-timeline-marker="true"
                  onClick={(e) => {
                    e.stopPropagation();
                    jumpToIncident(inc);
                  }}
                  style={{ left: `${pct}%` }}
                  aria-label={`${inc.severity} incident: ${inc.title} at ${formatHourTickWIB(
                    inc.timestampMs
                  )} WIB`}
                  title={`[${inc.severity}] ${formatHourTickWIB(
                    inc.timestampMs
                  )} WIB — ${inc.title}`}
                  className={`absolute top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full transition-transform cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white ${
                    style.bg
                  } ${
                    isSelected
                      ? 'w-3 h-3 ring-2 ring-white z-20 scale-110'
                      : 'w-2 h-2 opacity-90 hover:scale-125 hover:opacity-100 z-10'
                  }`}
                />
              );
            })}
          </div>

          {/* Vertical Playhead Scrubber Hairline */}
          <div
            style={{ left: `${playheadPct}%` }}
            className="absolute top-0 bottom-0 w-px bg-emerald-400 pointer-events-none z-30"
          >
            <div className="absolute -top-0.5 left-1/2 -translate-x-1/2 w-2.5 h-2.5 rotate-45 bg-emerald-400 border border-zinc-950" />
          </div>
        </div>

        {/* Accessible Precision Range Scrubber */}
        <div className="mt-2 flex items-center gap-3">
          <input
            type="range"
            min={0}
            max={1000}
            step={1}
            value={scrubPermille}
            aria-label="Scrub 24-hour security incident timeline"
            onChange={(e) => {
              setIsPlaying(false);
              setSelectedId(null);
              setScrubPermille(Number(e.target.value));
            }}
            className="w-full h-1.5 bg-zinc-800 rounded-lg appearance-none cursor-ew-resize accent-emerald-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-500"
          />
        </div>

        {/* 24-Hour Time Axis Ticks */}
        <div className="mt-1.5 flex items-center justify-between text-[10px] font-mono tabular-nums text-zinc-500">
          {axisTicks.map((tick) => (
            <div key={tick.relative} className="flex flex-col items-center">
              <span
                className={
                  tick.relative === 'LIVE' ? 'text-emerald-400 font-semibold' : ''
                }
              >
                {tick.clock}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Scrubbed Event Inspector Split */}
      <div className="border-t border-zinc-800/80 grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-zinc-800/80">
        {/* Focused Incident Detail (7 cols) */}
        <div className="lg:col-span-7 p-4 flex flex-col justify-between gap-3">
          {activeIncident && activeSevMeta ? (
            <>
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono tabular-nums">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`font-semibold ${activeSevMeta.text}`}>
                      {activeSevMeta.label}
                    </span>
                    <span aria-hidden="true" className="text-zinc-700">
                      ·
                    </span>
                    <span className="text-zinc-300">
                      {activeIncident.sourceLabel}
                    </span>
                    <span aria-hidden="true" className="text-zinc-700">
                      ·
                    </span>
                    <span className="text-zinc-400">
                      {formatShortDateTime(activeIncident.isoTimestamp)} WIB
                    </span>
                  </div>
                  <ActionTooltip
                    label={activeIncident.destinationLabel}
                    description="Buka halaman sumber detail dari insiden yang sedang disorot."
                    scope={isDemo ? 'DEMO' : 'LIVE'}
                  >
                    <button
                      type="button"
                      onClick={() => onNavigateView(activeIncident.destinationView)}
                      className="inline-flex items-center gap-1 text-[11px] font-sans font-medium text-emerald-400 hover:text-emerald-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <span>{activeIncident.destinationLabel}</span>
                      <ArrowUpRight className="w-3.5 h-3.5" />
                    </button>
                  </ActionTooltip>
                </div>

                <h3 className="text-sm font-semibold text-zinc-100 leading-snug">
                  {activeIncident.title}
                </h3>
                <p className="text-xs text-zinc-400 leading-relaxed line-clamp-2">
                  {activeIncident.detail}
                </p>
              </div>

              <div className="text-[11px] font-mono text-zinc-500 truncate">
                Target:{' '}
                <span className="text-zinc-300">{activeIncident.target}</span>
              </div>
            </>
          ) : (
            <div className="py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <p className="text-xs font-medium text-zinc-200">
                  No security incidents recorded near{' '}
                  <span className="font-mono tabular-nums text-emerald-400">
                    {formatHourTickWIB(playheadMs)} WIB
                  </span>
                </p>
                {isDemo && (
                  <p className="text-[11px] text-zinc-500 mt-0.5">
                    {filteredIncidents.length > 0
                      ? 'Scrub horizontally across highlighted bars or step to the nearest recorded incident.'
                      : 'No events matched the selected severity filter within the last 24 hours.'}
                  </p>
                )}
              </div>
              {filteredIncidents.length > 0 && (
                <ActionTooltip
                  label="Lompat ke Insiden Terbaru"
                  description="Arahkan playhead langsung ke insiden paling akhir pada rentang 24 jam."
                  scope={isDemo ? 'DEMO' : 'LIVE'}
                >
                  <button
                    type="button"
                    onClick={() =>
                      jumpToIncident(
                        filteredIncidents[filteredIncidents.length - 1]
                      )
                    }
                    className="px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Jump to Latest Incident
                  </button>
                </ActionTooltip>
              )}
            </div>
          )}
        </div>

        {/* Incidents in Scrubbed Time Window (5 cols) */}
        <div className="lg:col-span-5 p-4 flex flex-col gap-2">
          <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400">
            <span>Events in Scrubbed Window</span>
            <span className="tabular-nums text-zinc-500">
              {nearbyIncidents.length} matched
            </span>
          </div>

          {nearbyIncidents.length > 0 ? (
            <div className="divide-y divide-zinc-800/60 max-h-[124px] overflow-y-auto pr-1">
              {nearbyIncidents.slice(0, 8).map((inc) => {
                const sev = getSeverityColor(inc.severity);
                const selected = activeIncident?.id === inc.id;
                return (
                  <ActionTooltip
                    key={inc.id}
                    label={`${sev.label} · ${formatHourTickWIB(inc.timestampMs)} WIB`}
                    description={`Sorot detail "${inc.title}" di linimasa.`}
                    scope={isDemo ? 'DEMO' : 'LIVE'}
                    className="block w-full"
                  >
                    <button
                      type="button"
                      onClick={() => jumpToIncident(inc)}
                      className={`w-full py-1.5 px-2 text-left flex items-center justify-between gap-2 rounded transition-colors cursor-pointer ${
                        selected
                          ? 'bg-zinc-800/80 text-zinc-100'
                          : 'hover:bg-zinc-900/70 text-zinc-300'
                      }`}
                    >
                      <div className="min-w-0 flex items-center gap-2">
                        <span
                          className={`font-mono text-[10px] font-semibold w-14 shrink-0 ${sev.text}`}
                        >
                          {sev.label}
                        </span>
                        <span className="text-xs truncate">{inc.title}</span>
                      </div>
                      <span className="font-mono text-[10px] tabular-nums text-zinc-500 shrink-0">
                        {formatHourTickWIB(inc.timestampMs)}
                      </span>
                    </button>
                  </ActionTooltip>
                );
              })}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-zinc-500 py-3">
              Quiet period — no alerts in this ±45 min slice.
            </div>
          )}
        </div>
      </div>
    </section>
  );
};
