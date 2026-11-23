import React, { useMemo, useRef, useState } from 'react';
import { geoNaturalEarth1, geoPath, geoGraticule10 } from 'd3-geo';
import { feature } from 'topojson-client';
import type { Topology, GeometryCollection } from 'topojson-specification';
import worldAtlas from 'world-atlas/countries-110m.json';
import {
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Crosshair,
  Globe,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';
import {
  GlobalThreatIntelSnapshot,
  RealEndpointProbe,
} from '../types/soc';
import { useSocMode } from '../context/SocModeContext';
import { ActionTooltip } from './ActionTooltip';

interface RealInfrastructureMapProps {
  endpoints: RealEndpointProbe[];
  threatIntel: GlobalThreatIntelSnapshot | null;
  probeOriginLabel: string;
}

interface PlottedThreatNode {
  id: string;
  country: string;
  coords: [number, number]; // [lng, lat]
  kind: 'BOTNET_C2' | 'RANSOMWARE';
  count: number;
  headline: string;
  subline: string;
  onlineCount: number;
}

// Accurate [lng, lat] centroids for real ISO-2 country codes returned by abuse.ch Feodo & Ransomware.live
const COUNTRY_COORDS: Record<string, [number, number]> = {
  US: [-98.5, 39.8],
  CA: [-106.3, 56.1],
  MX: [-102.5, 23.6],
  BR: [-51.9, -14.2],
  AR: [-63.6, -38.4],
  CO: [-74.3, 4.6],
  CL: [-71.5, -35.7],
  GB: [-2.5, 54.0],
  UK: [-2.5, 54.0],
  DE: [10.4, 51.2],
  FR: [2.2, 46.2],
  NL: [5.3, 52.1],
  ES: [-3.7, 40.4],
  IT: [12.6, 41.9],
  CH: [8.2, 46.8],
  SE: [18.6, 60.1],
  NO: [8.5, 60.5],
  FI: [25.7, 61.9],
  PL: [19.1, 51.9],
  CZ: [15.5, 49.8],
  AT: [14.6, 47.5],
  BE: [4.5, 50.5],
  IE: [-8.2, 53.4],
  PT: [-8.2, 39.4],
  UA: [31.2, 48.4],
  RO: [25.0, 45.9],
  BG: [25.5, 42.7],
  RU: [60.6, 56.8],
  TR: [35.2, 39.0],
  IL: [34.8, 31.0],
  AE: [53.8, 23.4],
  SA: [45.1, 23.9],
  EG: [30.8, 26.8],
  ZA: [22.9, -30.6],
  NG: [8.7, 9.1],
  IN: [78.9, 20.6],
  PK: [69.3, 30.4],
  CN: [104.2, 35.9],
  HK: [114.2, 22.3],
  TW: [121.0, 23.7],
  JP: [138.2, 36.2],
  KR: [127.8, 35.9],
  VN: [108.3, 14.1],
  TH: [100.9, 15.9],
  MY: [101.9, 4.2],
  SG: [103.82, 1.35],
  PH: [121.8, 12.9],
  ID: [113.9, -2.5],
  AU: [133.8, -25.3],
  NZ: [174.9, -40.9],
};

const MAP_WIDTH = 1000;
const MAP_HEIGHT = 480;

const JAKARTA_COORDS: [number, number] = [106.8456, -6.2088];
const SG_PROBE_COORDS: [number, number] = [103.8198, 1.3521];

export const RealInfrastructureMap: React.FC<RealInfrastructureMapProps> = ({
  endpoints,
  threatIntel,
  probeOriginLabel,
}) => {
  const { isDemo } = useSocMode();
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [selectedNode, setSelectedNode] = useState<PlottedThreatNode | null>(
    null
  );
  const [showGlobalThreats, setShowGlobalThreats] = useState(true);
  const dragStartRef = useRef<{
    clientX: number;
    clientY: number;
    panX: number;
    panY: number;
  } | null>(null);

  // Build accurate Natural Earth vector geography once
  const { countries, graticulePath, projection, jktXY, sgXY } = useMemo(() => {
    const topo = worldAtlas as unknown as Topology<{
      countries: GeometryCollection<{ name: string }>;
    }>;
    const geoCountries = feature(topo, topo.objects.countries);
    const proj = geoNaturalEarth1().fitExtent(
      [
        [14, 14],
        [MAP_WIDTH - 14, MAP_HEIGHT - 14],
      ],
      geoCountries
    );
    const pathGen = geoPath(proj);

    const countryPaths = geoCountries.features
      .filter((f) => String(f.id) !== '010') // Exclude Antarctica for spacious tactical aspect ratio
      .map((f, idx) => ({
        id: String(f.id ?? idx),
        name: f.properties?.name ?? '',
        d: pathGen(f) ?? '',
        isIndonesia: String(f.id) === '360',
      }));

    const grat = pathGen(geoGraticule10()) ?? '';
    const jkt = proj(JAKARTA_COORDS) ?? [780, 290];
    const sg = proj(SG_PROBE_COORDS) ?? [770, 265];

    return {
      countries: countryPaths,
      graticulePath: grat,
      projection: proj,
      jktXY: jkt as [number, number],
      sgXY: sg as [number, number],
    };
  }, []);

  // Build 100% REAL global threat nodes from abuse.ch Feodo Botnet C2 + Ransomware.live
  const threatNodes: PlottedThreatNode[] = useMemo(() => {
    if (!threatIntel) return [];
    const grouped = new Map<string, PlottedThreatNode>();

    for (const c2 of threatIntel.botnetC2.indicators) {
      const cc = c2.country.toUpperCase();
      const coords = COUNTRY_COORDS[cc];
      if (!coords) continue;
      const key = `C2-${cc}`;
      const existing = grouped.get(key);
      if (existing) {
        existing.count += 1;
        if (c2.status === 'online') existing.onlineCount += 1;
      } else {
        grouped.set(key, {
          id: key,
          country: cc,
          coords,
          kind: 'BOTNET_C2',
          count: 1,
          onlineCount: c2.status === 'online' ? 1 : 0,
          headline: `${c2.malware} C2 · ${c2.ip_address}:${c2.port}`,
          subline: `${c2.as_name ?? (c2.as_number ? `AS${c2.as_number}` : cc)} · Last online ${c2.last_online}`,
        });
      }
    }

    for (const rw of threatIntel.ransomware.recent) {
      const cc = rw.country.toUpperCase();
      const coords = COUNTRY_COORDS[cc];
      if (!coords) continue;
      const key = `RW-${cc}`;
      const existing = grouped.get(key);
      if (existing) {
        existing.count += 1;
      } else {
        grouped.set(key, {
          id: key,
          country: cc,
          coords: [coords[0] + 1.8, coords[1] - 1.4], // Slight offset if same country has C2
          kind: 'RANSOMWARE',
          count: 1,
          onlineCount: 0,
          headline: `Ransomware (${rw.group}) · ${rw.victim}`,
          subline: `Sector: ${rw.activity} · Country: ${cc}`,
        });
      }
    }

    return Array.from(grouped.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 18);
  }, [threatIntel]);

  const primary = endpoints[0];
  const primaryHealthy = primary?.status === 'UP';
  const primaryDown = primary?.status === 'DOWN';
  const probeArcColor = primaryDown
    ? '#f43f5e'
    : primary?.status === 'DEGRADED'
    ? '#f59e0b'
    : '#10b981';

  // Clamp pan within reasonable viewport bounds
  const clampPan = (nx: number, ny: number, targetZoom: number) => {
    const maxOffsetX = ((targetZoom - 1) * MAP_WIDTH) / 2 + 80;
    const maxOffsetY = ((targetZoom - 1) * MAP_HEIGHT) / 2 + 60;
    return {
      x: Math.max(-maxOffsetX, Math.min(maxOffsetX, nx)),
      y: Math.max(-maxOffsetY, Math.min(maxOffsetY, ny)),
    };
  };

  const handleZoomIn = () => {
    setZoom((z) => {
      const next = Math.min(5.5, Number((z * 1.35).toFixed(2)));
      setPan((p) => clampPan(p.x * (next / z), p.y * (next / z), next));
      return next;
    });
  };

  const handleZoomOut = () => {
    setZoom((z) => {
      const next = Math.max(1, Number((z / 1.35).toFixed(2)));
      if (next <= 1.02) {
        setPan({ x: 0, y: 0 });
        return 1;
      }
      setPan((p) => clampPan(p.x * (next / z), p.y * (next / z), next));
      return next;
    });
  };

  const handleResetGlobal = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
  };

  const handleFocusIndonesia = () => {
    const targetZoom = 3.5;
    const centerX = MAP_WIDTH / 2;
    const centerY = MAP_HEIGHT / 2;
    // Focus slightly east of Jakarta so Sumatra → Papua sits squarely in center
    const indoCenter = projection([115.5, -2.5]) ?? jktXY;
    const nextX = (centerX - indoCenter[0]) * targetZoom;
    const nextY = (centerY - indoCenter[1]) * targetZoom;
    setZoom(targetZoom);
    setPan(clampPan(nextX, nextY, targetZoom));
  };

  const handleWheel = (e: React.WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    if (e.deltaY < 0) {
      handleZoomIn();
    } else {
      handleZoomOut();
    }
  };

  const handlePointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    setIsDragging(true);
    dragStartRef.current = {
      clientX: e.clientX,
      clientY: e.clientY,
      panX: pan.x,
      panY: pan.y,
    };
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const handlePointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!isDragging || !dragStartRef.current) return;
    const dx = e.clientX - dragStartRef.current.clientX;
    const dy = e.clientY - dragStartRef.current.clientY;
    setPan(
      clampPan(
        dragStartRef.current.panX + dx,
        dragStartRef.current.panY + dy,
        zoom
      )
    );
  };

  const handlePointerUp = (e: React.PointerEvent<SVGSVGElement>) => {
    if (isDragging) {
      setIsDragging(false);
      dragStartRef.current = null;
      if (e.currentTarget.hasPointerCapture(e.pointerId)) {
        e.currentTarget.releasePointerCapture(e.pointerId);
      }
    }
  };

  // Scale-compensated stroke & marker sizing for razor-sharp zoom
  const invScale = 1 / Math.sqrt(zoom);

  // Curved quadratic Bezier helper
  const makeCurve = (
    from: [number, number],
    to: [number, number],
    lift = 0.22
  ) => {
    const mx = (from[0] + to[0]) / 2;
    const my = (from[1] + to[1]) / 2;
    const dist = Math.hypot(to[0] - from[0], to[1] - from[1]);
    const cy = my - Math.min(110, dist * lift);
    return `M ${from[0].toFixed(1)} ${from[1].toFixed(1)} Q ${mx.toFixed(
      1
    )} ${cy.toFixed(1)} ${to[0].toFixed(1)} ${to[1].toFixed(1)}`;
  };

  const sgToJktCurve = makeCurve(sgXY, jktXY, 0.32);

  // SVG center transform for smooth zoom/pan
  const transformStr = `translate(${MAP_WIDTH / 2 + pan.x}, ${
    MAP_HEIGHT / 2 + pan.y
  }) scale(${zoom}) translate(${-MAP_WIDTH / 2}, ${-MAP_HEIGHT / 2})`;

  return (
    <div className="flex flex-col bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-zinc-800/80">
        <div className="flex items-center gap-2.5 min-w-0">
          <Globe className="w-4 h-4 text-emerald-400 shrink-0" />
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-zinc-100 truncate">
              Global Cyber Threat Radar &amp; Infrastructure Topology
            </h2>
            {isDemo && (
              <p className="text-xs text-zinc-400 truncate">
                Peta vektor Natural Earth interaktif · {probeOriginLabel} → Primary Origin Edge · Feed Botnet C2 &amp; Ransomware Live
              </p>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <ActionTooltip
            label="Toggle Global CTI Arcs"
            description="Tampilkan atau sembunyikan jalur node Botnet C2 & Ransomware global di peta."
            scope={isDemo ? 'DEMO' : 'LIVE'}
          >
            <label className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400 mr-1 cursor-pointer select-none whitespace-nowrap shrink-0">
              <input
                type="checkbox"
                checked={showGlobalThreats}
                onChange={(e) => setShowGlobalThreats(e.target.checked)}
                className="accent-rose-500"
              />
              Global CTI Arcs ({threatNodes.length})
            </label>
          </ActionTooltip>

          <div className="inline-flex items-center bg-zinc-950 border border-zinc-800 rounded-md p-0.5">
            <ActionTooltip
              label="Fokus Indonesia"
              description="Zoom dan pusatkan peta ke wilayah Indonesia & Primary Origin Edge."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={handleFocusIndonesia}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-emerald-400 hover:bg-zinc-900 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Crosshair className="w-3 h-3" />
                Indonesia
              </button>
            </ActionTooltip>
            <ActionTooltip
              label="Reset Peta Global"
              description="Kembalikan tampilan zoom 1.0x seluruh dunia."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={handleResetGlobal}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-zinc-300 hover:bg-zinc-900 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RotateCcw className="w-3 h-3" />
                Global
              </button>
            </ActionTooltip>
          </div>

          <div className="inline-flex items-center bg-zinc-950 border border-zinc-800 rounded-md p-0.5">
            <ActionTooltip
              label="Perkecil Peta"
              description="Kurangi perbesaran peta ancaman."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={handleZoomOut}
                disabled={zoom <= 1}
                aria-label="Zoom out map"
                className="p-1.5 text-zinc-300 hover:text-white hover:bg-zinc-900 rounded disabled:opacity-40 cursor-pointer"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
            </ActionTooltip>
            <span className="px-2 font-mono text-[11px] text-zinc-300 tabular-nums min-w-[44px] text-center">
              {zoom.toFixed(1)}x
            </span>
            <ActionTooltip
              label="Perbesar Peta"
              description="Perbesar tampilan peta ancaman."
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={handleZoomIn}
                disabled={zoom >= 5.5}
                aria-label="Zoom in map"
                className="p-1.5 text-zinc-300 hover:text-white hover:bg-zinc-900 rounded disabled:opacity-40 cursor-pointer"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
            </ActionTooltip>
          </div>
        </div>
      </div>

      {/* Interactive Zoomable World SVG Stage */}
      <div className="relative w-full h-[380px] sm:h-[430px] lg:h-[480px] bg-zinc-950 overflow-hidden">
        <svg
          viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
          onWheel={handleWheel}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerLeave={handlePointerUp}
          className={`w-full h-full select-none touch-none ${
            isDragging ? 'cursor-grabbing' : 'cursor-grab'
          }`}
          role="img"
          aria-label="Interactive global cyber threat map centered on primary target infrastructure"
        >
          <defs>
            <radialGradient id="oceanGlow" cx="76%" cy="62%" r="55%">
              <stop offset="0%" stopColor="#064e3b" stopOpacity="0.16" />
              <stop offset="100%" stopColor="#09090b" stopOpacity="0" />
            </radialGradient>
          </defs>

          <rect width={MAP_WIDTH} height={MAP_HEIGHT} fill="url(#oceanGlow)" />

          <g transform={transformStr}>
            {/* Subtle cartographic lat/lon graticule */}
            <path
              d={graticulePath}
              fill="none"
              stroke="#27272a"
              strokeWidth={0.5 * invScale}
              strokeOpacity={0.35}
            />

            {/* Accurate Natural Earth Countries & Islands */}
            <g>
              {countries.map((c) => (
                <path
                  key={c.id}
                  d={c.d}
                  fill={c.isIndonesia ? '#065f46' : '#18181b'}
                  fillOpacity={c.isIndonesia ? 0.88 : 0.96}
                  stroke={c.isIndonesia ? '#10b981' : '#3f3f46'}
                  strokeWidth={(c.isIndonesia ? 1.15 : 0.65) * invScale}
                  strokeLinejoin="round"
                />
              ))}
            </g>

            {/* 100% Real Global Threat Intelligence Arcs (Feodo Botnet C2 + Ransomware.live) */}
            {showGlobalThreats &&
              threatNodes.map((node) => {
                const xy = projection(node.coords);
                if (!xy) return null;
                const arcColor =
                  node.kind === 'BOTNET_C2' ? '#f43f5e' : '#f59e0b';
                const curve = makeCurve(xy as [number, number], jktXY, 0.2);
                const isSelected = selectedNode?.id === node.id;

                return (
                  <g
                    key={node.id}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNode(isSelected ? null : node);
                    }}
                    className="cursor-pointer"
                  >
                    <path
                      d={curve}
                      fill="none"
                      stroke={arcColor}
                      strokeWidth={(isSelected ? 1.8 : 0.95) * invScale}
                      strokeOpacity={isSelected ? 0.85 : 0.28}
                    />
                    <path
                      d={curve}
                      fill="none"
                      stroke={arcColor}
                      strokeWidth={(isSelected ? 2 : 1.1) * invScale}
                      strokeDasharray={`${4 * invScale} ${10 * invScale}`}
                      strokeOpacity={isSelected ? 1 : 0.6}
                      className="animate-arc-flow"
                    />
                    <circle
                      cx={xy[0]}
                      cy={xy[1]}
                      r={(isSelected ? 5.5 : Math.min(4.8, 2.6 + node.count * 0.28)) * invScale}
                      fill={arcColor}
                      fillOpacity={0.9}
                      stroke="#09090b"
                      strokeWidth={1 * invScale}
                    />
                    {(zoom >= 1.5 || isSelected || node.count >= 4) && (
                      <text
                        x={xy[0] + 6 * invScale}
                        y={xy[1] + 3 * invScale}
                        fill="#e4e4e7"
                        fontSize={8.5 * invScale}
                        fontFamily="IBM Plex Mono, monospace"
                        fontWeight="600"
                      >
                        {node.country} ({node.count})
                      </text>
                    )}
                  </g>
                );
              })}

            {/* Live SOC Probe Route: Asia-Southeast (SG) -> Primary Origin Edge */}
            <path
              d={sgToJktCurve}
              fill="none"
              stroke={probeArcColor}
              strokeWidth={1.9 * invScale}
              strokeOpacity={0.4}
            />
            <path
              d={sgToJktCurve}
              fill="none"
              stroke={probeArcColor}
              strokeWidth={2 * invScale}
              strokeDasharray={`${5 * invScale} ${7 * invScale}`}
              className="animate-arc-flow"
            />
            <circle r={2.8 * invScale} fill={probeArcColor}>
              <animateMotion
                dur="2s"
                repeatCount="indefinite"
                path={sgToJktCurve}
              />
            </circle>

            {/* Singapore Probe Node */}
            <circle
              cx={sgXY[0]}
              cy={sgXY[1]}
              r={3.8 * invScale}
              fill="#38bdf8"
              stroke="#09090b"
              strokeWidth={1.2 * invScale}
            />
            <text
              x={sgXY[0] - 58 * invScale}
              y={sgXY[1] - 7 * invScale}
              fill="#7dd3fc"
              fontSize={8.5 * invScale}
              fontFamily="IBM Plex Mono, monospace"
              fontWeight="600"
            >
              SOC PROBE (SG)
            </text>

            {/* Primary Target Core Hub */}
            <circle
              cx={jktXY[0]}
              cy={jktXY[1]}
              r={9 * invScale}
              fill="none"
              stroke={probeArcColor}
              strokeWidth={1.3 * invScale}
              className="animate-target-ripple"
            />
            <circle
              cx={jktXY[0]}
              cy={jktXY[1]}
              r={4.8 * invScale}
              fill={probeArcColor}
              stroke="#09090b"
              strokeWidth={1.4 * invScale}
            />
            <text
              x={jktXY[0] + 9 * invScale}
              y={jktXY[1] + 3 * invScale}
              fill="#f4f4f5"
              fontSize={9.5 * invScale}
              fontFamily="IBM Plex Mono, monospace"
              fontWeight="700"
            >
              TARGET EDGE · ID
            </text>
            {primary?.dns.ipv4[0] && (
              <text
                x={jktXY[0] + 9 * invScale}
                y={jktXY[1] + 14 * invScale}
                fill="#34d399"
                fontSize={8 * invScale}
                fontFamily="IBM Plex Mono, monospace"
              >
                {primary.dns.ipv4[0]} · {primary.latencyMs ?? '-'} ms
              </text>
            )}
          </g>
        </svg>

        {/* Floating Bottom-Left Legend */}
        <div className="absolute bottom-3 left-3 bg-zinc-950/90 backdrop-blur-sm border border-zinc-800/90 rounded-md px-3 py-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-zinc-300 pointer-events-none">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            Target Edge ({primaryHealthy ? 'UP' : primary?.status ?? '...'})
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-sky-400" />
            SOC Live Probe
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-rose-500" />
            abuse.ch Botnet C2
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            Ransomware.live
          </span>
        </div>

        {/* Floating Top-Right Selected Threat Inspector */}
        {selectedNode ? (
          <div className="absolute top-3 right-3 max-w-xs bg-zinc-950/95 backdrop-blur-sm border border-zinc-700 rounded-md p-3 text-xs space-y-1 shadow-lg">
            <div className="flex items-center justify-between gap-2">
              <span
                className={`font-mono text-[11px] font-semibold flex items-center gap-1 ${
                  selectedNode.kind === 'BOTNET_C2'
                    ? 'text-rose-400'
                    : 'text-amber-400'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                {selectedNode.kind === 'BOTNET_C2'
                  ? 'LIVE BOTNET C2 ORIGIN'
                  : 'LIVE RANSOMWARE CAMPAIGN'}
              </span>
              <ActionTooltip
                label="Tutup Detail Node"
                description="Tutup kartu inspeksi node ancaman yang dipilih."
                scope={isDemo ? 'DEMO' : 'LIVE'}
              >
                <button
                  type="button"
                  onClick={() => setSelectedNode(null)}
                  className="text-[11px] text-zinc-400 hover:text-zinc-100 cursor-pointer whitespace-nowrap shrink-0"
                >
                  Tutup
                </button>
              </ActionTooltip>
            </div>
            <p className="font-mono text-zinc-100 font-semibold break-all">
              {selectedNode.headline}
            </p>
            <p className="text-[11px] text-zinc-400">{selectedNode.subline}</p>
            <p className="font-mono text-[10px] text-zinc-500 pt-1 border-t border-zinc-800">
              Region: {selectedNode.country} · {selectedNode.count} active live indicator(s)
            </p>
          </div>
        ) : isDemo ? (
          <div className="hidden sm:flex absolute top-3 right-3 bg-zinc-950/85 backdrop-blur-sm border border-zinc-800/80 rounded-md px-3 py-1.5 items-center gap-2 text-[11px] font-mono text-zinc-400 pointer-events-none">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Scroll / Drag untuk Zoom &amp; Geser · Klik titik merah/amber untuk detail</span>
          </div>
        ) : null}
      </div>

      {/* Bottom Real Telemetry Strip */}
      <div className="px-4 py-2.5 border-t border-zinc-800/80 bg-zinc-950/70 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-zinc-400 tabular-nums">
        <span className="truncate">
          Target Edge: <strong className="text-zinc-200">{primary?.dns.cname[0] ?? primary?.hostname ?? '-'}</strong> · IPv4:{' '}
          <strong className="text-emerald-400">{primary?.dns.ipv4[0] ?? '-'}</strong>
        </span>
        <div className="flex items-center gap-4 shrink-0">
          <span>
            RTT:{' '}
            <strong className="text-zinc-100">
              {primary?.latencyMs !== null && primary?.latencyMs !== undefined
                ? `${primary.latencyMs} ms`
                : 'Probing...'}
            </strong>
          </span>
          <span className="text-emerald-400">
            {primary?.tls?.protocol ?? 'TLS'} · {primary?.tls?.daysRemaining ?? '-'}d valid
          </span>
        </div>
      </div>
    </div>
  );
};
