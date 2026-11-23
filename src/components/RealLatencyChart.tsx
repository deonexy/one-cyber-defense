import React from 'react';
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { RealLatencyPoint } from '../types/soc';
import { useSocMode } from '../context/SocModeContext';

interface RealLatencyChartProps {
  latencyHistory: RealLatencyPoint[];
  probeIntervalMs: number;
}

export const RealLatencyChart: React.FC<RealLatencyChartProps> = ({
  latencyHistory,
  probeIntervalMs,
}) => {
  const { isDemo } = useSocMode();
  const latest = latencyHistory[latencyHistory.length - 1];

  return (
    <div className="flex flex-col h-full bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-zinc-800/80">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">
            {isDemo
              ? 'Demo Sandbox Response Latency'
              : 'Live Measured Response Latency (HTTP Probes)'}
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5 font-mono tabular-nums">
            {latest
              ? `Portal Utama ${latest.primaryMs ?? '-'} ms · /login ${latest.loginMs ?? '-'} ms · Portal Sekunder ${latest.secondaryMs ?? '-'} ms`
              : 'Waiting for first HTTP/TLS probe cycle...'}
          </p>
        </div>

        <span className="font-mono text-[11px] text-emerald-400 whitespace-nowrap shrink-0">
          {isDemo
            ? `Demo Snapshot (${probeIntervalMs / 1000}s cadence)`
            : `Live Probe Every ${probeIntervalMs / 1000}s`}
        </span>
      </div>

      <div className="flex-1 p-4 min-h-[280px] flex items-center justify-center">
        {latencyHistory.length === 0 ? (
          <div className="text-center space-y-1.5">
            <p className="text-xs font-medium text-zinc-300">
              Executing initial real HTTP/TLS measurements...
            </p>
            <p className="text-[11px] font-mono text-zinc-500">
              Probing configured HTTPS targets...
            </p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <LineChart
              data={latencyHistory}
              margin={{ top: 10, right: 12, left: -10, bottom: 0 }}
            >
              <CartesianGrid
                stroke="#27272a"
                strokeDasharray="3 3"
                vertical={false}
              />
              <XAxis
                dataKey="time"
                stroke="#71717a"
                tick={{ fontSize: 10, fontFamily: 'IBM Plex Mono, monospace' }}
                tickLine={false}
                axisLine={false}
                minTickGap={24}
              />
              <YAxis
                stroke="#71717a"
                tick={{ fontSize: 10, fontFamily: 'IBM Plex Mono, monospace' }}
                tickLine={false}
                axisLine={false}
                unit="ms"
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#09090b',
                  borderColor: '#27272a',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontFamily: 'IBM Plex Mono, monospace',
                }}
                labelStyle={{ color: '#a1a1aa', marginBottom: '4px' }}
              />
              <Line
                type="monotone"
                dataKey="primaryMs"
                name="Portal Utama (ms)"
                stroke="#10b981"
                strokeWidth={2}
                dot={{ r: 3, fill: '#10b981' }}
                connectNulls
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="loginMs"
                name="/login Endpoint (ms)"
                stroke="#f59e0b"
                strokeWidth={1.75}
                dot={{ r: 2.5, fill: '#f59e0b' }}
                connectNulls
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="secondaryMs"
                name="Portal Sekunder (ms)"
                stroke="#38bdf8"
                strokeWidth={1.5}
                dot={{ r: 2.5, fill: '#38bdf8' }}
                connectNulls
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-t border-zinc-800/80 bg-zinc-950/60 text-[11px] text-zinc-400">
        <div className="flex flex-wrap items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-emerald-500 inline-block" />
            Portal Utama
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-amber-500 inline-block" />
            /login
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-sky-400 inline-block" />
            Portal Sekunder
          </span>
        </div>
        <span className="font-mono text-zinc-500 tabular-nums">
          {latencyHistory.length} {isDemo ? 'demo' : 'live'} sample{latencyHistory.length === 1 ? '' : 's'}
        </span>
      </div>
    </div>
  );
};
