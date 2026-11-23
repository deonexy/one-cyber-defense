import React, { useState } from 'react';
import { Lock, CheckCircle2, XCircle, Shield } from 'lucide-react';
import { RealEndpointProbe } from '../types/soc';
import { formatShortDateTime } from '../utils/socFormatters';
import { useSocMode } from '../context/SocModeContext';
import { ActionTooltip } from './ActionTooltip';

interface RealHeadersTlsViewProps {
  endpoints: RealEndpointProbe[];
}

const HEADER_SPECS: Array<{
  key: keyof RealEndpointProbe['securityHeaders'];
  name: string;
  purpose: string;
}> = [
  {
    key: 'hsts',
    name: 'Strict-Transport-Security (HSTS)',
    purpose: 'Enforces HTTPS-only connections & prevents SSL-stripping downgrade attacks',
  },
  {
    key: 'csp',
    name: 'Content-Security-Policy (CSP)',
    purpose: 'Restricts script/resource origins to mitigate XSS & data injection',
  },
  {
    key: 'xFrameOptions',
    name: 'X-Frame-Options',
    purpose: 'Prevents clickjacking via unauthorized iframe embedding',
  },
  {
    key: 'xContentTypeOptions',
    name: 'X-Content-Type-Options',
    purpose: 'Blocks MIME-type sniffing (nosniff)',
  },
  {
    key: 'referrerPolicy',
    name: 'Referrer-Policy',
    purpose: 'Prevents sensitive URL query parameters from leaking to third parties',
  },
  {
    key: 'permissionsPolicy',
    name: 'Permissions-Policy',
    purpose: 'Controls browser feature access (camera, mic, geolocation)',
  },
];

export const RealHeadersTlsView: React.FC<RealHeadersTlsViewProps> = ({
  endpoints,
}) => {
  const { isDemo } = useSocMode();
  const [selectedId, setSelectedId] = useState<string>(
    endpoints[0]?.id ?? 'ep-primary'
  );

  const selected =
    endpoints.find((e) => e.id === selectedId) ?? endpoints[0] ?? null;

  if (!selected) {
    return (
      <div className="p-10 text-center text-xs text-zinc-500 bg-zinc-900/40 border border-zinc-800/80 rounded-lg">
        Waiting for live HTTP &amp; TLS probe telemetry...
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Endpoint Selector Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-zinc-900/40 border border-zinc-800/80 rounded-lg">
        <div
          className="flex flex-wrap items-center gap-1 p-0.5 bg-zinc-950 border border-zinc-800 rounded-md"
          role="group"
          aria-label="Select endpoint for HTTP header and TLS inspection"
        >
          {endpoints.map((ep) => (
            <ActionTooltip
              key={ep.id}
              label={`Inspeksi ${ep.label}`}
              description={`Lihat detail sertifikat TLS dan 6 HTTP security header untuk ${ep.url}`}
              scope={isDemo ? 'DEMO' : 'LIVE'}
            >
              <button
                type="button"
                onClick={() => setSelectedId(ep.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  selected.id === ep.id
                    ? 'bg-zinc-800 text-zinc-100'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {ep.label}
              </button>
            </ActionTooltip>
          ))}
        </div>

        <div className="font-mono text-xs text-zinc-400 tabular-nums">
          Header Score:{' '}
          <span
            className={
              selected.headerScore >= 80
                ? 'text-emerald-400 font-semibold'
                : selected.headerScore >= 50
                ? 'text-amber-400 font-semibold'
                : 'text-rose-400 font-semibold'
            }
          >
            {selected.headerScore}%
          </span>
        </div>
      </div>

      {/* 2-Column Split: TLS Certificate Details + HTTP Security Headers */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch">
        {/* TLS / SSL Certificate Card */}
        <div className="xl:col-span-5 bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-zinc-100">
                Live TLS / SSL Certificate
              </h2>
            </div>
            <span className="font-mono text-xs text-emerald-400">
              {selected.tls?.protocol ?? 'N/A'}
            </span>
          </div>

          {selected.tls ? (
            <div className="divide-y divide-zinc-800/70 text-xs flex-1">
              <div className="px-4 py-3 flex items-center justify-between gap-3">
                <span className="text-zinc-400">Subject CN</span>
                <span className="font-mono text-zinc-100">
                  {selected.tls.subject ?? '—'}
                </span>
              </div>
              <div className="px-4 py-3 flex items-center justify-between gap-3">
                <span className="text-zinc-400">Issuer CA</span>
                <span className="font-mono text-zinc-100">
                  {selected.tls.issuer ?? '—'}
                </span>
              </div>
              <div className="px-4 py-3 flex items-center justify-between gap-3">
                <span className="text-zinc-400">Cipher Suite</span>
                <span className="font-mono text-[11px] text-emerald-300 text-right break-all">
                  {selected.tls.cipher ?? '—'}
                </span>
              </div>
              <div className="px-4 py-3 flex items-center justify-between gap-3">
                <span className="text-zinc-400">Valid From</span>
                <span className="font-mono text-zinc-300 tabular-nums">
                  {selected.tls.validFrom ?? '—'}
                </span>
              </div>
              <div className="px-4 py-3 flex items-center justify-between gap-3">
                <span className="text-zinc-400">Valid Until</span>
                <span className="font-mono text-zinc-200 tabular-nums">
                  {selected.tls.validTo ?? '—'}
                </span>
              </div>
              <div className="px-4 py-3 flex items-center justify-between gap-3">
                <span className="text-zinc-400">Days Remaining</span>
                <span
                  className={`font-mono font-semibold tabular-nums ${
                    (selected.tls.daysRemaining ?? 0) < 14
                      ? 'text-rose-400'
                      : (selected.tls.daysRemaining ?? 0) < 30
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {selected.tls.daysRemaining !== null
                    ? `${selected.tls.daysRemaining} days`
                    : '—'}
                </span>
              </div>
              <div className="px-4 py-3 flex items-center justify-between gap-3">
                <span className="text-zinc-400">SAN Entries</span>
                <span className="font-mono text-zinc-200 tabular-nums">
                  {selected.tls.sanCount}
                </span>
              </div>
              <div className="px-4 py-3 space-y-1">
                <span className="text-zinc-400 block">SHA-256 Fingerprint</span>
                <span className="font-mono text-[10px] text-zinc-400 break-all block">
                  {selected.tls.fingerprint256 ?? '—'}
                </span>
              </div>
            </div>
          ) : (
            <div className="p-6 text-xs text-zinc-500">
              TLS handshake data unavailable for this endpoint.
            </div>
          )}

          <div className="px-4 py-2.5 border-t border-zinc-800/80 bg-zinc-950/60 flex items-center justify-between text-[11px] font-mono text-zinc-400">
            <span>Cookies: {selected.cookies.count}</span>
            <span>
              Checked:{' '}
              {selected.lastCheckedAt
                ? formatShortDateTime(selected.lastCheckedAt)
                : '—'}
            </span>
          </div>
        </div>

        {/* Live HTTP Security Headers Inspection */}
        <div className="xl:col-span-7 bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
              <div className="min-w-0">
                <h2 className="text-sm font-semibold text-zinc-100">
                  Live HTTP Security Header Inspection
                </h2>
                <p className="font-mono text-[11px] text-zinc-400 truncate">
                  {selected.url}
                </p>
              </div>
            </div>
            <span className="font-mono text-xs text-zinc-300 shrink-0">
              {selected.httpStatus ? `HTTP ${selected.httpStatus}` : selected.status}
            </span>
          </div>

          <div className="divide-y divide-zinc-800/70 flex-1">
            {HEADER_SPECS.map((spec) => {
              const rawValue = selected.securityHeaders[spec.key];
              const present = Boolean(rawValue);
              return (
                <div key={spec.key} className="px-4 py-3.5 space-y-1.5">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs font-medium text-zinc-100">
                      {spec.name}
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 font-mono text-[11px] font-semibold shrink-0 ${
                        present ? 'text-emerald-400' : 'text-rose-400'
                      }`}
                    >
                      {present ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          PRESENT
                        </>
                      ) : (
                        <>
                          <XCircle className="w-3.5 h-3.5" />
                          MISSING
                        </>
                      )}
                    </span>
                  </div>
                  {isDemo && (
                    <p className="text-[11px] text-zinc-400">{spec.purpose}</p>
                  )}
                  {rawValue && (
                    <div className="p-2 bg-zinc-950 border border-zinc-800/80 rounded font-mono text-[10px] text-emerald-300/90 break-all">
                      {rawValue}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="px-4 py-2.5 border-t border-zinc-800/80 bg-zinc-950/60 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-zinc-400">
            <span>
              Server Header: {selected.serverHeader ?? 'Hidden (Good)'}
            </span>
            <span>
              X-Powered-By: {selected.poweredByHeader ?? 'Hidden (Good)'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
