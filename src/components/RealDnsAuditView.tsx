import React from 'react';
import { Globe, MailCheck, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { RealDnsSecurityAudit, RealEndpointProbe } from '../types/soc';
import { formatShortDateTime } from '../utils/socFormatters';
import { useSocMode } from '../context/SocModeContext';

interface RealDnsAuditViewProps {
  dnsAudit: RealDnsSecurityAudit | null;
  endpoints: RealEndpointProbe[];
}

export const RealDnsAuditView: React.FC<RealDnsAuditViewProps> = ({
  dnsAudit,
  endpoints,
}) => {
  const { isDemo } = useSocMode();
  if (!dnsAudit) {
    return (
      <div className="p-10 text-center text-xs text-zinc-500 bg-zinc-900/40 border border-zinc-800/80 rounded-lg">
        Running live public DNS (SPF, DMARC, CAA, MX, NS) lookup...
      </div>
    );
  }

  const spfGood =
    dnsAudit.spf.policy === 'HARD_FAIL' || dnsAudit.spf.policy === 'SOFT_FAIL';
  const dmarcStrong =
    dnsAudit.dmarc.policy === 'reject' || dnsAudit.dmarc.policy === 'quarantine';

  return (
    <div className="space-y-5">
      {/* Top KPI Summary Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-zinc-800/80 bg-zinc-900/40 border border-zinc-800/80 rounded-lg">
        <div className="p-4">
          <p className="text-xs text-zinc-400">DNS &amp; Email Score</p>
          <p
            className={`mt-1.5 font-mono text-2xl font-semibold tabular-nums ${
              dnsAudit.score >= 80
                ? 'text-emerald-400'
                : dnsAudit.score >= 50
                ? 'text-amber-400'
                : 'text-rose-400'
            }`}
          >
            {dnsAudit.score}/100
          </p>
          <p className="mt-1 text-[11px] font-mono text-zinc-500">
            Root: {dnsAudit.rootDomain}
          </p>
        </div>
        <div className="p-4">
          <p className="text-xs text-zinc-400">SPF Policy</p>
          <p
            className={`mt-1.5 font-mono text-xl font-semibold ${
              spfGood ? 'text-emerald-400' : 'text-rose-400'
            }`}
          >
            {dnsAudit.spf.policy}
          </p>
          {isDemo && (
            <p className="mt-1 text-[11px] text-zinc-500">
              Sender Policy Framework TXT
            </p>
          )}
        </div>
        <div className="p-4">
          <p className="text-xs text-zinc-400">DMARC Enforcement</p>
          <p
            className={`mt-1.5 font-mono text-xl font-semibold ${
              dmarcStrong
                ? 'text-emerald-400'
                : dnsAudit.dmarc.policy === 'none'
                ? 'text-amber-400'
                : 'text-rose-400'
            }`}
          >
            {dnsAudit.dmarc.policy === 'MISSING'
              ? 'MISSING'
              : `p=${dnsAudit.dmarc.policy}`}
          </p>
          {isDemo && (
            <p className="mt-1 text-[11px] text-zinc-500">
              Anti-spoofing &amp; phishing protection
            </p>
          )}
        </div>
        <div className="p-4">
          <p className="text-xs text-zinc-400">CAA Certificate Lock</p>
          <p
            className={`mt-1.5 font-mono text-xl font-semibold ${
              dnsAudit.caa.present ? 'text-emerald-400' : 'text-amber-400'
            }`}
          >
            {dnsAudit.caa.present
              ? `${dnsAudit.caa.records.length} Record(s)`
              : 'MISSING'}
          </p>
          {isDemo && (
            <p className="mt-1 text-[11px] text-zinc-500">
              CA issuance authorization
            </p>
          )}
        </div>
      </div>

      {/* Live DNS Records Audit Detail */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch">
        <div className="xl:col-span-7 bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <MailCheck className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-zinc-100">
                Live Anti-Phishing &amp; CA Authorization Records ({dnsAudit.rootDomain})
              </h2>
            </div>
            <span className="font-mono text-[11px] text-zinc-500 tabular-nums">
              {formatShortDateTime(dnsAudit.checkedAt)} WIB
            </span>
          </div>

          <div className="divide-y divide-zinc-800/70 text-xs">
            {/* SPF */}
            <div className="p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-zinc-100">
                  SPF Record ({dnsAudit.rootDomain})
                </span>
                <span
                  className={`inline-flex items-center gap-1 font-mono text-[11px] font-semibold ${
                    spfGood ? 'text-emerald-400' : 'text-rose-400'
                  }`}
                >
                  {spfGood ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : (
                    <ShieldAlert className="w-3.5 h-3.5" />
                  )}
                  {dnsAudit.spf.policy}
                </span>
              </div>
              <pre className="p-2.5 bg-zinc-950 border border-zinc-800 rounded font-mono text-[11px] text-zinc-300 whitespace-pre-wrap break-all">
                {dnsAudit.spf.record ?? 'No SPF TXT record published.'}
              </pre>
            </div>

            {/* DMARC */}
            <div className="p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-zinc-100">
                  DMARC Record (_dmarc.{dnsAudit.rootDomain})
                </span>
                <span
                  className={`inline-flex items-center gap-1 font-mono text-[11px] font-semibold ${
                    dmarcStrong
                      ? 'text-emerald-400'
                      : dnsAudit.dmarc.policy === 'none'
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {dmarcStrong ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : (
                    <ShieldAlert className="w-3.5 h-3.5" />
                  )}
                  {dnsAudit.dmarc.policy === 'MISSING'
                    ? 'MISSING'
                    : `p=${dnsAudit.dmarc.policy}`}
                </span>
              </div>
              <pre className="p-2.5 bg-zinc-950 border border-zinc-800 rounded font-mono text-[11px] text-amber-200/90 whitespace-pre-wrap break-all">
                {dnsAudit.dmarc.record ?? 'No _dmarc TXT record published.'}
              </pre>
              {isDemo && !dmarcStrong && (
                <p className="text-[11px] text-zinc-400">
                  Rekomendasi: Tingkatkan kebijakan DMARC menuju{' '}
                  <span className="font-mono text-emerald-400">p=quarantine</span>{' '}
                  atau{' '}
                  <span className="font-mono text-emerald-400">p=reject</span>{' '}
                  agar email spoofing mengatasnamakan organisasi ditolak otomatis.
                </p>
              )}
            </div>

            {/* CAA */}
            <div className="p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-zinc-100">
                  CAA Records ({dnsAudit.rootDomain})
                </span>
                <span
                  className={`font-mono text-[11px] font-semibold ${
                    dnsAudit.caa.present ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  {dnsAudit.caa.present ? 'CONFIGURED' : 'NOT CONFIGURED'}
                </span>
              </div>
              <pre className="p-2.5 bg-zinc-950 border border-zinc-800 rounded font-mono text-[11px] text-zinc-300 whitespace-pre-wrap break-all">
                {dnsAudit.caa.present
                  ? dnsAudit.caa.records.join('\n')
                  : isDemo
                  ? '0 CAA records returned — any public CA is technically permitted to issue certificates if domain validation is bypassed.'
                  : '0 CAA records returned'}
              </pre>
            </div>
          </div>
        </div>

        {/* Right Column: Live Resolved Endpoint IPs, MX & NS */}
        <div className="xl:col-span-5 space-y-5">
          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-zinc-800/80 flex items-center gap-2">
              <Globe className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-zinc-100">
                Resolved Live Hostnames &amp; IPv4
              </h2>
            </div>
            <div className="divide-y divide-zinc-800/70 text-xs">
              {endpoints.map((ep) => (
                <div key={ep.id} className="px-4 py-3 space-y-1">
                  <p className="font-mono text-zinc-200 truncate">{ep.hostname}</p>
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[11px] text-zinc-400">
                    <span className="text-emerald-400">
                      A: {ep.dns.ipv4.length > 0 ? ep.dns.ipv4.join(', ') : '—'}
                    </span>
                    {ep.dns.cname.length > 0 && (
                      <>
                        <span className="text-zinc-600">·</span>
                        <span className="truncate">
                          CNAME: {ep.dns.cname[0]}
                        </span>
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-zinc-800/80">
              <h2 className="text-sm font-semibold text-zinc-100">
                Mail Exchangers (MX) &amp; Authoritative NS
              </h2>
            </div>
            <div className="p-4 space-y-3 text-xs font-mono">
              <div>
                <span className="text-zinc-500 block font-sans mb-1">
                  MX Records ({dnsAudit.rootDomain})
                </span>
                {dnsAudit.mx.length > 0 ? (
                  dnsAudit.mx.map((m) => (
                    <div key={m.exchange} className="text-zinc-200 text-[11px]">
                      [{m.priority}] {m.exchange}
                    </div>
                  ))
                ) : (
                  <span className="text-zinc-500 text-[11px]">None</span>
                )}
              </div>
              <div className="pt-2 border-t border-zinc-800/70">
                <span className="text-zinc-500 block font-sans mb-1">
                  Authoritative Nameservers (NS)
                </span>
                {dnsAudit.ns.length > 0 ? (
                  <div className="space-y-0.5">
                    {dnsAudit.ns.map((ns) => (
                      <div key={ns} className="text-zinc-300 text-[11px]">
                        {ns}
                      </div>
                    ))}
                  </div>
                ) : (
                  <span className="text-zinc-500 text-[11px]">None</span>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
