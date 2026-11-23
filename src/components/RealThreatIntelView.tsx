import React, { useMemo, useState } from 'react';
import {
  RefreshCw,
  Download,
  Search,
  ShieldCheck,
  ShieldAlert,
  Globe,
  Radar,
  Bug,
  Server,
  AlertTriangle,
  Lock,
  ChevronRight,
  ChevronDown,
} from 'lucide-react';
import { GlobalThreatIntelSnapshot } from '../types/soc';
import { exportToCSV, formatShortDateTime } from '../utils/socFormatters';
import { ActionTooltip } from './ActionTooltip';
import { useSocMode } from '../context/SocModeContext';

interface RealThreatIntelViewProps {
  threatIntel: GlobalThreatIntelSnapshot | null;
  syncing: boolean;
  onSyncNow: () => void;
}

type CtiTab = 'cisa-kev' | 'ct-phish' | 'botnet-ransom' | 'ip-reputation';

export const RealThreatIntelView: React.FC<RealThreatIntelViewProps> = ({
  threatIntel,
  syncing,
  onSyncNow,
}) => {
  const { isDemo } = useSocMode();
  const [activeTab, setActiveTab] = useState<CtiTab>('cisa-kev');
  const [query, setQuery] = useState('');
  const [targetCertsOnly, setTargetCertsOnly] = useState(false);
  const [priorityRansomOnly, setPriorityRansomOnly] = useState(false);
  const [expandedKevActions, setExpandedKevActions] = useState<Record<string, boolean>>({});

  const toggleKevAction = (cveID: string) => {
    setExpandedKevActions((prev) => ({
      ...prev,
      [cveID]: !prev[cveID],
    }));
  };

  const normalizedQuery = query.trim().toLowerCase();

  const filteredKev = useMemo(() => {
    const list = threatIntel?.cisaKev.recent ?? [];
    if (!normalizedQuery) return list;
    return list.filter(
      (item) =>
        item.cveID.toLowerCase().includes(normalizedQuery) ||
        item.vendorProject.toLowerCase().includes(normalizedQuery) ||
        item.product.toLowerCase().includes(normalizedQuery) ||
        item.vulnerabilityName.toLowerCase().includes(normalizedQuery)
    );
  }, [threatIntel, normalizedQuery]);

  const filteredCerts = useMemo(() => {
    let list = threatIntel?.certTransparency.entries ?? [];
    if (targetCertsOnly) {
      list = list.filter((c) => c.isTargetRelated);
    }
    if (!normalizedQuery) return list;
    return list.filter(
      (c) =>
        c.dnsNames.some((n) => n.toLowerCase().includes(normalizedQuery)) ||
        c.issuer.toLowerCase().includes(normalizedQuery)
    );
  }, [threatIntel, targetCertsOnly, normalizedQuery]);

  const groupedCerts = useMemo(() => {
    const map = new Map<
      string,
      { cert: (typeof filteredCerts)[number]; count: number }
    >();
    for (const cert of filteredCerts) {
      const normalizedNames = [...cert.dnsNames]
        .map((n) => n.toLowerCase())
        .sort()
        .join('|');
      const key = `${normalizedNames}__${cert.issuer}__${cert.notBefore.slice(
        0,
        10
      )}__${cert.notAfter.slice(0, 10)}`;
      const existing = map.get(key);
      if (existing) {
        existing.count += 1;
      } else {
        map.set(key, { cert, count: 1 });
      }
    }
    return Array.from(map.entries()).map(([key, val]) => ({
      key,
      cert: val.cert,
      count: val.count,
    }));
  }, [filteredCerts]);

  const filteredBotnets = useMemo(() => {
    const list = threatIntel?.botnetC2.indicators ?? [];
    if (!normalizedQuery) return list;
    return list.filter(
      (b) =>
        b.ip_address.includes(normalizedQuery) ||
        b.malware.toLowerCase().includes(normalizedQuery) ||
        b.country.toLowerCase().includes(normalizedQuery) ||
        (b.as_name || '').toLowerCase().includes(normalizedQuery)
    );
  }, [threatIntel, normalizedQuery]);

  const filteredRansomware = useMemo(() => {
    let list = threatIntel?.ransomware.recent ?? [];
    if (priorityRansomOnly) {
      list = list.filter((r) => r.isPrioritySector);
    }
    if (!normalizedQuery) return list;
    return list.filter(
      (r) =>
        r.victim.toLowerCase().includes(normalizedQuery) ||
        r.group.toLowerCase().includes(normalizedQuery) ||
        r.activity.toLowerCase().includes(normalizedQuery) ||
        r.country.toLowerCase().includes(normalizedQuery)
    );
  }, [threatIntel, priorityRansomOnly, normalizedQuery]);

  const handleExportCtiCsv = () => {
    if (!threatIntel) return;
    const dateStamp = new Date().toISOString().slice(0, 10);
    if (activeTab === 'cisa-kev') {
      exportToCSV(
        threatIntel.cisaKev.recent.map((c) => ({
          cve_id: c.cveID,
          vendor: c.vendorProject,
          product: c.product,
          vulnerability: c.vulnerabilityName,
          date_added: c.dateAdded,
          due_date: c.dueDate,
          ransomware_campaign: c.knownRansomwareCampaignUse,
          required_action: c.requiredAction,
        })),
        `soc-cisa-kev-live-${dateStamp}.csv`
      );
    } else if (activeTab === 'ct-phish') {
      exportToCSV(
        threatIntel.certTransparency.entries.map((c) => ({
          cert_id: c.id,
          dns_names: c.dnsNames.join('; '),
          issuer: c.issuer,
          not_before: c.notBefore,
          not_after: c.notAfter,
          target_related: c.isTargetRelated,
          revoked: c.revoked,
          sha256: c.sha256,
        })),
        `soc-cert-transparency-${dateStamp}.csv`
      );
    } else if (activeTab === 'botnet-ransom') {
      exportToCSV(
        threatIntel.botnetC2.indicators.map((b) => ({
          ip_address: b.ip_address,
          port: b.port,
          malware: b.malware,
          status: b.status,
          country: b.country,
          as_number: b.as_number ?? '',
          as_name: b.as_name ?? '',
          last_online: b.last_online,
        })),
        `soc-botnet-c2-live-${dateStamp}.csv`
      );
    } else {
      exportToCSV(
        threatIntel.ipReputation.map((r) => ({
          ip: r.ip,
          hostname: r.hostname,
          endpoint: r.endpointLabel,
          net_name: r.netName ?? '',
          country: r.country ?? '',
          cidr: r.cidr ?? '',
          asn: r.asn ?? '',
          bgp_prefix: r.bgpPrefix ?? '',
          listed_in_threat_feeds: r.listedInThreatFeeds,
          matched_feeds: r.matchedFeeds.join('; '),
          checked_at: r.checkedAt,
        })),
        `soc-ip-bgp-reputation-${dateStamp}.csv`
      );
    }
  };

  const okSourcesCount =
    threatIntel?.sourcesStatus.filter((s) => s.status === 'OK').length ?? 0;
  const totalSourcesCount = threatIntel?.sourcesStatus.length ?? 6;

  return (
    <div className="space-y-5">
      {/* Header Control Bar */}
      <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-emerald-400 shrink-0" />
            <h2 className="text-sm font-semibold text-zinc-100">
              Global Open Threat Intelligence (Zero-Account Live Feeds)
            </h2>
          </div>
          {isDemo && (
            <p className="text-xs text-zinc-400">
              Menarik sumber intelijen siber global (CISA KEV, abuse.ch, EmergingThreats, CertSpotter CT, Ransomware.live, OpenPhish, APNIC RDAP &amp; RIPEstat BGP).
            </p>
          )}
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          {threatIntel?.lastSyncedAt && (
            <span className="hidden xl:inline font-mono text-[11px] text-zinc-400 whitespace-nowrap">
              Synced {formatShortDateTime(threatIntel.lastSyncedAt)} WIB ({okSourcesCount}/
              {totalSourcesCount} Live)
            </span>
          )}
          <ActionTooltip
            label="Ekspor CSV CTI"
            description="Unduh data Threat Intelligence dari tab aktif dalam format CSV."
          >
            <button
              type="button"
              disabled={!threatIntel}
              onClick={handleExportCtiCsv}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5 text-zinc-400" />
              Export CTI CSV
            </button>
          </ActionTooltip>
          <ActionTooltip
            label="Sinkronisasi Feed CTI"
            description="Tarik ulang feed terbaru dari CISA KEV, CertSpotter, OpenPhish, Feodo, Ransomware.live, dan APNIC/RIPE."
          >
            <button
              type="button"
              disabled={syncing}
              onClick={onSyncNow}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
              {syncing ? 'Syncing Feeds...' : 'Sync Global CTI'}
            </button>
          </ActionTooltip>
        </div>
      </section>

      {/* 6-Feed Live Telemetry Strip */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
        {(threatIntel?.sourcesStatus ?? []).map((src) => (
          <div
            key={src.id}
            className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg px-4 py-3 flex items-start justify-between gap-3"
          >
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span
                  className={`w-2 h-2 rounded-full shrink-0 ${
                    src.status === 'OK' ? 'bg-emerald-500' : 'bg-rose-500'
                  }`}
                />
                <span className="text-xs font-semibold text-zinc-100 truncate">
                  {src.name}
                </span>
              </div>
              <p className="text-[11px] font-mono text-zinc-500 mt-0.5 truncate">
                {src.provider}
              </p>
              <p className="text-[11px] text-zinc-300 mt-1.5 truncate">
                {src.detail}
              </p>
            </div>
            <div className="text-right font-mono shrink-0">
              <div className="text-sm font-semibold text-zinc-100 tabular-nums">
                {src.count.toLocaleString('id-ID')}
              </div>
              <div className="text-[10px] text-zinc-500 tabular-nums">
                {src.latencyMs} ms
              </div>
            </div>
          </div>
        ))}

        {!threatIntel && (
          <div className="sm:col-span-2 xl:col-span-3 bg-zinc-900/40 border border-zinc-800/80 rounded-lg p-6 text-center text-xs text-zinc-400 font-mono">
            Mengambil data real-time dari 6 sumber Open CTI global (CISA KEV, abuse.ch, CertSpotter, Ransomware.live, OpenPhish, APNIC RDAP)...
          </div>
        )}
      </section>

      {/* Workspace Tabs + Search */}
      {threatIntel && (
        <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex items-center gap-1 overflow-x-auto pb-1 lg:pb-0">
              {[
                {
                  id: 'cisa-kev' as const,
                  label: `CISA KEV (${threatIntel.cisaKev.totalCount})`,
                  desc: 'Katalog kerentanan yang terbukti aktif dieksploitasi secara global.',
                  icon: Bug,
                },
                {
                  id: 'ct-phish' as const,
                  label: `CT & Phishing Radar (${threatIntel.certTransparency.totalEntries})`,
                  desc: `Log sertifikat TLS *.${threatIntel.certTransparency.domain} & pemantauan OpenPhish.`,
                  icon: Lock,
                },
                {
                  id: 'botnet-ransom' as const,
                  label: `Botnet C2 & Ransomware (${threatIntel.botnetC2.feodoTotal + threatIntel.ransomware.recent.length})`,
                  desc: 'Daftar IP C2 botnet aktif dan klaim insiden ransomware global.',
                  icon: AlertTriangle,
                },
                {
                  id: 'ip-reputation' as const,
                  label: `Target IP & BGP (${threatIntel.ipReputation.length})`,
                  desc: 'Verifikasi kepemilikan ASN/RDAP serta cek blacklist IP endpoint target.',
                  icon: Server,
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
                        setQuery('');
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

            {activeTab !== 'ip-reputation' && (
              <div className="relative w-full lg:w-64 shrink-0">
                <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter CVE, domain, IP, malware..."
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-emerald-500/60"
                />
              </div>
            )}
          </div>

          {/* TAB 1: CISA KEV */}
          {activeTab === 'cisa-kev' && (
            <div className="overflow-x-auto">
              <div className="px-4 py-2.5 bg-zinc-950/60 border-b border-zinc-800/60 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-zinc-400">
                <span>
                  CISA Known Exploited Vulnerabilities · Version{' '}
                  <strong className="text-zinc-200">
                    {threatIntel.cisaKev.catalogVersion ?? '-'}
                  </strong>
                </span>
                <span>
                  Menampilkan 25 CVE terbaru dari{' '}
                  <strong className="text-zinc-200">
                    {threatIntel.cisaKev.totalCount}
                  </strong>{' '}
                  total CVE aktif dieksploitasi ({threatIntel.cisaKev.ransomwareCount}{' '}
                  terkait ransomware)
                </span>
              </div>
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400 uppercase">
                    <th className="py-2.5 px-4">CVE ID</th>
                    <th className="py-2.5 px-4">Vendor / Product</th>
                    <th className="py-2.5 px-4">Vulnerability &amp; Required Action</th>
                    <th className="py-2.5 px-4">Added</th>
                    <th className="py-2.5 px-4">Ransomware</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60 text-xs">
                  {filteredKev.map((item) => {
                    const isRansom =
                      item.knownRansomwareCampaignUse.toLowerCase() === 'known';
                    const isActionOpen = Boolean(expandedKevActions[item.cveID]);
                    return (
                      <tr
                        key={item.cveID}
                        className="hover:bg-zinc-900/60 transition-colors"
                      >
                        <td className="py-3 px-4 font-mono font-semibold text-rose-400 whitespace-nowrap align-top">
                          {item.cveID}
                        </td>
                        <td className="py-3 px-4 align-top">
                          <div className="font-medium text-zinc-100">
                            {item.vendorProject}
                          </div>
                          <div className="text-[11px] font-mono text-zinc-400">
                            {item.product}
                          </div>
                        </td>
                        <td className="py-3 px-4 align-top max-w-xl">
                          <ActionTooltip
                            label={
                              isActionOpen
                                ? 'Sembunyikan Required Action'
                                : 'Lihat Required Action CISA'
                            }
                            description={item.requiredAction || 'Klik untuk melihat detail rekomendasi mitigasi CVE.'}
                            className="flex w-full"
                          >
                            <button
                              type="button"
                              onClick={() => toggleKevAction(item.cveID)}
                              aria-expanded={isActionOpen}
                              className="group flex items-start gap-1.5 text-left w-full cursor-pointer"
                            >
                              {isActionOpen ? (
                                <ChevronDown className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                              ) : (
                                <ChevronRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-300 shrink-0 mt-0.5" />
                              )}
                              <span className="font-medium text-zinc-200 group-hover:text-zinc-100">
                                {item.vulnerabilityName}
                              </span>
                            </button>
                          </ActionTooltip>
                          {isActionOpen && item.requiredAction && (
                            <p className="text-[11px] text-zinc-400 mt-1.5 pl-5 leading-relaxed">
                              {item.requiredAction}
                            </p>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px] text-zinc-300 whitespace-nowrap align-top">
                          {item.dateAdded}
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px] whitespace-nowrap align-top">
                          <span
                            className={
                              isRansom ? 'text-rose-400 font-semibold' : 'text-zinc-500'
                            }
                          >
                            {isRansom ? 'KNOWN CAMPAIGN' : 'Unknown'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredKev.length === 0 && (
                    <tr>
                      <td
                        colSpan={5}
                        className="py-8 text-center text-xs text-zinc-500 font-mono"
                      >
                        Tidak ada CVE yang cocok dengan filter pencarian.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 2: CERTIFICATE TRANSPARENCY & OPENPHISH */}
          {activeTab === 'ct-phish' && (
            <div className="grid grid-cols-1 xl:grid-cols-12 divide-y xl:divide-y-0 xl:divide-x divide-zinc-800/80">
              {/* Left 7 cols: CertSpotter CT Logs for target domain */}
              <div className="xl:col-span-7 flex flex-col">
                <div className="px-4 py-2.5 bg-zinc-950/60 border-b border-zinc-800/60 flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-zinc-200">
                    Certificate Transparency Log:{' '}
                    <span className="font-mono text-emerald-400">
                      *.{threatIntel.certTransparency.domain}
                    </span>
                    {groupedCerts.length < filteredCerts.length && (
                      <span className="ml-2 font-mono text-[11px] font-normal text-zinc-500">
                        ({groupedCerts.length} unik dari {filteredCerts.length} entri)
                      </span>
                    )}
                  </span>
                  <ActionTooltip
                    label="Filter Sertifikat Target"
                    description="Tampilkan hanya sertifikat CT log yang terkait subdomain terpantau atau sertifikat wildcard."
                  >
                    <label className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={targetCertsOnly}
                        onChange={(e) => setTargetCertsOnly(e.target.checked)}
                        className="accent-emerald-500"
                      />
                      Target / Wildcard Only ({threatIntel.certTransparency.targetRelatedCount})
                    </label>
                  </ActionTooltip>
                </div>
                <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
                  <table className="w-full text-left border-collapse">
                    <thead className="sticky top-0 bg-zinc-950 z-10">
                      <tr className="border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400 uppercase">
                        <th className="py-2 px-4">DNS Names Issued</th>
                        <th className="py-2 px-4">Issuer CA</th>
                        <th className="py-2 px-4">Valid Period</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60 text-xs">
                      {groupedCerts.map(({ key, cert, count }) => (
                        <tr key={key} className="hover:bg-zinc-900/60">
                          <td className="py-2.5 px-4 font-mono text-[11px] align-top">
                            <div className="flex items-start justify-between gap-2">
                              <div className="space-y-0.5 min-w-0">
                                {cert.dnsNames.slice(0, 4).map((name) => {
                                  const isHighlighted =
                                    name.startsWith('*.') ||
                                    threatIntel.ipReputation.some(
                                      (r) =>
                                        r.hostname.toLowerCase() ===
                                        name.toLowerCase()
                                    );
                                  return (
                                    <div
                                      key={name}
                                      className={
                                        isHighlighted
                                          ? 'text-emerald-400 font-semibold'
                                          : 'text-zinc-200'
                                      }
                                    >
                                      {name}
                                    </div>
                                  );
                                })}
                                {cert.dnsNames.length > 4 && (
                                  <div className="text-zinc-500">
                                    +{cert.dnsNames.length - 4} more SANs
                                  </div>
                                )}
                              </div>
                              {count > 1 && (
                                <span
                                  title={`${count} entri CT log (pre-cert / leaf / re-issuance) dengan DNS Names, Issuer CA, dan Valid Period identik`}
                                  className="inline-flex items-center px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-[10px] font-mono font-semibold text-emerald-400 tabular-nums shrink-0"
                                >
                                  ×{count}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-4 text-zinc-300 align-top whitespace-nowrap">
                            {cert.issuer}
                          </td>
                          <td className="py-2.5 px-4 font-mono text-[11px] text-zinc-400 align-top whitespace-nowrap">
                            <div>{cert.notBefore.slice(0, 10)}</div>
                            <div className="text-zinc-500">→ {cert.notAfter.slice(0, 10)}</div>
                          </td>
                        </tr>
                      ))}
                      {groupedCerts.length === 0 && (
                        <tr>
                          <td
                            colSpan={3}
                            className="py-8 text-center text-xs text-zinc-500 font-mono"
                          >
                            Tidak ada sertifikat CT yang cocok.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Right 5 cols: OpenPhish Live Brand & Indonesia Radar */}
              <div className="xl:col-span-5 flex flex-col">
                <div className="px-4 py-2.5 bg-zinc-950/60 border-b border-zinc-800/60 flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-zinc-200">
                    OpenPhish Live Radar ({threatIntel.openPhish.totalActiveUrls} URLs)
                  </span>
                  <span className="font-mono text-[11px] text-zinc-400">
                    ID/Brand Hits:{' '}
                    <strong
                      className={
                        threatIntel.openPhish.brandOrIndonesiaMatches.length > 0
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }
                    >
                      {threatIntel.openPhish.brandOrIndonesiaMatches.length}
                    </strong>
                  </span>
                </div>

                <div className="p-4 space-y-4 max-h-[460px] overflow-y-auto">
                  <div>
                    <p className="text-[11px] font-mono uppercase text-zinc-400 mb-2">
                      Brand / Regional Keyword Matches
                    </p>
                    {threatIntel.openPhish.brandOrIndonesiaMatches.length === 0 ? (
                      <div className="border border-emerald-500/20 bg-emerald-500/5 rounded-md p-3 flex items-center gap-2.5 text-xs text-emerald-300">
                        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>
                          0 URL phishing aktif di feed OpenPhish yang mencatut kata kunci merek organisasi atau kata kunci terpantau saat ini.
                        </span>
                      </div>
                    ) : (
                      <div className="space-y-1.5">
                        {threatIntel.openPhish.brandOrIndonesiaMatches.map((m, idx) => (
                          <div
                            key={`${m.domain}-${idx}`}
                            className="border border-amber-500/30 bg-amber-500/5 rounded-md px-3 py-2 font-mono text-[11px]"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-amber-300 font-semibold truncate">
                                {m.domain}
                              </span>
                              <span className="text-[10px] text-amber-400 uppercase shrink-0">
                                kw:{m.matchedKeyword}
                              </span>
                            </div>
                            <p className="text-zinc-400 truncate mt-0.5">{m.url}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div>
                    <p className="text-[11px] font-mono uppercase text-zinc-400 mb-2">
                      Sampel Phishing Global Aktif (Live OpenPhish)
                    </p>
                    <div className="divide-y divide-zinc-800/60 border border-zinc-800/80 rounded-md">
                      {threatIntel.openPhish.sampleRecent.slice(0, 12).map((p, idx) => (
                        <div
                          key={`${p.domain}-${idx}`}
                          className="px-3 py-2 font-mono text-[11px] hover:bg-zinc-900/50"
                        >
                          <div className="text-zinc-200 truncate">{p.domain}</div>
                          <div className="text-zinc-500 truncate text-[10px]">
                            {p.url}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: BOTNET C2 & RANSOMWARE */}
          {activeTab === 'botnet-ransom' && (
            <div className="grid grid-cols-1 xl:grid-cols-12 divide-y xl:divide-y-0 xl:divide-x divide-zinc-800/80">
              {/* Left 6 cols: abuse.ch Feodo Botnet C2 */}
              <div className="xl:col-span-6 flex flex-col">
                <div className="px-4 py-2.5 bg-zinc-950/60 border-b border-zinc-800/60 flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-zinc-200">
                    abuse.ch Feodo Tracker (Botnet C2 IPs)
                  </span>
                  <span className="font-mono text-[11px] text-zinc-400">
                    + {threatIntel.botnetC2.etCompromisedTotal} ET Compromised IPs
                  </span>
                </div>
                <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
                  <table className="w-full text-left border-collapse">
                    <thead className="sticky top-0 bg-zinc-950 z-10">
                      <tr className="border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400 uppercase">
                        <th className="py-2 px-4">C2 IP : Port</th>
                        <th className="py-2 px-4">Malware</th>
                        <th className="py-2 px-4">ASN / Country</th>
                        <th className="py-2 px-4">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60 text-xs">
                      {filteredBotnets.map((b) => (
                        <tr
                          key={`${b.ip_address}:${b.port}`}
                          className="hover:bg-zinc-900/60"
                        >
                          <td className="py-2.5 px-4 font-mono text-zinc-100 whitespace-nowrap">
                            {b.ip_address}
                            <span className="text-zinc-500">:{b.port}</span>
                          </td>
                          <td className="py-2.5 px-4 font-mono text-rose-400 whitespace-nowrap">
                            {b.malware}
                          </td>
                          <td className="py-2.5 px-4 text-[11px] text-zinc-300">
                            <span className="font-mono text-zinc-200 mr-1.5">
                              {b.country}
                            </span>
                            <span className="text-zinc-400">
                              {b.as_name ?? (b.as_number ? `AS${b.as_number}` : '-')}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 font-mono text-[11px] whitespace-nowrap">
                            <span
                              className={
                                b.status === 'online'
                                  ? 'text-rose-400 font-semibold'
                                  : 'text-zinc-500'
                              }
                            >
                              {b.status.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      ))}
                      {filteredBotnets.length === 0 && (
                        <tr>
                          <td
                            colSpan={4}
                            className="py-8 text-center text-xs text-zinc-500 font-mono"
                          >
                            Tidak ada indikator C2 yang cocok.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Right 6 cols: Ransomware.live */}
              <div className="xl:col-span-6 flex flex-col">
                <div className="px-4 py-2.5 bg-zinc-950/60 border-b border-zinc-800/60 flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-zinc-200">
                    Ransomware.live Global Victims (Live Feed)
                  </span>
                  <ActionTooltip
                    label="Filter Sektor Prioritas"
                    description="Saring hanya insiden ransomware pada sektor Pemerintahan, Pendidikan, Keuangan, atau Indonesia."
                  >
                    <label className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={priorityRansomOnly}
                        onChange={(e) => setPriorityRansomOnly(e.target.checked)}
                        className="accent-rose-500"
                      />
                      Gov/Edu/Fin/ID ({threatIntel.ransomware.prioritySectorCount})
                    </label>
                  </ActionTooltip>
                </div>
                <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
                  <table className="w-full text-left border-collapse">
                    <thead className="sticky top-0 bg-zinc-950 z-10">
                      <tr className="border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400 uppercase">
                        <th className="py-2 px-4">Threat Group</th>
                        <th className="py-2 px-4">Victim / Sector</th>
                        <th className="py-2 px-4">Country</th>
                        <th className="py-2 px-4">Discovered</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60 text-xs">
                      {filteredRansomware.map((r, idx) => (
                        <tr
                          key={`${r.group}-${r.victim}-${idx}`}
                          className="hover:bg-zinc-900/60"
                        >
                          <td className="py-2.5 px-4 font-mono text-orange-400 font-medium whitespace-nowrap align-top">
                            {r.group}
                          </td>
                          <td className="py-2.5 px-4 align-top">
                            <div className="text-zinc-100 font-medium truncate max-w-[200px]">
                              {r.victim}
                            </div>
                            <div
                              className={`text-[11px] ${
                                r.isPrioritySector
                                  ? 'text-amber-400 font-medium'
                                  : 'text-zinc-500'
                              }`}
                            >
                              {r.activity}
                            </div>
                          </td>
                          <td className="py-2.5 px-4 font-mono text-[11px] text-zinc-300 align-top">
                            {r.country}
                          </td>
                          <td className="py-2.5 px-4 font-mono text-[11px] text-zinc-400 whitespace-nowrap align-top">
                            {r.discovered ? r.discovered.slice(0, 16).replace('T', ' ') : '-'}
                          </td>
                        </tr>
                      ))}
                      {filteredRansomware.length === 0 && (
                        <tr>
                          <td
                            colSpan={4}
                            className="py-8 text-center text-xs text-zinc-500 font-mono"
                          >
                            Tidak ada klaim ransomware yang cocok dengan filter.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: TARGET IP & BGP REPUTATION */}
          {activeTab === 'ip-reputation' && (
            <div className="p-4 space-y-4">
              {isDemo && (
                <div className="flex items-center justify-between text-xs text-zinc-400">
                  <span>
                    Verifikasi kepemilikan blok IP resmi melalui{' '}
                    <strong className="text-zinc-200">APNIC RDAP</strong>, routing{' '}
                    <strong className="text-zinc-200">RIPEstat BGP</strong>, serta pencocokan silang terhadap blocklist{' '}
                    <strong className="text-zinc-200">abuse.ch Feodo</strong> &amp;{' '}
                    <strong className="text-zinc-200">EmergingThreats</strong>.
                  </span>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {threatIntel.ipReputation.map((entry) => (
                  <div
                    key={entry.ip}
                    className="bg-zinc-950/70 border border-zinc-800/80 rounded-lg p-4 space-y-3"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="font-mono text-sm font-semibold text-zinc-100">
                          {entry.ip}
                        </p>
                        <p className="text-[11px] text-zinc-400 mt-0.5">
                          {entry.endpointLabel}
                        </p>
                      </div>
                      {entry.listedInThreatFeeds ? (
                        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-rose-400">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          LISTED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-emerald-400">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          CLEAN
                        </span>
                      )}
                    </div>

                    <dl className="grid grid-cols-2 gap-y-2 gap-x-3 text-[11px] border-t border-zinc-800/80 pt-3">
                      <div>
                        <dt className="text-zinc-500">APNIC NetName</dt>
                        <dd className="font-mono text-zinc-200 mt-0.5">
                          {entry.netName ?? '—'}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-zinc-500">Country</dt>
                        <dd className="font-mono text-zinc-200 mt-0.5">
                          {entry.country ?? '—'}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-zinc-500">BGP ASN</dt>
                        <dd className="font-mono text-emerald-400 mt-0.5">
                          {entry.asn ?? '—'}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-zinc-500">CIDR / Prefix</dt>
                        <dd className="font-mono text-zinc-200 mt-0.5">
                          {entry.bgpPrefix ?? entry.cidr ?? '—'}
                        </dd>
                      </div>
                    </dl>

                    <div className="text-[11px] font-mono text-zinc-500 border-t border-zinc-900 pt-2 flex items-center justify-between">
                      <span className="flex items-center gap-1 truncate">
                        <Globe className="w-3 h-3 shrink-0" />
                        {entry.hostname}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
};
