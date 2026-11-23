import type {
  BotnetC2Indicator,
  CertTransparencyEntry,
  CisaKevItem,
  CtiSourceStatus,
  GlobalThreatIntelSnapshot,
  IpReputationEntry,
  PhishingIndicator,
  RansomwareVictimItem,
  RealEndpointProbe,
} from '../src/types/soc.ts';

const USER_AGENT = 'CyberDefense-SOC-OpenCTI/1.0 (Public-Passive-Monitor)';

const BRAND_PHISHING_KEYWORDS = (
  process.env.CTI_BRAND_KEYWORDS || 'login,verify,portal,sso,webmail,banking'
)
  .split(',')
  .map((k) => k.trim().toLowerCase())
  .filter(Boolean);

const PRIORITY_SECTORS_RE =
  /government|education|university|school|finance|financial|bank|public|ministry|indonesia/i;

function extractDomainSafe(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return rawUrl.slice(0, 64);
  }
}

async function fetchCisaKev(): Promise<{
  status: CtiSourceStatus;
  data: GlobalThreatIntelSnapshot['cisaKev'];
}> {
  const t0 = Date.now();
  try {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      {
        signal: AbortSignal.timeout(9500),
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
      }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = (await res.json()) as {
      catalogVersion?: string;
      vulnerabilities?: Array<Record<string, unknown>>;
    };
    const vulns = Array.isArray(json.vulnerabilities) ? json.vulnerabilities : [];
    const ransomwareCount = vulns.filter(
      (v) => String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known'
    ).length;

    const sorted = [...vulns].sort((a, b) =>
      String(b.dateAdded || '').localeCompare(String(a.dateAdded || ''))
    );

    const recent: CisaKevItem[] = sorted.slice(0, 25).map((v) => ({
      cveID: String(v.cveID || 'CVE-UNKNOWN'),
      vendorProject: String(v.vendorProject || '-'),
      product: String(v.product || '-'),
      vulnerabilityName: String(v.vulnerabilityName || '-'),
      dateAdded: String(v.dateAdded || '-'),
      dueDate: String(v.dueDate || '-'),
      knownRansomwareCampaignUse: String(v.knownRansomwareCampaignUse || 'Unknown'),
      shortDescription: String(v.shortDescription || ''),
      requiredAction: String(v.requiredAction || ''),
    }));

    return {
      status: {
        id: 'cisa-kev',
        name: 'CISA KEV Catalog',
        provider: 'cisa.gov',
        status: 'OK',
        count: vulns.length,
        latencyMs: Date.now() - t0,
        detail: `Catalog ${json.catalogVersion ?? 'live'} · ${ransomwareCount} ransomware-linked`,
      },
      data: {
        catalogVersion: json.catalogVersion ?? null,
        totalCount: vulns.length,
        ransomwareCount,
        recent,
      },
    };
  } catch (err) {
    return {
      status: {
        id: 'cisa-kev',
        name: 'CISA KEV Catalog',
        provider: 'cisa.gov',
        status: 'ERROR',
        count: 0,
        latencyMs: Date.now() - t0,
        detail: err instanceof Error ? err.message : 'Fetch error',
      },
      data: {
        catalogVersion: null,
        totalCount: 0,
        ransomwareCount: 0,
        recent: [],
      },
    };
  }
}

async function fetchBotnetAndCompromisedIps(): Promise<{
  status: CtiSourceStatus;
  data: GlobalThreatIntelSnapshot['botnetC2'];
  feodoSet: Set<string>;
  etSet: Set<string>;
}> {
  const t0 = Date.now();
  const feodoSet = new Set<string>();
  const etSet = new Set<string>();
  let indicators: BotnetC2Indicator[] = [];
  let feodoOk = false;
  let etOk = false;

  const [feodoRes, etRes] = await Promise.allSettled([
    fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', {
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
    }),
    fetch('https://rules.emergingthreats.net/blockrules/compromised-ips.txt', {
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': USER_AGENT },
    }),
  ]);

  if (feodoRes.status === 'fulfilled' && feodoRes.value.ok) {
    try {
      const raw = (await feodoRes.value.json()) as Array<Record<string, unknown>>;
      if (Array.isArray(raw)) {
        feodoOk = true;
        indicators = raw.slice(0, 60).map((item) => {
          const ip = String(item.ip_address || '');
          if (ip) feodoSet.add(ip);
          return {
            ip_address: ip,
            port: Number(item.port || 0),
            status: String(item.status || 'unknown'),
            hostname: item.hostname ? String(item.hostname) : null,
            as_number:
              typeof item.as_number === 'number' ? item.as_number : null,
            as_name: item.as_name ? String(item.as_name) : null,
            country: String(item.country || 'XX'),
            first_seen: String(item.first_seen || '-'),
            last_online: String(item.last_online || '-'),
            malware: String(item.malware || 'Botnet C2'),
          };
        });
        for (const item of raw) {
          if (item.ip_address) feodoSet.add(String(item.ip_address));
        }
      }
    } catch {
      // ignore parse failure
    }
  }

  if (etRes.status === 'fulfilled' && etRes.value.ok) {
    try {
      const txt = await etRes.value.text();
      etOk = true;
      for (const line of txt.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#') && /^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) {
          etSet.add(trimmed);
        }
      }
    } catch {
      // ignore parse failure
    }
  }

  const ok = feodoOk || etOk;
  return {
    status: {
      id: 'botnet-et',
      name: 'Botnet C2 & Threat IPs',
      provider: 'abuse.ch + EmergingThreats',
      status: ok ? 'OK' : 'ERROR',
      count: feodoSet.size + etSet.size,
      latencyMs: Date.now() - t0,
      detail: ok
        ? `${feodoSet.size} Feodo C2 · ${etSet.size} ET Compromised IPs`
        : 'Feed temporarily unreachable',
    },
    data: {
      feodoTotal: feodoSet.size,
      etCompromisedTotal: etSet.size,
      indicators,
    },
    feodoSet,
    etSet,
  };
}

function resolveCtTargetDomain(): string {
  if (process.env.TARGET_ROOT_DOMAIN?.trim()) {
    return process.env.TARGET_ROOT_DOMAIN.trim().toLowerCase();
  }
  const raw = process.env.TARGET_PORTAL_URL || 'https://example.org/';
  try {
    const host = new URL(raw).hostname.toLowerCase();
    const parts = host.split('.');
    if (parts.length >= 3 && parts[parts.length - 2].length <= 3) {
      return parts.slice(-3).join('.');
    }
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return host;
  } catch {
    return 'example.org';
  }
}

async function fetchCertTransparency(): Promise<{
  status: CtiSourceStatus;
  data: GlobalThreatIntelSnapshot['certTransparency'];
}> {
  const t0 = Date.now();
  const domain = resolveCtTargetDomain();
  const orgKeywords = BRAND_PHISHING_KEYWORDS.slice(0, 6);
  try {
    const res = await fetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`,
      {
        signal: AbortSignal.timeout(9000),
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
      }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const raw = (await res.json()) as Array<Record<string, unknown>>;
    const list = Array.isArray(raw) ? raw : [];

    const mapped: CertTransparencyEntry[] = list.map((item) => {
      const dnsNames = Array.isArray(item.dns_names)
        ? item.dns_names.map(String)
        : [];
      const issuerObj =
        item.issuer && typeof item.issuer === 'object'
          ? (item.issuer as Record<string, unknown>)
          : null;
      const issuer = issuerObj
        ? String(issuerObj.friendly_name || issuerObj.name || 'Unknown CA')
        : 'Unknown CA';
      const isTargetRelated = dnsNames.some((n) => {
        const lower = n.toLowerCase();
        return (
          lower === domain ||
          lower === `*.${domain}` ||
          orgKeywords.some((kw) => lower.includes(kw))
        );
      });
      return {
        id: String(item.id || ''),
        dnsNames,
        issuer,
        notBefore: String(item.not_before || ''),
        notAfter: String(item.not_after || ''),
        revoked: Boolean(item.revoked),
        sha256: String(item.cert_sha256 || ''),
        isTargetRelated,
      };
    });

    mapped.sort((a, b) => b.notBefore.localeCompare(a.notBefore));
    const targetRelatedCount = mapped.filter((m) => m.isTargetRelated).length;

    return {
      status: {
        id: 'cert-transparency',
        name: 'Cert Transparency Log',
        provider: `CertSpotter (*.${domain})`,
        status: 'OK',
        count: mapped.length,
        latencyMs: Date.now() - t0,
        detail: `${mapped.length} live certs · ${targetRelatedCount} target/wildcard matches`,
      },
      data: {
        domain,
        totalEntries: mapped.length,
        targetRelatedCount,
        entries: mapped.slice(0, 40),
      },
    };
  } catch (err) {
    return {
      status: {
        id: 'cert-transparency',
        name: 'Cert Transparency Log',
        provider: `CertSpotter (*.${domain})`,
        status: 'ERROR',
        count: 0,
        latencyMs: Date.now() - t0,
        detail: err instanceof Error ? err.message : 'CT lookup failed',
      },
      data: {
        domain,
        totalEntries: 0,
        targetRelatedCount: 0,
        entries: [],
      },
    };
  }
}

async function fetchRansomwareLive(): Promise<{
  status: CtiSourceStatus;
  data: GlobalThreatIntelSnapshot['ransomware'];
}> {
  const t0 = Date.now();
  try {
    const res = await fetch('https://api.ransomware.live/v2/recentvictims', {
      signal: AbortSignal.timeout(9000),
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const raw = (await res.json()) as Array<Record<string, unknown>>;
    const list = Array.isArray(raw) ? raw : [];

    const mapped: RansomwareVictimItem[] = list.slice(0, 30).map((v) => {
      const country = String(v.country || '').toUpperCase();
      const activity = String(v.activity || 'Unclassified');
      const description = String(v.description || '');
      const isPrioritySector =
        country === 'ID' ||
        PRIORITY_SECTORS_RE.test(activity) ||
        PRIORITY_SECTORS_RE.test(description);
      return {
        victim: String(v.victim || 'Unknown'),
        group: String(v.group || 'unknown'),
        country: country || '—',
        activity: activity === 'Not Found' ? 'Unclassified' : activity,
        discovered: String(v.discovered || v.attackdate || ''),
        description,
        isPrioritySector,
      };
    });

    const prioritySectorCount = mapped.filter((m) => m.isPrioritySector).length;

    return {
      status: {
        id: 'ransomware-live',
        name: 'Global Ransomware Radar',
        provider: 'ransomware.live v2',
        status: 'OK',
        count: list.length,
        latencyMs: Date.now() - t0,
        detail: `${list.length} recent claims · ${prioritySectorCount} Gov/Edu/Fin/ID`,
      },
      data: {
        totalRecent: list.length,
        prioritySectorCount,
        recent: mapped,
      },
    };
  } catch (err) {
    return {
      status: {
        id: 'ransomware-live',
        name: 'Global Ransomware Radar',
        provider: 'ransomware.live v2',
        status: 'ERROR',
        count: 0,
        latencyMs: Date.now() - t0,
        detail: err instanceof Error ? err.message : 'Ransomware feed error',
      },
      data: {
        totalRecent: 0,
        prioritySectorCount: 0,
        recent: [],
      },
    };
  }
}

async function fetchOpenPhish(): Promise<{
  status: CtiSourceStatus;
  data: GlobalThreatIntelSnapshot['openPhish'];
}> {
  const t0 = Date.now();
  try {
    const res = await fetch('https://openphish.com/feed.txt', {
      signal: AbortSignal.timeout(9000),
      headers: { 'User-Agent': USER_AGENT },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const lines = text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.startsWith('http://') || l.startsWith('https://'));

    const brandOrIndonesiaMatches: PhishingIndicator[] = [];
    for (const url of lines) {
      const lower = url.toLowerCase();
      const matched = BRAND_PHISHING_KEYWORDS.find((kw) => lower.includes(kw));
      if (matched) {
        brandOrIndonesiaMatches.push({
          url,
          domain: extractDomainSafe(url),
          matchedKeyword: matched,
        });
      }
    }

    const sampleRecent: PhishingIndicator[] = lines.slice(0, 18).map((url) => ({
      url,
      domain: extractDomainSafe(url),
      matchedKeyword: null,
    }));

    return {
      status: {
        id: 'openphish',
        name: 'OpenPhish Live URLs',
        provider: 'openphish.com',
        status: 'OK',
        count: lines.length,
        latencyMs: Date.now() - t0,
        detail: `${lines.length} active URLs · ${brandOrIndonesiaMatches.length} ID/Brand hits`,
      },
      data: {
        totalActiveUrls: lines.length,
        brandOrIndonesiaMatches: brandOrIndonesiaMatches.slice(0, 25),
        sampleRecent,
      },
    };
  } catch (err) {
    return {
      status: {
        id: 'openphish',
        name: 'OpenPhish Live URLs',
        provider: 'openphish.com',
        status: 'ERROR',
        count: 0,
        latencyMs: Date.now() - t0,
        detail: err instanceof Error ? err.message : 'OpenPhish fetch error',
      },
      data: {
        totalActiveUrls: 0,
        brandOrIndonesiaMatches: [],
        sampleRecent: [],
      },
    };
  }
}

async function inspectIpReputation(
  endpoints: RealEndpointProbe[],
  feodoSet: Set<string>,
  etSet: Set<string>
): Promise<{
  status: CtiSourceStatus;
  entries: IpReputationEntry[];
}> {
  const t0 = Date.now();
  const uniqueMap = new Map<
    string,
    { ip: string; endpointLabel: string; hostname: string }
  >();

  for (const ep of endpoints) {
    for (const ip of ep.dns.ipv4) {
      if (!uniqueMap.has(ip)) {
        uniqueMap.set(ip, {
          ip,
          endpointLabel: ep.label,
          hostname: ep.hostname,
        });
      }
    }
  }

  const targets = Array.from(uniqueMap.values());
  if (targets.length === 0) {
    return {
      status: {
        id: 'ip-reputation',
        name: 'APNIC RDAP & BGP Audit',
        provider: 'rdap.apnic.net + RIPEstat',
        status: 'OK',
        count: 0,
        latencyMs: Date.now() - t0,
        detail: 'Waiting for endpoint DNS resolution',
      },
      entries: [],
    };
  }

  const entries = await Promise.all(
    targets.map(async (item): Promise<IpReputationEntry> => {
      const matchedFeeds: string[] = [];
      if (feodoSet.has(item.ip)) matchedFeeds.push('abuse.ch Feodo C2');
      if (etSet.has(item.ip)) matchedFeeds.push('EmergingThreats Compromised');

      let netName: string | null = null;
      let country: string | null = null;
      let cidr: string | null = null;
      let asn: string | null = null;
      let bgpPrefix: string | null = null;

      const [rdapRes, ripeRes] = await Promise.allSettled([
        fetch(`https://rdap.apnic.net/ip/${encodeURIComponent(item.ip)}`, {
          signal: AbortSignal.timeout(7000),
          headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
        }),
        fetch(
          `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(
            item.ip
          )}`,
          {
            signal: AbortSignal.timeout(7000),
            headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
          }
        ),
      ]);

      if (rdapRes.status === 'fulfilled' && rdapRes.value.ok) {
        try {
          const rdap = (await rdapRes.value.json()) as {
            name?: string;
            country?: string;
            cidr0_cidrs?: Array<{ v4prefix?: string; length?: number }>;
          };
          netName = rdap.name ?? null;
          country = rdap.country ?? null;
          if (rdap.cidr0_cidrs?.[0]?.v4prefix && rdap.cidr0_cidrs[0].length) {
            cidr = `${rdap.cidr0_cidrs[0].v4prefix}/${rdap.cidr0_cidrs[0].length}`;
          }
        } catch {
          // ignore
        }
      }

      if (ripeRes.status === 'fulfilled' && ripeRes.value.ok) {
        try {
          const ripe = (await ripeRes.value.json()) as {
            data?: { asns?: string[]; prefix?: string };
          };
          if (ripe.data?.asns && ripe.data.asns.length > 0) {
            asn = `AS${ripe.data.asns[0]}`;
          }
          bgpPrefix = ripe.data?.prefix ?? null;
        } catch {
          // ignore
        }
      }

      return {
        ip: item.ip,
        endpointLabel: item.endpointLabel,
        hostname: item.hostname,
        netName,
        country,
        cidr,
        asn,
        bgpPrefix,
        listedInThreatFeeds: matchedFeeds.length > 0,
        matchedFeeds,
        checkedAt: new Date().toISOString(),
      };
    })
  );

  const anyListed = entries.some((e) => e.listedInThreatFeeds);
  return {
    status: {
      id: 'ip-reputation',
      name: 'APNIC RDAP & BGP Audit',
      provider: 'rdap.apnic.net + RIPEstat',
      status: 'OK',
      count: entries.length,
      latencyMs: Date.now() - t0,
      detail: anyListed
        ? `${entries.length} Endpoint IPs checked · LISTED ALERT`
        : `${entries.length} Endpoint IPs verified · ALL CLEAN`,
    },
    entries,
  };
}

export async function fetchGlobalThreatIntelSnapshot(
  endpoints: RealEndpointProbe[]
): Promise<GlobalThreatIntelSnapshot> {
  const startedAt = Date.now();

  const [cisa, botnet, ct, ransomware, openPhish] = await Promise.all([
    fetchCisaKev(),
    fetchBotnetAndCompromisedIps(),
    fetchCertTransparency(),
    fetchRansomwareLive(),
    fetchOpenPhish(),
  ]);

  const ipRep = await inspectIpReputation(
    endpoints,
    botnet.feodoSet,
    botnet.etSet
  );

  return {
    lastSyncedAt: new Date().toISOString(),
    syncDurationMs: Date.now() - startedAt,
    sourcesStatus: [
      cisa.status,
      botnet.status,
      ct.status,
      ransomware.status,
      openPhish.status,
      ipRep.status,
    ],
    cisaKev: cisa.data,
    botnetC2: botnet.data,
    certTransparency: ct.data,
    ransomware: ransomware.data,
    openPhish: openPhish.data,
    ipReputation: ipRep.entries,
  };
}
