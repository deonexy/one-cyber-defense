import 'dotenv/config';
import express from 'express';
import type { Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { fileURLToPath } from 'node:url';
import type {
  ContentIntegrityScan,
  CookieInspection,
  CustomGlossaryTerm,
  CyberKnowledgeSnapshot,
  GlobalThreatIntelSnapshot,
  LiveAttackEvent,
  LocalAgentConfig,
  LocalWazuhSnapshot,
  ManualIncidentReport,
  RealDnsSecurityAudit,
  RealEndpointProbe,
  RealFindingStatus,
  RealLatencyPoint,
  RealLogType,
  RealProbeLogEntry,
  RealSecurityFinding,
  RealTelemetrySnapshot,
  SecurityHeaderInspection,
  ThreatIntelAlert,
  ThreatIntelStatus,
  TlsInspection,
} from './src/types/soc.ts';
import { fetchGlobalThreatIntelSnapshot } from './server/globalCtiFetcher.ts';
import { LocalWazuhEngine } from './server/localWazuhEngine.ts';
import { CyberKnowledgeStore } from './server/knowledgeFetcher.ts';
import { ContentIncidentStore } from './server/contentIncidentStore.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;
const ORG_NAME = process.env.ORG_NAME || 'Organization';
const PRIMARY_PORTAL_URL =
  process.env.TARGET_PORTAL_URL || 'https://example.org/';
const SECONDARY_PORTAL_URL =
  process.env.TARGET_SECONDARY_URL || 'https://www.iana.org/domains/reserved';
const LOGIN_PORTAL_URL = process.env.TARGET_LOGIN_URL || '';

const DEFAULT_TARGETS: Array<{ id: string; label: string; url: string }> = [
  {
    id: 'ep-primary',
    label: 'Primary Web Portal',
    url: PRIMARY_PORTAL_URL,
  },
  ...(LOGIN_PORTAL_URL
    ? [
        {
          id: 'ep-login',
          label: 'Portal Auth / Login Endpoint',
          url: LOGIN_PORTAL_URL,
        },
      ]
    : []),
  {
    id: 'ep-secondary',
    label: 'Secondary Web Target',
    url: SECONDARY_PORTAL_URL,
  },
];

function formatChartTimeWIB(date: Date): string {
  return date.toLocaleTimeString('id-ID', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function safeHostname(urlStr: string): string {
  try {
    return new URL(urlStr).hostname;
  } catch {
    return 'example.org';
  }
}

function extractRootDomain(hostname: string): string {
  if (process.env.TARGET_ROOT_DOMAIN?.trim()) {
    return process.env.TARGET_ROOT_DOMAIN.trim().toLowerCase();
  }
  const parts = hostname.split('.');
  if (parts.length >= 3 && parts[parts.length - 2].length <= 3) {
    return parts.slice(-3).join('.');
  }
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }
  return hostname;
}

async function inspectTlsCertificate(
  hostname: string
): Promise<TlsInspection | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 4500,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol();
          const cipherObj = socket.getCipher();
          const validFrom = cert?.valid_from || null;
          const validTo = cert?.valid_to || null;
          let daysRemaining: number | null = null;
          if (validTo) {
            const expiryMs = Date.parse(validTo);
            if (!Number.isNaN(expiryMs)) {
              daysRemaining = Math.floor(
                (expiryMs - Date.now()) / (1000 * 60 * 60 * 24)
              );
            }
          }
          const issuer =
            typeof cert?.issuer?.O === 'string'
              ? cert.issuer.O
              : typeof cert?.issuer?.CN === 'string'
              ? cert.issuer.CN
              : null;
          const subject =
            typeof cert?.subject?.CN === 'string' ? cert.subject.CN : null;
          const sanList =
            typeof cert?.subjectaltname === 'string'
              ? cert.subjectaltname.split(',').filter(Boolean)
              : [];

          socket.end();
          resolve({
            protocol,
            cipher: cipherObj?.standardName || cipherObj?.name || null,
            issuer,
            subject,
            sanCount: sanList.length,
            validFrom,
            validTo,
            daysRemaining,
            fingerprint256: cert?.fingerprint256 || null,
          });
        } catch {
          socket.destroy();
          resolve(null);
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

async function inspectEndpointDns(hostname: string) {
  const [ipv4, ipv6, cname] = await Promise.all([
    dns.resolve4(hostname).catch(() => [] as string[]),
    dns.resolve6(hostname).catch(() => [] as string[]),
    dns.resolveCname(hostname).catch(() => [] as string[]),
  ]);
  return { ipv4, ipv6, cname };
}

async function inspectRootDnsSecurity(
  portalHost: string
): Promise<RealDnsSecurityAudit> {
  const rootDomain = extractRootDomain(portalHost);
  const [txtRaw, dmarcRaw, caaRaw, mxRaw, nsRaw] = await Promise.all([
    dns.resolveTxt(rootDomain).catch(() => [] as string[][]),
    dns.resolveTxt(`_dmarc.${rootDomain}`).catch(() => [] as string[][]),
    dns.resolveCaa(rootDomain).catch(() => []),
    dns.resolveMx(rootDomain).catch(() => []),
    dns.resolveNs(rootDomain).catch(() => [] as string[]),
  ]);

  const txtRecords = txtRaw.map((chunks) => chunks.join(''));
  const spfRecord =
    txtRecords.find((r) => r.toLowerCase().startsWith('v=spf1')) ?? null;

  let spfPolicy: RealDnsSecurityAudit['spf']['policy'] = 'MISSING';
  if (spfRecord) {
    if (spfRecord.includes('-all')) spfPolicy = 'HARD_FAIL';
    else if (spfRecord.includes('~all')) spfPolicy = 'SOFT_FAIL';
    else spfPolicy = 'NEUTRAL';
  }

  const dmarcRecords = dmarcRaw.map((chunks) => chunks.join(''));
  const dmarcRecord =
    dmarcRecords.find((r) => r.toLowerCase().startsWith('v=dmarc1')) ?? null;

  let dmarcPolicy: RealDnsSecurityAudit['dmarc']['policy'] = 'MISSING';
  if (dmarcRecord) {
    const match = dmarcRecord.match(/p\s*=\s*(reject|quarantine|none)/i);
    if (match) {
      dmarcPolicy = match[1].toLowerCase() as 'reject' | 'quarantine' | 'none';
    }
  }

  const caaRecords = caaRaw.map((item) => {
    const rec = item as unknown as Record<string, unknown>;
    const tag = rec.issue
      ? `issue "${rec.issue}"`
      : rec.issuewild
      ? `issuewild "${rec.issuewild}"`
      : rec.iodef
      ? `iodef "${rec.iodef}"`
      : JSON.stringify(rec);
    return tag;
  });

  // Compute transparent 0-100 DNS/Email security score from real records
  let score = 0;
  if (spfPolicy === 'HARD_FAIL') score += 35;
  else if (spfPolicy === 'SOFT_FAIL') score += 25;
  else if (spfPolicy === 'NEUTRAL') score += 10;

  if (dmarcPolicy === 'reject') score += 40;
  else if (dmarcPolicy === 'quarantine') score += 30;
  else if (dmarcPolicy === 'none') score += 12;

  if (caaRecords.length > 0) score += 25;

  return {
    rootDomain,
    portalHost,
    checkedAt: new Date().toISOString(),
    spf: {
      present: Boolean(spfRecord),
      record: spfRecord,
      policy: spfPolicy,
    },
    dmarc: {
      present: Boolean(dmarcRecord),
      record: dmarcRecord,
      policy: dmarcPolicy,
    },
    caa: {
      present: caaRecords.length > 0,
      records: caaRecords,
    },
    mx: mxRaw.sort((a, b) => a.priority - b.priority),
    ns: nsRaw,
    score,
  };
}

function inspectCookies(headers: Headers): CookieInspection {
  // Node 22 Undici Headers supports getSetCookie()
  const rawCookies =
    typeof headers.getSetCookie === 'function'
      ? headers.getSetCookie()
      : headers.get('set-cookie')
      ? [headers.get('set-cookie') as string]
      : [];

  if (rawCookies.length === 0) {
    return { count: 0, allSecure: true, allHttpOnly: true, hasSameSite: true };
  }

  const allSecure = rawCookies.every((c) => /;\s*secure\b/i.test(c));
  const allHttpOnly = rawCookies.every((c) => /;\s*httponly\b/i.test(c));
  const hasSameSite = rawCookies.every((c) => /;\s*samesite\s*=/i.test(c));

  return {
    count: rawCookies.length,
    allSecure,
    allHttpOnly,
    hasSameSite,
  };
}

class RealSocMonitorStore {
  endpoints: RealEndpointProbe[] = [];
  dnsAudit: RealDnsSecurityAudit | null = null;
  threatIntel: GlobalThreatIntelSnapshot | null = null;
  threatIntelAlerts: ThreatIntelAlert[] = [];
  localWazuh: LocalWazuhSnapshot | null = null;
  knowledge: CyberKnowledgeSnapshot | null = null;
  latencyHistory: RealLatencyPoint[] = [];
  findings: RealSecurityFinding[] = [];
  probeLogs: RealProbeLogEntry[] = [];
  ingestedSiemEvents: LiveAttackEvent[] = [];
  probeIntervalMs = 15000;

  readonly localEngine = new LocalWazuhEngine(__dirname);
  readonly knowledgeStore = new CyberKnowledgeStore(__dirname);
  readonly contentIncidentStore = new ContentIncidentStore(__dirname);

  private sseClients = new Set<Response>();
  private acknowledgedFindingIds = new Set<string>();
  private threatAlertStatusOverrides = new Map<string, ThreatIntelStatus>();
  private logSeq = 1001;
  private siemSeq = 1;
  private isProbing = false;
  private isSyncingCti = false;
  private isSyncingKnowledge = false;
  private isScanningContent = false;
  private loopTimer: ReturnType<typeof setInterval> | null = null;
  private ctiTimer: ReturnType<typeof setInterval> | null = null;
  private localTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.endpoints = DEFAULT_TARGETS.map((t) => ({
      id: t.id,
      label: t.label,
      url: t.url,
      hostname: safeHostname(t.url),
      isDefault: true,
      status: 'PENDING',
      httpStatus: null,
      latencyMs: null,
      uptimePercent: 100,
      totalChecks: 0,
      successChecks: 0,
      lastCheckedAt: null,
      headerScore: 0,
      serverHeader: null,
      poweredByHeader: null,
      securityHeaders: {
        hsts: null,
        csp: null,
        xFrameOptions: null,
        xContentTypeOptions: null,
        referrerPolicy: null,
        permissionsPolicy: null,
      },
      cookies: {
        count: 0,
        allSecure: true,
        allHttpOnly: true,
        hasSameSite: true,
      },
      tls: null,
      dns: { ipv4: [], ipv6: [], cname: [] },
    }));

    this.startRealProbeSchedule();
    this.startCtiSchedule();
    this.startLocalSiemSchedule();
  }

  getSnapshot(): RealTelemetrySnapshot {
    return {
      mode: 'REAL_ONLY',
      probeIntervalMs: this.probeIntervalMs,
      connectedAnalysts: this.sseClients.size,
      probeOriginLabel: 'SOC Probe Node (Asia-Southeast)',
      endpoints: this.endpoints,
      dnsAudit: this.dnsAudit,
      threatIntel: this.threatIntel,
      threatIntelAlerts: this.threatIntelAlerts,
      localWazuh: this.localWazuh,
      knowledge: this.knowledge,
      contentScans: this.contentIncidentStore.getScans(),
      incidentReports: this.contentIncidentStore.getReports(),
      latencyHistory: this.latencyHistory,
      findings: this.findings,
      probeLogs: this.probeLogs,
      ingestedSiemEvents: this.ingestedSiemEvents,
    };
  }

  addClient(res: Response): void {
    this.sseClients.add(res);
    this.broadcast('clients:count', {
      connectedAnalysts: this.sseClients.size,
    });
  }

  removeClient(res: Response): void {
    this.sseClients.delete(res);
    this.broadcast('clients:count', {
      connectedAnalysts: this.sseClients.size,
    });
  }

  broadcast(eventName: string, payload: unknown): void {
    const frame = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(frame);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  appendLog(params: {
    actor: string;
    check_type: RealLogType;
    target: string;
    http_status: string;
    latency_ms: string;
    result: string;
  }): RealProbeLogEntry {
    const entry: RealProbeLogEntry = {
      id: `LOG-${this.logSeq++}`,
      timestamp: new Date().toISOString(),
      ...params,
    };
    this.probeLogs = [entry, ...this.probeLogs].slice(0, 200);
    this.broadcast('log:created', entry);
    return entry;
  }

  private async probeSingleEndpoint(
    current: RealEndpointProbe
  ): Promise<RealEndpointProbe> {
    const started = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5500);

    try {
      const [httpResp, tlsInfo, dnsInfo] = await Promise.all([
        fetch(current.url, {
          method: 'GET',
          redirect: 'follow',
          signal: controller.signal,
          headers: {
            'User-Agent': 'CyberDefense-SOC-RealMonitor/2.0',
            Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
          },
        }),
        inspectTlsCertificate(current.hostname),
        inspectEndpointDns(current.hostname),
      ]);

      const latencyMs = Math.max(1, Date.now() - started);
      const headers = httpResp.headers;

      // Drain body cleanly to free socket
      await httpResp.arrayBuffer().catch(() => undefined);

      const securityHeaders: SecurityHeaderInspection = {
        hsts: headers.get('strict-transport-security'),
        csp: headers.get('content-security-policy'),
        xFrameOptions: headers.get('x-frame-options'),
        xContentTypeOptions: headers.get('x-content-type-options'),
        referrerPolicy: headers.get('referrer-policy'),
        permissionsPolicy: headers.get('permissions-policy'),
      };

      const presentCount = Object.values(securityHeaders).filter(Boolean).length;
      const headerScore = Math.round((presentCount / 6) * 100);
      const cookies = inspectCookies(headers);

      const isHealthyHttp = httpResp.status < 500;
      const totalChecks = current.totalChecks + 1;
      const successChecks = current.successChecks + (isHealthyHttp ? 1 : 0);
      const uptimePercent = Number(
        ((successChecks / totalChecks) * 100).toFixed(2)
      );

      const status: RealEndpointProbe['status'] = !isHealthyHttp
        ? 'DOWN'
        : latencyMs > 1800
        ? 'DEGRADED'
        : 'UP';

      return {
        ...current,
        status,
        httpStatus: httpResp.status,
        latencyMs,
        uptimePercent,
        totalChecks,
        successChecks,
        lastCheckedAt: new Date().toISOString(),
        headerScore,
        serverHeader: headers.get('server') || null,
        poweredByHeader: headers.get('x-powered-by') || null,
        securityHeaders,
        cookies,
        tls: tlsInfo,
        dns: dnsInfo,
        errorMessage: undefined,
      };
    } catch (err) {
      const dnsInfo = await inspectEndpointDns(current.hostname).catch(() => ({
        ipv4: [],
        ipv6: [],
        cname: [],
      }));
      const totalChecks = current.totalChecks + 1;
      const successChecks = current.successChecks;
      const uptimePercent = Number(
        ((successChecks / totalChecks) * 100).toFixed(2)
      );

      return {
        ...current,
        status: 'DOWN',
        httpStatus: null,
        latencyMs: null,
        uptimePercent,
        totalChecks,
        successChecks,
        lastCheckedAt: new Date().toISOString(),
        dns: dnsInfo,
        errorMessage:
          err instanceof Error ? err.message : 'Request timeout / network error',
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private recomputeRealFindings(): void {
    const nowIso = new Date().toISOString();
    const discovered: RealSecurityFinding[] = [];

    const addFinding = (
      id: string,
      category: RealSecurityFinding['category'],
      severity: RealSecurityFinding['severity'],
      target: string,
      title: string,
      evidence: string,
      remediation: string
    ) => {
      const prev = this.findings.find((f) => f.finding_id === id);
      const status: RealFindingStatus = this.acknowledgedFindingIds.has(id)
        ? 'ACKNOWLEDGED'
        : 'OPEN';
      discovered.push({
        finding_id: id,
        detected_at: prev?.detected_at ?? nowIso,
        category,
        severity,
        target,
        title,
        evidence,
        remediation,
        status,
      });
    };

    for (const ep of this.endpoints) {
      if (ep.status === 'DOWN') {
        addFinding(
          `REAL-AVAIL-${ep.id}`,
          'AVAILABILITY',
          'CRITICAL',
          ep.url,
          `Endpoint Tidak Merespons (${ep.label})`,
          ep.errorMessage
            ? `Live probe error: ${ep.errorMessage}`
            : `HTTP ${ep.httpStatus ?? 'N/A'}`,
          'Periksa status origin server, load balancer, dan aturan firewall edge.'
        );
      } else if (ep.status === 'DEGRADED' && ep.latencyMs !== null) {
        addFinding(
          `REAL-LAT-${ep.id}`,
          'AVAILABILITY',
          'MEDIUM',
          ep.url,
          `Latensi Respons Tinggi (${ep.latencyMs} ms)`,
          `Measured live GET latency ${ep.latencyMs} ms (> 1800 ms threshold)`,
          'Evaluasi cache CDN/WAF, connection pool backend, serta kapasitas antrean pendaftaran.'
        );
      }

      if (ep.status !== 'DOWN' && ep.lastCheckedAt) {
        if (!ep.securityHeaders.hsts) {
          addFinding(
            `REAL-HSTS-${ep.id}`,
            'HTTP_HEADER',
            'HIGH',
            ep.url,
            'Header Strict-Transport-Security (HSTS) Tidak Ditemukan',
            `Live HTTP ${ep.httpStatus} response dari ${ep.hostname} tidak menyertakan header Strict-Transport-Security.`,
            'Tambahkan header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload pada reverse proxy / WAF.'
          );
        }
        if (!ep.securityHeaders.csp) {
          addFinding(
            `REAL-CSP-${ep.id}`,
            'HTTP_HEADER',
            'MEDIUM',
            ep.url,
            'Header Content-Security-Policy (CSP) Belum Diterapkan',
            `Live HTTP ${ep.httpStatus} response dari ${ep.hostname} tidak memiliki Content-Security-Policy.`,
            'Terapkan kebijakan Content-Security-Policy ketat untuk membatasi sumber script eksternal dan mencegah XSS.'
          );
        }
        if (!ep.securityHeaders.xFrameOptions) {
          addFinding(
            `REAL-XFO-${ep.id}`,
            'HTTP_HEADER',
            'MEDIUM',
            ep.url,
            'Header X-Frame-Options Tidak Aktif (Risiko Clickjacking)',
            `Live HTTP ${ep.httpStatus} response tidak menyertakan X-Frame-Options.`,
            'Aktifkan X-Frame-Options: SAMEORIGIN atau CSP frame-ancestors \'self\'.'
          );
        }
        if (ep.cookies.count > 0 && (!ep.cookies.allSecure || !ep.cookies.allHttpOnly)) {
          addFinding(
            `REAL-COOKIE-${ep.id}`,
            'HTTP_HEADER',
            'HIGH',
            ep.url,
            'Atribut Cookie Sesi Kurang Ketat (Secure / HttpOnly)',
            `Terdeteksi ${ep.cookies.count} Set-Cookie header dengan allSecure=${ep.cookies.allSecure}, allHttpOnly=${ep.cookies.allHttpOnly}.`,
            'Pastikan seluruh session cookie menggunakan atribut Secure; HttpOnly; SameSite=Lax/Strict.'
          );
        }
        if (ep.poweredByHeader) {
          addFinding(
            `REAL-DISCL-${ep.id}`,
            'INFO_DISCLOSURE',
            'LOW',
            ep.url,
            `Information Disclosure melalui X-Powered-By (${ep.poweredByHeader})`,
            `Header respons mengekspos stack teknologi: X-Powered-By: ${ep.poweredByHeader}`,
            'Hapus header X-Powered-By dan samarkan banner versi server pada konfigurasi web server / WAF.'
          );
        }
      }

      if (ep.tls && ep.tls.daysRemaining !== null && ep.tls.daysRemaining < 30) {
        addFinding(
          `REAL-TLS-EXP-${ep.id}`,
          'TLS_CERT',
          ep.tls.daysRemaining < 14 ? 'CRITICAL' : 'HIGH',
          ep.hostname,
          `Sertifikat TLS Mendekati Kedaluwarsa (${ep.tls.daysRemaining} hari)`,
          `CN=${ep.tls.subject}, Issuer=${ep.tls.issuer}, ValidTo=${ep.tls.validTo}`,
          'Segera perbarui sertifikat SSL/TLS sebelum masa berlaku habis untuk mencegah gangguan layanan HTTPS.'
        );
      }
    }

    if (this.dnsAudit) {
      const d = this.dnsAudit;
      if (d.dmarc.policy === 'none' || d.dmarc.policy === 'MISSING') {
        addFinding(
          `REAL-DMARC-${d.rootDomain}`,
          'DNS_EMAIL',
          d.dmarc.policy === 'MISSING' ? 'HIGH' : 'MEDIUM',
          `_dmarc.${d.rootDomain}`,
          d.dmarc.policy === 'MISSING'
            ? `Record DMARC Tidak Ditemukan pada ${d.rootDomain}`
            : `Kebijakan DMARC Masih Monitor-Only (p=none) pada ${d.rootDomain}`,
          d.dmarc.record
            ? `Live DNS TXT _dmarc.${d.rootDomain}: "${d.dmarc.record}"`
            : `Tidak ditemukan record TXT pada _dmarc.${d.rootDomain}`,
          'Tingkatkan kebijakan DMARC secara bertahap dari p=none ke p=quarantine lalu p=reject untuk mencegah email phishing mengatasnamakan organisasi Anda.'
        );
      }

      if (!d.caa.present) {
        addFinding(
          `REAL-CAA-${d.rootDomain}`,
          'DNS_EMAIL',
          'MEDIUM',
          d.rootDomain,
          `DNS CAA Record Belum Dikonfigurasi pada ${d.rootDomain}`,
          `Live DNS CAA lookup pada ${d.rootDomain} mengembalikan 0 record.`,
          'Tambahkan DNS CAA record (mis. 0 issue "sectigo.com") agar hanya Certificate Authority resmi yang diizinkan menerbitkan sertifikat domain.'
        );
      }

      if (!d.spf.present || d.spf.policy === 'NEUTRAL') {
        addFinding(
          `REAL-SPF-${d.rootDomain}`,
          'DNS_EMAIL',
          'HIGH',
          d.rootDomain,
          `Konfigurasi SPF Lemah / Hilang pada ${d.rootDomain}`,
          d.spf.record
            ? `SPF TXT: "${d.spf.record}"`
            : `Tidak ada SPF record pada ${d.rootDomain}`,
          'Terapkan SPF record dengan mekanisme -all untuk menolak pengirim email tidak sah.'
        );
      }
    }

    if (this.threatIntel) {
      for (const ipRep of this.threatIntel.ipReputation) {
        if (ipRep.listedInThreatFeeds) {
          addFinding(
            `REAL-CTI-IP-${ipRep.ip.replace(/\./g, '-')}`,
            'GLOBAL_CTI',
            'CRITICAL',
            `${ipRep.ip} (${ipRep.hostname})`,
            `IP Resmi ${ORG_NAME} Terdeteksi pada Blocklist Ancaman Global`,
            `IP ${ipRep.ip} cocok dengan feed: ${ipRep.matchedFeeds.join(', ')}.`,
            'Segera lakukan investigasi server, audit egress traffic, dan ajukan delisting setelah bersih.'
          );
        }
      }

      const brandKeywords = (
        process.env.CTI_BRAND_KEYWORDS || ''
      )
        .split(',')
        .map((k) => k.trim().toLowerCase())
        .filter(Boolean);
      const brandDirectPhish = brandKeywords.length > 0
        ? this.threatIntel.openPhish.brandOrIndonesiaMatches.filter((m) =>
            m.matchedKeyword && brandKeywords.includes(m.matchedKeyword.toLowerCase())
          )
        : [];
      if (brandDirectPhish.length > 0) {
        addFinding(
          'REAL-CTI-OPENPHISH-BRAND',
          'GLOBAL_CTI',
          'CRITICAL',
          brandDirectPhish[0].domain,
          `Terdeteksi ${brandDirectPhish.length} URL Phishing Aktif Mencatut Brand ${ORG_NAME} (OpenPhish)`,
          `Live OpenPhish match: ${brandDirectPhish
            .slice(0, 3)
            .map((m) => m.url)
            .join(' | ')}`,
          'Laporkan segera ke Tim CSIRT / National CERT & Registrar untuk takedown domain serta publikasikan imbauan resmi kepada pengguna.'
        );
      }
    }

    // Automated Live HTML Defacement & Googlebot Cloaking Detections
    for (const scan of this.contentIncidentStore.getScans()) {
      if (scan.defacementSuspected) {
        const kwList = Array.from(
          new Set([...scan.browserKeywordsFound, ...scan.googlebotKeywordsFound])
        ).join(', ');
        addFinding(
          `REAL-CONTENT-DEFACE-${scan.endpointId.toUpperCase()}`,
          'CONTENT_DEFACEMENT',
          'CRITICAL',
          scan.hostname,
          `Indikasi Web Defacement / Konten Judol Terdeteksi pada ${scan.hostname}`,
          `Live HTML scan menemukan signature mencurigakan: ${kwList} (${scan.url})`,
          'Segera koordinasi dengan Tim Infra / pengelola server untuk isolasi file terinjeksi, audit webshell/backdoor, pulihkan dari backup bersih, dan ajukan pembersihan cache di Google Search Console.'
        );
      } else if (scan.cloakingSuspected) {
        addFinding(
          `REAL-CONTENT-CLOAK-${scan.endpointId.toUpperCase()}`,
          'CONTENT_DEFACEMENT',
          'HIGH',
          scan.hostname,
          `Indikasi Googlebot Cloaking pada ${scan.hostname}`,
          scan.cloakingReason ||
            'Respons HTML berbeda signifikan antara Browser biasa dan User-Agent Googlebot.',
          'Audit konfigurasi .htaccess, reverse proxy, dan kode PHP/CMS untuk mendeteksi skrip cloaking berbasis User-Agent.'
        );
      }
    }

    const severityRank: Record<RealSecurityFinding['severity'], number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
    };
    discovered.sort(
      (a, b) => severityRank[a.severity] - severityRank[b.severity]
    );

    this.findings = discovered;
    this.broadcast('findings:updated', this.findings);
    this.recomputeThreatIntelAlerts();
  }

  recomputeThreatIntelAlerts(): void {
    const derived: ThreatIntelAlert[] = [];
    const seenIds = new Set<string>();
    const nowIso = new Date().toISOString();

    const pushAlert = (
      alert: Omit<ThreatIntelAlert, 'status'>
    ): void => {
      if (seenIds.has(alert.intel_id)) return;
      seenIds.add(alert.intel_id);
      const override = this.threatAlertStatusOverrides.get(alert.intel_id);
      derived.push({
        ...alert,
        status: override ?? 'OPEN',
      });
    };

    // 1. Derive ZERO_DAY_CVE alerts from live CISA KEV feed
    if (this.threatIntel) {
      for (const kev of this.threatIntel.cisaKev.recent.slice(0, 6)) {
        const isRansom =
          kev.knownRansomwareCampaignUse.toLowerCase() === 'known';
        pushAlert({
          intel_id: `TI-${kev.cveID}`,
          detected_at: kev.dateAdded
            ? new Date(kev.dateAdded).toISOString()
            : this.threatIntel.lastSyncedAt || nowIso,
          source: 'CVE Feed',
          category: 'ZERO_DAY_CVE',
          affected_entity: `${kev.vendorProject} ${kev.product} (${kev.cveID})`,
          confidence_score: isRansom ? 98 : 92,
          recommended_playbook:
            'PB-CVE-01: Emergency Vendor Patching & WAF Virtual Patch Rule',
        });
      }

      // 2. Derive PHISHING_DOMAIN alerts from live OpenPhish & CT logs
      const phishPool =
        this.threatIntel.openPhish.brandOrIndonesiaMatches.length > 0
          ? this.threatIntel.openPhish.brandOrIndonesiaMatches.slice(0, 4)
          : this.threatIntel.openPhish.sampleRecent.slice(0, 2);

      phishPool.forEach((phish, idx) => {
        const safeDomain = phish.domain.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 48);
        pushAlert({
          intel_id: `TI-PHISH-${safeDomain || idx + 1}`,
          detected_at: this.threatIntel?.lastSyncedAt || nowIso,
          source: 'Domain Typosquatting Radar',
          category: 'PHISHING_DOMAIN',
          affected_entity: phish.domain || phish.url,
          confidence_score: phish.matchedKeyword ? 95 : 81,
          recommended_playbook:
            'PB-PHISH-02: Domain Takedown, DNS Sinkhole & DMARC Enforcement',
        });
      });

      // 3. Derive IP reputation / National CERT alert if any monitored IP hits blocklist
      for (const ipRep of this.threatIntel.ipReputation) {
        if (ipRep.listedInThreatFeeds) {
          pushAlert({
            intel_id: `TI-IPREP-${ipRep.ip.replace(/\./g, '-')}`,
            detected_at: ipRep.checkedAt,
            source: 'Gov-CSIRT / National CERT',
            category: 'CREDENTIAL_LEAK',
            affected_entity: `${ipRep.hostname} (${ipRep.ip})`,
            confidence_score: 97,
            recommended_playbook:
              'PB-CRED-03: Credential Rotation, Session Revocation & Egress Audit',
          });
        }
      }
    }

    // 4. Derive credential/auth alerts from real Local SIEM/Wazuh SSH/Auth detections or manual credential incidents
    if (this.localWazuh) {
      for (const al of this.localWazuh.alerts) {
        if (al.mitre_tactic === 'Credential Access' || al.rule_id === '5710') {
          pushAlert({
            intel_id: `TI-WAZUH-${al.alert_id}`,
            detected_at: al.timestamp,
            source: 'DarkWeb Forum',
            category: 'CREDENTIAL_LEAK',
            affected_entity: `${al.agent_name} · ${al.target}`,
            confidence_score: 88,
            recommended_playbook:
              'PB-CRED-03: Credential Rotation, Session Revocation & MFA Enforcement',
          });
        }
      }
    }

    for (const rep of this.contentIncidentStore.getReports()) {
      if (rep.category === 'CREDENTIAL_LEAK' && rep.status !== 'CLOSED') {
        pushAlert({
          intel_id: `TI-INC-${rep.id}`,
          detected_at: rep.occurredAt,
          source: 'Telegram Stealer Logs',
          category: 'CREDENTIAL_LEAK',
          affected_entity: rep.affectedUrl,
          confidence_score: 94,
          recommended_playbook:
            'PB-CRED-03: Credential Rotation, Session Revocation & MFA Enforcement',
        });
      }
    }

    this.threatIntelAlerts = derived;
    this.broadcast('threat-alerts:updated', this.threatIntelAlerts);
  }

  runThreatIntelPlaybook(
    intelId: string,
    nextStatus: ThreatIntelStatus,
    actor: string
  ): { alert: ThreatIntelAlert; threatIntelAlerts: ThreatIntelAlert[] } | null {
    const target = this.threatIntelAlerts.find((a) => a.intel_id === intelId);
    if (!target) return null;

    this.threatAlertStatusOverrides.set(intelId, nextStatus);
    this.threatIntelAlerts = this.threatIntelAlerts.map((a) =>
      a.intel_id === intelId ? { ...a, status: nextStatus } : a
    );
    const updated = this.threatIntelAlerts.find((a) => a.intel_id === intelId)!;

    this.broadcast('threat-alerts:updated', this.threatIntelAlerts);
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: updated.affected_entity,
      http_status: nextStatus,
      latency_ms: '-',
      result: `Executed playbook "${updated.recommended_playbook}" for ${updated.intel_id} -> status ${nextStatus}`,
    });
    return { alert: updated, threatIntelAlerts: this.threatIntelAlerts };
  }

  mitigateSiemEvent(
    eventId: string,
    mitigatedBy: string,
    mitigatedAt: string,
    actor: string
  ): { event: LiveAttackEvent; ingestedSiemEvents: LiveAttackEvent[] } | null {
    const idx = this.ingestedSiemEvents.findIndex((e) => e.event_id === eventId);
    if (idx === -1) return null;

    const existing = this.ingestedSiemEvents[idx];
    const updated: LiveAttackEvent = {
      ...existing,
      action_taken: 'MITIGATED',
      mitigated_by: mitigatedBy || 'SOC-Analyst-Auto',
      mitigated_at: mitigatedAt || new Date().toISOString(),
    };

    const next = [...this.ingestedSiemEvents];
    next[idx] = updated;
    this.ingestedSiemEvents = next;

    this.broadcast('siem:updated', this.ingestedSiemEvents);
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: updated.target_asset,
      http_status: 'MITIGATED',
      latency_ms: '-',
      result: `Mitigated ${updated.event_id} (${updated.attack_vector} from ${updated.source_ip}) by ${updated.mitigated_by}`,
    });

    return { event: updated, ingestedSiemEvents: this.ingestedSiemEvents };
  }

  async runFullRealCycle(actor = 'AUTO-PROBE-SCHEDULER'): Promise<void> {
    if (this.isProbing) return;
    this.isProbing = true;

    try {
      const snapshotList = [...this.endpoints];
      const updatedEndpoints = await Promise.all(
        snapshotList.map((ep) => this.probeSingleEndpoint(ep))
      );
      const updatedById = new Map(updatedEndpoints.map((ep) => [ep.id, ep]));
      // Merge by ID so endpoints added or removed mid-cycle are never overwritten
      this.endpoints = this.endpoints.map((ep) => updatedById.get(ep.id) ?? ep);

      const primary =
        this.endpoints.find((e) => e.id === 'ep-primary') ?? this.endpoints[0];
      const loginEp = this.endpoints.find((e) => e.id === 'ep-login');
      const secondaryEp = this.endpoints.find((e) => e.id === 'ep-secondary');

      const validLatencies = this.endpoints
        .map((e) => e.latencyMs)
        .filter((v): v is number => typeof v === 'number');
      const avgMs =
        validLatencies.length > 0
          ? Math.round(
              validLatencies.reduce((s, n) => s + n, 0) / validLatencies.length
            )
          : null;

      const point: RealLatencyPoint = {
        time: formatChartTimeWIB(new Date()),
        primaryMs: primary?.latencyMs ?? null,
        loginMs: loginEp?.latencyMs ?? null,
        secondaryMs: secondaryEp?.latencyMs ?? null,
        avgMs,
      };
      this.latencyHistory = [...this.latencyHistory.slice(-29), point];

      // Refresh DNS audit on first run or manual trigger or every 4 cycles
      const shouldAuditDns =
        !this.dnsAudit ||
        actor !== 'AUTO-PROBE-SCHEDULER' ||
        this.latencyHistory.length % 4 === 1;

      if (shouldAuditDns && primary) {
        this.dnsAudit = await inspectRootDnsSecurity(primary.hostname);
        this.broadcast('dns:updated', this.dnsAudit);
        this.appendLog({
          actor,
          check_type: 'DNS_AUDIT',
          target: this.dnsAudit.rootDomain,
          http_status: `DNS ${this.dnsAudit.score}%`,
          latency_ms: '-',
          result: `SPF:${this.dnsAudit.spf.policy} · DMARC:${this.dnsAudit.dmarc.policy} · CAA:${
            this.dnsAudit.caa.present ? 'ON' : 'MISSING'
          }`,
        });
      }

      this.recomputeRealFindings();

      this.broadcast('probe:cycle', {
        endpoints: this.endpoints,
        point,
      });

      if (primary) {
        this.appendLog({
          actor,
          check_type: 'HTTP_TLS_PROBE',
          target: primary.url,
          http_status: primary.httpStatus ? `HTTP ${primary.httpStatus}` : 'DOWN',
          latency_ms: primary.latencyMs !== null ? `${primary.latencyMs} ms` : '-',
          result:
            primary.status === 'DOWN'
              ? `Unreachable (${primary.errorMessage ?? 'timeout'})`
              : `${primary.tls?.protocol ?? 'HTTPS'} (${
                  primary.tls?.daysRemaining ?? '?'
                }d) · Headers ${primary.headerScore}% · IP ${
                  primary.dns.ipv4[0] ?? '-'
                }`,
        });
      }
    } finally {
      this.isProbing = false;
    }
  }

  async syncGlobalThreatIntel(
    actor = 'AUTO-CTI-SCHEDULER'
  ): Promise<GlobalThreatIntelSnapshot> {
    if (this.isSyncingCti && this.threatIntel) {
      return this.threatIntel;
    }
    this.isSyncingCti = true;
    try {
      const snapshot = await fetchGlobalThreatIntelSnapshot(this.endpoints);
      this.threatIntel = snapshot;
      this.recomputeRealFindings();
      this.broadcast('cti:updated', snapshot);

      const okSources = snapshot.sourcesStatus.filter(
        (s) => s.status === 'OK'
      ).length;
      this.appendLog({
        actor,
        check_type: 'CTI_SYNC',
        target: 'Global Open CTI (6 Public Feeds)',
        http_status: `${okSources}/${snapshot.sourcesStatus.length} OK`,
        latency_ms: snapshot.syncDurationMs ? `${snapshot.syncDurationMs} ms` : '-',
        result: `CISA KEV:${snapshot.cisaKev.totalCount} · Feodo/ET:${
          snapshot.botnetC2.feodoTotal + snapshot.botnetC2.etCompromisedTotal
        } · CT:${snapshot.certTransparency.totalEntries} · OpenPhish:${
          snapshot.openPhish.totalActiveUrls
        }`,
      });
      return snapshot;
    } finally {
      this.isSyncingCti = false;
    }
  }

  runLocalWazuhScan(actor = 'LOCAL-SIEM-AGENT'): LocalWazuhSnapshot {
    const snapshot = this.localEngine.runFullLocalScan();
    this.localWazuh = snapshot;
    this.broadcast('wazuh:updated', snapshot);

    if (actor !== 'LOCAL-SIEM-SCHEDULER') {
      this.appendLog({
        actor,
        check_type: 'LOCAL_SIEM_SCAN',
        target: snapshot.config.agentName,
        http_status: `SCA ${snapshot.sca.scorePercent}%`,
        latency_ms: snapshot.scanDurationMs ? `${snapshot.scanDurationMs} ms` : '-',
        result: `FIM ${snapshot.fim.okCount}/${snapshot.fim.totalMonitored} OK (${snapshot.fim.modifiedCount} mod) · Ports ${snapshot.network.listeningPorts.length} · Alerts ${snapshot.alerts.length}`,
      });
    }
    return snapshot;
  }

  acceptLocalFimBaseline(actor: string): LocalWazuhSnapshot {
    const snapshot = this.localEngine.acceptCurrentFimBaseline();
    this.localWazuh = snapshot;
    this.broadcast('wazuh:updated', snapshot);
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: snapshot.config.agentName,
      http_status: 'BASELINE OK',
      latency_ms: '-',
      result: `Accepted new SHA-256 FIM baseline for ${snapshot.fim.okCount} monitored files`,
    });
    return snapshot;
  }

  updateLocalAgentConfig(
    patch: Partial<LocalAgentConfig>,
    actor: string
  ): LocalWazuhSnapshot {
    const updated = this.localEngine.updateConfig(patch);
    this.startLocalSiemSchedule();
    const snapshot = this.runLocalWazuhScan(actor);
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: updated.agentName,
      http_status: 'CONFIG SAVED',
      latency_ms: '-',
      result: `Updated local sensor config (${updated.fimPaths.length} FIM paths, ${updated.logSources.length} log sources, interval ${updated.scanIntervalSec}s)`,
    });
    return snapshot;
  }

  async syncCyberKnowledge(
    actor = 'SYSTEM-KNOWLEDGE-SYNC'
  ): Promise<CyberKnowledgeSnapshot> {
    if (this.isSyncingKnowledge && this.knowledge) {
      return this.knowledge;
    }
    this.isSyncingKnowledge = true;
    try {
      const snap = await this.knowledgeStore.fetchLiveKnowledgeSnapshot();
      this.knowledge = snap;
      this.broadcast('knowledge:updated', snap);
      const okCount = snap.sourcesStatus.filter((s) => s.status === 'OK').length;
      this.appendLog({
        actor,
        check_type: 'KNOWLEDGE_SYNC',
        target: 'Cyber Academy Live Knowledge Feeds',
        http_status: `${okCount}/${snap.sourcesStatus.length} OK`,
        latency_ms: snap.updateDurationMs ? `${snap.updateDurationMs} ms` : '-',
        result: `Synced ${snap.liveBriefings.length} live advisories & briefings · SANS InfoCon: ${snap.sansInfocon.toUpperCase()}`,
      });
      return snap;
    } finally {
      this.isSyncingKnowledge = false;
    }
  }

  addCustomGlossaryTerm(
    termInput: Omit<CustomGlossaryTerm, 'id' | 'addedAt'>,
    actor: string
  ): CyberKnowledgeSnapshot {
    const updatedTerms = this.knowledgeStore.addCustomTerm(termInput);
    const snap: CyberKnowledgeSnapshot = this.knowledge
      ? { ...this.knowledge, customTerms: updatedTerms }
      : {
          lastUpdatedAt: new Date().toISOString(),
          updateDurationMs: 0,
          sansInfocon: 'unknown',
          sourcesStatus: [],
          liveBriefings: [],
          customTerms: updatedTerms,
        };
    this.knowledge = snap;
    this.broadcast('knowledge:updated', snap);
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: 'Cyber Academy Glossary',
      http_status: 'TERM ADDED',
      latency_ms: '-',
      result: `Added custom glossary term: ${termInput.term}`,
    });
    return snap;
  }

  async runContentIntegrityScan(
    actor = 'AUTO-CONTENT-SCANNER'
  ): Promise<ContentIntegrityScan[]> {
    if (this.isScanningContent) {
      return this.contentIncidentStore.getScans();
    }
    this.isScanningContent = true;
    try {
      const t0 = Date.now();
      const scans = await this.contentIncidentStore.scanAllEndpoints(
        this.endpoints
      );
      this.recomputeRealFindings();
      this.broadcast('content:updated', scans);
      const flagged = scans.filter((s) => s.riskLevel !== 'CLEAN').length;
      this.appendLog({
        actor,
        check_type: 'CONTENT_INTEGRITY_SCAN',
        target: `${scans.length} Monitored URLs (Browser vs Googlebot UA)`,
        http_status: flagged > 0 ? `${flagged} ALERT` : 'ALL CLEAN',
        latency_ms: `${Date.now() - t0} ms`,
        result:
          flagged > 0
            ? `Detected ${flagged} URL(s) with defacement/cloaking/content-drift signals`
            : `Scanned ${scans.length} endpoints (HTML title/meta/body SHA-256 + Judol signatures clean)`,
      });
      return scans;
    } finally {
      this.isScanningContent = false;
    }
  }

  acceptContentIntegrityBaselines(actor: string): ContentIntegrityScan[] {
    const scans = this.contentIncidentStore.acceptContentBaselines();
    this.recomputeRealFindings();
    this.broadcast('content:updated', scans);
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: 'HTML Content SHA-256 Baselines',
      http_status: 'BASELINE OK',
      latency_ms: '-',
      result: `Accepted HTML content hash baseline for ${scans.length} monitored URLs`,
    });
    return scans;
  }

  createManualIncidentReport(
    body: Record<string, unknown>,
    actor: string
  ): { report: ManualIncidentReport; reports: ManualIncidentReport[] } {
    const report = this.contentIncidentStore.createReport({
      title: String(body.title ?? ''),
      affectedUrl: String(body.affectedUrl ?? ''),
      category: typeof body.category === 'string' ? body.category : undefined,
      severity: typeof body.severity === 'string' ? body.severity : undefined,
      source: typeof body.source === 'string' ? body.source : undefined,
      reporterName:
        typeof body.reporterName === 'string' ? body.reporterName : undefined,
      occurredAt:
        typeof body.occurredAt === 'string' ? body.occurredAt : undefined,
      description:
        typeof body.description === 'string' ? body.description : undefined,
      evidenceSnippet:
        typeof body.evidenceSnippet === 'string'
          ? body.evidenceSnippet
          : undefined,
      coordinationNotes:
        typeof body.coordinationNotes === 'string'
          ? body.coordinationNotes
          : undefined,
      actionTaken:
        typeof body.actionTaken === 'string' ? body.actionTaken : undefined,
      status: typeof body.status === 'string' ? body.status : undefined,
      includeInBoardReport:
        typeof body.includeInBoardReport === 'boolean'
          ? body.includeInBoardReport
          : true,
    });
    const reports = this.contentIncidentStore.getReports();
    this.broadcast('incidents:updated', reports);
    this.appendLog({
      actor,
      check_type: 'INCIDENT_REPORT',
      target: report.affectedUrl,
      http_status: report.severity,
      latency_ms: '-',
      result: `Recorded incident ${report.id} (${report.category}) from ${report.source}: ${report.title}`,
    });
    return { report, reports };
  }

  updateManualIncidentReport(
    id: string,
    body: Record<string, unknown>,
    actor: string
  ): { report: ManualIncidentReport; reports: ManualIncidentReport[] } | null {
    const updated = this.contentIncidentStore.updateReport(id, {
      status: body.status as ManualIncidentReport['status'] | undefined,
      severity: body.severity as ManualIncidentReport['severity'] | undefined,
      coordinationNotes:
        typeof body.coordinationNotes === 'string'
          ? body.coordinationNotes
          : undefined,
      actionTaken:
        typeof body.actionTaken === 'string' ? body.actionTaken : undefined,
      description:
        typeof body.description === 'string' ? body.description : undefined,
      evidenceSnippet:
        typeof body.evidenceSnippet === 'string'
          ? body.evidenceSnippet
          : undefined,
      includeInBoardReport:
        typeof body.includeInBoardReport === 'boolean'
          ? body.includeInBoardReport
          : undefined,
    });
    if (!updated) return null;
    const reports = this.contentIncidentStore.getReports();
    this.broadcast('incidents:updated', reports);
    this.appendLog({
      actor,
      check_type: 'INCIDENT_REPORT',
      target: updated.affectedUrl,
      http_status: updated.status,
      latency_ms: '-',
      result: `Updated incident ${updated.id} → status ${updated.status} (Board Report: ${
        updated.includeInBoardReport ? 'YES' : 'NO'
      })`,
    });
    return { report: updated, reports };
  }

  deleteManualIncidentReport(
    id: string,
    actor: string
  ): ManualIncidentReport[] | null {
    const ok = this.contentIncidentStore.deleteReport(id);
    if (!ok) return null;
    const reports = this.contentIncidentStore.getReports();
    this.broadcast('incidents:updated', reports);
    this.appendLog({
      actor,
      check_type: 'INCIDENT_REPORT',
      target: id,
      http_status: 'DELETED',
      latency_ms: '-',
      result: `Deleted incident report ${id}`,
    });
    return reports;
  }

  async addCustomEndpoint(url: string, label: string, actor: string) {
    let cleaned = url.trim();
    // Fix accidental double scheme when pasting into prefilled input
    cleaned = cleaned.replace(/^(https?:\/\/)+(https?:\/\/)/i, '$2');
    if (!/^https?:\/\//i.test(cleaned)) {
      cleaned = `https://${cleaned}`;
    }

    const parsed = new URL(cleaned);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new Error('URL must start with https:// or http://');
    }

    const normalizeKey = (u: string) => {
      try {
        const p = new URL(u);
        return `${p.protocol}//${p.hostname.toLowerCase()}${p.pathname.replace(/\/+$/, '')}`;
      } catch {
        return u.toLowerCase().replace(/\/+$/, '');
      }
    };
    const nextKey = normalizeKey(parsed.toString());
    if (this.endpoints.some((e) => normalizeKey(e.url) === nextKey)) {
      throw new Error(`Endpoint ${parsed.hostname} sudah ada di daftar pantauan`);
    }

    const id = `ep-custom-${Date.now().toString(36)}`;
    const base: RealEndpointProbe = {
      id,
      label: label.trim() || parsed.hostname,
      url: parsed.toString(),
      hostname: parsed.hostname,
      isDefault: false,
      status: 'PENDING',
      httpStatus: null,
      latencyMs: null,
      uptimePercent: 100,
      totalChecks: 0,
      successChecks: 0,
      lastCheckedAt: null,
      headerScore: 0,
      serverHeader: null,
      poweredByHeader: null,
      securityHeaders: {
        hsts: null,
        csp: null,
        xFrameOptions: null,
        xContentTypeOptions: null,
        referrerPolicy: null,
        permissionsPolicy: null,
      },
      cookies: {
        count: 0,
        allSecure: true,
        allHttpOnly: true,
        hasSameSite: true,
      },
      tls: null,
      dns: { ipv4: [], ipv6: [], cname: [] },
    };

    const probed = await this.probeSingleEndpoint(base);
    // Insert right after the primary portal so newly added targets are immediately visible
    if (this.endpoints.length > 0) {
      this.endpoints = [this.endpoints[0], probed, ...this.endpoints.slice(1)];
    } else {
      this.endpoints = [probed];
    }
    this.recomputeRealFindings();
    this.broadcast('probe:cycle', {
      endpoints: this.endpoints,
      point: this.latencyHistory[this.latencyHistory.length - 1] ?? null,
    });
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: probed.url,
      http_status: probed.httpStatus ? `HTTP ${probed.httpStatus}` : 'DOWN',
      latency_ms: probed.latencyMs !== null ? `${probed.latencyMs} ms` : '-',
      result: `Added & probed live target (${probed.label})`,
    });
    return probed;
  }

  removeCustomEndpoint(id: string, actor: string): boolean {
    const target = this.endpoints.find((e) => e.id === id && e.id !== 'ep-primary');
    if (!target) return false;
    this.endpoints = this.endpoints.filter((e) => e.id !== id);
    this.recomputeRealFindings();
    this.broadcast('probe:cycle', {
      endpoints: this.endpoints,
      point: this.latencyHistory[this.latencyHistory.length - 1] ?? null,
    });
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: target.url,
      http_status: '-',
      latency_ms: '-',
      result: `Removed monitored target (${target.label})`,
    });
    return true;
  }

  updateFindingStatus(
    findingId: string,
    status: RealFindingStatus,
    actor: string
  ): RealSecurityFinding | null {
    const existing = this.findings.find((f) => f.finding_id === findingId);
    if (!existing) return null;

    if (status === 'ACKNOWLEDGED') {
      this.acknowledgedFindingIds.add(findingId);
    } else {
      this.acknowledgedFindingIds.delete(findingId);
    }

    const updated: RealSecurityFinding = { ...existing, status };
    this.findings = this.findings.map((f) =>
      f.finding_id === findingId ? updated : f
    );
    this.broadcast('findings:updated', this.findings);
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: existing.target,
      http_status: status,
      latency_ms: '-',
      result: `${findingId} (${existing.title}) marked as ${status}`,
    });
    return updated;
  }

  updateProbeInterval(ms: number, actor: string): number {
    this.probeIntervalMs = Math.max(10000, Math.min(120000, ms));
    this.startRealProbeSchedule();
    this.broadcast('config:updated', { probeIntervalMs: this.probeIntervalMs });
    this.appendLog({
      actor,
      check_type: 'ANALYST_ACTION',
      target: 'SOC Real Probe Scheduler',
      http_status: 'OK',
      latency_ms: '-',
      result: `Updated real live probe interval to ${this.probeIntervalMs / 1000}s`,
    });
    return this.probeIntervalMs;
  }

  ingestRealSiemWebhook(body: Partial<LiveAttackEvent>): LiveAttackEvent {
    const evt: LiveAttackEvent = {
      event_id:
        body.event_id ||
        `SIEM-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${String(
          this.siemSeq++
        ).padStart(4, '0')}`,
      timestamp: body.timestamp || new Date().toISOString(),
      source_ip: body.source_ip || 'unknown',
      source_country: body.source_country || 'XX',
      source_coords: body.source_coords || [0, 0],
      target_asset: body.target_asset || safeHostname(PRIMARY_PORTAL_URL),
      attack_vector: body.attack_vector || 'DDoS L7',
      severity: body.severity || 'HIGH',
      action_taken: body.action_taken || 'DETECTED',
      payload_snippet:
        body.payload_snippet || 'External SIEM/WAF webhook payload received',
    };
    this.ingestedSiemEvents = [evt, ...this.ingestedSiemEvents].slice(0, 100);
    this.broadcast('siem:ingested', evt);
    this.appendLog({
      actor: 'EXTERNAL-SIEM-WEBHOOK',
      check_type: 'SIEM_INGEST',
      target: evt.target_asset,
      http_status: evt.severity,
      latency_ms: '-',
      result: `Real SIEM webhook ingested: ${evt.attack_vector} from ${evt.source_ip}`,
    });
    return evt;
  }

  private startRealProbeSchedule(): void {
    if (this.loopTimer) {
      clearInterval(this.loopTimer);
    }
    this.loopTimer = setInterval(() => {
      void this.runFullRealCycle('AUTO-PROBE-SCHEDULER');
    }, this.probeIntervalMs);
  }

  private startCtiSchedule(): void {
    if (this.ctiTimer) {
      clearInterval(this.ctiTimer);
    }
    // Refresh public Open CTI feeds every 5 minutes politely
    this.ctiTimer = setInterval(() => {
      void this.syncGlobalThreatIntel('AUTO-CTI-SCHEDULER');
    }, 300000);
  }

  private startLocalSiemSchedule(): void {
    if (this.localTimer) {
      clearInterval(this.localTimer);
    }
    const intervalMs = Math.max(
      10000,
      this.localEngine.getConfig().scanIntervalSec * 1000
    );
    this.localTimer = setInterval(() => {
      this.runLocalWazuhScan('LOCAL-SIEM-SCHEDULER');
    }, intervalMs);
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  const store = new RealSocMonitorStore();

  // Real local HTTP sensor middleware (detects SQLi/XSS/Traversal hitting this server)
  app.use((req: Request, _res: Response, next) => {
    const remoteIp =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      '127.0.0.1';
    const alert = store.localEngine.inspectIncomingHttpRequest(
      req.originalUrl,
      remoteIp
    );
    if (alert) {
      const snap = store.localEngine.runFullLocalScan();
      store.localWazuh = snap;
      store.broadcast('wazuh:updated', snap);
    }
    next();
  });

  // Immediately run initial local SIEM scan + external probe cycle + Global Open CTI + Knowledge Feed
  store.runLocalWazuhScan('SYSTEM-BOOT-LOCAL-SIEM');
  void store
    .runFullRealCycle('SYSTEM-BOOT-PROBE')
    .then(() =>
      Promise.all([
        store.syncGlobalThreatIntel('SYSTEM-BOOT-CTI'),
        store.syncCyberKnowledge('SYSTEM-BOOT-KNOWLEDGE'),
        store.runContentIntegrityScan('SYSTEM-BOOT-CONTENT-SCAN'),
      ])
    );

  // 1. 100% Real Telemetry Snapshot & SSE Stream
  app.get('/api/real/snapshot', (_req: Request, res: Response) => {
    res.json(store.getSnapshot());
  });

  app.get('/api/real/stream', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    store.addClient(res);
    res.write(`event: init\ndata: ${JSON.stringify(store.getSnapshot())}\n\n`);

    const heartbeat = setInterval(() => {
      try {
        res.write(': heartbeat\n\n');
      } catch {
        clearInterval(heartbeat);
      }
    }, 20000);

    req.on('close', () => {
      clearInterval(heartbeat);
      store.removeClient(res);
    });
  });

  // 2. Manual Full Live Scan Trigger & Global CTI Sync Trigger
  app.post('/api/real/probe', async (req: Request, res: Response) => {
    const actor = req.body?.actor || 'SOC-Analyst (Manual Scan)';
    await store.runFullRealCycle(actor);
    res.json(store.getSnapshot());
  });

  app.post('/api/real/cti/sync', async (req: Request, res: Response) => {
    const actor = req.body?.actor || 'SOC-Analyst (Manual CTI Sync)';
    const threatIntel = await store.syncGlobalThreatIntel(actor);
    res.json({ threatIntel });
  });

  // 2b. Local Host SIEM / XDR (Wazuh-Style) Controls & Configuration
  app.post('/api/real/local/scan', (req: Request, res: Response) => {
    const actor = req.body?.actor || 'SOC-Analyst (Local SIEM Scan)';
    const localWazuh = store.runLocalWazuhScan(actor);
    res.json({ localWazuh });
  });

  app.post('/api/real/local/fim/baseline', (req: Request, res: Response) => {
    const actor = req.body?.actor || 'SOC-Analyst (FIM Baseline)';
    const localWazuh = store.acceptLocalFimBaseline(actor);
    res.json({ localWazuh });
  });

  app.put('/api/real/local/config', (req: Request, res: Response) => {
    const { config, actor } = req.body ?? {};
    if (!config || typeof config !== 'object') {
      res.status(400).json({ error: 'Valid config object is required' });
      return;
    }
    const localWazuh = store.updateLocalAgentConfig(
      config as Partial<LocalAgentConfig>,
      actor || 'SOC-Analyst (Local Config)'
    );
    res.json({ localWazuh });
  });

  app.post('/api/real/local/verify-path', (req: Request, res: Response) => {
    const targetPath = typeof req.body?.path === 'string' ? req.body.path : '';
    if (!targetPath.trim()) {
      res.status(400).json({ error: 'Path is required' });
      return;
    }
    res.json(store.localEngine.verifyPathAccess(targetPath));
  });

  // 2c. Live Cyber Knowledge & Academy Refresh
  app.post('/api/real/knowledge/refresh', async (req: Request, res: Response) => {
    const actor = req.body?.actor || 'SOC-Analyst (Update Pengetahuan)';
    const knowledge = await store.syncCyberKnowledge(actor);
    res.json({ knowledge });
  });

  app.post('/api/real/knowledge/terms', (req: Request, res: Response) => {
    const { term, category, definition, analogy, orgRelevance, actor } =
      req.body ?? {};
    if (!term || !definition) {
      res.status(400).json({ error: 'Istilah dan definisi wajib diisi' });
      return;
    }
    const knowledge = store.addCustomGlossaryTerm(
      {
        term: String(term),
        category: category || 'Threat Intelligence',
        definition: String(definition),
        analogy: String(analogy || ''),
        orgRelevance: String(orgRelevance || ''),
      },
      actor || 'SOC-Analyst'
    );
    res.status(201).json({ knowledge });
  });

  // 2d. Live HTML Defacement & Googlebot Cloaking Scan + Manual/Ops Incident Reports
  app.post('/api/real/content-scan', async (req: Request, res: Response) => {
    const actor = req.body?.actor || 'SOC-Analyst (Content & Cloaking Scan)';
    const contentScans = await store.runContentIntegrityScan(actor);
    res.json({ contentScans });
  });

  app.post('/api/real/content-scan/baseline', (req: Request, res: Response) => {
    const actor = req.body?.actor || 'SOC-Analyst (Content Baseline)';
    const contentScans = store.acceptContentIntegrityBaselines(actor);
    res.json({ contentScans });
  });

  app.get('/api/real/incidents', (_req: Request, res: Response) => {
    res.json({ incidentReports: store.contentIncidentStore.getReports() });
  });

  app.post('/api/real/incidents', (req: Request, res: Response) => {
    try {
      const actor = String(req.body?.actor || 'SOC-Analyst');
      const result = store.createManualIncidentReport(req.body ?? {}, actor);
      res.status(201).json({
        report: result.report,
        incidentReports: result.reports,
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Invalid incident payload',
      });
    }
  });

  app.patch('/api/real/incidents/:id', (req: Request, res: Response) => {
    const actor = String(req.body?.actor || 'SOC-Analyst');
    const result = store.updateManualIncidentReport(
      String(req.params.id),
      req.body ?? {},
      actor
    );
    if (!result) {
      res.status(404).json({ error: 'Incident report not found' });
      return;
    }
    res.json({
      report: result.report,
      incidentReports: result.reports,
    });
  });

  app.delete('/api/real/incidents/:id', (req: Request, res: Response) => {
    const reports = store.deleteManualIncidentReport(
      String(req.params.id),
      'SOC-Analyst'
    );
    if (!reports) {
      res.status(404).json({ error: 'Incident report not found' });
      return;
    }
    res.json({ ok: true, incidentReports: reports });
  });

  // 3. Add / Remove Custom Monitored Public HTTPS Endpoints
  app.post('/api/real/endpoints', async (req: Request, res: Response) => {
    const { url, label, actor } = req.body ?? {};
    if (!url || typeof url !== 'string') {
      res.status(400).json({ error: 'Valid HTTPS URL is required' });
      return;
    }
    try {
      const endpoint = await store.addCustomEndpoint(
        url,
        label || '',
        actor || 'SOC-Analyst'
      );
      res.status(201).json({ endpoint });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Invalid target URL',
      });
    }
  });

  app.delete('/api/real/endpoints/:id', (req: Request, res: Response) => {
    const removed = store.removeCustomEndpoint(
      String(req.params.id),
      'SOC-Analyst'
    );
    if (!removed) {
      res.status(404).json({ error: 'Custom endpoint not found' });
      return;
    }
    res.json({ ok: true });
  });

  // 4. Acknowledge / Reopen Real Verified Findings
  app.post('/api/real/findings/:id/status', (req: Request, res: Response) => {
    const { status, actor } = req.body ?? {};
    if (status !== 'OPEN' && status !== 'ACKNOWLEDGED') {
      res.status(400).json({ error: 'status must be OPEN or ACKNOWLEDGED' });
      return;
    }
    const updated = store.updateFindingStatus(
      String(req.params.id),
      status,
      actor || 'SOC-Analyst'
    );
    if (!updated) {
      res.status(404).json({ error: 'Finding not found' });
      return;
    }
    res.json({ finding: updated });
  });

  // 5. Real Probe Interval Configuration
  app.put('/api/real/config', (req: Request, res: Response) => {
    const ms = Number(req.body?.probeIntervalMs);
    if (Number.isNaN(ms)) {
      res.status(400).json({ error: 'probeIntervalMs must be a number' });
      return;
    }
    const updatedMs = store.updateProbeInterval(ms, req.body?.actor || 'SOC-Analyst');
    res.json({ probeIntervalMs: updatedMs });
  });

  // 6. Real External SIEM / WAF Webhook Ingestion (Zero fake events — only real pushes)
  app.post('/api/ingest/siem', (req: Request, res: Response) => {
    const sharedSecret = process.env.INGEST_SHARED_SECRET;
    if (sharedSecret) {
      const provided =
        req.headers.authorization?.replace(/^Bearer\s+/i, '') ||
        req.headers['x-soc-ingest-secret'];
      if (provided !== sharedSecret) {
        res.status(401).json({ error: 'Invalid ingest secret' });
        return;
      }
    }
    const event = store.ingestRealSiemWebhook(req.body ?? {});
    res.status(201).json({ ingested: true, event });
  });

  // 7. Incident Response Playbook Execution & Attack Event Mitigation
  app.post(
    '/api/real/threat-alerts/:intelId/run-playbook',
    (req: Request, res: Response) => {
      const intelId = String(req.params.intelId);
      const nextStatus: ThreatIntelStatus =
        req.body?.status === 'FALSE_POSITIVE' || req.body?.status === 'OPEN'
          ? req.body.status
          : 'MITIGATED';
      const actor = String(req.body?.actor || 'SOC-Analyst-Auto');
      const result = store.runThreatIntelPlaybook(intelId, nextStatus, actor);
      if (!result) {
        res.status(404).json({ error: 'ThreatIntelAlert not found' });
        return;
      }
      res.json(result);
    }
  );

  app.post('/api/real/siem/:eventId/mitigate', (req: Request, res: Response) => {
    const eventId = String(req.params.eventId);
    const mitigatedBy =
      typeof req.body?.mitigated_by === 'string' && req.body.mitigated_by.trim()
        ? req.body.mitigated_by.trim()
        : 'SOC-Analyst-Auto';
    const mitigatedAt =
      typeof req.body?.mitigated_at === 'string' && req.body.mitigated_at.trim()
        ? req.body.mitigated_at.trim()
        : new Date().toISOString();
    const actor = String(req.body?.actor || mitigatedBy);
    const result = store.mitigateSiemEvent(
      eventId,
      mitigatedBy,
      mitigatedAt,
      actor
    );
    if (!result) {
      res.status(404).json({ error: 'LiveAttackEvent not found' });
      return;
    }
    res.json(result);
  });

  // Vite middleware in development, static dist in production
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `[CyberDefense-SOC] Listening on http://0.0.0.0:${PORT} · Target: ${PRIMARY_PORTAL_URL}`
    );
  });
}

void startServer();
