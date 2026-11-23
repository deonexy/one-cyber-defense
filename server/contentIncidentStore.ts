import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  ContentIntegrityScan,
  IncidentReportCategory,
  IncidentReportSource,
  IncidentReportStatus,
  ManualIncidentReport,
  RealEndpointProbe,
  Severity,
} from '../src/types/soc.ts';

const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const GOOGLEBOT_UA =
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

// High-confidence Indonesian Judol / SEO Poisoning / Web Defacement signatures
const SUSPICIOUS_SIGNATURES: Array<{ label: string; regex: RegExp }> = [
  { label: 'SLOT777', regex: /\bslot\s*777\b/i },
  { label: 'SLOT88 / SLOT ONLINE', regex: /\b(slot\s*88|slot\s+online|game\s+slot|situs\s+slot|daftar\s+slot|link\s+slot)\b/i },
  { label: 'SLOT GACOR / MAXWIN', regex: /\b(slot\s+gacor|gacor\s+hari\s+ini|maxwin|pola\s+gacor|rtp\s+live|rtp\s+slot)\b/i },
  { label: 'JUDI ONLINE / JUDOL', regex: /\b(judi\s+online|judol|bandar\s+togel|togel\s+online|toto\s+macau|sbobet|taruhan\s+bola)\b/i },
  { label: 'CASINO / PRAGMATIC', regex: /\b(pragmatic\s+play|mahjong\s+ways|gates\s+of\s+olympus|live\s+casino|bonus\s+new\s+member)\b/i },
  { label: 'DEFACEMENT SIGNATURE', regex: /\b(hacked\s+by|defaced\s+by|owned\s+by|touched\s+by|pwned\s+by|greetz\s+to)\b/i },
];

const VALID_CATEGORIES = new Set<IncidentReportCategory>([
  'SEO_POISONING_JUDOL',
  'WEB_DEFACEMENT',
  'GOOGLE_CLOAKING',
  'PHISHING_IMPERSONATION',
  'CREDENTIAL_LEAK',
  'VULNERABILITY_REPORT',
  'OTHER',
]);

const VALID_SOURCES = new Set<IncidentReportSource>([
  'INFRA_OPS',
  'ORG_CSIRT',
  'GOV_CERT',
  'INTERNAL_STAFF',
  'GOOGLE_SEARCH_OSINT',
  'AUTO_SCANNER',
  'EXTERNAL_REPORTER',
]);

const VALID_STATUSES = new Set<IncidentReportStatus>([
  'OPEN',
  'INVESTIGATING',
  'ESCALATED_INFRA',
  'MITIGATED',
  'CLOSED',
]);

const VALID_SEVERITIES = new Set<Severity>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

interface ExtractedHtmlMeta {
  status: number | null;
  title: string | null;
  metaDesc: string | null;
  hashSha256: string | null;
  keywordsFound: string[];
  error?: string;
}

function decodeBasicEntities(text: string): string {
  return text
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractHtmlSignals(html: string): {
  title: string | null;
  metaDesc: string | null;
  hashSha256: string;
  keywordsFound: string[];
} {
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? decodeBasicEntities(titleMatch[1]).slice(0, 180) : null;

  const metaMatch1 = html.match(
    /<meta[^>]+name=["']description["'][^>]+content=["']([\s\S]*?)["'][^>]*>/i
  );
  const metaMatch2 = html.match(
    /<meta[^>]+content=["']([\s\S]*?)["'][^>]+name=["']description["'][^>]*>/i
  );
  const rawMeta = metaMatch1?.[1] ?? metaMatch2?.[1] ?? null;
  const metaDesc = rawMeta ? decodeBasicEntities(rawMeta).slice(0, 260) : null;

  // Strip scripts, styles, comments, and dynamic nonce/csrf tokens before hashing
  const normalizedText = html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  // Hash title + metaDesc + stable visible snippet (first 16 KB) to avoid dynamic CSRF token noise
  const stableCore = `${title ?? ''}|${metaDesc ?? ''}|${normalizedText.slice(0, 16000)}`;
  const hashSha256 = crypto
    .createHash('sha256')
    .update(stableCore)
    .digest('hex');

  const scanText = `${title ?? ''} ${metaDesc ?? ''} ${normalizedText.slice(0, 60000)}`;
  const keywordsFound: string[] = [];
  for (const sig of SUSPICIOUS_SIGNATURES) {
    if (sig.regex.test(scanText)) {
      keywordsFound.push(sig.label);
    }
  }

  return { title, metaDesc, hashSha256, keywordsFound };
}

async function fetchWithUserAgent(
  url: string,
  userAgent: string
): Promise<ExtractedHtmlMeta> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 7000);
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': userAgent,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
      },
    });
    const text = (await res.text()).slice(0, 220000);
    const extracted = extractHtmlSignals(text);
    return {
      status: res.status,
      title: extracted.title,
      metaDesc: extracted.metaDesc,
      hashSha256: extracted.hashSha256,
      keywordsFound: extracted.keywordsFound,
    };
  } catch (err) {
    return {
      status: null,
      title: null,
      metaDesc: null,
      hashSha256: null,
      keywordsFound: [],
      error: err instanceof Error ? err.message : 'Fetch error',
    };
  } finally {
    clearTimeout(timer);
  }
}

export class ContentIncidentStore {
  private readonly dataDir: string;
  private readonly reportsFile: string;
  private readonly baselineHashes = new Map<string, string>();
  private reports: ManualIncidentReport[] = [];
  private scans: ContentIntegrityScan[] = [];

  constructor(workspaceRoot: string) {
    this.dataDir = path.join(workspaceRoot, 'data');
    this.reportsFile = path.join(this.dataDir, 'incident-reports.json');
    this.loadReportsFromDisk();
  }

  private loadReportsFromDisk(): void {
    try {
      if (fs.existsSync(this.reportsFile)) {
        const raw = fs.readFileSync(this.reportsFile, 'utf8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          this.reports = parsed as ManualIncidentReport[];
        }
      }
    } catch {
      this.reports = [];
    }
  }

  private saveReportsToDisk(): void {
    try {
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }
      fs.writeFileSync(
        this.reportsFile,
        JSON.stringify(this.reports, null, 2),
        'utf8'
      );
    } catch {
      // Non-fatal if container filesystem is read-only
    }
  }

  getReports(): ManualIncidentReport[] {
    return this.reports;
  }

  getScans(): ContentIntegrityScan[] {
    return this.scans;
  }

  createReport(input: {
    title: string;
    affectedUrl: string;
    category?: string;
    severity?: string;
    source?: string;
    reporterName?: string;
    occurredAt?: string;
    description?: string;
    evidenceSnippet?: string;
    coordinationNotes?: string;
    actionTaken?: string;
    status?: string;
    includeInBoardReport?: boolean;
  }): ManualIncidentReport {
    const title = String(input.title || '').trim();
    const affectedUrl = String(input.affectedUrl || '').trim();
    if (!title || !affectedUrl) {
      throw new Error('Judul insiden dan URL/sistem terdampak wajib diisi');
    }

    const nowIso = new Date().toISOString();
    const datePart = nowIso.slice(0, 10).replace(/-/g, '');
    const seq = String(this.reports.length + 1).padStart(3, '0');

    const category = VALID_CATEGORIES.has(input.category as IncidentReportCategory)
      ? (input.category as IncidentReportCategory)
      : 'SEO_POISONING_JUDOL';
    const severity = VALID_SEVERITIES.has(input.severity as Severity)
      ? (input.severity as Severity)
      : 'HIGH';
    const source = VALID_SOURCES.has(input.source as IncidentReportSource)
      ? (input.source as IncidentReportSource)
      : 'INFRA_OPS';
    const status = VALID_STATUSES.has(input.status as IncidentReportStatus)
      ? (input.status as IncidentReportStatus)
      : 'OPEN';

    let occurredAt = nowIso;
    if (input.occurredAt) {
      const parsedMs = Date.parse(input.occurredAt);
      if (Number.isFinite(parsedMs)) {
        occurredAt = new Date(parsedMs).toISOString();
      }
    }

    const report: ManualIncidentReport = {
      id: `INC-${datePart}-${seq}-${Date.now().toString(36).slice(-3).toUpperCase()}`,
      reportedAt: nowIso,
      occurredAt,
      title: title.slice(0, 200),
      affectedUrl: affectedUrl.slice(0, 300),
      category,
      severity,
      source,
      reporterName: String(input.reporterName || 'Tim SOC / Pengelola Layanan').trim().slice(0, 120),
      description: String(input.description || '').trim().slice(0, 2000),
      evidenceSnippet: String(input.evidenceSnippet || '').trim().slice(0, 1000),
      coordinationNotes: String(input.coordinationNotes || '').trim().slice(0, 1000),
      actionTaken: String(input.actionTaken || '').trim().slice(0, 1000),
      status,
      includeInBoardReport: input.includeInBoardReport !== false,
      updatedAt: nowIso,
    };

    this.reports = [report, ...this.reports];
    this.saveReportsToDisk();
    return report;
  }

  updateReport(
    id: string,
    patch: Partial<{
      status: IncidentReportStatus;
      severity: Severity;
      coordinationNotes: string;
      actionTaken: string;
      includeInBoardReport: boolean;
      description: string;
      evidenceSnippet: string;
    }>
  ): ManualIncidentReport | null {
    const existing = this.reports.find((r) => r.id === id);
    if (!existing) return null;

    const updated: ManualIncidentReport = {
      ...existing,
      status:
        patch.status && VALID_STATUSES.has(patch.status)
          ? patch.status
          : existing.status,
      severity:
        patch.severity && VALID_SEVERITIES.has(patch.severity)
          ? patch.severity
          : existing.severity,
      coordinationNotes:
        typeof patch.coordinationNotes === 'string'
          ? patch.coordinationNotes.trim().slice(0, 1000)
          : existing.coordinationNotes,
      actionTaken:
        typeof patch.actionTaken === 'string'
          ? patch.actionTaken.trim().slice(0, 1000)
          : existing.actionTaken,
      description:
        typeof patch.description === 'string'
          ? patch.description.trim().slice(0, 2000)
          : existing.description,
      evidenceSnippet:
        typeof patch.evidenceSnippet === 'string'
          ? patch.evidenceSnippet.trim().slice(0, 1000)
          : existing.evidenceSnippet,
      includeInBoardReport:
        typeof patch.includeInBoardReport === 'boolean'
          ? patch.includeInBoardReport
          : existing.includeInBoardReport,
      updatedAt: new Date().toISOString(),
    };

    this.reports = this.reports.map((r) => (r.id === id ? updated : r));
    this.saveReportsToDisk();
    return updated;
  }

  deleteReport(id: string): boolean {
    const before = this.reports.length;
    this.reports = this.reports.filter((r) => r.id !== id);
    if (this.reports.length === before) return false;
    this.saveReportsToDisk();
    return true;
  }

  acceptContentBaselines(): ContentIntegrityScan[] {
    for (const scan of this.scans) {
      if (scan.browserHashSha256) {
        this.baselineHashes.set(scan.endpointId, scan.browserHashSha256);
      }
    }
    this.scans = this.scans.map((scan) => ({
      ...scan,
      baselineHashSha256: scan.browserHashSha256 ?? scan.baselineHashSha256,
      contentChangedFromBaseline: false,
      riskLevel:
        scan.defacementSuspected || scan.cloakingSuspected ? 'CRITICAL' : 'CLEAN',
    }));
    return this.scans;
  }

  async scanAllEndpoints(
    endpoints: RealEndpointProbe[]
  ): Promise<ContentIntegrityScan[]> {
    const results = await Promise.all(
      endpoints.map(async (ep): Promise<ContentIntegrityScan> => {
        const [browser, googlebot] = await Promise.all([
          fetchWithUserAgent(ep.url, BROWSER_UA),
          fetchWithUserAgent(ep.url, GOOGLEBOT_UA),
        ]);

        // Initialize SHA-256 content baseline on first clean observation
        if (browser.hashSha256 && !this.baselineHashes.has(ep.id)) {
          this.baselineHashes.set(ep.id, browser.hashSha256);
        }
        const baselineHash = this.baselineHashes.get(ep.id) ?? null;
        const contentChangedFromBaseline = Boolean(
          baselineHash &&
            browser.hashSha256 &&
            browser.hashSha256 !== baselineHash
        );

        const defacementSuspected =
          browser.keywordsFound.length > 0 ||
          googlebot.keywordsFound.length > 0;

        let cloakingSuspected = false;
        let cloakingReason: string | null = null;

        if (
          googlebot.keywordsFound.length > 0 &&
          browser.keywordsFound.length === 0
        ) {
          cloakingSuspected = true;
          cloakingReason = `Googlebot UA menerima konten mencurigakan (${googlebot.keywordsFound.join(
            ', '
          )}) sementara Browser biasa bersih.`;
        } else if (
          browser.title &&
          googlebot.title &&
          browser.title.toLowerCase() !== googlebot.title.toLowerCase()
        ) {
          cloakingSuspected = true;
          cloakingReason = `Judul halaman (<title>) berbeda antara Browser ("${browser.title.slice(
            0,
            60
          )}") vs Googlebot ("${googlebot.title.slice(0, 60)}").`;
        } else if (
          browser.metaDesc &&
          googlebot.metaDesc &&
          browser.metaDesc.toLowerCase() !== googlebot.metaDesc.toLowerCase()
        ) {
          cloakingSuspected = true;
          cloakingReason =
            'Meta description berbeda antara respons Browser biasa dan Googlebot UA.';
        }

        const riskLevel: ContentIntegrityScan['riskLevel'] =
          defacementSuspected || cloakingSuspected
            ? 'CRITICAL'
            : contentChangedFromBaseline
            ? 'SUSPICIOUS'
            : 'CLEAN';

        return {
          endpointId: ep.id,
          label: ep.label,
          url: ep.url,
          hostname: ep.hostname,
          scannedAt: new Date().toISOString(),
          browserStatus: browser.status,
          browserTitle: browser.title,
          browserMetaDesc: browser.metaDesc,
          browserHashSha256: browser.hashSha256,
          browserKeywordsFound: browser.keywordsFound,
          googlebotStatus: googlebot.status,
          googlebotTitle: googlebot.title,
          googlebotMetaDesc: googlebot.metaDesc,
          googlebotHashSha256: googlebot.hashSha256,
          googlebotKeywordsFound: googlebot.keywordsFound,
          baselineHashSha256: baselineHash,
          contentChangedFromBaseline,
          cloakingSuspected,
          cloakingReason,
          defacementSuspected,
          riskLevel,
          errorMessage: browser.error || googlebot.error,
        };
      })
    );

    this.scans = results;
    return results;
  }
}
