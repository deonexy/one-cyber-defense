import fs from 'node:fs';
import path from 'node:path';
import type {
  CustomGlossaryTerm,
  CyberKnowledgeSnapshot,
  LiveKnowledgeBriefing,
} from '../src/types/soc.ts';

const USER_AGENT = 'CyberDefense-SOC-Academy/1.0 (Live-Briefing-Reader)';
const CUSTOM_GLOSSARY_FILE = 'soc-custom-glossary.json';

function decodeXmlEntities(input: string): string {
  return input
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_m, code) => {
      const n = Number(code);
      return Number.isFinite(n) ? String.fromCharCode(n) : '';
    })
    .replace(/\s+/g, ' ')
    .trim();
}

function extractTag(block: string, tag: string): string {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const m = block.match(re);
  return m ? decodeXmlEntities(m[1]) : '';
}

function detectRelatedConcepts(text: string): string[] {
  const concepts: string[] = [];
  const lower = text.toLowerCase();
  if (/cve-\d{4}|zero-day|0-day|vulnerab|patch|kev/.test(lower))
    concepts.push('CVE & CISA KEV');
  if (/ransomware|extortion|encrypt/.test(lower)) concepts.push('Ransomware');
  if (/phish|credential|spoof|dmarc|domain/.test(lower))
    concepts.push('Phishing & DMARC');
  if (/botnet|malware|trojan|c2|backdoor|stealer/.test(lower))
    concepts.push('Botnet C2 & Malware');
  if (/siem|wazuh|soc|edr|xdr|log|detect/.test(lower))
    concepts.push('SIEM & XDR');
  if (/tls|ssl|https|certificate|waf|ddos|sql|xss/.test(lower))
    concepts.push('Web & TLS Hardening');
  if (/mitre|apt|nation-state|threat actor|campaign/.test(lower))
    concepts.push('Threat Intelligence (CTI)');
  if (concepts.length === 0) concepts.push('Cyber Security');
  return concepts.slice(0, 3);
}

function parseRssItems(
  xml: string,
  source: LiveKnowledgeBriefing['source'],
  limit = 6
): LiveKnowledgeBriefing[] {
  const items: LiveKnowledgeBriefing[] = [];
  const itemMatches = xml.match(/<item\b[\s\S]*?<\/item>/gi) ?? [];

  for (let i = 0; i < Math.min(itemMatches.length, limit); i++) {
    const raw = itemMatches[i];
    const title = extractTag(raw, 'title');
    const link = extractTag(raw, 'link');
    const pubDate = extractTag(raw, 'pubDate') || extractTag(raw, 'dc:date');
    const desc = extractTag(raw, 'description');
    if (!title) continue;

    let isoDate = new Date().toISOString();
    if (pubDate) {
      const parsed = Date.parse(pubDate);
      if (!Number.isNaN(parsed)) {
        isoDate = new Date(parsed).toISOString();
      }
    }

    const safeLink =
      link.startsWith('https://') || link.startsWith('http://') ? link : '';

    items.push({
      id: `${source.toLowerCase().replace(/\s+/g, '-')}-${i}-${isoDate.slice(0, 10)}`,
      source,
      title: title.slice(0, 180),
      link: safeLink,
      publishedAt: isoDate,
      summary: desc.slice(0, 240),
      relatedConcepts: detectRelatedConcepts(`${title} ${desc}`),
    });
  }

  return items;
}

export class CyberKnowledgeStore {
  private filePath: string;
  private customTerms: CustomGlossaryTerm[] = [];

  constructor(rootDir: string) {
    this.filePath = path.join(rootDir, CUSTOM_GLOSSARY_FILE);
    this.customTerms = this.loadCustomTerms();
  }

  private loadCustomTerms(): CustomGlossaryTerm[] {
    try {
      if (fs.existsSync(this.filePath)) {
        const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
        if (Array.isArray(parsed)) return parsed.slice(0, 50);
      }
    } catch {
      // ignore
    }
    return [];
  }

  addCustomTerm(
    input: Omit<CustomGlossaryTerm, 'id' | 'addedAt'>
  ): CustomGlossaryTerm[] {
    const item: CustomGlossaryTerm = {
      id: `term-${Date.now().toString(36)}`,
      term: input.term.trim().slice(0, 80),
      category: input.category,
      definition: input.definition.trim().slice(0, 400),
      analogy: input.analogy.trim().slice(0, 300),
      orgRelevance: input.orgRelevance.trim().slice(0, 300),
      addedAt: new Date().toISOString(),
    };
    this.customTerms = [item, ...this.customTerms].slice(0, 50);
    try {
      fs.writeFileSync(
        this.filePath,
        JSON.stringify(this.customTerms, null, 2),
        'utf8'
      );
    } catch {
      // ignore read-only fs
    }
    return this.customTerms;
  }

  getCustomTerms(): CustomGlossaryTerm[] {
    return this.customTerms;
  }

  async fetchLiveKnowledgeSnapshot(): Promise<CyberKnowledgeSnapshot> {
    const startedAt = Date.now();
    const sourcesStatus: CyberKnowledgeSnapshot['sourcesStatus'] = [];
    const liveBriefings: LiveKnowledgeBriefing[] = [];
    let sansInfocon: CyberKnowledgeSnapshot['sansInfocon'] = 'unknown';

    const fetchFeed = async (
      name: string,
      url: string,
      source: LiveKnowledgeBriefing['source'],
      limit: number
    ) => {
      const t0 = Date.now();
      try {
        const res = await fetch(url, {
          signal: AbortSignal.timeout(8000),
          headers: { 'User-Agent': USER_AGENT },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const xml = await res.text();
        const parsed = parseRssItems(xml, source, limit);
        liveBriefings.push(...parsed);
        sourcesStatus.push({
          name,
          status: 'OK',
          count: parsed.length,
          latencyMs: Date.now() - t0,
        });
      } catch {
        sourcesStatus.push({
          name,
          status: 'ERROR',
          count: 0,
          latencyMs: Date.now() - t0,
        });
      }
    };

    const fetchSans = async () => {
      const t0 = Date.now();
      try {
        const res = await fetch('https://isc.sans.edu/api/infocon?json', {
          signal: AbortSignal.timeout(6000),
          headers: { 'User-Agent': USER_AGENT },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as { status?: string };
        const st = String(json.status || 'unknown').toLowerCase();
        if (st === 'green' || st === 'yellow' || st === 'orange' || st === 'red') {
          sansInfocon = st;
        }
        sourcesStatus.push({
          name: 'SANS ISC InfoCon',
          status: 'OK',
          count: 1,
          latencyMs: Date.now() - t0,
        });
      } catch {
        sourcesStatus.push({
          name: 'SANS ISC InfoCon',
          status: 'ERROR',
          count: 0,
          latencyMs: Date.now() - t0,
        });
      }
    };

    await Promise.all([
      fetchFeed(
        'CISA Advisories',
        'https://www.cisa.gov/cybersecurity-advisories/all.xml',
        'CISA Advisory',
        6
      ),
      fetchFeed(
        'BleepingComputer',
        'https://www.bleepingcomputer.com/feed/',
        'BleepingComputer',
        6
      ),
      fetchFeed(
        'The Hacker News',
        'https://feeds.feedburner.com/TheHackersNews',
        'The Hacker News',
        6
      ),
      fetchSans(),
    ]);

    liveBriefings.sort((a, b) => b.publishedAt.localeCompare(a.publishedAt));

    return {
      lastUpdatedAt: new Date().toISOString(),
      updateDurationMs: Date.now() - startedAt,
      sansInfocon,
      sourcesStatus,
      liveBriefings,
      customTerms: this.customTerms,
    };
  }
}
