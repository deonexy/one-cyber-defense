export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AttackVector =
  | 'Credential Stuffing'
  | 'SQLi'
  | 'XSS'
  | 'DDoS L7'
  | 'BOLA'
  | 'Malware Upload';

export type AttackAction =
  | 'DETECTED'
  | 'CHALLENGED'
  | 'BLOCKED_BY_WAF'
  | 'MITIGATED';

export interface LiveAttackEvent {
  event_id: string;
  timestamp: string;
  source_ip: string;
  source_country: string;
  source_coords: [number, number];
  target_asset: string;
  attack_vector: AttackVector;
  severity: Severity;
  action_taken: AttackAction;
  payload_snippet: string;
  mitigated_by?: string;
  mitigated_at?: string;
}

export type ThreatIntelSource =
  | 'Telegram Stealer Logs'
  | 'DarkWeb Forum'
  | 'Gov-CSIRT / National CERT'
  | 'Domain Typosquatting Radar'
  | 'CVE Feed';

export type ThreatIntelCategory =
  | 'CREDENTIAL_LEAK'
  | 'PHISHING_DOMAIN'
  | 'ZERO_DAY_CVE';

export type ThreatIntelStatus = 'OPEN' | 'MITIGATED' | 'FALSE_POSITIVE';

export interface ThreatIntelAlert {
  intel_id: string;
  detected_at: string;
  source: ThreatIntelSource;
  category: ThreatIntelCategory;
  affected_entity: string;
  confidence_score: number;
  recommended_playbook: string;
  status: ThreatIntelStatus;
}

export type FinancialModule =
  | 'Disbursement_Gateway'
  | 'Beneficiary_Bank_Registry'
  | 'Core_DB_Privilege';

export type FinancialAnomalyStatus =
  | 'PENDING_APPROVAL_LOCK'
  | 'FROZEN'
  | 'CLEARED';

export interface FinancialAnomaly {
  anomaly_id: string;
  timestamp: string;
  module: FinancialModule;
  description: string;
  actor_id: string;
  risk_score: number;
  status: FinancialAnomalyStatus;
}

export type ServiceStatus = 'OPERATIONAL' | 'DEGRADED' | 'UNDER_ATTACK';

export interface ServiceHealth {
  id: string;
  name: string;
  status: ServiceStatus;
  uptime_percent: number;
  latency_ms: number;
  rps: number;
}

export interface AuditTrailEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target_id: string;
  result: string;
}

// --- 100% Real Public Security Telemetry Contracts ---

export type EndpointAvailability = 'UP' | 'DEGRADED' | 'DOWN' | 'PENDING';

export interface SecurityHeaderInspection {
  hsts: string | null;
  csp: string | null;
  xFrameOptions: string | null;
  xContentTypeOptions: string | null;
  referrerPolicy: string | null;
  permissionsPolicy: string | null;
}

export interface TlsInspection {
  protocol: string | null;
  cipher: string | null;
  issuer: string | null;
  subject: string | null;
  sanCount: number;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  fingerprint256: string | null;
}

export interface CookieInspection {
  count: number;
  allSecure: boolean;
  allHttpOnly: boolean;
  hasSameSite: boolean;
}

export interface RealEndpointProbe {
  id: string;
  label: string;
  url: string;
  hostname: string;
  isDefault: boolean;
  status: EndpointAvailability;
  httpStatus: number | null;
  latencyMs: number | null;
  uptimePercent: number;
  totalChecks: number;
  successChecks: number;
  lastCheckedAt: string | null;
  headerScore: number; // 0-100
  serverHeader: string | null;
  poweredByHeader: string | null;
  securityHeaders: SecurityHeaderInspection;
  cookies: CookieInspection;
  tls: TlsInspection | null;
  dns: {
    ipv4: string[];
    ipv6: string[];
    cname: string[];
  };
  errorMessage?: string;
}

export interface RealDnsSecurityAudit {
  rootDomain: string;
  portalHost: string;
  checkedAt: string;
  spf: {
    present: boolean;
    record: string | null;
    policy: 'HARD_FAIL' | 'SOFT_FAIL' | 'NEUTRAL' | 'MISSING';
  };
  dmarc: {
    present: boolean;
    record: string | null;
    policy: 'reject' | 'quarantine' | 'none' | 'MISSING';
  };
  caa: {
    present: boolean;
    records: string[];
  };
  mx: Array<{ exchange: string; priority: number }>;
  ns: string[];
  score: number; // 0-100
}

export interface RealLatencyPoint {
  time: string;
  primaryMs: number | null;
  loginMs: number | null;
  secondaryMs: number | null;
  avgMs: number | null;
}

export type RealFindingCategory =
  | 'HTTP_HEADER'
  | 'TLS_CERT'
  | 'DNS_EMAIL'
  | 'AVAILABILITY'
  | 'INFO_DISCLOSURE'
  | 'GLOBAL_CTI'
  | 'CONTENT_DEFACEMENT';

export type RealFindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';

export interface RealSecurityFinding {
  finding_id: string;
  detected_at: string;
  category: RealFindingCategory;
  severity: Severity;
  target: string;
  title: string;
  evidence: string;
  remediation: string;
  status: RealFindingStatus;
}

export type RealLogType =
  | 'HTTP_TLS_PROBE'
  | 'DNS_AUDIT'
  | 'CTI_SYNC'
  | 'LOCAL_SIEM_SCAN'
  | 'KNOWLEDGE_SYNC'
  | 'CONTENT_INTEGRITY_SCAN'
  | 'INCIDENT_REPORT'
  | 'ANALYST_ACTION'
  | 'SIEM_INGEST';

export interface RealProbeLogEntry {
  id: string;
  timestamp: string;
  actor: string;
  check_type: RealLogType;
  target: string;
  http_status: string;
  latency_ms: string;
  result: string;
}

// --- 100% Real Zero-Account Global Open CTI Contracts ---

export interface CtiSourceStatus {
  id: string;
  name: string;
  provider: string;
  status: 'OK' | 'ERROR';
  count: number;
  latencyMs: number;
  detail: string;
}

export interface CisaKevItem {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  shortDescription: string;
  requiredAction: string;
}

export interface BotnetC2Indicator {
  ip_address: string;
  port: number;
  status: string;
  hostname: string | null;
  as_number: number | null;
  as_name: string | null;
  country: string;
  first_seen: string;
  last_online: string;
  malware: string;
}

export interface CertTransparencyEntry {
  id: string;
  dnsNames: string[];
  issuer: string;
  notBefore: string;
  notAfter: string;
  revoked: boolean;
  sha256: string;
  isTargetRelated: boolean;
}

export interface RansomwareVictimItem {
  victim: string;
  group: string;
  country: string;
  activity: string;
  discovered: string;
  description: string;
  isPrioritySector: boolean;
}

export interface PhishingIndicator {
  url: string;
  domain: string;
  matchedKeyword: string | null;
}

export interface IpReputationEntry {
  ip: string;
  endpointLabel: string;
  hostname: string;
  netName: string | null;
  country: string | null;
  cidr: string | null;
  asn: string | null;
  bgpPrefix: string | null;
  listedInThreatFeeds: boolean;
  matchedFeeds: string[];
  checkedAt: string;
}

export interface GlobalThreatIntelSnapshot {
  lastSyncedAt: string | null;
  syncDurationMs: number | null;
  sourcesStatus: CtiSourceStatus[];
  cisaKev: {
    catalogVersion: string | null;
    totalCount: number;
    ransomwareCount: number;
    recent: CisaKevItem[];
  };
  botnetC2: {
    feodoTotal: number;
    etCompromisedTotal: number;
    indicators: BotnetC2Indicator[];
  };
  certTransparency: {
    domain: string;
    totalEntries: number;
    targetRelatedCount: number;
    entries: CertTransparencyEntry[];
  };
  ransomware: {
    totalRecent: number;
    prioritySectorCount: number;
    recent: RansomwareVictimItem[];
  };
  openPhish: {
    totalActiveUrls: number;
    brandOrIndonesiaMatches: PhishingIndicator[];
    sampleRecent: PhishingIndicator[];
  };
  ipReputation: IpReputationEntry[];
}

// --- 100% Real Local Host SIEM / XDR (Wazuh-Style) Contracts ---

export type LogSourceFormat = 'syslog' | 'nginx' | 'auth' | 'app-json';

export interface LocalLogSourceConfig {
  id: string;
  label: string;
  path: string;
  format: LogSourceFormat;
  enabled: boolean;
}

export interface LocalAgentConfig {
  agentName: string;
  clusterGroup: string;
  environment: 'PRODUCTION' | 'STAGING' | 'LOCAL_DEV';
  scanIntervalSec: number;
  alertLevelThreshold: number; // Wazuh rule level 1-15
  bruteForceThreshold: number;
  bruteForceWindowSec: number;
  allowedListeningPorts: number[];
  activeResponseMode: 'MONITOR_ONLY' | 'WEBHOOK_NOTIFY';
  webhookUrl: string;
  fimPaths: string[];
  logSources: LocalLogSourceConfig[];
  enabledRules: {
    sshBruteForce: boolean;
    webSqlInjection: boolean;
    webXssAndTraversal: boolean;
    fimIntegrityChange: boolean;
    unexpectedOpenPort: boolean;
  };
}

export interface LocalHostMetrics {
  hostname: string;
  platform: string;
  osRelease: string;
  arch: string;
  cpuModel: string;
  cpuCores: number;
  loadAvg1m: number;
  loadAvg5m: number;
  loadAvg15m: number;
  memTotalMb: number;
  memUsedMb: number;
  memUsagePercent: number;
  uptimeSeconds: number;
  nodeVersion: string;
  processUid: number | null;
  interfaces: Array<{ name: string; address: string; family: string; mac: string }>;
}

export type FimFileStatus =
  | 'BASELINE_OK'
  | 'MODIFIED'
  | 'ADDED'
  | 'DELETED'
  | 'UNREADABLE';

export interface FimEntry {
  path: string;
  status: FimFileStatus;
  sha256: string | null;
  baselineSha256: string | null;
  sizeBytes: number | null;
  permissions: string | null;
  modifiedAt: string | null;
  lastCheckedAt: string;
  note?: string;
}

export interface ScaCheckResult {
  id: string;
  cisControl: string;
  title: string;
  category: 'FILESYSTEM' | 'NETWORK' | 'AUTH_SSH' | 'RUNTIME';
  status: 'PASS' | 'FAIL' | 'NOT_APPLICABLE';
  severity: Severity;
  evidence: string;
  remediation: string;
}

export interface LocalListeningPort {
  protocol: 'TCP' | 'TCP6';
  localAddress: string;
  port: number;
  state: 'LISTEN' | 'ESTABLISHED';
  remoteAddress: string | null;
  remotePort: number | null;
  isAllowed: boolean;
}

export interface LocalLogSourceStatus {
  id: string;
  label: string;
  path: string;
  format: LogSourceFormat;
  enabled: boolean;
  accessStatus: 'READABLE' | 'NOT_FOUND' | 'PERMISSION_DENIED' | 'DISABLED';
  linesScanned: number;
  alertsMatched: number;
  lastScannedAt: string;
}

export interface LocalSecurityAlert {
  alert_id: string;
  timestamp: string;
  rule_id: string;
  rule_level: number; // 1-15 Wazuh-style severity scale
  severity: Severity;
  mitre_id: string;
  mitre_tactic: string;
  agent_name: string;
  source: 'FIM' | 'SCA' | 'LOGCOLLECTOR' | 'NET_SENSOR' | 'HTTP_SENSOR';
  title: string;
  detail: string;
  target: string;
}

export interface LocalWazuhSnapshot {
  lastScannedAt: string | null;
  scanDurationMs: number | null;
  config: LocalAgentConfig;
  host: LocalHostMetrics | null;
  fim: {
    baselineEstablishedAt: string | null;
    totalMonitored: number;
    okCount: number;
    modifiedCount: number;
    unreadableCount: number;
    entries: FimEntry[];
  };
  sca: {
    scorePercent: number;
    passed: number;
    failed: number;
    notApplicable: number;
    checks: ScaCheckResult[];
  };
  network: {
    listeningPorts: LocalListeningPort[];
    establishedCount: number;
    unexpectedPortCount: number;
  };
  logSourcesStatus: LocalLogSourceStatus[];
  alerts: LocalSecurityAlert[];
  ruleLevelHistogram: Array<{ level: string; count: number }>;
  mitreBreakdown: Array<{ tactic: string; count: number }>;
}

// --- 100% Real Live Cyber Knowledge & Briefings Contracts ---

export interface LiveKnowledgeBriefing {
  id: string;
  source: 'CISA Advisory' | 'BleepingComputer' | 'The Hacker News';
  title: string;
  link: string;
  publishedAt: string;
  summary: string;
  relatedConcepts: string[];
}

export interface CustomGlossaryTerm {
  id: string;
  term: string;
  category: 'Threat Intelligence' | 'SIEM & Wazuh' | 'Web & DNS Security' | 'Serangan & MITRE';
  definition: string;
  analogy: string;
  orgRelevance: string;
  addedAt: string;
}

export interface CyberKnowledgeSnapshot {
  lastUpdatedAt: string | null;
  updateDurationMs: number | null;
  sansInfocon: 'green' | 'yellow' | 'orange' | 'red' | 'unknown';
  sourcesStatus: Array<{
    name: string;
    status: 'OK' | 'ERROR';
    count: number;
    latencyMs: number;
  }>;
  liveBriefings: LiveKnowledgeBriefing[];
  customTerms: CustomGlossaryTerm[];
}

// --- 100% Real Automated HTML Defacement / Googlebot Cloaking & Manual/Ops Incident Reports ---

export interface ContentIntegrityScan {
  endpointId: string;
  label: string;
  url: string;
  hostname: string;
  scannedAt: string;
  browserStatus: number | null;
  browserTitle: string | null;
  browserMetaDesc: string | null;
  browserHashSha256: string | null;
  browserKeywordsFound: string[];
  googlebotStatus: number | null;
  googlebotTitle: string | null;
  googlebotMetaDesc: string | null;
  googlebotHashSha256: string | null;
  googlebotKeywordsFound: string[];
  baselineHashSha256: string | null;
  contentChangedFromBaseline: boolean;
  cloakingSuspected: boolean;
  cloakingReason: string | null;
  defacementSuspected: boolean;
  riskLevel: 'CLEAN' | 'SUSPICIOUS' | 'CRITICAL';
  errorMessage?: string;
}

export type IncidentReportCategory =
  | 'SEO_POISONING_JUDOL'
  | 'WEB_DEFACEMENT'
  | 'GOOGLE_CLOAKING'
  | 'PHISHING_IMPERSONATION'
  | 'CREDENTIAL_LEAK'
  | 'VULNERABILITY_REPORT'
  | 'OTHER';

export type IncidentReportSource =
  | 'INFRA_OPS'
  | 'ORG_CSIRT'
  | 'GOV_CERT'
  | 'INTERNAL_STAFF'
  | 'GOOGLE_SEARCH_OSINT'
  | 'AUTO_SCANNER'
  | 'EXTERNAL_REPORTER';

export type IncidentReportStatus =
  | 'OPEN'
  | 'INVESTIGATING'
  | 'ESCALATED_INFRA'
  | 'MITIGATED'
  | 'CLOSED';

export interface ManualIncidentReport {
  id: string;
  reportedAt: string;
  occurredAt: string;
  title: string;
  affectedUrl: string;
  category: IncidentReportCategory;
  severity: Severity;
  source: IncidentReportSource;
  reporterName: string;
  description: string;
  evidenceSnippet: string;
  coordinationNotes: string;
  actionTaken: string;
  status: IncidentReportStatus;
  includeInBoardReport: boolean;
  updatedAt: string;
}

export interface RealTelemetrySnapshot {
  mode: 'REAL_ONLY' | 'DEMO_SANDBOX';
  probeIntervalMs: number;
  connectedAnalysts: number;
  probeOriginLabel: string;
  endpoints: RealEndpointProbe[];
  dnsAudit: RealDnsSecurityAudit | null;
  threatIntel: GlobalThreatIntelSnapshot | null;
  threatIntelAlerts: ThreatIntelAlert[];
  localWazuh: LocalWazuhSnapshot | null;
  knowledge: CyberKnowledgeSnapshot | null;
  contentScans: ContentIntegrityScan[];
  incidentReports: ManualIncidentReport[];
  latencyHistory: RealLatencyPoint[];
  findings: RealSecurityFinding[];
  probeLogs: RealProbeLogEntry[];
  ingestedSiemEvents: LiveAttackEvent[];
}

export type SseConnectionState = 'CONNECTING' | 'CONNECTED' | 'RECONNECTING';

export type RealSocView =
  | 'overview'
  | 'action-advisor'
  | 'playbooks'
  | 'service-health'
  | 'executive-report'
  | 'incident-reports'
  | 'wazuh-dashboard'
  | 'local-config'
  | 'threat-intel'
  | 'headers-tls'
  | 'dns-audit'
  | 'findings'
  | 'academy'
  | 'audit';
