import {
  ContentIntegrityScan,
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
  RealProbeLogEntry,
  RealSecurityFinding,
  RealTelemetrySnapshot,
  SseConnectionState,
  ThreatIntelAlert,
  ThreatIntelStatus,
} from '../types/soc';

export const PRIMARY_PORTAL_URL = 'https://example.org/';
export const PRIMARY_PORTAL_HOST = 'example.org';

export interface RealStreamCallbacks {
  onInit: (snapshot: RealTelemetrySnapshot) => void;
  onProbeCycle: (data: {
    endpoints: RealEndpointProbe[];
    point: RealLatencyPoint | null;
  }) => void;
  onDnsUpdated: (audit: RealDnsSecurityAudit) => void;
  onThreatIntelUpdated: (cti: GlobalThreatIntelSnapshot) => void;
  onThreatAlertsUpdated: (alerts: ThreatIntelAlert[]) => void;
  onWazuhUpdated: (localWazuh: LocalWazuhSnapshot) => void;
  onKnowledgeUpdated: (knowledge: CyberKnowledgeSnapshot) => void;
  onContentScansUpdated: (scans: ContentIntegrityScan[]) => void;
  onIncidentReportsUpdated: (reports: ManualIncidentReport[]) => void;
  onFindingsUpdated: (findings: RealSecurityFinding[]) => void;
  onLogCreated: (entry: RealProbeLogEntry) => void;
  onSiemIngested: (event: LiveAttackEvent) => void;
  onSiemUpdated: (events: LiveAttackEvent[]) => void;
  onConfigUpdated: (data: { probeIntervalMs: number }) => void;
  onClientsCount: (count: number) => void;
  onConnectionStateChange: (state: SseConnectionState) => void;
}

export class RealTelemetryAdapter {
  private eventSource: EventSource | null = null;

  connectStream(callbacks: RealStreamCallbacks): void {
    this.disconnectStream();
    callbacks.onConnectionStateChange('CONNECTING');

    const es = new EventSource('/api/real/stream');
    this.eventSource = es;

    es.onopen = () => {
      callbacks.onConnectionStateChange('CONNECTED');
    };

    es.onerror = () => {
      callbacks.onConnectionStateChange('RECONNECTING');
    };

    const bind = <T>(eventName: string, handler: (data: T) => void) => {
      es.addEventListener(eventName, (msg: MessageEvent) => {
        try {
          handler(JSON.parse(msg.data) as T);
        } catch {
          // Ignore malformed frame
        }
      });
    };

    bind<RealTelemetrySnapshot>('init', callbacks.onInit);
    bind<{ endpoints: RealEndpointProbe[]; point: RealLatencyPoint | null }>(
      'probe:cycle',
      callbacks.onProbeCycle
    );
    bind<RealDnsSecurityAudit>('dns:updated', callbacks.onDnsUpdated);
    bind<GlobalThreatIntelSnapshot>(
      'cti:updated',
      callbacks.onThreatIntelUpdated
    );
    bind<ThreatIntelAlert[]>(
      'threat-alerts:updated',
      callbacks.onThreatAlertsUpdated
    );
    bind<LocalWazuhSnapshot>('wazuh:updated', callbacks.onWazuhUpdated);
    bind<CyberKnowledgeSnapshot>(
      'knowledge:updated',
      callbacks.onKnowledgeUpdated
    );
    bind<ContentIntegrityScan[]>(
      'content:updated',
      callbacks.onContentScansUpdated
    );
    bind<ManualIncidentReport[]>(
      'incidents:updated',
      callbacks.onIncidentReportsUpdated
    );
    bind<RealSecurityFinding[]>('findings:updated', callbacks.onFindingsUpdated);
    bind<RealProbeLogEntry>('log:created', callbacks.onLogCreated);
    bind<LiveAttackEvent>('siem:ingested', callbacks.onSiemIngested);
    bind<LiveAttackEvent[]>('siem:updated', callbacks.onSiemUpdated);
    bind<{ probeIntervalMs: number }>('config:updated', callbacks.onConfigUpdated);
    bind<{ connectedAnalysts: number }>('clients:count', (d) =>
      callbacks.onClientsCount(d.connectedAnalysts)
    );
  }

  disconnectStream(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  async triggerFullScan(actor: string): Promise<RealTelemetrySnapshot> {
    const res = await fetch('/api/real/probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as RealTelemetrySnapshot;
  }

  async triggerCtiSync(actor: string): Promise<GlobalThreatIntelSnapshot> {
    const res = await fetch('/api/real/cti/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as {
      threatIntel: GlobalThreatIntelSnapshot;
    };
    return data.threatIntel;
  }

  async refreshKnowledge(actor: string): Promise<CyberKnowledgeSnapshot> {
    const res = await fetch('/api/real/knowledge/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { knowledge: CyberKnowledgeSnapshot };
    return data.knowledge;
  }

  async addCustomGlossaryTerm(
    term: Omit<CustomGlossaryTerm, 'id' | 'addedAt'>,
    actor: string
  ): Promise<CyberKnowledgeSnapshot> {
    const res = await fetch('/api/real/knowledge/terms', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...term, actor }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    const data = (await res.json()) as { knowledge: CyberKnowledgeSnapshot };
    return data.knowledge;
  }

  async triggerLocalScan(actor: string): Promise<LocalWazuhSnapshot> {
    const res = await fetch('/api/real/local/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { localWazuh: LocalWazuhSnapshot };
    return data.localWazuh;
  }

  async acceptFimBaseline(actor: string): Promise<LocalWazuhSnapshot> {
    const res = await fetch('/api/real/local/fim/baseline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { localWazuh: LocalWazuhSnapshot };
    return data.localWazuh;
  }

  async updateLocalConfig(
    config: Partial<LocalAgentConfig>,
    actor: string
  ): Promise<LocalWazuhSnapshot> {
    const res = await fetch('/api/real/local/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config, actor }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    const data = (await res.json()) as { localWazuh: LocalWazuhSnapshot };
    return data.localWazuh;
  }

  async verifyLocalPath(path: string): Promise<{
    path: string;
    status: 'READABLE' | 'NOT_FOUND' | 'PERMISSION_DENIED';
    sizeBytes: number | null;
    permissions: string | null;
  }> {
    const res = await fetch('/api/real/local/verify-path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as {
      path: string;
      status: 'READABLE' | 'NOT_FOUND' | 'PERMISSION_DENIED';
      sizeBytes: number | null;
      permissions: string | null;
    };
  }

  async addEndpoint(
    url: string,
    label: string,
    actor: string
  ): Promise<RealEndpointProbe> {
    const res = await fetch('/api/real/endpoints', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, label, actor }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    const data = (await res.json()) as { endpoint: RealEndpointProbe };
    return data.endpoint;
  }

  async removeEndpoint(id: string): Promise<void> {
    const res = await fetch(`/api/real/endpoints/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
  }

  async updateFindingStatus(
    findingId: string,
    status: RealFindingStatus,
    actor: string
  ): Promise<RealSecurityFinding> {
    const res = await fetch(
      `/api/real/findings/${encodeURIComponent(findingId)}/status`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, actor }),
      }
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { finding: RealSecurityFinding };
    return data.finding;
  }

  async updateProbeInterval(
    probeIntervalMs: number,
    actor: string
  ): Promise<number> {
    const res = await fetch('/api/real/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ probeIntervalMs, actor }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { probeIntervalMs: number };
    return data.probeIntervalMs;
  }

  async triggerContentScan(actor: string): Promise<ContentIntegrityScan[]> {
    const res = await fetch('/api/real/content-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { contentScans: ContentIntegrityScan[] };
    return data.contentScans;
  }

  async acceptContentBaseline(actor: string): Promise<ContentIntegrityScan[]> {
    const res = await fetch('/api/real/content-scan/baseline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { contentScans: ContentIntegrityScan[] };
    return data.contentScans;
  }

  async createIncidentReport(
    payload: Omit<ManualIncidentReport, 'id' | 'reportedAt' | 'updatedAt'>,
    actor: string
  ): Promise<{ report: ManualIncidentReport; incidentReports: ManualIncidentReport[] }> {
    const res = await fetch('/api/real/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, actor }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return (await res.json()) as {
      report: ManualIncidentReport;
      incidentReports: ManualIncidentReport[];
    };
  }

  async updateIncidentReport(
    id: string,
    patch: Partial<
      Pick<
        ManualIncidentReport,
        | 'status'
        | 'severity'
        | 'coordinationNotes'
        | 'actionTaken'
        | 'includeInBoardReport'
        | 'description'
        | 'evidenceSnippet'
      >
    >,
    actor: string
  ): Promise<{ report: ManualIncidentReport; incidentReports: ManualIncidentReport[] }> {
    const res = await fetch(`/api/real/incidents/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...patch, actor }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return (await res.json()) as {
      report: ManualIncidentReport;
      incidentReports: ManualIncidentReport[];
    };
  }

  async deleteIncidentReport(id: string): Promise<ManualIncidentReport[]> {
    const res = await fetch(`/api/real/incidents/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as {
      incidentReports: ManualIncidentReport[];
    };
    return data.incidentReports;
  }

  async runThreatIntelPlaybook(
    intelId: string,
    status: ThreatIntelStatus,
    actor: string
  ): Promise<{ alert: ThreatIntelAlert; threatIntelAlerts: ThreatIntelAlert[] }> {
    const res = await fetch(
      `/api/real/threat-alerts/${encodeURIComponent(intelId)}/run-playbook`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, actor }),
      }
    );
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return (await res.json()) as {
      alert: ThreatIntelAlert;
      threatIntelAlerts: ThreatIntelAlert[];
    };
  }

  async mitigateSiemEvent(
    eventId: string,
    mitigatedBy = 'SOC-Analyst-Auto',
    mitigatedAt = new Date().toISOString()
  ): Promise<{ event: LiveAttackEvent; ingestedSiemEvents: LiveAttackEvent[] }> {
    const res = await fetch(
      `/api/real/siem/${encodeURIComponent(eventId)}/mitigate`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mitigated_by: mitigatedBy,
          mitigated_at: mitigatedAt,
          actor: mitigatedBy,
        }),
      }
    );
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return (await res.json()) as {
      event: LiveAttackEvent;
      ingestedSiemEvents: LiveAttackEvent[];
    };
  }

  async pushSiemWebhookEvent(
    payload: Partial<LiveAttackEvent>
  ): Promise<LiveAttackEvent> {
    const res = await fetch('/api/ingest/siem', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    const data = (await res.json()) as { ingested: boolean; event: LiveAttackEvent };
    return data.event;
  }
}

export function createRealTelemetryAdapter(): RealTelemetryAdapter {
  return new RealTelemetryAdapter();
}

export function createInitialRealSnapshot(): RealTelemetrySnapshot {
  return {
    mode: 'REAL_ONLY',
    probeIntervalMs: 15000,
    connectedAnalysts: 1,
    probeOriginLabel: 'SOC Probe Node (Asia-Southeast)',
    endpoints: [],
    dnsAudit: null,
    threatIntel: null,
    threatIntelAlerts: [],
    localWazuh: null,
    knowledge: null,
    contentScans: [],
    incidentReports: [],
    latencyHistory: [],
    findings: [],
    probeLogs: [],
    ingestedSiemEvents: [],
  };
}
