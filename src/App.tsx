import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Shield,
  Briefcase,
  ClipboardList,
  BookOpen,
  Radar,
  Server,
  Sliders,
  Lock,
  Globe,
  ShieldAlert,
  FileText,
  Pause,
  Play,
  RefreshCw,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  X,
  CheckCircle2,
  ShieldCheck,
  Compass,
  Headphones,
  Terminal,
  FlaskConical,
  Radio,
  RotateCcw,
} from 'lucide-react';
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
  RealSocView,
  RealTelemetrySnapshot,
  SseConnectionState,
  ThreatIntelAlert,
  ThreatIntelStatus,
} from './types/soc';
import {
  createInitialRealSnapshot,
  createRealTelemetryAdapter,
  PRIMARY_PORTAL_HOST,
  RealTelemetryAdapter,
} from './services/telemetryService';
import {
  createDemoSiemEvent,
  createFullDemoTelemetrySnapshot,
} from './services/demoSandbox';
import { SocAppMode, SocModeProvider } from './context/SocModeContext';
import { ActionTooltip } from './components/ActionTooltip';
import { CopyToLiveDraft, CopyToLiveModal } from './components/CopyToLiveModal';
import { triggerFileDownload } from './utils/socFormatters';
import { RealLatencyChart } from './components/RealLatencyChart';
import { RealEndpointsPanel } from './components/RealEndpointsPanel';
import { RealInfrastructureMap } from './components/RealInfrastructureMap';
import { IncidentTimeline24h } from './components/IncidentTimeline24h';
import { IncidentReportsView } from './components/IncidentReportsView';
import { RealThreatIntelView } from './components/RealThreatIntelView';
import { LocalWazuhDashboardView } from './components/LocalWazuhDashboardView';
import { LocalConfigView } from './components/LocalConfigView';
import { CyberAcademyView } from './components/CyberAcademyView';
import { ExecutiveReportView } from './components/ExecutiveReportView';
import { RealHeadersTlsView } from './components/RealHeadersTlsView';
import { RealDnsAuditView } from './components/RealDnsAuditView';
import { RealFindingsView } from './components/RealFindingsView';
import { RealAuditLogView } from './components/RealAuditLogView';
import { ActionAdvisorView } from './components/ActionAdvisorView';
import { ServiceHealthSupportView } from './components/ServiceHealthSupportView';
import { PlaybookIntegrationView } from './components/PlaybookIntegrationView';

const VIEW_TITLES: Record<RealSocView, string> = {
  overview: 'Command Overview',
  'action-advisor': 'Action Advisor (Saran Tindakan)',
  playbooks: 'Incident Response Playbooks & Mitigation',
  'service-health': 'Service Health & Support IT Hub',
  'executive-report': 'Executive Brief & Board Report',
  'incident-reports': 'Incident Reports & Defacement Monitor',
  'wazuh-dashboard': 'Local Host SIEM / XDR (Wazuh-Style)',
  'local-config': 'Local Agent & Sensor Configuration',
  'threat-intel': 'Global Threat Intelligence (Open CTI)',
  'headers-tls': 'HTTP Headers & TLS Audit',
  'dns-audit': 'DNS & Anti-Spoofing Audit',
  findings: 'Verified Security Findings',
  academy: 'Cyber Academy & Live Glossary',
  audit: 'Audit Log & Compliance Export',
};

const CURRENT_ANALYST = 'SOC-Analyst';

export default function App() {
  const adapterRef = useRef<RealTelemetryAdapter | null>(null);
  if (!adapterRef.current) {
    adapterRef.current = createRealTelemetryAdapter();
  }

  const initial = useMemo(() => createInitialRealSnapshot(), []);

  const [appMode, setAppMode] = useState<SocAppMode>('LIVE');
  const isDemo = appMode === 'DEMO';
  const [demoSnapshot, setDemoSnapshot] = useState<RealTelemetrySnapshot>(() =>
    createFullDemoTelemetrySnapshot()
  );
  const [copyToLiveDraft, setCopyToLiveDraft] =
    useState<CopyToLiveDraft | null>(null);
  const [copyingToLive, setCopyingToLive] = useState(false);

  const [activeView, setActiveView] = useState<RealSocView>('overview');
  const [desktopSidebarOpen, setDesktopSidebarOpen] = useState(true);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [isStreaming, setIsStreaming] = useState(true);
  const [connectionState, setConnectionState] =
    useState<SseConnectionState>('CONNECTING');
  const [scanningNow, setScanningNow] = useState(false);
  const [syncingCti, setSyncingCti] = useState(false);
  const [scanningLocal, setScanningLocal] = useState(false);
  const [savingLocalConfig, setSavingLocalConfig] = useState(false);
  const [updatingKnowledge, setUpdatingKnowledge] = useState(false);
  const [scanningContent, setScanningContent] = useState(false);

  const [endpoints, setEndpoints] = useState<RealEndpointProbe[]>(
    initial.endpoints
  );
  const [dnsAudit, setDnsAudit] = useState<RealDnsSecurityAudit | null>(
    initial.dnsAudit
  );
  const [threatIntel, setThreatIntel] =
    useState<GlobalThreatIntelSnapshot | null>(initial.threatIntel);
  const [threatIntelAlerts, setThreatIntelAlerts] = useState<
    ThreatIntelAlert[]
  >(initial.threatIntelAlerts);
  const [localWazuh, setLocalWazuh] = useState<LocalWazuhSnapshot | null>(
    initial.localWazuh
  );
  const [knowledge, setKnowledge] = useState<CyberKnowledgeSnapshot | null>(
    initial.knowledge
  );
  const [contentScans, setContentScans] = useState<ContentIntegrityScan[]>(
    initial.contentScans
  );
  const [incidentReports, setIncidentReports] = useState<ManualIncidentReport[]>(
    initial.incidentReports
  );
  const [latencyHistory, setLatencyHistory] = useState<RealLatencyPoint[]>(
    initial.latencyHistory
  );
  const [findings, setFindings] = useState<RealSecurityFinding[]>(
    initial.findings
  );
  const [probeLogs, setProbeLogs] = useState<RealProbeLogEntry[]>(
    initial.probeLogs
  );
  const [ingestedSiemEvents, setIngestedSiemEvents] = useState<
    LiveAttackEvent[]
  >(initial.ingestedSiemEvents);
  const [probeIntervalMs, setProbeIntervalMs] = useState<number>(
    initial.probeIntervalMs
  );
  const [connectedAnalysts, setConnectedAnalysts] = useState<number>(
    initial.connectedAnalysts
  );
  const [probeOriginLabel, setProbeOriginLabel] = useState<string>(
    initial.probeOriginLabel
  );

  const [toast, setToast] = useState<{ title: string; detail: string } | null>(
    null
  );
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = useCallback((title: string, detail: string) => {
    setToast({ title, detail });
    if (toastTimerRef.current) {
      clearTimeout(toastTimerRef.current);
    }
    toastTimerRef.current = setTimeout(() => {
      setToast(null);
    }, 4200);
  }, []);

  // Connect to 100% Real Server-Authoritative SSE Stream
  useEffect(() => {
    const adapter = adapterRef.current;
    if (!adapter) return;

    if (!isStreaming) {
      adapter.disconnectStream();
      return;
    }

    adapter.connectStream({
      onInit: (snapshot) => {
        setEndpoints(snapshot.endpoints);
        setDnsAudit(snapshot.dnsAudit);
        setThreatIntel(snapshot.threatIntel);
        setThreatIntelAlerts(snapshot.threatIntelAlerts ?? []);
        setLocalWazuh(snapshot.localWazuh);
        setKnowledge(snapshot.knowledge);
        setContentScans(snapshot.contentScans ?? []);
        setIncidentReports(snapshot.incidentReports ?? []);
        setLatencyHistory(snapshot.latencyHistory);
        setFindings(snapshot.findings);
        setProbeLogs(snapshot.probeLogs);
        setIngestedSiemEvents(snapshot.ingestedSiemEvents);
        setProbeIntervalMs(snapshot.probeIntervalMs);
        setConnectedAnalysts(snapshot.connectedAnalysts);
        setProbeOriginLabel(snapshot.probeOriginLabel);
      },
      onProbeCycle: ({ endpoints: nextEndpoints, point }) => {
        setEndpoints(nextEndpoints);
        if (point) {
          setLatencyHistory((prev) => {
            if (prev.length > 0 && prev[prev.length - 1].time === point.time) {
              return prev;
            }
            return [...prev.slice(-29), point];
          });
        }
      },
      onDnsUpdated: (audit) => {
        setDnsAudit(audit);
      },
      onThreatIntelUpdated: (cti) => {
        setThreatIntel(cti);
      },
      onThreatAlertsUpdated: (alerts) => {
        setThreatIntelAlerts(alerts);
      },
      onWazuhUpdated: (nextWazuh) => {
        setLocalWazuh(nextWazuh);
      },
      onKnowledgeUpdated: (nextKnowledge) => {
        setKnowledge(nextKnowledge);
      },
      onContentScansUpdated: (scans) => {
        setContentScans(scans);
      },
      onIncidentReportsUpdated: (reports) => {
        setIncidentReports(reports);
      },
      onFindingsUpdated: (nextFindings) => {
        setFindings(nextFindings);
      },
      onLogCreated: (entry) => {
        setProbeLogs((prev) =>
          prev.some((l) => l.id === entry.id)
            ? prev
            : [entry, ...prev].slice(0, 200)
        );
      },
      onSiemIngested: (evt) => {
        setIngestedSiemEvents((prev) =>
          prev.some((e) => e.event_id === evt.event_id)
            ? prev
            : [evt, ...prev].slice(0, 100)
        );
      },
      onSiemUpdated: (events) => {
        setIngestedSiemEvents(events);
      },
      onConfigUpdated: ({ probeIntervalMs: nextMs }) => {
        setProbeIntervalMs(nextMs);
      },
      onClientsCount: (count) => {
        setConnectedAnalysts(count);
      },
      onConnectionStateChange: (state) => {
        setConnectionState(state);
      },
    });

    return () => {
      adapter.disconnectStream();
    };
  }, [isStreaming]);

  // Active Telemetry Selector: Strict isolation between Live Server vs Demo Sandbox
  const activeEndpoints = isDemo ? demoSnapshot.endpoints : endpoints;
  const activeDnsAudit = isDemo ? demoSnapshot.dnsAudit : dnsAudit;
  const activeThreatIntel = isDemo ? demoSnapshot.threatIntel : threatIntel;
  const activeThreatIntelAlerts = isDemo
    ? demoSnapshot.threatIntelAlerts
    : threatIntelAlerts;
  const activeLocalWazuh = isDemo ? demoSnapshot.localWazuh : localWazuh;
  const activeKnowledge = isDemo ? demoSnapshot.knowledge : knowledge;
  const activeContentScans = isDemo ? demoSnapshot.contentScans : contentScans;
  const activeIncidentReports = isDemo
    ? demoSnapshot.incidentReports
    : incidentReports;
  const activeLatencyHistory = isDemo
    ? demoSnapshot.latencyHistory
    : latencyHistory;
  const activeFindings = isDemo ? demoSnapshot.findings : findings;
  const activeProbeLogs = isDemo ? demoSnapshot.probeLogs : probeLogs;
  const activeIngestedSiemEvents = isDemo
    ? demoSnapshot.ingestedSiemEvents
    : ingestedSiemEvents;
  const activeProbeIntervalMs = isDemo
    ? demoSnapshot.probeIntervalMs
    : probeIntervalMs;
  const activeConnectedAnalysts = isDemo
    ? demoSnapshot.connectedAnalysts
    : connectedAnalysts;
  const activeProbeOriginLabel = isDemo
    ? demoSnapshot.probeOriginLabel
    : probeOriginLabel;

  // Derived Telemetry Metrics
  const primaryEndpoint = activeEndpoints[0] ?? null;
  const openFindingsCount = useMemo(
    () => activeFindings.filter((f) => f.status === 'OPEN').length,
    [activeFindings]
  );
  const highOrCriticalFindings = useMemo(
    () =>
      activeFindings.filter(
        (f) =>
          f.status === 'OPEN' &&
          (f.severity === 'CRITICAL' || f.severity === 'HIGH')
      ).length,
    [activeFindings]
  );
  const anyDown = useMemo(
    () => activeEndpoints.some((e) => e.status === 'DOWN'),
    [activeEndpoints]
  );

  const postureStatus: 'HEALTHY' | 'ATTENTION' | 'DEGRADED' = anyDown
    ? 'DEGRADED'
    : highOrCriticalFindings > 0
    ? 'ATTENTION'
    : 'HEALTHY';

  const postureColor =
    postureStatus === 'DEGRADED'
      ? 'text-rose-400'
      : postureStatus === 'ATTENTION'
      ? 'text-amber-400'
      : 'text-emerald-400';

  const handleSwitchMode = useCallback(
    (nextMode: SocAppMode) => {
      if (nextMode === appMode) return;
      setAppMode(nextMode);
      showToast(
        nextMode === 'DEMO'
          ? 'Demo Mode Aktif (Sandbox Latihan)'
          : 'Live Mode Aktif (Data Real Server)',
        nextMode === 'DEMO'
          ? 'Seluruh halaman memuat skenario latihan SOC tanpa mengubah data Live.'
          : 'Menampilkan 100% telemetri nyata tanpa teks panduan tambahan.'
      );
    },
    [appMode, showToast]
  );

  const handleResetDemo = useCallback(() => {
    setDemoSnapshot(createFullDemoTelemetrySnapshot());
    showToast(
      'Demo Sandbox Direset',
      'Seluruh skenario latihan (serangan, defacement SLOT777, playbook) dikembalikan ke kondisi awal.'
    );
  }, [showToast]);

  const handleConfirmCopyToLive = useCallback(
    async (
      payload: Omit<ManualIncidentReport, 'id' | 'reportedAt' | 'updatedAt'>
    ) => {
      setCopyingToLive(true);
      try {
        const res = await adapterRef.current!.createIncidentReport(
          payload,
          `${CURRENT_ANALYST} (Demo Promotion)`
        );
        setIncidentReports(res.incidentReports);
        setCopyToLiveDraft(null);
        showToast(
          `Disalin ke Live (${res.report.id})`,
          res.report.includeInBoardReport
            ? 'Tersimpan di Incident Reports Live & ikut Laporan CTO/BoD.'
            : 'Tersimpan di Incident Reports Live (ditandai sebagai salinan latihan Demo).'
        );
      } catch (err) {
        showToast(
          'Gagal Menyalin ke Live',
          err instanceof Error ? err.message : 'Server error'
        );
      } finally {
        setCopyingToLive(false);
      }
    },
    [showToast]
  );

  // Handlers
  const handleRunLiveScan = useCallback(async () => {
    if (isDemo) {
      setScanningNow(true);
      setTimeout(() => {
        setDemoSnapshot((prev) => ({
          ...prev,
          endpoints: prev.endpoints.map((ep) => ({
            ...ep,
            lastCheckedAt: new Date().toISOString(),
          })),
        }));
        setScanningNow(false);
        showToast(
          '[Demo] Refresh Simulasi Selesai',
          'Timestamp pengecekan endpoint latihan diperbarui di Demo Sandbox.'
        );
      }, 350);
      return;
    }
    setScanningNow(true);
    try {
      const snap = await adapterRef.current!.triggerFullScan(CURRENT_ANALYST);
      setEndpoints(snap.endpoints);
      setDnsAudit(snap.dnsAudit);
      if (snap.threatIntel) setThreatIntel(snap.threatIntel);
      setLatencyHistory(snap.latencyHistory);
      setFindings(snap.findings);
      const p = snap.endpoints[0];
      showToast(
        'Live Scan Completed',
        p
          ? `${p.hostname} · ${p.httpStatus ? `HTTP ${p.httpStatus}` : 'DOWN'} (${
              p.latencyMs ?? '-'
            } ms) · ${snap.findings.length} finding(s)`
          : 'All targets probed live'
      );
    } catch (err) {
      showToast(
        'Live Scan Failed',
        err instanceof Error ? err.message : 'Unable to reach server probe'
      );
    } finally {
      setScanningNow(false);
    }
  }, [isDemo, showToast]);

  const handleSyncCtiNow = useCallback(async () => {
    if (isDemo) {
      setSyncingCti(true);
      setTimeout(() => {
        setDemoSnapshot((prev) =>
          prev.threatIntel
            ? {
                ...prev,
                threatIntel: {
                  ...prev.threatIntel,
                  lastSyncedAt: new Date().toISOString(),
                },
              }
            : prev
        );
        setSyncingCti(false);
        showToast(
          '[Demo] Feed CTI Latihan Disegarkan',
          'Data CISA KEV, OpenPhish & Botnet C2 simulasi tetap terisolasi.'
        );
      }, 300);
      return;
    }
    setSyncingCti(true);
    try {
      const cti = await adapterRef.current!.triggerCtiSync(CURRENT_ANALYST);
      setThreatIntel(cti);
      const okCount = cti.sourcesStatus.filter((s) => s.status === 'OK').length;
      showToast(
        'Global Open CTI Synced',
        `${okCount}/${cti.sourcesStatus.length} public feeds live · CISA KEV ${cti.cisaKev.totalCount} CVEs · OpenPhish ${cti.openPhish.totalActiveUrls} URLs`
      );
    } catch (err) {
      showToast(
        'CTI Sync Failed',
        err instanceof Error ? err.message : 'Unable to sync public CTI feeds'
      );
    } finally {
      setSyncingCti(false);
    }
  }, [isDemo, showToast]);

  const handleRunLocalScan = useCallback(async () => {
    if (isDemo) {
      setScanningLocal(true);
      setTimeout(() => {
        setDemoSnapshot((prev) =>
          prev.localWazuh
            ? {
                ...prev,
                localWazuh: {
                  ...prev.localWazuh,
                  lastScannedAt: new Date().toISOString(),
                },
              }
            : prev
        );
        setScanningLocal(false);
        showToast(
          '[Demo] Local Host SIEM Scan Simulasi',
          'Menampilkan alert FIM & SSH latihan pada node demo.'
        );
      }, 300);
      return;
    }
    setScanningLocal(true);
    try {
      const snap = await adapterRef.current!.triggerLocalScan(CURRENT_ANALYST);
      setLocalWazuh(snap);
      showToast(
        'Local Host SIEM Scan Completed',
        `SCA ${snap.sca.scorePercent}% · FIM ${snap.fim.okCount}/${snap.fim.totalMonitored} OK · ${snap.alerts.length} rule alert(s)`
      );
    } catch (err) {
      showToast(
        'Local Scan Failed',
        err instanceof Error ? err.message : 'Unable to scan local host'
      );
    } finally {
      setScanningLocal(false);
    }
  }, [isDemo, showToast]);

  const handleAcceptFimBaseline = useCallback(async () => {
    if (isDemo) {
      setDemoSnapshot((prev) => {
        if (!prev.localWazuh) return prev;
        const entries = prev.localWazuh.fim.entries.map((e) => ({
          ...e,
          status: 'BASELINE_OK' as const,
          baselineSha256: e.sha256,
          note: 'Baseline diterima dalam Demo Sandbox',
        }));
        return {
          ...prev,
          localWazuh: {
            ...prev.localWazuh,
            fim: {
              ...prev.localWazuh.fim,
              baselineEstablishedAt: new Date().toISOString(),
              okCount: entries.length,
              modifiedCount: 0,
              entries,
            },
          },
        };
      });
      showToast(
        '[Demo] Baseline FIM Diperbarui',
        'Perubahan file latihan ditandai aman di Demo Sandbox.'
      );
      return;
    }
    try {
      const snap = await adapterRef.current!.acceptFimBaseline(CURRENT_ANALYST);
      setLocalWazuh(snap);
      showToast(
        'FIM SHA-256 Baseline Updated',
        `Accepted cryptographic baseline for ${snap.fim.okCount} monitored files`
      );
    } catch (err) {
      showToast(
        'Baseline Update Failed',
        err instanceof Error ? err.message : 'Server error'
      );
    }
  }, [isDemo, showToast]);

  const handleSaveLocalConfig = useCallback(
    async (nextConfig: LocalAgentConfig) => {
      if (isDemo) {
        setDemoSnapshot((prev) =>
          prev.localWazuh
            ? {
                ...prev,
                localWazuh: {
                  ...prev.localWazuh,
                  config: nextConfig,
                },
              }
            : prev
        );
        showToast(
          '[Demo] Konfigurasi Agent Disimpan (Sandbox)',
          `Perubahan pada ${nextConfig.agentName} hanya berlaku di Demo Mode.`
        );
        return;
      }
      setSavingLocalConfig(true);
      try {
        const snap = await adapterRef.current!.updateLocalConfig(
          nextConfig,
          CURRENT_ANALYST
        );
        setLocalWazuh(snap);
        showToast(
          'Local Agent Config Saved',
          `Applied to ${snap.config.agentName} · ${snap.fim.totalMonitored} FIM paths · ${snap.logSourcesStatus.length} log sources`
        );
      } catch (err) {
        showToast(
          'Save Config Failed',
          err instanceof Error ? err.message : 'Unable to save local config'
        );
      } finally {
        setSavingLocalConfig(false);
      }
    },
    [isDemo, showToast]
  );

  const handleVerifyLocalPath = useCallback(
    async (targetPath: string) => {
      if (isDemo) {
        return {
          path: targetPath,
          status: 'READABLE' as const,
          sizeBytes: 2048,
          permissions: '0644',
        };
      }
      return adapterRef.current!.verifyLocalPath(targetPath);
    },
    [isDemo]
  );

  const handleUpdateKnowledge = useCallback(async () => {
    if (isDemo) {
      showToast(
        '[Demo] Briefings Latihan',
        'Menampilkan materi latihan statis pada Demo Sandbox.'
      );
      return;
    }
    setUpdatingKnowledge(true);
    try {
      const snap = await adapterRef.current!.refreshKnowledge(CURRENT_ANALYST);
      setKnowledge(snap);
      showToast(
        'Pengetahuan Diperbarui',
        `${snap.liveBriefings.length} advisory & berita keamanan terbaru berhasil ditarik (SANS InfoCon: ${snap.sansInfocon.toUpperCase()})`
      );
    } catch (err) {
      showToast(
        'Gagal Memperbarui Pengetahuan',
        err instanceof Error ? err.message : 'Unable to refresh live briefings'
      );
    } finally {
      setUpdatingKnowledge(false);
    }
  }, [isDemo, showToast]);

  const handleAddCustomTerm = useCallback(
    async (term: Omit<CustomGlossaryTerm, 'id' | 'addedAt'>) => {
      if (isDemo) {
        setDemoSnapshot((prev) =>
          prev.knowledge
            ? {
                ...prev,
                knowledge: {
                  ...prev.knowledge,
                  customTerms: [
                    {
                      ...term,
                      id: `term-demo-${Date.now()}`,
                      addedAt: new Date().toISOString(),
                    },
                    ...prev.knowledge.customTerms,
                  ],
                },
              }
            : prev
        );
        showToast(
          '[Demo] Istilah Ditambahkan ke Sandbox',
          `"${term.term}" hanya disimpan sementara di Demo Mode.`
        );
        return;
      }
      const snap = await adapterRef.current!.addCustomGlossaryTerm(
        term,
        CURRENT_ANALYST
      );
      setKnowledge(snap);
      showToast(
        'Istilah Ditambahkan',
        `"${term.term}" tersimpan pada kamus hidup SOC`
      );
    },
    [isDemo, showToast]
  );

  const handleAddEndpoint = useCallback(
    async (url: string, label: string) => {
      if (isDemo) {
        const hostname = new URL(url).hostname;
        const added: RealEndpointProbe = {
          id: `ep-demo-${Date.now().toString(36)}`,
          label: label || hostname,
          url,
          hostname,
          isDefault: false,
          status: 'UP',
          httpStatus: 200,
          latencyMs: 215,
          uptimePercent: 100,
          totalChecks: 1,
          successChecks: 1,
          lastCheckedAt: new Date().toISOString(),
          headerScore: 67,
          serverHeader: 'nginx',
          poweredByHeader: null,
          securityHeaders: {
            hsts: 'max-age=31536000',
            csp: null,
            xFrameOptions: 'SAMEORIGIN',
            xContentTypeOptions: 'nosniff',
            referrerPolicy: 'strict-origin-when-cross-origin',
            permissionsPolicy: null,
          },
          cookies: {
            count: 1,
            allSecure: true,
            allHttpOnly: true,
            hasSameSite: true,
          },
          tls: {
            protocol: 'TLSv1.3',
            cipher: 'TLS_AES_256_GCM_SHA384',
            issuer: 'Demo Sandbox CA',
            subject: hostname,
            sanCount: 1,
            validFrom: '2026-01-01',
            validTo: '2027-01-01',
            daysRemaining: 40,
            fingerprint256: 'DEMO:CUSTOM:ENDPOINT',
          },
          dns: { ipv4: ['203.0.113.10'], ipv6: [], cname: [] },
        };
        setDemoSnapshot((prev) => ({
          ...prev,
          endpoints: [prev.endpoints[0], added, ...prev.endpoints.slice(1)],
        }));
        showToast(`[Demo] Endpoint ${hostname} Ditambahkan`, 'Hanya aktif di Demo Sandbox');
        return;
      }
      const added = await adapterRef.current!.addEndpoint(
        url,
        label,
        CURRENT_ANALYST
      );
      setEndpoints((prev) => {
        if (prev.some((e) => e.id === added.id)) return prev;
        return prev.length > 0
          ? [prev[0], added, ...prev.slice(1)]
          : [added];
      });
      showToast(
        `Added & Probed ${added.hostname}`,
        `${added.httpStatus ? `HTTP ${added.httpStatus}` : added.status} · ${
          added.latencyMs ?? '-'
        } ms`
      );
    },
    [isDemo, showToast]
  );

  const handleRemoveEndpoint = useCallback(
    async (id: string) => {
      if (isDemo) {
        setDemoSnapshot((prev) => ({
          ...prev,
          endpoints: prev.endpoints.filter((e) => e.id !== id),
        }));
        showToast('[Demo] Endpoint Dihapus', 'Dihapus dari Demo Sandbox');
        return;
      }
      try {
        await adapterRef.current!.removeEndpoint(id);
        setEndpoints((prev) => prev.filter((e) => e.id !== id));
        showToast('Endpoint Removed', 'Stopped passive monitoring for URL');
      } catch (err) {
        showToast(
          'Remove Failed',
          err instanceof Error ? err.message : 'Unable to remove endpoint'
        );
      }
    },
    [isDemo, showToast]
  );

  const handleUpdateFindingStatus = useCallback(
    async (findingId: string, status: RealFindingStatus) => {
      if (isDemo) {
        setDemoSnapshot((prev) => ({
          ...prev,
          findings: prev.findings.map((f) =>
            f.finding_id === findingId ? { ...f, status } : f
          ),
        }));
        showToast(`[Demo] ${findingId} Updated`, `Status simulasi: ${status}`);
        return;
      }
      try {
        await adapterRef.current!.updateFindingStatus(
          findingId,
          status,
          CURRENT_ANALYST
        );
        showToast(`${findingId} Updated`, `Marked as ${status}`);
      } catch (err) {
        showToast(
          'Update Failed',
          err instanceof Error ? err.message : 'Server error'
        );
      }
    },
    [isDemo, showToast]
  );

  const handleUpdateInterval = useCallback(
    async (ms: number) => {
      if (isDemo) {
        setDemoSnapshot((prev) => ({ ...prev, probeIntervalMs: ms }));
        showToast('[Demo] Cadence Simulasi Diubah', `${ms / 1000}s (Sandbox)`);
        return;
      }
      try {
        const updated = await adapterRef.current!.updateProbeInterval(
          ms,
          CURRENT_ANALYST
        );
        setProbeIntervalMs(updated);
        showToast(
          'Probe Cadence Updated',
          `Live passive scan runs every ${updated / 1000}s`
        );
      } catch (err) {
        showToast(
          'Cadence Update Failed',
          err instanceof Error ? err.message : 'Server error'
        );
      }
    },
    [isDemo, showToast]
  );

  const handleScanContent = useCallback(async () => {
    if (isDemo) {
      setScanningContent(true);
      setTimeout(() => {
        setDemoSnapshot((prev) => ({
          ...prev,
          contentScans: prev.contentScans.map((s) => ({
            ...s,
            scannedAt: new Date().toISOString(),
          })),
        }));
        setScanningContent(false);
        showToast(
          '[Demo] Scan HTML & Cloaking Simulasi',
          'Menampilkan contoh temuan Googlebot Cloaking (SLOT777) untuk latihan.'
        );
      }, 300);
      return;
    }
    setScanningContent(true);
    try {
      const scans = await adapterRef.current!.triggerContentScan(CURRENT_ANALYST);
      setContentScans(scans);
      const flagged = scans.filter((s) => s.riskLevel !== 'CLEAN').length;
      showToast(
        'HTML & Cloaking Scan Selesai',
        flagged > 0
          ? `Terdeteksi ${flagged} URL dengan indikasi defacement / cloaking / perubahan HTML`
          : `${scans.length} URL bersih (Browser vs Googlebot UA cocok, 0 keyword judol)`
      );
    } catch (err) {
      showToast(
        'Content Scan Gagal',
        err instanceof Error ? err.message : 'Server error'
      );
    } finally {
      setScanningContent(false);
    }
  }, [isDemo, showToast]);

  const handleAcceptContentBaseline = useCallback(async () => {
    if (isDemo) {
      setDemoSnapshot((prev) => ({
        ...prev,
        contentScans: prev.contentScans.map((s) => ({
          ...s,
          baselineHashSha256: s.browserHashSha256,
          contentChangedFromBaseline: false,
          cloakingSuspected: false,
          cloakingReason: null,
          defacementSuspected: false,
          browserKeywordsFound: [],
          googlebotKeywordsFound: [],
          riskLevel: 'CLEAN' as const,
        })),
      }));
      showToast(
        '[Demo] Baseline HTML Diterima',
        'Skenario konten defacement dibersihkan di Demo Sandbox.'
      );
      return;
    }
    try {
      const scans = await adapterRef.current!.acceptContentBaseline(
        CURRENT_ANALYST
      );
      setContentScans(scans);
      showToast(
        'Baseline HTML SHA-256 Diperbarui',
        `Baseline hash konten diterima untuk ${scans.length} endpoint terpantau`
      );
    } catch (err) {
      showToast(
        'Gagal Update Baseline',
        err instanceof Error ? err.message : 'Server error'
      );
    }
  }, [isDemo, showToast]);

  const handleCreateIncident = useCallback(
    async (
      payload: Omit<ManualIncidentReport, 'id' | 'reportedAt' | 'updatedAt'>
    ) => {
      if (isDemo) {
        const nowIso = new Date().toISOString();
        const created: ManualIncidentReport = {
          ...payload,
          id: `INC-DEMO-${Math.floor(100 + Math.random() * 900)}`,
          reportedAt: nowIso,
          updatedAt: nowIso,
        };
        setDemoSnapshot((prev) => ({
          ...prev,
          incidentReports: [created, ...prev.incidentReports],
        }));
        showToast(
          `[Demo] ${created.id} Disimpan ke Sandbox`,
          'Gunakan tombol "Salin ke Live" jika hasil latihan ingin dijadikan laporan Live.'
        );
        return;
      }
      const res = await adapterRef.current!.createIncidentReport(
        payload,
        CURRENT_ANALYST
      );
      setIncidentReports(res.incidentReports);
      showToast(
        `Laporan ${res.report.id} Tersimpan`,
        res.report.includeInBoardReport
          ? 'Tercatat permanen & otomatis masuk Laporan CTO & BoD'
          : 'Tercatat pada daftar Incident Reports'
      );
    },
    [isDemo, showToast]
  );

  const handleUpdateIncident = useCallback(
    async (
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
      >
    ) => {
      if (isDemo) {
        const nowIso = new Date().toISOString();
        setDemoSnapshot((prev) => ({
          ...prev,
          incidentReports: prev.incidentReports.map((r) =>
            r.id === id ? { ...r, ...patch, updatedAt: nowIso } : r
          ),
        }));
        showToast(`[Demo] ${id} Diperbarui`, 'Perubahan disimpan di Demo Sandbox');
        return;
      }
      try {
        const res = await adapterRef.current!.updateIncidentReport(
          id,
          patch,
          CURRENT_ANALYST
        );
        setIncidentReports(res.incidentReports);
        showToast(`${id} Diperbarui`, `Status: ${res.report.status}`);
      } catch (err) {
        showToast(
          'Gagal Memperbarui Laporan',
          err instanceof Error ? err.message : 'Server error'
        );
      }
    },
    [isDemo, showToast]
  );

  const handleDeleteIncident = useCallback(
    async (id: string) => {
      if (isDemo) {
        setDemoSnapshot((prev) => ({
          ...prev,
          incidentReports: prev.incidentReports.filter((r) => r.id !== id),
        }));
        showToast('[Demo] Laporan Dihapus', `${id} dihapus dari Demo Sandbox`);
        return;
      }
      try {
        const next = await adapterRef.current!.deleteIncidentReport(id);
        setIncidentReports(next);
        showToast('Laporan Dihapus', `${id} dihapus dari daftar insiden`);
      } catch (err) {
        showToast(
          'Gagal Menghapus',
          err instanceof Error ? err.message : 'Server error'
        );
      }
    },
    [isDemo, showToast]
  );

  const handleRunPlaybook = useCallback(
    async (intelId: string, nextStatus: ThreatIntelStatus) => {
      if (isDemo) {
        setDemoSnapshot((prev) => ({
          ...prev,
          threatIntelAlerts: prev.threatIntelAlerts.map((a) =>
            a.intel_id === intelId ? { ...a, status: nextStatus } : a
          ),
        }));
        showToast(
          `[Demo] Playbook ${nextStatus === 'MITIGATED' ? 'Selesai' : 'Diperbarui'}`,
          `${intelId} berstatus ${nextStatus} (Sandbox). Bisa disalin ke Laporan Live.`
        );
        return;
      }
      try {
        const res = await adapterRef.current!.runThreatIntelPlaybook(
          intelId,
          nextStatus,
          CURRENT_ANALYST
        );
        setThreatIntelAlerts(res.threatIntelAlerts);
        showToast(
          `Playbook ${nextStatus === 'MITIGATED' ? 'Executed' : 'Updated'}`,
          `${res.alert.intel_id} status updated to ${res.alert.status}`
        );
      } catch (err) {
        showToast(
          'Playbook Execution Failed',
          err instanceof Error ? err.message : 'Server error'
        );
      }
    },
    [isDemo, showToast]
  );

  const handleMitigateAttackEvent = useCallback(
    async (eventId: string, mitigatedBy: string, mitigatedAt: string) => {
      if (isDemo) {
        setDemoSnapshot((prev) => ({
          ...prev,
          ingestedSiemEvents: prev.ingestedSiemEvents.map((e) =>
            e.event_id === eventId
              ? {
                  ...e,
                  action_taken: 'MITIGATED',
                  mitigated_by: mitigatedBy,
                  mitigated_at: mitigatedAt,
                }
              : e
          ),
        }));
        showToast(
          `[Demo] ${eventId} Mitigated`,
          `Mitigated by ${mitigatedBy} (Sandbox). Bisa disalin ke Laporan Live.`
        );
        return;
      }
      try {
        const res = await adapterRef.current!.mitigateSiemEvent(
          eventId,
          mitigatedBy,
          mitigatedAt
        );
        setIngestedSiemEvents(res.ingestedSiemEvents);
        showToast(
          `${res.event.event_id} Mitigated`,
          `Mitigated by ${res.event.mitigated_by} · ${res.event.attack_vector}`
        );
      } catch (err) {
        showToast(
          'Mitigation Failed',
          err instanceof Error ? err.message : 'Server error'
        );
      }
    },
    [isDemo, showToast]
  );

  const handlePushSiemTestEvent = useCallback(
    async (payload: Partial<LiveAttackEvent>) => {
      if (!isDemo) return;
      const evt = createDemoSiemEvent(
        payload.action_taken ?? 'DETECTED',
        payload.attack_vector ?? 'SQLi',
        payload.severity ?? 'CRITICAL'
      );
      setDemoSnapshot((prev) => ({
        ...prev,
        ingestedSiemEvents: [evt, ...prev.ingestedSiemEvents].slice(0, 50),
      }));
      showToast(
        `[Demo] SIEM Event ${evt.event_id}`,
        `${evt.action_taken} · ${evt.attack_vector} from ${evt.source_ip}`
      );
    },
    [isDemo, showToast]
  );

  const handleExportComplianceJson = useCallback(() => {
    const payload = {
      generated_at: new Date().toISOString(),
      mode: isDemo
        ? 'DEMO SANDBOX PRACTICE EXPORT (SIMULATION DATA)'
        : '100% REAL PUBLIC TELEMETRY + OPEN CTI + LOCAL HOST SIEM',
      primary_portal: primaryEndpoint?.hostname ?? PRIMARY_PORTAL_HOST,
      endpoints: activeEndpoints,
      dns_audit: activeDnsAudit,
      global_threat_intel: activeThreatIntel,
      local_host_siem: activeLocalWazuh,
      content_integrity_scans: activeContentScans,
      manual_incident_reports: activeIncidentReports,
      findings: activeFindings,
      latency_history: activeLatencyHistory,
      probe_logs: activeProbeLogs,
      external_siem_events: activeIngestedSiemEvents,
    };
    triggerFileDownload(
      JSON.stringify(payload, null, 2),
      `cyber-defense-${isDemo ? 'demo-sandbox' : 'real'}-security-report-${new Date()
        .toISOString()
        .slice(0, 10)}.json`,
      'application/json'
    );
    showToast(
      isDemo ? 'Demo JSON Exported' : 'Compliance JSON Exported',
      isDemo
        ? 'Downloaded isolated Demo training dataset'
        : 'Downloaded verified HTTP, TLS, DNS, Open CTI & Local SIEM report'
    );
  }, [
    isDemo,
    activeEndpoints,
    activeDnsAudit,
    activeThreatIntel,
    activeLocalWazuh,
    activeContentScans,
    activeIncidentReports,
    activeFindings,
    activeLatencyHistory,
    activeProbeLogs,
    activeIngestedSiemEvents,
    showToast,
  ]);

  const ctiOkCount = useMemo(
    () =>
      activeThreatIntel?.sourcesStatus.filter((s) => s.status === 'OK').length ?? 0,
    [activeThreatIntel]
  );

  const activeIncidentReportCount = useMemo(
    () =>
      activeIncidentReports.filter(
        (r) => r.status !== 'CLOSED' && r.status !== 'MITIGATED'
      ).length,
    [activeIncidentReports]
  );

  const actionAdvisorCount = useMemo(() => {
    const nonCleanScans = activeContentScans.filter(
      (s) => s.riskLevel !== 'CLEAN'
    ).length;
    const openReports = activeIncidentReports.filter(
      (r) => r.status !== 'CLOSED'
    ).length;
    const unresolvedFindings = activeFindings.filter(
      (f) => f.status !== 'RESOLVED'
    ).length;
    const wazuhAlerts = Math.min(activeLocalWazuh?.alerts.length ?? 0, 8);
    return nonCleanScans + openReports + unresolvedFindings + wazuhAlerts;
  }, [
    activeContentScans,
    activeIncidentReports,
    activeFindings,
    activeLocalWazuh,
  ]);

  const openPlaybookQueueCount = useMemo(() => {
    const openIntel = activeThreatIntelAlerts.filter(
      (a) => a.status === 'OPEN'
    ).length;
    const unmitigatedAttacks = activeIngestedSiemEvents.filter(
      (e) => e.action_taken === 'DETECTED' || e.action_taken === 'CHALLENGED'
    ).length;
    return openIntel + unmitigatedAttacks;
  }, [activeThreatIntelAlerts, activeIngestedSiemEvents]);

  const navItems: Array<{
    id: RealSocView;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    counter?: number;
    counterSuffix?: string;
    counterTone?: string;
  }> = [
    { id: 'overview', label: 'Command Overview', icon: Shield },
    {
      id: 'action-advisor',
      label: 'Action Advisor',
      icon: Compass,
      counter: actionAdvisorCount > 0 ? actionAdvisorCount : undefined,
      counterTone:
        activeIncidentReportCount > 0 || highOrCriticalFindings > 0
          ? 'text-rose-400'
          : 'text-emerald-400',
    },
    {
      id: 'playbooks',
      label: 'IR Playbooks',
      icon: Terminal,
      counter: openPlaybookQueueCount > 0 ? openPlaybookQueueCount : undefined,
      counterTone: openPlaybookQueueCount > 0 ? 'text-rose-400' : 'text-emerald-400',
    },
    {
      id: 'service-health',
      label: 'Support IT & Health',
      icon: Headphones,
      counter: activeEndpoints.length > 0 ? activeEndpoints.length : undefined,
      counterTone:
        activeEndpoints.some((e) => e.status === 'DOWN') ||
        activeContentScans.some((s) => s.riskLevel === 'CRITICAL')
          ? 'text-rose-400'
          : activeEndpoints.some((e) => e.status === 'DEGRADED')
          ? 'text-amber-400'
          : 'text-emerald-400',
    },
    {
      id: 'executive-report',
      label: 'Board & CTO Report',
      icon: Briefcase,
    },
    {
      id: 'incident-reports',
      label: 'Incident Reports',
      icon: ClipboardList,
      counter:
        activeIncidentReportCount > 0
          ? activeIncidentReportCount
          : activeIncidentReports.length > 0
          ? activeIncidentReports.length
          : undefined,
      counterTone:
        activeIncidentReportCount > 0 ? 'text-rose-400' : 'text-zinc-400',
    },
    {
      id: 'wazuh-dashboard',
      label: 'Local SIEM / XDR',
      icon: Server,
      counter: activeLocalWazuh?.sca.scorePercent,
      counterSuffix: '%',
      counterTone:
        (activeLocalWazuh?.sca.scorePercent ?? 0) >= 80
          ? 'text-emerald-400'
          : 'text-amber-400',
    },
    {
      id: 'local-config',
      label: 'Local Agent Config',
      icon: Sliders,
    },
    {
      id: 'threat-intel',
      label: 'Global Threat Intel',
      icon: Radar,
      counter: activeThreatIntel ? ctiOkCount : undefined,
      counterSuffix: '/6',
      counterTone: 'text-emerald-400',
    },
    {
      id: 'headers-tls',
      label: 'Headers & TLS Audit',
      icon: Lock,
      counter: primaryEndpoint?.headerScore,
      counterSuffix: '%',
      counterTone:
        (primaryEndpoint?.headerScore ?? 0) >= 80
          ? 'text-emerald-400'
          : 'text-amber-400',
    },
    {
      id: 'dns-audit',
      label: 'DNS & Anti-Spoofing',
      icon: Globe,
      counter: activeDnsAudit?.score,
      counterSuffix: '%',
      counterTone:
        (activeDnsAudit?.score ?? 0) >= 80 ? 'text-emerald-400' : 'text-amber-400',
    },
    {
      id: 'findings',
      label: 'Verified Findings',
      icon: ShieldAlert,
      counter: openFindingsCount,
      counterTone: openFindingsCount > 0 ? 'text-amber-400' : 'text-emerald-400',
    },
    {
      id: 'academy',
      label: 'Cyber Academy',
      icon: BookOpen,
      counter: activeKnowledge?.liveBriefings.length,
      counterTone: 'text-emerald-400',
    },
    {
      id: 'audit',
      label: 'Audit Log & Export',
      icon: FileText,
      counter: activeProbeLogs.length,
      counterTone: 'text-zinc-500',
    },
  ];

  const streamLabel = isDemo
    ? 'DEMO SANDBOX'
    : !isStreaming
    ? 'SSE Paused'
    : connectionState === 'CONNECTED'
    ? 'SSE Live'
    : 'SSE Reconnecting';

  return (
    <SocModeProvider mode={appMode} onChangeMode={handleSwitchMode}>
      <div className="min-h-screen bg-zinc-950 text-zinc-100 flex">
        {/* Desktop Sidebar (244px — Show/Hide Toggleable) */}
        {desktopSidebarOpen && (
          <aside className="hidden lg:flex lg:flex-col lg:w-[244px] lg:shrink-0 border-r border-zinc-800/80 bg-zinc-950 sticky top-0 h-screen print:hidden">
            <div className="h-14 px-4 flex items-center justify-between gap-2 border-b border-zinc-800/80">
              <div className="flex items-center gap-2.5 min-w-0">
                <Shield
                  className={`w-5 h-5 shrink-0 ${
                    isDemo ? 'text-amber-400' : 'text-emerald-500'
                  }`}
                />
                <span className="text-sm font-bold tracking-tight text-zinc-100 whitespace-nowrap truncate">
                  Cyber Defense SOC
                </span>
              </div>
              <ActionTooltip
                label="Sembunyikan Sidebar"
                description="Memperluas area kerja tabel & peta ke lebar penuh layar."
                scope="UI"
                side="right"
              >
                <button
                  type="button"
                  onClick={() => setDesktopSidebarOpen(false)}
                  aria-label="Sembunyikan menu sidebar"
                  className="p-1.5 text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900 rounded-md transition-colors cursor-pointer shrink-0"
                >
                  <PanelLeftClose className="w-4 h-4" />
                </button>
              </ActionTooltip>
            </div>

            <nav
              className="flex-1 px-3 py-3 space-y-1 overflow-y-auto"
              aria-label="SOC Workspace Navigation"
            >
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = activeView === item.id;
                return (
                  <ActionTooltip
                    key={item.id}
                    label={item.label}
                    description={`Buka modul ${VIEW_TITLES[item.id]}`}
                    scope={isDemo ? 'Demo' : 'Live'}
                    side="right"
                    className="block w-full"
                  >
                    <button
                      type="button"
                      onClick={() => setActiveView(item.id)}
                      className={`w-full flex items-center justify-between gap-2 px-3 py-2 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                        active
                          ? 'bg-zinc-900 text-zinc-100 border border-zinc-800'
                          : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900/50 border border-transparent'
                      }`}
                    >
                      <span className="flex items-center gap-2.5 min-w-0">
                        <Icon
                          className={`w-4 h-4 shrink-0 ${
                            active
                              ? isDemo
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                              : 'text-zinc-500'
                          }`}
                        />
                        <span className="truncate whitespace-nowrap">
                          {item.label}
                        </span>
                      </span>
                      {typeof item.counter === 'number' && (
                        <span
                          className={`font-mono text-[11px] tabular-nums shrink-0 ${
                            item.counterTone ?? 'text-zinc-500'
                          }`}
                        >
                          {item.counter}
                          {item.counterSuffix ?? ''}
                        </span>
                      )}
                    </button>
                  </ActionTooltip>
                );
              })}
            </nav>

            <div className="p-4 border-t border-zinc-800/80 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-zinc-500">
                  {isDemo ? 'Sandbox Posture' : 'Live Posture'}
                </span>
                <span className={`font-mono font-semibold ${postureColor}`}>
                  {postureStatus}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400">
                <span>Telemetry Mode</span>
                <span className={isDemo ? 'text-amber-400' : 'text-emerald-400'}>
                  {isDemo ? 'DEMO SANDBOX' : '100% REAL'}
                </span>
              </div>
              <div className="text-[11px] font-mono text-zinc-500 pt-1 border-t border-zinc-900 truncate">
                {primaryEndpoint?.hostname ?? PRIMARY_PORTAL_HOST}
              </div>
            </div>
          </aside>
        )}

        {/* Mobile Navigation Drawer */}
        {mobileNavOpen && (
          <div
            className="fixed inset-0 z-50 lg:hidden flex bg-black/70"
            onClick={() => setMobileNavOpen(false)}
          >
            <div
              className="w-64 bg-zinc-950 border-r border-zinc-800 h-full flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="h-14 px-4 flex items-center justify-between border-b border-zinc-800">
                <span className="text-sm font-bold text-zinc-100">
                  Cyber Defense SOC
                </span>
                <button
                  type="button"
                  onClick={() => setMobileNavOpen(false)}
                  aria-label="Close navigation menu"
                  className="p-1.5 text-zinc-400 hover:text-zinc-100"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
                {navItems.map((item) => {
                  const Icon = item.icon;
                  const active = activeView === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setActiveView(item.id);
                        setMobileNavOpen(false);
                      }}
                      className={`w-full flex items-center justify-between px-3 py-2.5 rounded-md text-xs font-medium ${
                        active
                          ? 'bg-zinc-900 text-zinc-100 border border-zinc-800'
                          : 'text-zinc-400 hover:text-zinc-100'
                      }`}
                    >
                      <span className="flex items-center gap-2.5">
                        <Icon className="w-4 h-4" />
                        {item.label}
                      </span>
                    </button>
                  );
                })}
              </nav>
            </div>
          </div>
        )}

        {/* Main Content Column */}
        <div className="flex-1 min-w-0 flex flex-col">
          {/* Top Bar Contract */}
          <header className="h-14 px-4 sm:px-6 border-b border-zinc-800/80 bg-zinc-950/90 backdrop-blur-sm sticky top-0 z-30 flex items-center justify-between gap-4 print:hidden">
            <div className="flex items-center gap-3 min-w-0">
              {/* Mobile Drawer Trigger */}
              <ActionTooltip label="Buka Menu Navigasi" scope="Navigasi" side="bottom">
                <button
                  type="button"
                  onClick={() => setMobileNavOpen(true)}
                  aria-label="Open navigation menu"
                  className="lg:hidden p-1.5 text-zinc-400 hover:text-zinc-100 rounded-md border border-zinc-800 cursor-pointer"
                >
                  <Menu className="w-4 h-4" />
                </button>
              </ActionTooltip>

              {/* Desktop Show/Hide Sidebar Trigger */}
              <ActionTooltip
                label={desktopSidebarOpen ? 'Sembunyikan Menu' : 'Tampilkan Menu'}
                description="Atur visibilitas panel navigasi samping."
                scope="UI"
                side="bottom"
              >
                <button
                  type="button"
                  onClick={() => setDesktopSidebarOpen((prev) => !prev)}
                  aria-label={
                    desktopSidebarOpen ? 'Sembunyikan menu' : 'Tampilkan menu'
                  }
                  className="hidden lg:inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 hover:text-zinc-100 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {desktopSidebarOpen ? (
                    <>
                      <PanelLeftClose className="w-3.5 h-3.5 text-zinc-400" />
                      <span>Hide Menu</span>
                    </>
                  ) : (
                    <>
                      <PanelLeftOpen className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Show Menu</span>
                    </>
                  )}
                </button>
              </ActionTooltip>

              <div className="flex items-center gap-2 text-xs sm:text-sm min-w-0">
                {!desktopSidebarOpen && (
                  <>
                    <Shield
                      className={`hidden lg:inline w-4 h-4 shrink-0 ${
                        isDemo ? 'text-amber-400' : 'text-emerald-500'
                      }`}
                    />
                    <span className="hidden lg:inline font-bold text-zinc-100 whitespace-nowrap">
                      Cyber Defense SOC
                    </span>
                    <span className="text-zinc-700 hidden lg:inline">/</span>
                  </>
                )}
                <h1 className="font-semibold text-zinc-100 truncate">
                  {VIEW_TITLES[activeView]}
                </h1>
                <span className="text-zinc-700 hidden md:inline">·</span>
                <span
                  className={`hidden md:inline font-mono text-[11px] whitespace-nowrap ${
                    isDemo
                      ? 'text-amber-400'
                      : isStreaming && connectionState === 'CONNECTED'
                      ? 'text-emerald-400'
                      : 'text-amber-400'
                  }`}
                >
                  {streamLabel}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {/* Segmented LIVE / DEMO Mode Switcher */}
              <div
                role="group"
                aria-label="Pilih Mode Data Aplikasi"
                className="inline-flex items-center p-0.5 bg-zinc-900 border border-zinc-800 rounded-md shrink-0"
              >
                <ActionTooltip
                  label="Aktifkan Live Mode"
                  description="Menampilkan data nyata server, probe HTTPS/DNS, & Open CTI tanpa teks panduan."
                  scope="Data Real"
                  side="bottom"
                >
                  <button
                    type="button"
                    onClick={() => handleSwitchMode('LIVE')}
                    aria-pressed={!isDemo}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      !isDemo
                        ? 'bg-emerald-600 text-white'
                        : 'text-zinc-400 hover:text-zinc-100'
                    }`}
                  >
                    <Radio className="w-3.5 h-3.5 shrink-0" />
                    Live
                  </button>
                </ActionTooltip>

                <ActionTooltip
                  label="Aktifkan Demo Mode"
                  description="Masuk ke sandbox latihan SOC (serangan, SLOT777, playbook) & panduan lengkap."
                  scope="Latihan"
                  side="bottom"
                >
                  <button
                    type="button"
                    onClick={() => handleSwitchMode('DEMO')}
                    aria-pressed={isDemo}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      isDemo
                        ? 'bg-amber-600 text-white'
                        : 'text-zinc-400 hover:text-zinc-100'
                    }`}
                  >
                    <FlaskConical className="w-3.5 h-3.5 shrink-0" />
                    Demo
                  </button>
                </ActionTooltip>
              </div>

              {!isDemo && (
                <ActionTooltip
                  label={isStreaming ? 'Jeda Pembaruan Live' : 'Lanjutkan Stream Live'}
                  description={
                    isStreaming
                      ? 'Menahan pembaruan SSE sementara agar tabel mudah dibaca.'
                      : 'Menghubungkan kembali stream pemantauan real-time.'
                  }
                  scope="SSE"
                  side="bottom"
                >
                  <button
                    type="button"
                    onClick={() => setIsStreaming((prev) => !prev)}
                    className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    {isStreaming ? (
                      <>
                        <Pause className="w-3.5 h-3.5 text-amber-400" />
                        Pause
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5 text-emerald-400" />
                        Resume
                      </>
                    )}
                  </button>
                </ActionTooltip>
              )}

              {isDemo && (
                <ActionTooltip
                  label="Reset Data Demo"
                  description="Mengembalikan seluruh skenario serangan, insiden, dan playbook Demo ke kondisi awal."
                  scope="Sandbox"
                  side="bottom"
                >
                  <button
                    type="button"
                    onClick={handleResetDemo}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-amber-300 border border-amber-500/30 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    Reset Demo
                  </button>
                </ActionTooltip>
              )}

              <ActionTooltip
                label={isDemo ? 'Segarkan Simulasi Demo' : 'Jalankan Live Scan Sekarang'}
                description={
                  isDemo
                    ? 'Memperbarui timestamp pengecekan pada Demo Sandbox.'
                    : 'Melakukan HTTP GET, TLS handshake, & DNS lookup langsung dari server.'
                }
                scope={isDemo ? 'Sandbox' : 'Live Probe'}
                side="bottom"
              >
                <button
                  type="button"
                  disabled={scanningNow}
                  onClick={() => void handleRunLiveScan()}
                  className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60 ${
                    isDemo
                      ? 'bg-amber-600 hover:bg-amber-500'
                      : 'bg-emerald-600 hover:bg-emerald-500'
                  }`}
                >
                  <RefreshCw
                    className={`w-3.5 h-3.5 ${scanningNow ? 'animate-spin' : ''}`}
                  />
                  {scanningNow ? 'Scanning...' : isDemo ? 'Refresh Demo' : 'Run Live Scan'}
                </button>
              </ActionTooltip>
            </div>
          </header>

          {/* Demo Sandbox Active Indicator Strip */}
          {isDemo && (
            <div className="px-4 sm:px-6 py-2 bg-amber-500/10 border-b border-amber-500/30 flex flex-wrap items-center justify-between gap-2 text-xs print:hidden">
              <div className="flex items-center gap-2 text-amber-200 min-w-0">
                <FlaskConical className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                <span className="truncate">
                  <strong className="text-amber-300">Mode Latihan Demo (Sandbox):</strong>{' '}
                  Memuat paket skenario serangan SQLi, Googlebot Cloaking SLOT777, playbook &amp; laporan latihan. Tidak mengubah data Live kecuali disalin via <em>Salin ke Live</em>.
                </span>
              </div>
              <ActionTooltip
                label="Kembali ke Live Mode"
                description="Menampilkan data nyata server tanpa data simulasi latihan."
                scope="Data Real"
                side="bottom"
              >
                <button
                  type="button"
                  onClick={() => handleSwitchMode('LIVE')}
                  className="px-2.5 py-1 text-[11px] font-medium bg-zinc-950 hover:bg-zinc-900 text-emerald-300 border border-emerald-500/40 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Beralih ke Live Mode
                </button>
              </ActionTooltip>
            </div>
          )}

          {/* Main Viewport — Expands to Full Monitor Width when Sidebar Hidden */}
          <main
            className={`flex-1 p-4 sm:p-6 w-full mx-auto space-y-5 transition-all ${
              desktopSidebarOpen ? 'max-w-[1640px]' : 'max-w-full'
            }`}
          >
          {activeView === 'overview' && (
            <>
              {/* 4-Column 100% Real Measured KPI Strip */}
              <section
                aria-label="Live Portal Security KPIs"
                className="grid grid-cols-2 xl:grid-cols-4 divide-y xl:divide-y-0 xl:divide-x divide-zinc-800/80 bg-zinc-900/40 border border-zinc-800/80 rounded-lg"
              >
                <div className="p-4">
                  <p className="text-xs text-zinc-400">Primary Portal Status</p>
                  <div className="mt-1.5 flex items-baseline gap-2.5 font-mono tabular-nums">
                    <span
                      className={`text-2xl font-semibold ${
                        primaryEndpoint?.status === 'UP'
                          ? 'text-emerald-400'
                          : primaryEndpoint?.status === 'DOWN'
                          ? 'text-rose-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {primaryEndpoint?.httpStatus
                        ? `HTTP ${primaryEndpoint.httpStatus}`
                        : primaryEndpoint?.status ?? 'PROBING'}
                    </span>
                    <span className="text-xs text-zinc-400">
                      {primaryEndpoint
                        ? `${primaryEndpoint.uptimePercent.toFixed(1)}% Up`
                        : ''}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] font-mono text-zinc-500 truncate">
                    {primaryEndpoint?.hostname ?? PRIMARY_PORTAL_HOST}
                  </p>
                </div>

                <div className="p-4">
                  <p className="text-xs text-zinc-400">Live Response Latency</p>
                  <div className="mt-1.5 flex items-baseline gap-2 font-mono tabular-nums">
                    <span className="text-2xl font-semibold text-zinc-100">
                      {primaryEndpoint?.latencyMs !== null &&
                      primaryEndpoint?.latencyMs !== undefined
                        ? `${primaryEndpoint.latencyMs} ms`
                        : '—'}
                    </span>
                    <span className="text-xs text-zinc-500">
                      ({primaryEndpoint?.totalChecks ?? 0} checks)
                    </span>
                  </div>
                  {isDemo && (
                    <p className="mt-1 text-[11px] text-amber-400/90">
                      Simulasi lonjakan latensi untuk latihan triage
                    </p>
                  )}
                </div>

                <div className="p-4">
                  <p className="text-xs text-zinc-400">TLS &amp; Header Posture</p>
                  <div className="mt-1.5 flex items-baseline gap-2.5 font-mono tabular-nums">
                    <span
                      className={`text-2xl font-semibold ${
                        (primaryEndpoint?.headerScore ?? 0) >= 80
                          ? 'text-emerald-400'
                          : 'text-amber-400'
                      }`}
                    >
                      {primaryEndpoint ? `${primaryEndpoint.headerScore}%` : '—'}
                    </span>
                    <span className="text-xs text-zinc-400">
                      {primaryEndpoint?.tls?.protocol ?? 'TLS'} ·{' '}
                      {primaryEndpoint?.tls?.daysRemaining ?? '-'}d left
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-zinc-500 truncate">
                    CA: {primaryEndpoint?.tls?.issuer ?? 'Inspecting...'}
                  </p>
                </div>

                <div className="p-4">
                  <p className="text-xs text-zinc-400">Verified Security Findings</p>
                  <div className="mt-1.5 flex items-baseline gap-2.5 font-mono tabular-nums">
                    <span
                      className={`text-2xl font-semibold ${
                        highOrCriticalFindings > 0
                          ? 'text-orange-400'
                          : openFindingsCount > 0
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {openFindingsCount}
                    </span>
                    <ActionTooltip
                      label="Buka Audit DNS & Anti-Spoofing"
                      description="Periksa detail SPF, DMARC, dan CAA domain resmi."
                      scope="Navigasi"
                    >
                      <button
                        type="button"
                        onClick={() => setActiveView('dns-audit')}
                        className="text-xs font-sans text-zinc-400 hover:text-zinc-200 underline underline-offset-2 cursor-pointer"
                      >
                        DNS Score {activeDnsAudit ? `${activeDnsAudit.score}/100` : '...'}
                      </button>
                    </ActionTooltip>
                  </div>
                  {isDemo && (
                    <p className="mt-1 text-[11px] text-amber-400/90">
                      Termasuk simulasi temuan SLOT777 &amp; DMARC p=none
                    </p>
                  )}
                </div>
              </section>

              {/* HERO CENTERPIECE: Full-Width Interactive Zoomable Global Threat & Infrastructure Map */}
              <section aria-label="Global Cyber Threat Radar Map">
                <RealInfrastructureMap
                  endpoints={activeEndpoints}
                  threatIntel={activeThreatIntel}
                  probeOriginLabel={activeProbeOriginLabel}
                />
              </section>

              {/* 24-Hour Interactive Horizontal Security Incident Timeline */}
              <IncidentTimeline24h
                findings={activeFindings}
                localWazuh={activeLocalWazuh}
                ingestedSiemEvents={activeIngestedSiemEvents}
                probeLogs={activeProbeLogs}
                threatIntel={activeThreatIntel}
                incidentReports={activeIncidentReports}
                onNavigateView={setActiveView}
              />

              {/* Telemetry Split: Live Latency Time-Series (7 cols) + Live Monitored Endpoints (5 cols) */}
              <section className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch">
                <div className="xl:col-span-7">
                  <RealLatencyChart
                    latencyHistory={activeLatencyHistory}
                    probeIntervalMs={activeProbeIntervalMs}
                  />
                </div>
                <div className="xl:col-span-5">
                  <RealEndpointsPanel
                    endpoints={activeEndpoints}
                    onAddEndpoint={handleAddEndpoint}
                    onRemoveEndpoint={handleRemoveEndpoint}
                    onInspectHeaders={() => setActiveView('headers-tls')}
                  />
                </div>
              </section>

              {/* Verified Live Security Findings */}
              <section>
                <RealFindingsView
                  findings={activeFindings}
                  ingestedSiemEvents={activeIngestedSiemEvents}
                  compact
                  onUpdateStatus={(id, st) =>
                    void handleUpdateFindingStatus(id, st)
                  }
                  onViewAll={() => setActiveView('findings')}
                />
              </section>
              {/* Global Open CTI Live Pulse Strip (Zero-Account Public Feeds) */}
              <section className="bg-zinc-900/40 border border-zinc-800/80 rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Radar className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div>
                      <h2 className="text-sm font-semibold text-zinc-100">
                        Global Open Threat Intelligence Pulse
                      </h2>
                      {isDemo && (
                        <p className="text-xs text-zinc-400">
                          Sumber intelijen siber terbuka global: CISA KEV, abuse.ch Feodo, EmergingThreats, CertSpotter CT, Ransomware.live, OpenPhish &amp; APNIC RDAP
                        </p>
                      )}
                    </div>
                  </div>
                  <ActionTooltip
                    label="Buka Global Threat Intel"
                    description="Lihat daftar lengkap CISA KEV, Botnet C2, OpenPhish, & reputasi IP server."
                    scope="Navigasi"
                  >
                    <button
                      type="button"
                      onClick={() => setActiveView('threat-intel')}
                      className="text-xs font-medium text-emerald-400 hover:text-emerald-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Open Global Threat Intel →
                    </button>
                  </ActionTooltip>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-zinc-800/80">
                  <div className="p-4">
                    <p className="text-[11px] text-zinc-400">
                      CISA KEV (Exploited CVEs)
                    </p>
                    <p className="mt-1 font-mono text-lg font-semibold text-rose-400 tabular-nums">
                      {activeThreatIntel
                        ? activeThreatIntel.cisaKev.totalCount.toLocaleString('id-ID')
                        : '...'}
                    </p>
                    <p className="mt-0.5 text-[11px] font-mono text-zinc-500 truncate">
                      {activeThreatIntel?.cisaKev.recent[0]
                        ? `Latest: ${activeThreatIntel.cisaKev.recent[0].cveID} (${activeThreatIntel.cisaKev.recent[0].vendorProject})`
                        : 'Fetching CISA catalog...'}
                    </p>
                  </div>

                  <div className="p-4">
                    <p className="text-[11px] text-zinc-400">
                      Botnet C2 &amp; Compromised IPs
                    </p>
                    <p className="mt-1 font-mono text-lg font-semibold text-amber-400 tabular-nums">
                      {activeThreatIntel
                        ? (
                            activeThreatIntel.botnetC2.feodoTotal +
                            activeThreatIntel.botnetC2.etCompromisedTotal
                          ).toLocaleString('id-ID')
                        : '...'}
                    </p>
                    <p className="mt-0.5 text-[11px] font-mono text-zinc-500 truncate">
                      abuse.ch Feodo + EmergingThreats
                    </p>
                  </div>

                  <div className="p-4">
                    <p className="text-[11px] text-zinc-400">
                      Cert Transparency &amp; OpenPhish
                    </p>
                    <p className="mt-1 font-mono text-lg font-semibold text-zinc-100 tabular-nums">
                      {activeThreatIntel
                        ? `${activeThreatIntel.certTransparency.totalEntries} CT · ${activeThreatIntel.openPhish.totalActiveUrls} Phish`
                        : '...'}
                    </p>
                    <p className="mt-0.5 text-[11px] font-mono text-zinc-500 truncate">
                      {activeThreatIntel
                        ? `ID/Brand Phish Hits: ${activeThreatIntel.openPhish.brandOrIndonesiaMatches.length}`
                        : 'Scanning target CT logs...'}
                    </p>
                  </div>

                  <div className="p-4">
                    <p className="text-[11px] text-zinc-400">
                      Endpoint IP &amp; BGP Blocklist Check
                    </p>
                    <div className="mt-1 flex items-center gap-1.5 font-mono text-lg font-semibold">
                      {activeThreatIntel &&
                      activeThreatIntel.ipReputation.every(
                        (r) => !r.listedInThreatFeeds
                      ) ? (
                        <>
                          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                          <span className="text-emerald-400">ALL CLEAN</span>
                        </>
                      ) : activeThreatIntel ? (
                        <span className="text-rose-400">CHECK ALERT</span>
                      ) : (
                        <span className="text-zinc-400">...</span>
                      )}
                    </div>
                    <p className="mt-0.5 text-[11px] font-mono text-zinc-500 truncate">
                      {activeThreatIntel?.ipReputation[0]
                        ? `${activeThreatIntel.ipReputation[0].ip} · ${
                            activeThreatIntel.ipReputation[0].netName ?? 'APNIC'
                          } (${activeThreatIntel.ipReputation[0].asn ?? 'BGP'})`
                        : 'Verifying APNIC RDAP & BGP...'}
                    </p>
                  </div>
                </div>
              </section>
            </>
          )}

          {activeView === 'action-advisor' && (
            <ActionAdvisorView
              endpoints={activeEndpoints}
              dnsAudit={activeDnsAudit}
              findings={activeFindings}
              contentScans={activeContentScans}
              incidentReports={activeIncidentReports}
              localWazuh={activeLocalWazuh}
              threatIntel={activeThreatIntel}
              scanningNow={scanningNow}
              onRunLiveScan={handleRunLiveScan}
              onCreateIncident={handleCreateIncident}
              onNavigateView={setActiveView}
            />
          )}

          {activeView === 'playbooks' && (
            <PlaybookIntegrationView
              threatIntelAlerts={activeThreatIntelAlerts}
              ingestedSiemEvents={activeIngestedSiemEvents}
              onRunPlaybook={handleRunPlaybook}
              onMitigateAttackEvent={handleMitigateAttackEvent}
              onPushSiemTestEvent={handlePushSiemTestEvent}
              onCopyToLive={(draft) => setCopyToLiveDraft(draft)}
            />
          )}

          {activeView === 'service-health' && (
            <ServiceHealthSupportView
              endpoints={activeEndpoints}
              contentScans={activeContentScans}
              findings={activeFindings}
              incidentReports={activeIncidentReports}
              localWazuh={activeLocalWazuh}
              ingestedSiemEvents={activeIngestedSiemEvents}
              scanningNow={scanningNow}
              onRunLiveScan={handleRunLiveScan}
              onNavigateView={setActiveView}
            />
          )}

          {activeView === 'executive-report' && (
            <ExecutiveReportView
              endpoints={activeEndpoints}
              dnsAudit={activeDnsAudit}
              threatIntel={activeThreatIntel}
              localWazuh={activeLocalWazuh}
              findings={activeFindings}
              incidentReports={activeIncidentReports}
              contentScans={activeContentScans}
              onOpenIncidentReports={() => setActiveView('incident-reports')}
            />
          )}

          {activeView === 'incident-reports' && (
            <IncidentReportsView
              incidentReports={activeIncidentReports}
              contentScans={activeContentScans}
              endpoints={activeEndpoints}
              scanningContent={scanningContent}
              onScanContent={handleScanContent}
              onAcceptContentBaseline={handleAcceptContentBaseline}
              onCreateIncident={handleCreateIncident}
              onUpdateIncident={handleUpdateIncident}
              onDeleteIncident={handleDeleteIncident}
              onOpenBoardReport={() => setActiveView('executive-report')}
              onCopyToLive={(draft) => setCopyToLiveDraft(draft)}
            />
          )}

          {activeView === 'wazuh-dashboard' && (
            <LocalWazuhDashboardView
              localWazuh={activeLocalWazuh}
              scanning={scanningLocal}
              onRunScan={() => void handleRunLocalScan()}
              onAcceptBaseline={() => void handleAcceptFimBaseline()}
              onOpenConfig={() => setActiveView('local-config')}
            />
          )}

          {activeView === 'local-config' && (
            <LocalConfigView
              config={activeLocalWazuh?.config ?? null}
              saving={savingLocalConfig}
              onSaveConfig={handleSaveLocalConfig}
              onVerifyPath={handleVerifyLocalPath}
              onBackToWazuh={() => setActiveView('wazuh-dashboard')}
            />
          )}

          {activeView === 'threat-intel' && (
            <RealThreatIntelView
              threatIntel={activeThreatIntel}
              syncing={syncingCti}
              onSyncNow={() => void handleSyncCtiNow()}
            />
          )}

          {activeView === 'headers-tls' && (
            <RealHeadersTlsView endpoints={activeEndpoints} />
          )}

          {activeView === 'dns-audit' && (
            <RealDnsAuditView dnsAudit={activeDnsAudit} endpoints={activeEndpoints} />
          )}

          {activeView === 'findings' && (
            <RealFindingsView
              findings={activeFindings}
              ingestedSiemEvents={activeIngestedSiemEvents}
              onUpdateStatus={(id, st) => void handleUpdateFindingStatus(id, st)}
              onMitigateEvent={handleMitigateAttackEvent}
            />
          )}

          {activeView === 'academy' && (
            <CyberAcademyView
              knowledge={activeKnowledge}
              endpoints={activeEndpoints}
              dnsAudit={activeDnsAudit}
              threatIntel={activeThreatIntel}
              localWazuh={activeLocalWazuh}
              updating={updatingKnowledge}
              onUpdateKnowledge={() => void handleUpdateKnowledge()}
              onAddCustomTerm={handleAddCustomTerm}
            />
          )}

          {activeView === 'audit' && (
            <RealAuditLogView
              probeLogs={activeProbeLogs}
              findings={activeFindings}
              probeIntervalMs={activeProbeIntervalMs}
              connectedAnalysts={activeConnectedAnalysts}
              onUpdateInterval={(ms) => void handleUpdateInterval(ms)}
              onExportComplianceJson={handleExportComplianceJson}
            />
          )}
        </main>
      </div>

      {/* Copy Demo Practice Result to Live Incident Reports Modal */}
      <CopyToLiveModal
        draft={copyToLiveDraft}
        submitting={copyingToLive}
        onCancel={() => setCopyToLiveDraft(null)}
        onConfirm={handleConfirmCopyToLive}
      />

      {/* Transient Notification Toast */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          className="fixed bottom-5 right-5 z-50 max-w-sm bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-3 shadow-lg flex items-start gap-3"
        >
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <p className="text-xs font-semibold text-zinc-100">{toast.title}</p>
            <p className="text-[11px] text-zinc-400 mt-0.5 leading-snug">
              {toast.detail}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setToast(null)}
            aria-label="Dismiss notification"
            className="text-zinc-500 hover:text-zinc-200 p-0.5 cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
    </SocModeProvider>
  );
}
