import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  FimEntry,
  LocalAgentConfig,
  LocalHostMetrics,
  LocalListeningPort,
  LocalLogSourceConfig,
  LocalLogSourceStatus,
  LocalSecurityAlert,
  LocalWazuhSnapshot,
  ScaCheckResult,
  Severity,
} from '../src/types/soc.ts';

const CONFIG_FILE_NAME = 'soc-local-config.json';
const MAX_FIM_FILE_BYTES = 2 * 1024 * 1024; // 2 MB cap for safe hashing
const MAX_LOG_TAIL_BYTES = 64 * 1024; // 64 KB tail scan per log source

function sanitizePathString(raw: string): string {
  return raw.replace(/\0/g, '').trim();
}

function levelToSeverity(level: number): Severity {
  if (level >= 12) return 'CRITICAL';
  if (level >= 9) return 'HIGH';
  if (level >= 6) return 'MEDIUM';
  return 'LOW';
}

function formatOctalMode(mode: number): string {
  return `0${(mode & 0o777).toString(8)}`;
}

function createDefaultLocalConfig(rootDir: string): LocalAgentConfig {
  return {
    agentName: `soc-local-${os.hostname().slice(0, 24)}`,
    clusterGroup: 'Primary-SOC-Cluster',
    environment: 'LOCAL_DEV',
    scanIntervalSec: 30,
    alertLevelThreshold: 5,
    bruteForceThreshold: 5,
    bruteForceWindowSec: 60,
    allowedListeningPorts: [80, 443, 3000],
    activeResponseMode: 'MONITOR_ONLY',
    webhookUrl: '',
    fimPaths: [
      '/etc/passwd',
      '/etc/hosts',
      '/etc/ssh/sshd_config',
      path.join(rootDir, 'package.json'),
      path.join(rootDir, 'server.ts'),
      path.join(rootDir, '.env.example'),
    ],
    logSources: [
      {
        id: 'log-auth',
        label: 'Linux SSH & PAM Auth Log',
        path: '/var/log/auth.log',
        format: 'auth',
        enabled: true,
      },
      {
        id: 'log-syslog',
        label: 'Linux System Log',
        path: '/var/log/syslog',
        format: 'syslog',
        enabled: true,
      },
      {
        id: 'log-nginx-access',
        label: 'Nginx Portal Access Log',
        path: '/var/log/nginx/access.log',
        format: 'nginx',
        enabled: true,
      },
      {
        id: 'log-nginx-error',
        label: 'Nginx Portal Error Log',
        path: '/var/log/nginx/error.log',
        format: 'nginx',
        enabled: true,
      },
    ],
    enabledRules: {
      sshBruteForce: true,
      webSqlInjection: true,
      webXssAndTraversal: true,
      fimIntegrityChange: true,
      unexpectedOpenPort: true,
    },
  };
}

function parseProcHexIpv4(hexIp: string): string {
  if (hexIp.length !== 8) return hexIp;
  const parts: number[] = [];
  for (let i = 6; i >= 0; i -= 2) {
    parts.push(parseInt(hexIp.slice(i, i + 2), 16));
  }
  return parts.join('.');
}

function parseProcTcpFile(
  filePath: string,
  protocol: 'TCP' | 'TCP6',
  allowedPorts: Set<number>
): { listening: LocalListeningPort[]; establishedCount: number } {
  const listening: LocalListeningPort[] = [];
  let establishedCount = 0;

  try {
    if (!fs.existsSync(filePath)) {
      return { listening, establishedCount };
    }
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n').slice(1);
    const seenListen = new Set<string>();

    for (const line of lines) {
      const cols = line.trim().split(/\s+/);
      if (cols.length < 4) continue;
      const [localHex, remoteHex, stateHex] = [cols[1], cols[2], cols[3]];
      const [lIpHex, lPortHex] = localHex.split(':');
      const [rIpHex, rPortHex] = remoteHex.split(':');
      const localPort = parseInt(lPortHex, 16);
      const remotePort = parseInt(rPortHex, 16);

      if (stateHex === '0A') {
        // TCP_LISTEN
        const localAddr =
          protocol === 'TCP'
            ? parseProcHexIpv4(lIpHex)
            : lIpHex === '00000000000000000000000000000000'
            ? '::'
            : lIpHex === '00000000000000000000000001000000'
            ? '::1'
            : '::*';
        const dedupKey = `${protocol}:${localAddr}:${localPort}`;
        if (!seenListen.has(dedupKey)) {
          seenListen.add(dedupKey);
          listening.push({
            protocol,
            localAddress: localAddr,
            port: localPort,
            state: 'LISTEN',
            remoteAddress: null,
            remotePort: null,
            isAllowed: allowedPorts.has(localPort),
          });
        }
      } else if (stateHex === '01') {
        // TCP_ESTABLISHED
        establishedCount += 1;
        if (listening.length < 40 && rIpHex && remotePort > 0) {
          // Keep established count accurate; only list listening ports in listening array
        }
      }
    }
  } catch {
    // Non-Linux or restricted /proc
  }

  return { listening, establishedCount };
}

function collectRealHostMetrics(): LocalHostMetrics {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = Math.max(0, totalMem - freeMem);
  const [l1, l5, l15] = os.loadavg();
  const nets = os.networkInterfaces();
  const interfaces: LocalHostMetrics['interfaces'] = [];

  for (const [name, list] of Object.entries(nets)) {
    if (!list) continue;
    for (const item of list) {
      if (item.family === 'IPv4' || !item.internal) {
        interfaces.push({
          name,
          address: item.address,
          family: String(item.family),
          mac: item.mac,
        });
      }
    }
  }

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    osRelease: os.release(),
    arch: os.arch(),
    cpuModel: cpus[0]?.model?.trim() || 'Unknown CPU',
    cpuCores: cpus.length,
    loadAvg1m: Number(l1.toFixed(2)),
    loadAvg5m: Number(l5.toFixed(2)),
    loadAvg15m: Number(l15.toFixed(2)),
    memTotalMb: Math.round(totalMem / (1024 * 1024)),
    memUsedMb: Math.round(usedMem / (1024 * 1024)),
    memUsagePercent:
      totalMem > 0 ? Math.round((usedMem / totalMem) * 100) : 0,
    uptimeSeconds: Math.floor(os.uptime()),
    nodeVersion: process.version,
    processUid: typeof process.getuid === 'function' ? process.getuid() : null,
    interfaces: interfaces.slice(0, 8),
  };
}

function readSysctlSafe(procPath: string): string | null {
  try {
    return fs.readFileSync(procPath, 'utf8').trim();
  } catch {
    return null;
  }
}

function runRealScaChecks(
  rootDir: string,
  listeningPorts: LocalListeningPort[]
): ScaCheckResult[] {
  const checks: ScaCheckResult[] = [];

  // 1. /etc/passwd permissions (CIS 6.1.2)
  try {
    const st = fs.statSync('/etc/passwd');
    const perms = st.mode & 0o777;
    const pass = (perms & 0o133) === 0; // <= 0644
    checks.push({
      id: 'SCA-CIS-6.1.2',
      cisControl: 'CIS 6.1.2',
      title: 'Permissions pada /etc/passwd harus <= 0644',
      category: 'FILESYSTEM',
      status: pass ? 'PASS' : 'FAIL',
      severity: 'HIGH',
      evidence: `Live stat /etc/passwd mode=${formatOctalMode(st.mode)}`,
      remediation: 'Jalankan: chmod 644 /etc/passwd && chown root:root /etc/passwd',
    });
  } catch {
    checks.push({
      id: 'SCA-CIS-6.1.2',
      cisControl: 'CIS 6.1.2',
      title: 'Permissions pada /etc/passwd harus <= 0644',
      category: 'FILESYSTEM',
      status: 'NOT_APPLICABLE',
      severity: 'HIGH',
      evidence: '/etc/passwd tidak ditemukan pada OS host ini',
      remediation: 'Verifikasi integritas file akun lokal OS.',
    });
  }

  // 2. /etc/shadow permissions (CIS 6.1.3)
  try {
    const st = fs.statSync('/etc/shadow');
    const perms = st.mode & 0o777;
    const worldReadable = (perms & 0o007) !== 0;
    checks.push({
      id: 'SCA-CIS-6.1.3',
      cisControl: 'CIS 6.1.3',
      title: 'File /etc/shadow tidak boleh world-readable',
      category: 'FILESYSTEM',
      status: !worldReadable ? 'PASS' : 'FAIL',
      severity: 'CRITICAL',
      evidence: `Live stat /etc/shadow mode=${formatOctalMode(st.mode)}`,
      remediation: 'Jalankan: chmod 640 /etc/shadow && chown root:shadow /etc/shadow',
    });
  } catch {
    checks.push({
      id: 'SCA-CIS-6.1.3',
      cisControl: 'CIS 6.1.3',
      title: 'File /etc/shadow tidak boleh world-readable',
      category: 'FILESYSTEM',
      status: 'PASS',
      severity: 'CRITICAL',
      evidence: '/etc/shadow terproteksi (akses baca ditolak bagi proses non-privileged)',
      remediation: 'Pertahankan hak akses terbatas pada /etc/shadow.',
    });
  }

  // 3. /tmp sticky bit (CIS 1.1.21)
  try {
    const st = fs.statSync('/tmp');
    const hasSticky = (st.mode & 0o1000) !== 0;
    checks.push({
      id: 'SCA-CIS-1.1.21',
      cisControl: 'CIS 1.1.21',
      title: 'Sticky bit aktif pada direktori /tmp',
      category: 'FILESYSTEM',
      status: hasSticky ? 'PASS' : 'FAIL',
      severity: 'MEDIUM',
      evidence: `Live stat /tmp mode=0${(st.mode & 0o1777).toString(8)}`,
      remediation: 'Jalankan: chmod +t /tmp agar pengguna tidak dapat menghapus file milik pengguna lain.',
    });
  } catch {
    checks.push({
      id: 'SCA-CIS-1.1.21',
      cisControl: 'CIS 1.1.21',
      title: 'Sticky bit aktif pada direktori /tmp',
      category: 'FILESYSTEM',
      status: 'NOT_APPLICABLE',
      severity: 'MEDIUM',
      evidence: '/tmp tidak tersedia pada sistem ini',
      remediation: 'Pastikan direktori temp memiliki isolasi izin yang tepat.',
    });
  }

  // 4. Kernel IPv4 Forwarding disabled (CIS 3.1.1)
  const ipForward = readSysctlSafe('/proc/sys/net/ipv4/ip_forward');
  checks.push({
    id: 'SCA-CIS-3.1.1',
    cisControl: 'CIS 3.1.1',
    title: 'IPv4 Packet Forwarding dinonaktifkan pada server aplikasi',
    category: 'NETWORK',
    status:
      ipForward === null
        ? 'NOT_APPLICABLE'
        : ipForward === '0'
        ? 'PASS'
        : 'FAIL',
    severity: 'MEDIUM',
    evidence:
      ipForward === null
        ? '/proc/sys/net/ipv4/ip_forward tidak dapat dibaca'
        : `net.ipv4.ip_forward = ${ipForward}`,
    remediation: 'Set net.ipv4.ip_forward = 0 pada /etc/sysctl.conf lalu sysctl -p.',
  });

  // 5. TCP SYN Cookies enabled (CIS 3.2.8 - Anti SYN Flood)
  const synCookies = readSysctlSafe('/proc/sys/net/ipv4/tcp_syncookies');
  checks.push({
    id: 'SCA-CIS-3.2.8',
    cisControl: 'CIS 3.2.8',
    title: 'Proteksi TCP SYN Cookies aktif (Mitigasi SYN Flood DDoS)',
    category: 'NETWORK',
    status:
      synCookies === null
        ? 'NOT_APPLICABLE'
        : synCookies === '1'
        ? 'PASS'
        : 'FAIL',
    severity: 'HIGH',
    evidence:
      synCookies === null
        ? '/proc/sys/net/ipv4/tcp_syncookies tidak dapat dibaca'
        : `net.ipv4.tcp_syncookies = ${synCookies}`,
    remediation: 'Aktifkan: sysctl -w net.ipv4.tcp_syncookies=1 untuk menahan serangan SYN flood.',
  });

  // 6. SSH Root Login Disabled (CIS 5.2.10)
  try {
    if (fs.existsSync('/etc/ssh/sshd_config')) {
      const sshCfg = fs.readFileSync('/etc/ssh/sshd_config', 'utf8');
      const rootNo = /^\s*PermitRootLogin\s+no\b/im.test(sshCfg);
      const passNo = /^\s*PasswordAuthentication\s+no\b/im.test(sshCfg);
      checks.push({
        id: 'SCA-CIS-5.2.10',
        cisControl: 'CIS 5.2.10',
        title: 'SSH PermitRootLogin dinonaktifkan',
        category: 'AUTH_SSH',
        status: rootNo ? 'PASS' : 'FAIL',
        severity: 'HIGH',
        evidence: rootNo
          ? '/etc/ssh/sshd_config memuat PermitRootLogin no'
          : 'PermitRootLogin no tidak ditemukan secara eksplisit di /etc/ssh/sshd_config',
        remediation: 'Tambahkan PermitRootLogin no pada /etc/ssh/sshd_config lalu reload sshd.',
      });
      checks.push({
        id: 'SCA-CIS-5.2.12',
        cisControl: 'CIS 5.2.12',
        title: 'SSH Autentikasi Berbasis Kunci (PasswordAuthentication no)',
        category: 'AUTH_SSH',
        status: passNo ? 'PASS' : 'FAIL',
        severity: 'MEDIUM',
        evidence: passNo
          ? '/etc/ssh/sshd_config memuat PasswordAuthentication no'
          : 'PasswordAuthentication masih default/aktif pada /etc/ssh/sshd_config',
        remediation: 'Gunakan SSH key + MFA bastion dan set PasswordAuthentication no.',
      });
    } else {
      checks.push({
        id: 'SCA-CIS-5.2.10',
        cisControl: 'CIS 5.2.10',
        title: 'SSH Hardening (/etc/ssh/sshd_config)',
        category: 'AUTH_SSH',
        status: 'NOT_APPLICABLE',
        severity: 'HIGH',
        evidence: 'OpenSSH server (/etc/ssh/sshd_config) tidak terpasang pada host/container ini',
        remediation: 'Saat dipasang di VM server lokal organisasi, pastikan PermitRootLogin no dan SSH hanya lewat VPN/Bastion.',
      });
    }
  } catch {
    checks.push({
      id: 'SCA-CIS-5.2.10',
      cisControl: 'CIS 5.2.10',
      title: 'SSH Hardening (/etc/ssh/sshd_config)',
      category: 'AUTH_SSH',
      status: 'NOT_APPLICABLE',
      severity: 'HIGH',
      evidence: 'Akses baca /etc/ssh/sshd_config dibatasi oleh izin OS',
      remediation: 'Verifikasi sshd_config secara berkala sebagai administrator server.',
    });
  }

  // 7. Least Privilege Runtime (App should not run as UID 0 root)
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  checks.push({
    id: 'SCA-CIS-APP-01',
    cisControl: 'CIS App 1.1',
    title: 'Layanan SOC / Aplikasi berjalan dengan prinsip Least Privilege (non-root)',
    category: 'RUNTIME',
    status: uid === null ? 'NOT_APPLICABLE' : uid !== 0 ? 'PASS' : 'FAIL',
    severity: 'HIGH',
    evidence:
      uid === null
        ? 'UID tidak tersedia'
        : `Proses Node.js berjalan dengan UID=${uid} (${uid === 0 ? 'root' : 'non-root'})`,
    remediation: 'Jalankan service systemd sebagai dedicated user non-root (mis. User=soc-monitor) dengan read-only log group (adm).',
  });

  // 8. Local .env secret file permission hygiene
  const envPath = path.join(rootDir, '.env');
  if (fs.existsSync(envPath)) {
    try {
      const st = fs.statSync(envPath);
      const worldAccess = (st.mode & 0o007) !== 0;
      checks.push({
        id: 'SCA-CIS-APP-02',
        cisControl: 'CIS App 2.4',
        title: 'File konfigurasi .env tidak dapat dibaca publik (chmod 600/640)',
        category: 'RUNTIME',
        status: !worldAccess ? 'PASS' : 'FAIL',
        severity: 'CRITICAL',
        evidence: `Live stat .env mode=${formatOctalMode(st.mode)}`,
        remediation: 'Jalankan: chmod 600 .env agar kredensial lokal tidak terbaca user lain.',
      });
    } catch {
      // ignore
    }
  }

  // 9. Listening Ports Whitelist Compliance
  const unexpected = listeningPorts.filter((p) => !p.isAllowed);
  checks.push({
    id: 'SCA-CIS-NET-01',
    cisControl: 'CIS Net 3.4',
    title: 'Seluruh TCP Listening Port sesuai Whitelist Kebijakan Lokal',
    category: 'NETWORK',
    status: unexpected.length === 0 ? 'PASS' : 'FAIL',
    severity: unexpected.length > 0 ? 'HIGH' : 'LOW',
    evidence:
      unexpected.length === 0
        ? `${listeningPorts.length} port aktif seluruhnya masuk whitelist`
        : `${unexpected.length} port di luar whitelist: ${unexpected
            .map((u) => `${u.localAddress}:${u.port}`)
            .join(', ')}`,
    remediation: 'Tutup layanan port yang tidak diperlukan atau tambahkan port resmi pada halaman Local Agent Config.',
  });

  return checks;
}

export class LocalWazuhEngine {
  private rootDir: string;
  private configFilePath: string;
  private config: LocalAgentConfig;
  private fimBaseline = new Map<string, string>();
  private baselineEstablishedAt: string | null = null;
  private liveAlerts: LocalSecurityAlert[] = [];
  private alertSeq = 5001;
  private lastSnapshot: LocalWazuhSnapshot | null = null;

  constructor(rootDir: string) {
    this.rootDir = rootDir;
    this.configFilePath = path.join(rootDir, CONFIG_FILE_NAME);
    this.config = this.loadPersistedConfig();
  }

  private loadPersistedConfig(): LocalAgentConfig {
    const defaults = createDefaultLocalConfig(this.rootDir);
    try {
      if (fs.existsSync(this.configFilePath)) {
        const raw = fs.readFileSync(this.configFilePath, 'utf8');
        const parsed = JSON.parse(raw) as Partial<LocalAgentConfig>;
        return {
          ...defaults,
          ...parsed,
          enabledRules: {
            ...defaults.enabledRules,
            ...(parsed.enabledRules ?? {}),
          },
          allowedListeningPorts: Array.isArray(parsed.allowedListeningPorts)
            ? parsed.allowedListeningPorts.filter(
                (p) => typeof p === 'number' && p > 0 && p <= 65535
              )
            : defaults.allowedListeningPorts,
          fimPaths: Array.isArray(parsed.fimPaths)
            ? parsed.fimPaths.map(sanitizePathString).filter(Boolean).slice(0, 30)
            : defaults.fimPaths,
          logSources: Array.isArray(parsed.logSources)
            ? parsed.logSources.slice(0, 15)
            : defaults.logSources,
        };
      }
    } catch {
      // Fallback to defaults if config file is corrupted
    }
    return defaults;
  }

  getConfig(): LocalAgentConfig {
    return this.config;
  }

  getSnapshot(): LocalWazuhSnapshot | null {
    return this.lastSnapshot;
  }

  updateConfig(patch: Partial<LocalAgentConfig>): LocalAgentConfig {
    const next: LocalAgentConfig = {
      ...this.config,
      ...patch,
      agentName: String(patch.agentName ?? this.config.agentName).trim().slice(0, 64) || this.config.agentName,
      clusterGroup: String(patch.clusterGroup ?? this.config.clusterGroup).trim().slice(0, 64) || this.config.clusterGroup,
      scanIntervalSec: Math.max(
        10,
        Math.min(300, Number(patch.scanIntervalSec ?? this.config.scanIntervalSec) || 30)
      ),
      alertLevelThreshold: Math.max(
        1,
        Math.min(15, Number(patch.alertLevelThreshold ?? this.config.alertLevelThreshold) || 5)
      ),
      bruteForceThreshold: Math.max(
        2,
        Math.min(100, Number(patch.bruteForceThreshold ?? this.config.bruteForceThreshold) || 5)
      ),
      bruteForceWindowSec: Math.max(
        10,
        Math.min(3600, Number(patch.bruteForceWindowSec ?? this.config.bruteForceWindowSec) || 60)
      ),
      webhookUrl: String(patch.webhookUrl ?? this.config.webhookUrl).trim().slice(0, 300),
      allowedListeningPorts: Array.isArray(patch.allowedListeningPorts)
        ? Array.from(
            new Set(
              patch.allowedListeningPorts
                .map(Number)
                .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
            )
          ).sort((a, b) => a - b)
        : this.config.allowedListeningPorts,
      fimPaths: Array.isArray(patch.fimPaths)
        ? Array.from(
            new Set(patch.fimPaths.map(sanitizePathString).filter(Boolean))
          ).slice(0, 30)
        : this.config.fimPaths,
      logSources: Array.isArray(patch.logSources)
        ? patch.logSources.slice(0, 15).map((ls, idx) => ({
            id: ls.id || `log-${Date.now()}-${idx}`,
            label: String(ls.label || ls.path).trim().slice(0, 80),
            path: sanitizePathString(String(ls.path || '')),
            format: ls.format || 'syslog',
            enabled: Boolean(ls.enabled),
          })).filter((ls) => ls.path.length > 0)
        : this.config.logSources,
      enabledRules: {
        ...this.config.enabledRules,
        ...(patch.enabledRules ?? {}),
      },
    };

    this.config = next;
    try {
      fs.writeFileSync(
        this.configFilePath,
        JSON.stringify(this.config, null, 2),
        'utf8'
      );
    } catch {
      // Ignore write error on read-only filesystems
    }

    return this.config;
  }

  verifyPathAccess(rawPath: string): {
    path: string;
    status: 'READABLE' | 'NOT_FOUND' | 'PERMISSION_DENIED';
    sizeBytes: number | null;
    permissions: string | null;
  } {
    const clean = sanitizePathString(rawPath);
    if (!clean) {
      return { path: clean, status: 'NOT_FOUND', sizeBytes: null, permissions: null };
    }
    try {
      const st = fs.statSync(clean);
      fs.accessSync(clean, fs.constants.R_OK);
      return {
        path: clean,
        status: 'READABLE',
        sizeBytes: st.size,
        permissions: formatOctalMode(st.mode),
      };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      return {
        path: clean,
        status: code === 'EACCES' || code === 'EPERM' ? 'PERMISSION_DENIED' : 'NOT_FOUND',
        sizeBytes: null,
        permissions: null,
      };
    }
  }

  // Real-time HTTP sensor for incoming requests hitting this local Express server
  inspectIncomingHttpRequest(reqPath: string, remoteIp: string): LocalSecurityAlert | null {
    if (!this.config.enabledRules.webSqlInjection && !this.config.enabledRules.webXssAndTraversal) {
      return null;
    }
    let decoded = reqPath;
    try {
      decoded = decodeURIComponent(reqPath);
    } catch {
      // keep raw
    }

    const sqliRe = /(\bunion\b.+\bselect\b|\bor\b\s+1\s*=\s*1|'--|;\s*drop\s+table)/i;
    const traversalRe = /(\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow)/i;
    const xssRe = /(<script\b|javascript:|onerror\s*=|onload\s*=)/i;

    let alert: LocalSecurityAlert | null = null;

    if (this.config.enabledRules.webSqlInjection && sqliRe.test(decoded)) {
      alert = this.pushLiveAlert({
        rule_id: '31103',
        rule_level: 11,
        mitre_id: 'T1190',
        mitre_tactic: 'Initial Access',
        source: 'HTTP_SENSOR',
        title: 'Web SQL Injection Attempt Detected on Local Listener',
        detail: `Client ${remoteIp} sent suspicious SQLi pattern in URI`,
        target: decoded.slice(0, 140),
      });
    } else if (this.config.enabledRules.webXssAndTraversal && traversalRe.test(decoded)) {
      alert = this.pushLiveAlert({
        rule_id: '31104',
        rule_level: 10,
        mitre_id: 'T1083',
        mitre_tactic: 'Discovery',
        source: 'HTTP_SENSOR',
        title: 'Directory / Path Traversal Attempt Detected on Local Listener',
        detail: `Client ${remoteIp} attempted path traversal URI`,
        target: decoded.slice(0, 140),
      });
    } else if (this.config.enabledRules.webXssAndTraversal && xssRe.test(decoded)) {
      alert = this.pushLiveAlert({
        rule_id: '31105',
        rule_level: 8,
        mitre_id: 'T1059.007',
        mitre_tactic: 'Execution',
        source: 'HTTP_SENSOR',
        title: 'Cross-Site Scripting (XSS) Probe Detected on Local Listener',
        detail: `Client ${remoteIp} sent script injection pattern`,
        target: decoded.slice(0, 140),
      });
    }

    return alert;
  }

  private pushLiveAlert(params: {
    rule_id: string;
    rule_level: number;
    mitre_id: string;
    mitre_tactic: string;
    source: LocalSecurityAlert['source'];
    title: string;
    detail: string;
    target: string;
  }): LocalSecurityAlert {
    const alert: LocalSecurityAlert = {
      alert_id: `WZH-${this.alertSeq++}`,
      timestamp: new Date().toISOString(),
      agent_name: this.config.agentName,
      severity: levelToSeverity(params.rule_level),
      ...params,
    };
    this.liveAlerts = [alert, ...this.liveAlerts].slice(0, 80);
    return alert;
  }

  acceptCurrentFimBaseline(): LocalWazuhSnapshot {
    this.fimBaseline.clear();
    this.baselineEstablishedAt = new Date().toISOString();
    for (const filePath of this.config.fimPaths) {
      const hash = this.computeFileSha256(filePath);
      if (hash) {
        this.fimBaseline.set(filePath, hash);
      }
    }
    return this.runFullLocalScan();
  }

  private computeFileSha256(filePath: string): string | null {
    try {
      const st = fs.statSync(filePath);
      if (!st.isFile() || st.size > MAX_FIM_FILE_BYTES) return null;
      const buf = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(buf).digest('hex');
    } catch {
      return null;
    }
  }

  private scanFim(): { entries: FimEntry[]; scanAlerts: LocalSecurityAlert[] } {
    const now = new Date().toISOString();
    const isInitialBaseline = this.baselineEstablishedAt === null;
    if (isInitialBaseline) {
      this.baselineEstablishedAt = now;
    }

    const entries: FimEntry[] = [];
    const scanAlerts: LocalSecurityAlert[] = [];

    for (const filePath of this.config.fimPaths) {
      const baselineHash = this.fimBaseline.get(filePath) ?? null;
      try {
        const st = fs.statSync(filePath);
        if (!st.isFile()) {
          entries.push({
            path: filePath,
            status: 'UNREADABLE',
            sha256: null,
            baselineSha256: baselineHash,
            sizeBytes: null,
            permissions: formatOctalMode(st.mode),
            modifiedAt: st.mtime.toISOString(),
            lastCheckedAt: now,
            note: 'Target bukan regular file',
          });
          continue;
        }
        if (st.size > MAX_FIM_FILE_BYTES) {
          entries.push({
            path: filePath,
            status: 'UNREADABLE',
            sha256: null,
            baselineSha256: baselineHash,
            sizeBytes: st.size,
            permissions: formatOctalMode(st.mode),
            modifiedAt: st.mtime.toISOString(),
            lastCheckedAt: now,
            note: 'Ukuran melebihi batas aman 2 MB',
          });
          continue;
        }

        const hash = crypto
          .createHash('sha256')
          .update(fs.readFileSync(filePath))
          .digest('hex');

        if (isInitialBaseline) {
          this.fimBaseline.set(filePath, hash);
          entries.push({
            path: filePath,
            status: 'BASELINE_OK',
            sha256: hash,
            baselineSha256: hash,
            sizeBytes: st.size,
            permissions: formatOctalMode(st.mode),
            modifiedAt: st.mtime.toISOString(),
            lastCheckedAt: now,
          });
        } else if (baselineHash === null) {
          this.fimBaseline.set(filePath, hash);
          entries.push({
            path: filePath,
            status: 'ADDED',
            sha256: hash,
            baselineSha256: hash,
            sizeBytes: st.size,
            permissions: formatOctalMode(st.mode),
            modifiedAt: st.mtime.toISOString(),
            lastCheckedAt: now,
            note: 'File baru didaftarkan ke baseline FIM',
          });
        } else if (hash !== baselineHash) {
          entries.push({
            path: filePath,
            status: 'MODIFIED',
            sha256: hash,
            baselineSha256: baselineHash,
            sizeBytes: st.size,
            permissions: formatOctalMode(st.mode),
            modifiedAt: st.mtime.toISOString(),
            lastCheckedAt: now,
            note: 'Checksum SHA-256 berubah dari baseline!',
          });
          if (this.config.enabledRules.fimIntegrityChange) {
            scanAlerts.push({
              alert_id: `FIM-${crypto.createHash('md5').update(filePath).digest('hex').slice(0, 6).toUpperCase()}`,
              timestamp: now,
              rule_id: '550',
              rule_level: 12,
              severity: 'CRITICAL',
              mitre_id: 'T1565.001',
              mitre_tactic: 'Impact',
              agent_name: this.config.agentName,
              source: 'FIM',
              title: `Integrity Checksum Changed: ${path.basename(filePath)}`,
              detail: `SHA-256 berubah dari ${baselineHash.slice(0, 12)}… menjadi ${hash.slice(0, 12)}…`,
              target: filePath,
            });
          }
        } else {
          entries.push({
            path: filePath,
            status: 'BASELINE_OK',
            sha256: hash,
            baselineSha256: baselineHash,
            sizeBytes: st.size,
            permissions: formatOctalMode(st.mode),
            modifiedAt: st.mtime.toISOString(),
            lastCheckedAt: now,
          });
        }
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if (baselineHash && code === 'ENOENT') {
          entries.push({
            path: filePath,
            status: 'DELETED',
            sha256: null,
            baselineSha256: baselineHash,
            sizeBytes: null,
            permissions: null,
            modifiedAt: null,
            lastCheckedAt: now,
            note: 'File yang sebelumnya ada di baseline telah dihapus!',
          });
          if (this.config.enabledRules.fimIntegrityChange) {
            scanAlerts.push({
              alert_id: `FIM-DEL-${crypto.createHash('md5').update(filePath).digest('hex').slice(0, 5).toUpperCase()}`,
              timestamp: now,
              rule_id: '553',
              rule_level: 10,
              severity: 'HIGH',
              mitre_id: 'T1485',
              mitre_tactic: 'Impact',
              agent_name: this.config.agentName,
              source: 'FIM',
              title: `Monitored File Deleted: ${path.basename(filePath)}`,
              detail: `File ${filePath} tidak lagi ditemukan pada filesystem lokal`,
              target: filePath,
            });
          }
        } else {
          entries.push({
            path: filePath,
            status: 'UNREADABLE',
            sha256: null,
            baselineSha256: baselineHash,
            sizeBytes: null,
            permissions: null,
            modifiedAt: null,
            lastCheckedAt: now,
            note:
              code === 'EACCES' || code === 'EPERM'
                ? 'Permission denied (butuh grup adm/root)'
                : 'File belum ada di host ini',
          });
        }
      }
    }

    return { entries, scanAlerts };
  }

  private scanLocalLogs(): {
    statuses: LocalLogSourceStatus[];
    logAlerts: LocalSecurityAlert[];
  } {
    const now = new Date().toISOString();
    const statuses: LocalLogSourceStatus[] = [];
    const logAlerts: LocalSecurityAlert[] = [];

    const sshFailRe = /(Failed password|Invalid user|authentication failure)/i;
    const sqliRe = /(\bunion\b.+\bselect\b|\bor\b\s+1\s*=\s*1|sqlmap|sleep\(\d+\))/i;
    const travRe = /(\.\.\/|\/etc\/passwd|wp-login\.php|\.env\s+HTTP)/i;

    for (const src of this.config.logSources) {
      if (!src.enabled) {
        statuses.push({
          ...src,
          accessStatus: 'DISABLED',
          linesScanned: 0,
          alertsMatched: 0,
          lastScannedAt: now,
        });
        continue;
      }

      try {
        const st = fs.statSync(src.path);
        const start = Math.max(0, st.size - MAX_LOG_TAIL_BYTES);
        const fd = fs.openSync(src.path, 'r');
        const buf = Buffer.alloc(Math.min(st.size, MAX_LOG_TAIL_BYTES));
        fs.readSync(fd, buf, 0, buf.length, start);
        fs.closeSync(fd);

        const lines = buf
          .toString('utf8')
          .split(/\r?\n/)
          .filter((l) => l.trim().length > 0);

        let sshFailCount = 0;
        let matchedCount = 0;

        for (const line of lines.slice(-250)) {
          if (this.config.enabledRules.sshBruteForce && sshFailRe.test(line)) {
            sshFailCount += 1;
          }
          if (this.config.enabledRules.webSqlInjection && sqliRe.test(line)) {
            matchedCount += 1;
            if (logAlerts.length < 30) {
              logAlerts.push({
                alert_id: `LOG-SQLI-${matchedCount}`,
                timestamp: now,
                rule_id: '31103',
                rule_level: 11,
                severity: 'HIGH',
                mitre_id: 'T1190',
                mitre_tactic: 'Initial Access',
                agent_name: this.config.agentName,
                source: 'LOGCOLLECTOR',
                title: `SQL Injection Signature Matched in ${src.label}`,
                detail: line.slice(0, 160),
                target: src.path,
              });
            }
          } else if (
            this.config.enabledRules.webXssAndTraversal &&
            travRe.test(line)
          ) {
            matchedCount += 1;
            if (logAlerts.length < 30) {
              logAlerts.push({
                alert_id: `LOG-SCAN-${matchedCount}`,
                timestamp: now,
                rule_id: '31104',
                rule_level: 9,
                severity: 'HIGH',
                mitre_id: 'T1595',
                mitre_tactic: 'Reconnaissance',
                agent_name: this.config.agentName,
                source: 'LOGCOLLECTOR',
                title: `Recon / Path Traversal Probe in ${src.label}`,
                detail: line.slice(0, 160),
                target: src.path,
              });
            }
          }
        }

        if (sshFailCount >= this.config.bruteForceThreshold) {
          matchedCount += 1;
          logAlerts.push({
            alert_id: `LOG-SSH-${src.id}`,
            timestamp: now,
            rule_id: '5710',
            rule_level: 10,
            severity: 'HIGH',
            mitre_id: 'T1110',
            mitre_tactic: 'Credential Access',
            agent_name: this.config.agentName,
            source: 'LOGCOLLECTOR',
            title: `SSH Authentication Failures (${sshFailCount} events >= threshold ${this.config.bruteForceThreshold})`,
            detail: `Terdeteksi ${sshFailCount} kegagalan login pada tail ${src.path}`,
            target: src.path,
          });
        }

        statuses.push({
          ...src,
          accessStatus: 'READABLE',
          linesScanned: lines.length,
          alertsMatched: matchedCount,
          lastScannedAt: now,
        });
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        statuses.push({
          ...src,
          accessStatus:
            code === 'EACCES' || code === 'EPERM'
              ? 'PERMISSION_DENIED'
              : 'NOT_FOUND',
          linesScanned: 0,
          alertsMatched: 0,
          lastScannedAt: now,
        });
      }
    }

    return { statuses, logAlerts };
  }

  runFullLocalScan(): LocalWazuhSnapshot {
    const t0 = Date.now();
    const now = new Date().toISOString();
    const host = collectRealHostMetrics();
    const allowedSet = new Set(this.config.allowedListeningPorts);

    const tcp4 = parseProcTcpFile('/proc/net/tcp', 'TCP', allowedSet);
    const tcp6 = parseProcTcpFile('/proc/net/tcp6', 'TCP6', allowedSet);
    const listeningPorts = [...tcp4.listening, ...tcp6.listening].sort(
      (a, b) => a.port - b.port
    );
    const establishedCount = tcp4.establishedCount + tcp6.establishedCount;
    const unexpectedPorts = listeningPorts.filter((p) => !p.isAllowed);

    const { entries: fimEntries, scanAlerts: fimAlerts } = this.scanFim();
    const scaChecks = runRealScaChecks(this.rootDir, listeningPorts);
    const { statuses: logSourcesStatus, logAlerts } = this.scanLocalLogs();

    const scaAlerts: LocalSecurityAlert[] = [];
    for (const chk of scaChecks) {
      if (chk.status === 'FAIL') {
        const lvl =
          chk.severity === 'CRITICAL'
            ? 12
            : chk.severity === 'HIGH'
            ? 9
            : 6;
        scaAlerts.push({
          alert_id: `SCA-${chk.id}`,
          timestamp: now,
          rule_id: '19001',
          rule_level: lvl,
          severity: chk.severity,
          mitre_id:
            chk.category === 'NETWORK'
              ? 'T1046'
              : chk.category === 'AUTH_SSH'
              ? 'T1021.004'
              : 'T1068',
          mitre_tactic:
            chk.category === 'NETWORK'
              ? 'Discovery'
              : chk.category === 'AUTH_SSH'
              ? 'Lateral Movement'
              : 'Privilege Escalation',
          agent_name: this.config.agentName,
          source: 'SCA',
          title: `[${chk.cisControl}] ${chk.title}`,
          detail: chk.evidence,
          target: host.hostname,
        });
      }
    }

    const portAlerts: LocalSecurityAlert[] = [];
    if (this.config.enabledRules.unexpectedOpenPort) {
      for (const up of unexpectedPorts) {
        portAlerts.push({
          alert_id: `PORT-${up.protocol}-${up.port}`,
          timestamp: now,
          rule_id: '19102',
          rule_level: 9,
          severity: 'HIGH',
          mitre_id: 'T1571',
          mitre_tactic: 'Command and Control',
          agent_name: this.config.agentName,
          source: 'NET_SENSOR',
          title: `Unexpected Listening Port Detected (${up.protocol} :${up.port})`,
          detail: `Port ${up.localAddress}:${up.port} aktif namun tidak terdaftar di Allowed Ports whitelist`,
          target: `${up.localAddress}:${up.port}`,
        });
      }
    }

    const allAlerts = [
      ...this.liveAlerts,
      ...fimAlerts,
      ...logAlerts,
      ...portAlerts,
      ...scaAlerts,
    ]
      .filter((a) => a.rule_level >= this.config.alertLevelThreshold)
      .sort((a, b) => b.rule_level - a.rule_level);

    // Build real rule level histogram
    const buckets: Record<string, number> = {
      'L1–4 (Low)': 0,
      'L5–8 (Med)': 0,
      'L9–11 (High)': 0,
      'L12–15 (Crit)': 0,
    };
    const mitreMap = new Map<string, number>();

    for (const a of allAlerts) {
      if (a.rule_level >= 12) buckets['L12–15 (Crit)'] += 1;
      else if (a.rule_level >= 9) buckets['L9–11 (High)'] += 1;
      else if (a.rule_level >= 5) buckets['L5–8 (Med)'] += 1;
      else buckets['L1–4 (Low)'] += 1;

      mitreMap.set(a.mitre_tactic, (mitreMap.get(a.mitre_tactic) ?? 0) + 1);
    }

    const passed = scaChecks.filter((c) => c.status === 'PASS').length;
    const failed = scaChecks.filter((c) => c.status === 'FAIL').length;
    const notApplicable = scaChecks.filter(
      (c) => c.status === 'NOT_APPLICABLE'
    ).length;
    const applicable = passed + failed;
    const scorePercent =
      applicable > 0 ? Math.round((passed / applicable) * 100) : 100;

    const snapshot: LocalWazuhSnapshot = {
      lastScannedAt: now,
      scanDurationMs: Date.now() - t0,
      config: this.config,
      host,
      fim: {
        baselineEstablishedAt: this.baselineEstablishedAt,
        totalMonitored: fimEntries.length,
        okCount: fimEntries.filter((e) => e.status === 'BASELINE_OK').length,
        modifiedCount: fimEntries.filter(
          (e) => e.status === 'MODIFIED' || e.status === 'DELETED'
        ).length,
        unreadableCount: fimEntries.filter((e) => e.status === 'UNREADABLE')
          .length,
        entries: fimEntries,
      },
      sca: {
        scorePercent,
        passed,
        failed,
        notApplicable,
        checks: scaChecks,
      },
      network: {
        listeningPorts,
        establishedCount,
        unexpectedPortCount: unexpectedPorts.length,
      },
      logSourcesStatus,
      alerts: allAlerts,
      ruleLevelHistogram: Object.entries(buckets).map(([level, count]) => ({
        level,
        count,
      })),
      mitreBreakdown: Array.from(mitreMap.entries())
        .map(([tactic, count]) => ({ tactic, count }))
        .sort((a, b) => b.count - a.count),
    };

    this.lastSnapshot = snapshot;
    return snapshot;
  }
}
