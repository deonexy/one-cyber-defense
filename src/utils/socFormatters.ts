import {
  AttackAction,
  FinancialAnomalyStatus,
  ServiceStatus,
  Severity,
  ThreatIntelCategory,
  ThreatIntelStatus,
} from '../types/soc';

export function formatTimeWIB(isoString: string): string {
  try {
    const date = new Date(isoString);
    return (
      date.toLocaleTimeString('id-ID', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      }) + ' WIB'
    );
  } catch {
    return isoString;
  }
}

export function formatShortDateTime(isoString: string): string {
  try {
    const date = new Date(isoString);
    const day = date.toLocaleDateString('id-ID', {
      day: '2-digit',
      month: 'short',
    });
    const time = date.toLocaleTimeString('id-ID', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
    return `${day} ${time}`;
  } catch {
    return isoString;
  }
}

export function getSeverityColor(severity: Severity): {
  text: string;
  hex: string;
  barBg: string;
  label: string;
} {
  switch (severity) {
    case 'CRITICAL':
      return {
        text: 'text-rose-400',
        hex: '#f43f5e',
        barBg: 'bg-rose-500',
        label: 'CRITICAL',
      };
    case 'HIGH':
      return {
        text: 'text-orange-400',
        hex: '#f97316',
        barBg: 'bg-orange-500',
        label: 'HIGH',
      };
    case 'MEDIUM':
      return {
        text: 'text-amber-400',
        hex: '#f59e0b',
        barBg: 'bg-amber-500',
        label: 'MEDIUM',
      };
    case 'LOW':
    default:
      return {
        text: 'text-emerald-400',
        hex: '#10b981',
        barBg: 'bg-emerald-500',
        label: 'LOW',
      };
  }
}

export function getActionColor(action: AttackAction): {
  text: string;
  label: string;
} {
  switch (action) {
    case 'MITIGATED':
      return { text: 'text-emerald-400', label: 'Mitigated' };
    case 'BLOCKED_BY_WAF':
      return { text: 'text-emerald-300', label: 'Blocked by WAF' };
    case 'CHALLENGED':
      return { text: 'text-amber-400', label: 'Challenged' };
    case 'DETECTED':
    default:
      return { text: 'text-rose-400', label: 'Detected (Open)' };
  }
}

export function getServiceStatusMeta(status: ServiceStatus): {
  text: string;
  label: string;
  indicatorHex: string;
} {
  switch (status) {
    case 'UNDER_ATTACK':
      return {
        text: 'text-rose-400',
        label: 'Under Attack',
        indicatorHex: '#f43f5e',
      };
    case 'DEGRADED':
      return {
        text: 'text-amber-400',
        label: 'Degraded',
        indicatorHex: '#f59e0b',
      };
    case 'OPERATIONAL':
    default:
      return {
        text: 'text-emerald-400',
        label: 'Operational',
        indicatorHex: '#10b981',
      };
  }
}

export function getIntelStatusMeta(status: ThreatIntelStatus): {
  text: string;
  label: string;
} {
  switch (status) {
    case 'MITIGATED':
      return { text: 'text-emerald-400', label: 'Mitigated' };
    case 'FALSE_POSITIVE':
      return { text: 'text-zinc-400', label: 'False Positive' };
    case 'OPEN':
    default:
      return { text: 'text-rose-400', label: 'Open Alert' };
  }
}

export function getIntelCategoryLabel(category: ThreatIntelCategory): string {
  switch (category) {
    case 'CREDENTIAL_LEAK':
      return 'Credential Leak';
    case 'PHISHING_DOMAIN':
      return 'Phishing Domain';
    case 'ZERO_DAY_CVE':
      return 'Zero-Day CVE';
  }
}

export function getFinancialStatusMeta(status: FinancialAnomalyStatus): {
  text: string;
  label: string;
} {
  switch (status) {
    case 'PENDING_APPROVAL_LOCK':
      return { text: 'text-orange-400', label: 'Pending Lock' };
    case 'FROZEN':
      return { text: 'text-rose-400', label: 'Frozen / Locked' };
    case 'CLEARED':
    default:
      return { text: 'text-emerald-400', label: 'Cleared' };
  }
}

export const COUNTRY_NAMES: Record<string, string> = {
  RU: 'Russia',
  CN: 'China',
  US: 'United States',
  NL: 'Netherlands',
  DE: 'Germany',
  SG: 'Singapore',
  VN: 'Vietnam',
  BR: 'Brazil',
  UA: 'Ukraine',
  ID: 'Indonesia',
  KR: 'South Korea',
  TR: 'Turkey',
  GB: 'United Kingdom',
  FR: 'France',
  HK: 'Hong Kong',
};

export function triggerFileDownload(
  content: string,
  filename: string,
  mimeType: string
): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

function escapeCsvCell(value: unknown): string {
  if (value === null || value === undefined) {
    return '""';
  }
  const raw =
    typeof value === 'object' ? JSON.stringify(value) : String(value);
  return `"${raw.replace(/"/g, '""')}"`;
}

export function exportToCSV<T extends object>(
  data: readonly T[],
  filename: string
): void {
  if (!data || data.length === 0) {
    return;
  }

  const headerSet = new Set<string>();
  data.forEach((row) => {
    Object.keys(row).forEach((key) => headerSet.add(key));
  });
  const headers = Array.from(headerSet);

  const headerLine = headers.map((h) => escapeCsvCell(h)).join(',');
  const dataLines = data.map((row) => {
    const record = row as Record<string, unknown>;
    return headers.map((key) => escapeCsvCell(record[key])).join(',');
  });

  const csvContent = '\uFEFF' + [headerLine, ...dataLines].join('\r\n');
  const safeFilename = filename.toLowerCase().endsWith('.csv')
    ? filename
    : `${filename}.csv`;

  triggerFileDownload(csvContent, safeFilename, 'text/csv;charset=utf-8;');
}

