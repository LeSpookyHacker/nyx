/** Hex color map for severity levels, used in charts and visualizations. */
export const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#64748b',
}

/** Tailwind text-color classes keyed by uppercase severity. */
export const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-blue-400',
  INFO: 'text-gray-400',
}

/** Palette for per-scanner bar/pie slices. */
export const SCANNER_COLORS = ['#7c3aed', '#6366f1', '#8b5cf6', '#a78bfa', '#4f46e5', '#818cf8', '#c4b5fd']

/** Canonical severity levels in descending order. */
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

/** All possible finding statuses. */
export const STATUSES = ['OPEN', 'IN_REMEDIATION', 'FIXED', 'SUPPRESSED', 'ACCEPTED_RISK'] as const
