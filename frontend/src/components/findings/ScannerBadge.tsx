import { clsx } from 'clsx'
import type { ScannerType } from '../../types'

const SCANNER_COLORS: Record<ScannerType | string, string> = {
  SEMGREP:  'bg-emerald-900/40 text-emerald-400 border-emerald-800/40',
  ZAP:      'bg-blue-900/40 text-blue-400 border-blue-800/40',
  SNYK:     'bg-purple-900/40 text-purple-400 border-purple-800/40',
  TRIVY:    'bg-cyan-900/40 text-cyan-400 border-cyan-800/40',
  BANDIT:   'bg-amber-900/40 text-amber-400 border-amber-800/40',
  GRYPE:    'bg-pink-900/40 text-pink-400 border-pink-800/40',
  CHECKOV:  'bg-indigo-900/40 text-indigo-400 border-indigo-800/40',
}

interface Props {
  scanner: string
}

export default function ScannerBadge({ scanner }: Props) {
  const colorClass = SCANNER_COLORS[scanner.toUpperCase()] || 'bg-slate-800/60 text-slate-400 border-slate-700/40'
  return (
    <span className={clsx('nyx-badge border', colorClass)}>
      {scanner}
    </span>
  )
}
