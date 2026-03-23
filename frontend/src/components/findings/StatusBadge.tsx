import { clsx } from 'clsx'
import type { FindingStatus } from '../../types'

const STATUS_CONFIG: Record<FindingStatus, { label: string; className: string }> = {
  OPEN:           { label: 'Open',           className: 'bg-red-900/30 text-red-400 border-red-800/30' },
  IN_REMEDIATION: { label: 'Remediating',    className: 'bg-purple-900/30 text-purple-400 border-purple-800/30' },
  FIXED:          { label: 'Fixed',          className: 'bg-green-900/30 text-green-400 border-green-800/30' },
  SUPPRESSED:     { label: 'Suppressed',     className: 'bg-slate-800/60 text-slate-400 border-slate-700/30' },
  ACCEPTED_RISK:  { label: 'Accepted Risk',  className: 'bg-yellow-900/30 text-yellow-400 border-yellow-800/30' },
}

interface Props {
  status: FindingStatus
}

export default function StatusBadge({ status }: Props) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.OPEN
  return (
    <span className={clsx('nyx-badge border', config.className)}>
      {config.label}
    </span>
  )
}
