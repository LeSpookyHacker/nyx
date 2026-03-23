import { clsx } from 'clsx'
import type { Severity } from '../../types'
import { AlertOctagon, AlertTriangle, Info, ShieldAlert, ShieldCheck } from 'lucide-react'

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

const SEVERITY_CONFIG: Record<Severity, { label: string; className: string; Icon: React.ElementType }> = {
  CRITICAL: { label: 'Critical', className: 'severity-critical', Icon: AlertOctagon },
  HIGH:     { label: 'High',     className: 'severity-high',     Icon: ShieldAlert },
  MEDIUM:   { label: 'Medium',   className: 'severity-medium',   Icon: AlertTriangle },
  LOW:      { label: 'Low',      className: 'severity-low',      Icon: ShieldCheck },
  INFO:     { label: 'Info',     className: 'severity-info',     Icon: Info },
}

export default function SeverityBadge({ severity, size = 'md' }: Props) {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.INFO
  const { label, className, Icon } = config

  return (
    <span className={clsx('nyx-badge', className, size === 'sm' && 'text-[10px]')}>
      <Icon size={size === 'sm' ? 10 : 11} />
      {label}
    </span>
  )
}
