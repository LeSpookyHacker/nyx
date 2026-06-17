import { Zap } from 'lucide-react'

/** Amber badge marking a finding that Auto PR Mode has queued or committed a fix for. */
export default function AutoPrBadge() {
  return (
    <span
      className="nyx-badge text-[10px] bg-amber-900/30 text-amber-400 border border-amber-800/30"
      title="Queued for automatic remediation by Auto PR Mode."
    >
      <Zap size={10} /> AUTO
    </span>
  )
}
