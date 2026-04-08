/** Pulsing placeholder skeleton for loading states. */
export default function LoadingSkeleton({ lines = 3, className = '' }: { lines?: number; className?: string }) {
  return (
    <div className={`space-y-3 animate-pulse ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="h-4 bg-nyx-twilight/40 rounded" style={{ width: `${85 - i * 10}%` }} />
      ))}
    </div>
  )
}
