import { useQuery } from '@tanstack/react-query'
import client from '../api/client'
import type { Scan } from '../types'
import { formatDistanceToNow } from 'date-fns'
import { CheckCircle, Clock, Upload, XCircle } from 'lucide-react'
import { clsx } from 'clsx'
import ScannerBadge from '../components/findings/ScannerBadge'

const STATUS_ICON: Record<string, React.ElementType> = {
  COMPLETED: CheckCircle,
  RUNNING: Clock,
  FAILED: XCircle,
  PENDING: Clock,
}
const STATUS_COLOR: Record<string, string> = {
  COMPLETED: 'text-green-400',
  RUNNING: 'text-purple-400',
  FAILED: 'text-red-400',
  PENDING: 'text-slate-400',
}

export default function ScansPage() {
  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await client.get('/scans')
      return res.data as Scan[]
    },
    refetchInterval: 10_000,
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-nyx-mist text-sm">{scans.length} scans</p>
        <div className="flex gap-2">
          <label className="nyx-btn-primary cursor-pointer gap-2">
            <Upload size={14} />
            Import Scan Results
            <input type="file" className="hidden" accept=".json" onChange={async e => {
              const file = e.target.files?.[0]
              if (!file) return
              const repoId = prompt('Repository ID (from Repositories page):')
              const scanner = prompt('Scanner name (SEMGREP, BANDIT, TRIVY, ZAP, SNYK, GRYPE, CHECKOV):')
              if (!repoId || !scanner) return
              const formData = new FormData()
              formData.append('file', file)
              formData.append('repository_id', repoId)
              formData.append('scanner', scanner.toUpperCase())
              await client.post('/scans/import', formData, { headers: { 'Content-Type': 'multipart/form-data' } })
              e.target.value = ''
            }} />
          </label>
        </div>
      </div>

      <div className="nyx-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
            <tr>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Status</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Scanner</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Repository</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Trigger</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Findings</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Started</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Duration</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-nyx-iris/5">
            {isLoading && <tr><td colSpan={7} className="px-4 py-8 text-center text-nyx-mist">Loading...</td></tr>}
            {!isLoading && scans.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-nyx-mist">No scans yet. Import scanner results to get started.</td></tr>
            )}
            {scans.map((scan: Scan) => {
              const StatusIcon = STATUS_ICON[scan.status] || Clock
              const duration = scan.started_at && scan.completed_at
                ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
                : null
              return (
                <tr key={scan.id} className="hover:bg-nyx-twilight/20">
                  <td className="px-4 py-3">
                    <span className={clsx('flex items-center gap-1.5 text-xs font-medium', STATUS_COLOR[scan.status])}>
                      <StatusIcon size={12} className={scan.status === 'RUNNING' ? 'animate-spin' : ''} />
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-4 py-3"><ScannerBadge scanner={scan.scanner} /></td>
                  <td className="px-4 py-3 text-nyx-mist text-xs">{scan.repository_id.slice(0, 8)}...</td>
                  <td className="px-4 py-3">
                    <span className="nyx-badge bg-nyx-dusk text-nyx-mist border border-nyx-iris/10 text-[10px]">
                      {scan.trigger}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-nyx-moonbeam font-semibold">{scan.finding_count}</span>
                    {scan.new_finding_count > 0 && (
                      <span className="text-red-400 text-xs ml-1.5">+{scan.new_finding_count} new</span>
                    )}
                    {scan.fixed_finding_count > 0 && (
                      <span className="text-green-400 text-xs ml-1.5">-{scan.fixed_finding_count} fixed</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-nyx-mist text-xs">
                    {scan.started_at ? formatDistanceToNow(new Date(scan.started_at)) + ' ago' : '—'}
                  </td>
                  <td className="px-4 py-3 text-nyx-mist text-xs">
                    {duration !== null ? `${duration}s` : '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
