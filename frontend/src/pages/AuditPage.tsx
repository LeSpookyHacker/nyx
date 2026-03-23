import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import client from '../api/client'
import { format } from 'date-fns'

export default function AuditPage() {
  const [page] = useState(1)

  const { data = [], isLoading } = useQuery({
    queryKey: ['audit', page],
    queryFn: async () => {
      const res = await client.get('/audit', { params: { page, page_size: 100 } })
      return res.data
    },
  })

  return (
    <div className="space-y-4">
      <div className="nyx-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
            <tr>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Time</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Actor</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Action</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Resource</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-nyx-iris/5">
            {isLoading && <tr><td colSpan={5} className="px-4 py-8 text-center text-nyx-mist">Loading...</td></tr>}
            {!isLoading && data.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-nyx-mist">No audit events yet.</td></tr>
            )}
            {data.map((log: any) => (
              <tr key={log.id} className="hover:bg-nyx-twilight/20">
                <td className="px-4 py-3 text-nyx-mist text-xs whitespace-nowrap">
                  {format(new Date(log.created_at), 'MMM d HH:mm:ss')}
                </td>
                <td className="px-4 py-3 text-nyx-moonbeam text-xs">{log.actor}</td>
                <td className="px-4 py-3">
                  <code className="text-nyx-amethyst text-xs">{log.action}</code>
                </td>
                <td className="px-4 py-3 text-nyx-mist text-xs">
                  {log.resource_type} <span className="text-nyx-iris/50">{log.resource_id?.slice(0, 8)}</span>
                </td>
                <td className="px-4 py-3 text-nyx-mist text-xs">
                  {log.metadata && (
                    <code className="text-[10px] text-nyx-mist/70">
                      {JSON.stringify(log.metadata)}
                    </code>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
