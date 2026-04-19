import client from './client'

export interface SbomComponent {
  name: string
  version: string
  purl: string | null
  license: string | null
  component_type: string
}

export interface SbomSnapshot {
  id: string
  repository_id: string
  format: string
  tool: string | null
  component_count: number
  git_ref: string | null
  created_at: string
  components?: SbomComponent[]
}

export interface SbomChange {
  type: 'added' | 'removed' | 'updated'
  name: string
  old_version?: string
  new_version?: string
  purl?: string | null
}

export interface SbomAlert {
  id: string
  repository_id: string
  repository_name: string | null
  sbom_id: string
  previous_sbom_id: string | null
  added_count: number
  removed_count: number
  updated_count: number
  changes: SbomChange[]
  acknowledged: boolean
  acknowledged_at: string | null
  created_at: string
}

export const sbomApi = {
  getAlerts: (unacknowledgedOnly = false): Promise<SbomAlert[]> =>
    client.get('/sbom/alerts', { params: { unacknowledged_only: unacknowledgedOnly } })
      .then((r: { data: SbomAlert[] }) => r.data),

  acknowledgeAlert: (id: string): Promise<void> =>
    client.post(`/sbom/alerts/${id}/acknowledge`).then(() => undefined),

  acknowledgeAll: (): Promise<{ acknowledged: number }> =>
    client.post('/sbom/alerts/acknowledge-all').then((r: { data: { acknowledged: number } }) => r.data),

  getCurrentSbom: (repoId: string): Promise<SbomSnapshot> =>
    client.get(`/sbom/repositories/${repoId}/current`).then((r: { data: SbomSnapshot }) => r.data),

  getHistory: (repoId: string): Promise<SbomSnapshot[]> =>
    client.get(`/sbom/repositories/${repoId}/history`).then((r: { data: SbomSnapshot[] }) => r.data),

  generateSbom: (repoId: string): Promise<{ triggered: boolean; repository: string }> =>
    client.post(`/sbom/repositories/${repoId}/generate`).then((r: { data: { triggered: boolean; repository: string } }) => r.data),

  exportSbom: async (repoId: string, format: 'cyclonedx' | 'csv', sbomId?: string): Promise<void> => {
    const params: Record<string, string> = { format }
    if (sbomId) params.sbom_id = sbomId
    const response = await client.get(`/sbom/repositories/${repoId}/export`, {
      params,
      responseType: 'blob',
    })
    const disposition: string = response.headers['content-disposition'] ?? ''
    const match = disposition.match(/filename="([^"]+)"/)
    const filename = match ? match[1] : `sbom.${format === 'cyclonedx' ? 'cdx.json' : 'csv'}`
    const url = URL.createObjectURL(response.data as Blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  },
}
