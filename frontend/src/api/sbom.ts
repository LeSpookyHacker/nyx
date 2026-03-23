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
}
