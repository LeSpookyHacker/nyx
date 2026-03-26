import client from './client'

export interface RegressionAutoFinding {
  finding_id: string
  title: string
  severity: string
  restored_status: string
}

export interface RegressionAutoAlert {
  id: string
  repository_id: string
  repository_name: string | null
  scan_id: string | null
  auto_sorted_count: number
  findings: RegressionAutoFinding[]
  acknowledged: boolean
  acknowledged_at: string | null
  created_at: string
}

export const regressionAlertsApi = {
  getAlerts: (unacknowledgedOnly = false): Promise<RegressionAutoAlert[]> =>
    client.get('/regression-alerts', { params: { unacknowledged_only: unacknowledgedOnly } })
      .then((r: { data: RegressionAutoAlert[] }) => r.data),

  acknowledgeAlert: (id: string): Promise<void> =>
    client.post(`/regression-alerts/${id}/acknowledge`).then(() => undefined),

  acknowledgeAll: (): Promise<{ acknowledged: number }> =>
    client.post('/regression-alerts/acknowledge-all').then((r: { data: { acknowledged: number } }) => r.data),
}
