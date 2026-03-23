import type { Finding, PaginatedResponse } from '../types'
import client from './client'

export interface FindingsParams {
  severity?: string[]
  scanner?: string[]
  status?: string[]
  category?: string[]
  repository_id?: string
  search?: string
  assigned_to?: string
  is_regression?: boolean
  page?: number
  page_size?: number
  sort_by?: string
  sort_desc?: boolean
}

export const findingsApi = {
  list: async (params: FindingsParams = {}): Promise<PaginatedResponse<Finding>> => {
    const p: Record<string, unknown> = { ...params }
    if (params.severity) p['severity'] = params.severity
    if (params.scanner) p['scanner'] = params.scanner
    if (params.status) p['status'] = params.status
    const response = await client.get('/findings', { params: p })
    return response.data
  },

  get: async (id: string): Promise<Finding> => {
    const response = await client.get(`/findings/${id}`)
    return response.data
  },

  updateStatus: async (id: string, status: string, notes?: string): Promise<Finding> => {
    const response = await client.patch(`/findings/${id}/status`, { status, notes })
    return response.data
  },

  suppress: async (id: string, reason: string, expiresDays?: number): Promise<Finding> => {
    const response = await client.post(`/findings/${id}/suppress`, {
      reason,
      expires_days: expiresDays,
    })
    return response.data
  },

  unsuppress: async (id: string): Promise<Finding> => {
    const response = await client.delete(`/findings/${id}/suppress`)
    return response.data
  },

  updateNotes: async (id: string, notes: string): Promise<Finding> => {
    const response = await client.patch(`/findings/${id}/notes`, { notes })
    return response.data
  },

  bulkUpdateStatus: async (ids: string[], status: string): Promise<{ updated: number }> => {
    const response = await client.post('/findings/bulk/status', {
      finding_ids: ids,
      status,
    })
    return response.data
  },

  assign: async (id: string, assignee: string): Promise<Finding> => {
    const response = await client.patch(`/findings/${id}/assign`, { assignee })
    return response.data
  },

  getSuppressionSuggestion: async (id: string) => {
    const response = await client.get(`/findings/${id}/suppression-suggestion`)
    return response.data
  },

  listSuppressionPatterns: async (params?: { scanner?: string; rule_id?: string; repository_id?: string }) => {
    const response = await client.get('/findings/suppression-patterns', { params })
    return response.data
  },

  bulkRequestFix: async (finding_ids: string[]): Promise<{ requested: number; skipped: number; remediation_ids: string[] }> => {
    const response = await client.post('/remediation/bulk', { finding_ids })
    return response.data
  },

  export: (format: 'csv' | 'json', params: FindingsParams = {}) => {
    const searchParams = new URLSearchParams()
    searchParams.set('format', format)
    if (params.severity) params.severity.forEach(s => searchParams.append('severity', s))
    if (params.scanner) params.scanner.forEach(s => searchParams.append('scanner', s))
    if (params.status) params.status.forEach(s => searchParams.append('status', s))
    window.open(`/api/v1/findings/export?${searchParams.toString()}`, '_blank')
  },
}
