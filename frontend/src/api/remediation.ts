import type { Remediation } from '../types'
import client from './client'

export const remediationApi = {
  list: async (): Promise<Remediation[]> => {
    const response = await client.get('/remediation')
    return response.data
  },

  get: async (id: string): Promise<Remediation> => {
    const response = await client.get(`/remediation/${id}`)
    return response.data
  },

  request: async (findingId: string, requestedBy?: string, context?: string): Promise<Remediation> => {
    const response = await client.post('/remediation', {
      finding_id: findingId,
      requested_by: requestedBy || 'engineer',
      engineer_context: context,
    })
    return response.data
  },

  approve: async (id: string, notes?: string): Promise<Remediation> => {
    const response = await client.post(`/remediation/${id}/approve`, { engineer_notes: notes })
    return response.data
  },

  reject: async (id: string, notes: string): Promise<Remediation> => {
    const response = await client.post(`/remediation/${id}/reject`, { engineer_notes: notes })
    return response.data
  },

  regenerate: async (id: string, context: string): Promise<Remediation> => {
    const response = await client.post(`/remediation/${id}/regenerate`, { engineer_context: context })
    return response.data
  },

  getPrStatus: async (id: string) => {
    const response = await client.get(`/remediation/${id}/pr-status`)
    return response.data
  },
}
