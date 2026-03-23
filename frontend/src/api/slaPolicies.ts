import apiClient from './client'
import type { SlaPolicy } from '../types'

export const slaPoliciesApi = {
  list: (repository_id?: string): Promise<SlaPolicy[]> =>
    apiClient.get('/sla-policies', { params: repository_id ? { repository_id } : {} }).then(r => r.data),
  create: (data: Omit<SlaPolicy, 'id' | 'created_at' | 'updated_at'>): Promise<SlaPolicy> =>
    apiClient.post('/sla-policies', data).then(r => r.data),
  update: (id: string, data: Partial<SlaPolicy>): Promise<SlaPolicy> =>
    apiClient.patch(`/sla-policies/${id}`, data).then(r => r.data),
  delete: (id: string): Promise<void> =>
    apiClient.delete(`/sla-policies/${id}`).then(r => r.data),
}
