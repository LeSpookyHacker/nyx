import apiClient from './client'
import type { ScanSchedule } from '../types'

export const schedulesApi = {
  list: (repository_id?: string): Promise<ScanSchedule[]> =>
    apiClient.get('/schedules', { params: repository_id ? { repository_id } : {} }).then(r => r.data),
  get: (id: string): Promise<ScanSchedule> =>
    apiClient.get(`/schedules/${id}`).then(r => r.data),
  create: (data: { repository_id: string; enabled_scanners: string[]; interval_hours: number }): Promise<ScanSchedule> =>
    apiClient.post('/schedules', data).then(r => r.data),
  update: (id: string, data: Partial<{ enabled_scanners: string[]; interval_hours: number; enabled: boolean }>): Promise<ScanSchedule> =>
    apiClient.patch(`/schedules/${id}`, data).then(r => r.data),
  delete: (id: string): Promise<void> =>
    apiClient.delete(`/schedules/${id}`).then(r => r.data),
  trigger: (id: string): Promise<{ message: string; scan_ids: string[] }> =>
    apiClient.post(`/schedules/${id}/trigger`).then(r => r.data),
}
