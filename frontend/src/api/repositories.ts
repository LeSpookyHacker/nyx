import type { Repository, Scan } from '../types'
import client from './client'

export const repositoriesApi = {
  list: async (): Promise<Repository[]> => {
    const response = await client.get('/repositories')
    return response.data
  },

  get: async (id: string): Promise<Repository> => {
    const response = await client.get(`/repositories/${id}`)
    return response.data
  },

  create: async (githubFullName: string, enabledScanners: string[]): Promise<Repository> => {
    const response = await client.post('/repositories', {
      github_full_name: githubFullName,
      enabled_scanners: enabledScanners,
    })
    return response.data
  },

  update: async (id: string, data: { enabled_scanners?: string[]; default_branch?: string }): Promise<Repository> => {
    const response = await client.patch(`/repositories/${id}`, data)
    return response.data
  },

  delete: async (id: string): Promise<void> => {
    await client.delete(`/repositories/${id}`)
  },

  refreshWebhook: async (id: string): Promise<Repository> => {
    const response = await client.post(`/repositories/${id}/webhook`)
    return response.data
  },

  syncCodeScanning: async (id: string): Promise<Record<string, unknown>> => {
    const response = await client.post(`/repositories/${id}/sync-code-scanning`)
    return response.data
  },

  getScans: async (id: string): Promise<Scan[]> => {
    const response = await client.get('/scans', { params: { repository_id: id } })
    return response.data
  },

  getRiskHistory: async (id: string, days: number = 30) => {
    const response = await client.get(`/repositories/${id}/risk-history`, { params: { days } })
    return response.data
  },

  pushWorkflow: async (id: string): Promise<{ created: boolean; html_url: string; repository: string }> => {
    const response = await client.post(`/repositories/${id}/push-workflow`)
    return response.data
  },

  generateClaudePrompt: async (id: string): Promise<{ prompt: string; updated: number }> => {
    const response = await client.post(`/findings/generate-claude-prompt/repository/${id}`)
    return response.data
  },

  detectScanners: async (id: string, autoApply = false): Promise<{
    repository: string
    current_scanners: string[]
    recommended_scanners: string[]
    newly_detected: string[]
    detection_reasons: Record<string, string>
    applied: boolean
  }> => {
    const response = await client.post(`/repositories/${id}/detect-scanners`, null, {
      params: { auto_apply: autoApply },
    })
    return response.data
  },
}
