import type { DashboardSummary, TrendDataPoint } from '../types'
import client from './client'

export const dashboardApi = {
  getSummary: async (repositoryId?: string): Promise<DashboardSummary> => {
    const response = await client.get('/dashboard/summary', {
      params: repositoryId ? { repository_id: repositoryId } : {},
    })
    return response.data
  },

  getTrends: async (days: number = 30, repositoryId?: string): Promise<{ days: number; data: TrendDataPoint[] }> => {
    const response = await client.get('/dashboard/trends', {
      params: { days, ...(repositoryId ? { repository_id: repositoryId } : {}) },
    })
    return response.data
  },

  getTopVulnerabilities: async (limit: number = 10) => {
    const response = await client.get('/dashboard/top-vulnerabilities', { params: { limit } })
    return response.data
  },

  getRepoRisk: async () => {
    const response = await client.get('/dashboard/repo-risk')
    return response.data
  },

  getMttr: async (repositoryId?: string) => {
    const response = await client.get('/dashboard/mttr', {
      params: repositoryId ? { repository_id: repositoryId } : {},
    })
    return response.data
  },

  getSeverityTrend: async (days: number = 90, repositoryId?: string) => {
    const response = await client.get('/dashboard/severity-trend', {
      params: { days, ...(repositoryId ? { repository_id: repositoryId } : {}) },
    })
    return response.data
  },

  getHotRepos: async (days: number = 7, limit: number = 8) => {
    const response = await client.get('/dashboard/hot-repos', { params: { days, limit } })
    return response.data
  },

  getCoverageGaps: async () => {
    const response = await client.get('/dashboard/coverage-gaps')
    return response.data
  },

  getRegressions: async (days: number = 7, limit: number = 5) => {
    const response = await client.get('/dashboard/regressions', { params: { days, limit } })
    return response.data
  },

  getOrgRiskHistory: async (days: number = 30) => {
    const response = await client.get('/dashboard/org-risk-history', { params: { days } })
    return response.data
  },

  getComplianceTrends: async (framework_id: string, days: number = 30) => {
    const response = await client.get('/dashboard/compliance-trends', { params: { framework_id, days } })
    return response.data
  },
}
