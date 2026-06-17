import client from './client'
import type { AiCostsData } from '../types'

export const aiCostsApi = {
  getData: async (days = 30, repositoryId?: string): Promise<AiCostsData> => {
    const response = await client.get('/dashboard/ai-costs', {
      params: { days, ...(repositoryId ? { repository_id: repositoryId } : {}) },
    })
    return response.data
  },
}
