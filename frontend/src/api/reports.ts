import type { AutoPrDigest } from '../types'
import client from './client'

export const reportsApi = {
  downloadExecutiveReport: async (days: number = 30): Promise<void> => {
    const response = await client.get('/reports/executive', {
      params: { days },
      responseType: 'blob',
    })
    const blob = new Blob([response.data], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const win = window.open(url, '_blank')
    // Revoke the object URL after the new tab has loaded to free memory
    if (win) {
      win.addEventListener('load', () => URL.revokeObjectURL(url), { once: true })
    }
  },

  getDailyDigest: async (digestDate?: string): Promise<AutoPrDigest> => {
    const response = await client.get('/reports/auto-pr-digest', {
      params: digestDate ? { digest_date: digestDate } : undefined,
    })
    return response.data
  },

  downloadDailyDigestReport: async (digestDate?: string): Promise<void> => {
    const response = await client.get('/reports/auto-pr-digest/export', {
      params: digestDate ? { digest_date: digestDate } : undefined,
      responseType: 'blob',
    })
    const blob = new Blob([response.data], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const win = window.open(url, '_blank')
    if (win) {
      win.addEventListener('load', () => URL.revokeObjectURL(url), { once: true })
    }
  },
}
