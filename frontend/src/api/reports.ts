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
}
