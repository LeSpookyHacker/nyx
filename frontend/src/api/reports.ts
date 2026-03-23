export const reportsApi = {
  downloadExecutiveReport: (days: number = 30): void => {
    const params = new URLSearchParams({ days: String(days) })
    const apiKey = localStorage.getItem('nyx_api_key') || ''
    // Build the URL and open in new tab (api key passed via stored header in interceptor)
    window.open(`/api/v1/reports/executive?${params}&_key=${encodeURIComponent(apiKey)}`, '_blank')
  },
}
