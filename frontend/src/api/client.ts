import axios from 'axios'

const apiClient = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
  // Send session cookie with every request (C1 — HTTP-only cookie replaces localStorage)
  withCredentials: true,
  // FastAPI expects repeated query keys for arrays: ?severity=CRITICAL&severity=HIGH
  // Axios default bracket notation (?severity[]=CRITICAL) is not recognised by FastAPI.
  paramsSerializer: (params) => {
    const sp = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null) continue
      if (Array.isArray(value)) {
        value.forEach(v => sp.append(key, String(v)))
      } else {
        sp.append(key, String(value))
      }
    }
    return sp.toString()
  },
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.error('Nyx: Authentication required. Set your API key in Settings.')
    }
    return Promise.reject(error)
  }
)

export default apiClient
