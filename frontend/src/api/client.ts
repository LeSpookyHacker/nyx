import axios from 'axios'

const apiClient = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
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

apiClient.interceptors.request.use((config) => {
  const key = localStorage.getItem('nyx_api_key')
  if (key) config.headers['X-API-Key'] = key
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.error('Nyx: Authentication required. Set VITE_NYX_API_KEY.')
    }
    return Promise.reject(error)
  }
)

export default apiClient
