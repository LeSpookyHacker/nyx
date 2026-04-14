import axios from 'axios'

export interface WhoAmI {
  identity: string
  scopes: string
}

const authClient = axios.create({ withCredentials: true })

export const authApi = {
  login: async (apiKey: string): Promise<{ identity: string; scopes: string }> => {
    const { data } = await authClient.post('/auth/session', { api_key: apiKey })
    return data
  },

  logout: async (): Promise<void> => {
    await authClient.post('/auth/logout', {})
  },

  whoami: async (): Promise<WhoAmI> => {
    const { data } = await authClient.get('/auth/whoami')
    return data
  },
}
