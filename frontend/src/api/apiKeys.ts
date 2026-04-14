import client from './client'

export interface ApiKeyRecord {
  id: string
  name: string
  scopes: string
  is_active: boolean
  expires_at: string | null
  last_used_at: string | null
  created_at: string
  created_by: string
}

export interface ApiKeyCreated extends ApiKeyRecord {
  key: string
  warning: string
}

export const apiKeysApi = {
  list: async (): Promise<ApiKeyRecord[]> => {
    const { data } = await client.get('/api-keys')
    return data
  },

  create: async (name: string, scopes: string, expiresInDays?: number): Promise<ApiKeyCreated> => {
    const { data } = await client.post('/api-keys', {
      name,
      scopes,
      expires_in_days: expiresInDays,
    })
    return data
  },

  revoke: async (id: string): Promise<void> => {
    await client.delete(`/api-keys/${id}`)
  },
}
