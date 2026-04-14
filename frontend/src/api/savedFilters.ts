import apiClient from './client'

export interface FindingFilterState {
  severity?: string[]
  scanner?: string[]
  status?: string[]
  search?: string
  repository_id?: string
  is_regression?: boolean
  sort_by?: string
  sort_desc?: boolean
}

export interface SavedFilter {
  id: string
  name: string
  filters: FindingFilterState
  is_default: boolean
  scope: string
  created_at: string | null
}

export const savedFiltersApi = {
  async list(scope: string = 'findings'): Promise<SavedFilter[]> {
    const { data } = await apiClient.get('/saved-filters', { params: { scope } })
    return data
  },
  async create(
    name: string,
    filters: FindingFilterState,
    opts: { isDefault?: boolean; scope?: string } = {},
  ): Promise<SavedFilter> {
    const { data } = await apiClient.post('/saved-filters', {
      name,
      filters,
      is_default: opts.isDefault ?? false,
      scope: opts.scope ?? 'findings',
    })
    return data
  },
  async remove(id: string): Promise<void> {
    await apiClient.delete(`/saved-filters/${id}`)
  },
}
