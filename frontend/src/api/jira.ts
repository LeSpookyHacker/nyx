import client from './client'

export interface JiraLink {
  finding_id: string
  jira_issue_key: string
  jira_issue_url: string
  jira_project_key: string
  jira_status: string | null
  jira_priority: string | null
  jira_assignee: string | null
  synced_at: string | null
  created_at: string | null
}

export interface JiraProject {
  key: string
  name: string
  type: string
}

export interface JiraHealth {
  ok: boolean
  mode: 'real' | 'mock'
  user?: string
  url?: string
  error?: string
}

export interface RepoJiraTicket extends JiraLink {
  finding_title: string
  finding_severity: string
  finding_status: string
  finding_priority_score: number
}

export interface BulkTicketResult {
  created: number
  skipped: number
  failed: number
  tickets: { finding_id: string; ticket: string }[]
}

export const jiraApi = {
  health: (): Promise<JiraHealth> =>
    client.get('/jira/health').then((r: { data: JiraHealth }) => r.data),

  listProjects: (): Promise<JiraProject[]> =>
    client.get('/jira/projects').then((r: { data: JiraProject[] }) => r.data),

  getTicket: (findingId: string): Promise<JiraLink> =>
    client.get(`/jira/findings/${findingId}/ticket`).then((r: { data: JiraLink }) => r.data),

  createTicket: (findingId: string, projectKey?: string): Promise<JiraLink> =>
    client.post(`/jira/findings/${findingId}/ticket`, { project_key: projectKey ?? null })
      .then((r: { data: JiraLink }) => r.data),

  syncTicket: (findingId: string): Promise<JiraLink> =>
    client.post(`/jira/findings/${findingId}/sync`).then((r: { data: JiraLink }) => r.data),

  unlinkTicket: (findingId: string): Promise<void> =>
    client.delete(`/jira/findings/${findingId}/ticket`).then(() => undefined),

  listRepoTickets: (repoId: string): Promise<RepoJiraTicket[]> =>
    client.get(`/jira/repositories/${repoId}/tickets`).then((r: { data: RepoJiraTicket[] }) => r.data),

  bulkCreateTickets: (
    repoId: string,
    projectKey?: string,
    severities?: string[],
  ): Promise<BulkTicketResult> =>
    client.post(`/jira/repositories/${repoId}/bulk-tickets`, {
      project_key: projectKey ?? null,
      severities: severities ?? ['CRITICAL', 'HIGH'],
    }).then((r: { data: BulkTicketResult }) => r.data),
}
