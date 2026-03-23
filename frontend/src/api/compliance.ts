import client from './client'

export interface Framework {
  id: string
  name: string
  description: string
}

export interface ControlReport {
  id: string
  title: string
  description: string
  open_findings: number
  total_findings: number
  is_compliant: boolean
  coverage_pct: number
  cwe_ids: string[]
  owasp_categories: string[]
}

export interface FrameworkReport {
  framework_id: string
  framework: { name: string; description: string }
  overall_compliance_pct: number
  compliant_controls: number
  total_controls: number
  controls: ControlReport[]
}

export interface ComplianceSummaryItem {
  framework_id: string
  name: string
  compliance_pct: number
  compliant_controls: number
  total_controls: number
  open_findings: number
}

export interface ControlFinding {
  id: string
  title: string
  severity: string
  scanner: string
  file_path: string | null
  line_start: number | null
  priority_score: number
  cve_id: string | null
  first_seen_at: string | null
}

export interface ControlFindingRepo {
  repository_id: string
  repository_name: string
  repository_full_name: string
  findings: ControlFinding[]
}

export interface ControlFindings {
  control_id: string
  control_title: string
  repositories: ControlFindingRepo[]
  total_open: number
}

export const complianceApi = {
  listFrameworks: (): Promise<Framework[]> =>
    client.get('/compliance/frameworks').then((r: { data: Framework[] }) => r.data),

  getSummary: (repository_id?: string): Promise<ComplianceSummaryItem[]> =>
    client.get('/compliance/summary', { params: { repository_id } }).then((r: { data: ComplianceSummaryItem[] }) => r.data),

  getReport: (framework_id: string, repository_id?: string): Promise<FrameworkReport> =>
    client.get(`/compliance/report/${framework_id}`, { params: { repository_id } }).then((r: { data: FrameworkReport }) => r.data),

  getControlFindings: (framework_id: string, control_id: string, repository_id?: string): Promise<ControlFindings> =>
    client.get(`/compliance/report/${framework_id}/controls/${control_id}/findings`, { params: { repository_id } }).then((r: { data: ControlFindings }) => r.data),
}
