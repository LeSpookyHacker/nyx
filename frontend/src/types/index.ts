export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type FindingStatus = 'OPEN' | 'IN_REMEDIATION' | 'FIXED' | 'SUPPRESSED' | 'ACCEPTED_RISK'
export type ScannerType = 'SEMGREP' | 'ZAP' | 'SNYK' | 'TRIVY' | 'BANDIT' | 'GRYPE' | 'CHECKOV'
export type FindingCategory = 'SAST' | 'DAST' | 'SCA' | 'CONTAINER' | 'IAC' | 'SECRETS'
export type RemediationStatus = 'PENDING' | 'GENERATING' | 'REVIEW' | 'PR_CREATING' | 'PR_OPEN' | 'MERGED' | 'FAILED' | 'REJECTED'

export interface Finding {
  id: string
  fingerprint: string
  repository_id: string
  scan_id?: string
  title: string
  description: string
  rule_id: string
  scanner: ScannerType
  scanner_sources: string
  category: FindingCategory
  severity: Severity
  file_path?: string
  line_start?: number
  line_end?: number
  code_snippet?: string
  url?: string
  cwe_ids: string // JSON string
  cve_id?: string
  owasp_category?: string
  remediation_guidance?: string
  cvss_score?: number
  epss_score?: number
  priority_score: number
  is_exploitable: boolean
  sla_breach_at?: string
  status: FindingStatus
  first_seen_at: string
  last_seen_at: string
  resolved_at?: string
  fix_pr_url?: string
  notes?: string
  suppression_reason?: string
  assigned_to?: string
  assigned_at?: string
  is_regression?: boolean
  regression_detected_at?: string
  sla_notified_at?: string
  created_at: string
  updated_at: string
}

export interface Repository {
  id: string
  github_full_name: string
  github_repo_id?: number
  default_branch: string
  description?: string
  language?: string
  is_private: boolean
  webhook_active: boolean
  webhook_secret?: string
  enabled_scanners: string
  risk_score: number
  open_critical: number
  open_high: number
  open_medium: number
  open_low: number
  open_info: number
  last_scan_at?: string
  created_at: string
  updated_at: string
}

export interface Scan {
  id: string
  repository_id: string
  scanner: ScannerType
  trigger: string
  status: string
  git_sha?: string
  git_ref?: string
  finding_count: number
  new_finding_count: number
  fixed_finding_count: number
  started_at?: string
  completed_at?: string
  error_message?: string
  created_at: string
}

export interface Remediation {
  id: string
  finding_id: string
  requested_by: string
  status: RemediationStatus
  ai_explanation?: string
  ai_fix_diff?: string
  ai_fix_summary?: string
  ai_confidence?: number
  ai_model?: string
  pr_number?: number
  pr_url?: string
  pr_branch?: string
  pr_merged_at?: string
  deployment_url?: string
  engineer_approved?: boolean
  engineer_notes?: string
  error_message?: string
  ci_status?: 'pending' | 'pass' | 'fail' | null
  ci_failure_details?: string | null
  jira_issue_key?: string
  jira_issue_url?: string
  created_at: string
  updated_at: string
}

export interface DashboardSummary {
  open_by_severity: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  by_status: Record<string, number>
  by_scanner: Array<{ scanner: string; count: number }>
  by_category: Array<{ category: string; count: number }>
  sla_breached: number
  total_repositories: number
}

export interface TrendDataPoint {
  date: string
  new_findings: number
  fixed_findings: number
}

export interface PaginatedResponse<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export interface ScanSchedule {
  id: string
  repository_id: string
  enabled_scanners: string
  interval_hours: number
  enabled: boolean
  last_run_at?: string
  next_run_at?: string
  created_at: string
  updated_at: string
}

export interface SlaPolicy {
  id: string
  name: string
  repository_id?: string
  severity: string
  max_days: number
  escalation_action: string
  jira_project_key?: string
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface RepoRiskHistory {
  snapshot_date: string
  risk_score: number
  open_critical: number
  open_high: number
  open_medium: number
  open_low: number
  total_findings: number
}

export interface HotRepo {
  repository_id: string
  github_full_name: string
  new_findings: number
  critical_new: number
  high_new: number
  risk_score: number
}

export interface CoverageGaps {
  stale_repos: Array<{ id: string; github_full_name: string; last_scan_at: string | null; days_since_scan: number }>
  unconfigured_repos: Array<{ id: string; github_full_name: string }>
  partial_coverage: Array<{ id: string; github_full_name: string; has_scanners: string[]; missing_categories: string[] }>
}

export interface OrgRiskHistory {
  date: string
  avg_risk_score: number
  total_open: number
  total_critical: number
  repos_at_risk: number
}

export interface RegressionFinding {
  id: string
  title: string
  severity: string
  scanner: string
  file_path?: string
  repository_id: string
  github_full_name?: string
  regression_detected_at: string
}
