import { lazy } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import AppShell from './components/layout/AppShell'

const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const FindingsPage = lazy(() => import('./pages/FindingsPage'))
const FindingDetailPage = lazy(() => import('./pages/FindingDetailPage'))
const RemediationPage = lazy(() => import('./pages/RemediationPage'))
const RepositoriesPage = lazy(() => import('./pages/RepositoriesPage'))
const RepositoryDetailPage = lazy(() => import('./pages/RepositoryDetailPage'))
const ScansPage = lazy(() => import('./pages/ScansPage'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))
const AuditPage = lazy(() => import('./pages/AuditPage'))
const CompliancePage = lazy(() => import('./pages/CompliancePage'))
const SbomPage = lazy(() => import('./pages/SbomPage'))
const SchedulesPage = lazy(() => import('./pages/SchedulesPage'))
const SlaPoliciesPage = lazy(() => import('./pages/SlaPoliciesPage'))
const ReportsPage = lazy(() => import('./pages/ReportsPage'))

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:id" element={<FindingDetailPage />} />
          <Route path="remediation" element={<RemediationPage />} />
          <Route path="repositories" element={<RepositoriesPage />} />
          <Route path="repositories/:id" element={<RepositoryDetailPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="compliance" element={<CompliancePage />} />
          <Route path="sbom" element={<SbomPage />} />
          <Route path="schedules" element={<SchedulesPage />} />
          <Route path="sla-policies" element={<SlaPoliciesPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
