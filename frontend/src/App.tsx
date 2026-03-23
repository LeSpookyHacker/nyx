import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import AppShell from './components/layout/AppShell'
import DashboardPage from './pages/DashboardPage'
import FindingsPage from './pages/FindingsPage'
import FindingDetailPage from './pages/FindingDetailPage'
import RemediationPage from './pages/RemediationPage'
import RepositoriesPage from './pages/RepositoriesPage'
import RepositoryDetailPage from './pages/RepositoryDetailPage'
import ScansPage from './pages/ScansPage'
import SettingsPage from './pages/SettingsPage'
import AuditPage from './pages/AuditPage'
import CompliancePage from './pages/CompliancePage'
import SbomPage from './pages/SbomPage'
import SchedulesPage from './pages/SchedulesPage'
import SlaPoliciesPage from './pages/SlaPoliciesPage'
import ReportsPage from './pages/ReportsPage'

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
