import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Shield,
  Wand2,
  GitBranch,
  ScanLine,
  Settings,
  ScrollText,
  Moon,
  BadgeCheck,
  Package,
  Clock,
  ShieldAlert,
  FileText,
} from 'lucide-react'
import { clsx } from 'clsx'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/findings', icon: Shield, label: 'Findings' },
  { to: '/remediation', icon: Wand2, label: 'Remediation' },
  { to: '/repositories', icon: GitBranch, label: 'Repositories' },
  { to: '/scans', icon: ScanLine, label: 'Scans' },
  { to: '/compliance', icon: BadgeCheck, label: 'Compliance' },
  { to: '/sbom', icon: Package, label: 'SBOM' },
  { to: '/schedules', icon: Clock, label: 'Schedules' },
  { to: '/sla-policies', icon: ShieldAlert, label: 'SLA Policies' },
  { to: '/reports', icon: FileText, label: 'Reports' },
  { to: '/audit', icon: ScrollText, label: 'Audit Log' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function Sidebar() {
  return (
    <aside className="w-60 bg-nyx-dusk border-r border-nyx-iris/10 flex flex-col shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-nyx-iris/10">
        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-nyx-iris to-nyx-stardust flex items-center justify-center shadow-nyx-glow">
          <Moon size={16} className="text-white" />
        </div>
        <div>
          <span className="text-nyx-moonbeam font-bold text-lg tracking-wide">Nyx</span>
          <p className="text-nyx-mist text-[10px] uppercase tracking-widest">Security Dashboard</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {navItems.map(({ to, icon: Icon, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150',
                isActive
                  ? 'bg-nyx-eclipse text-nyx-moonbeam shadow-sm border border-nyx-iris/30'
                  : 'text-nyx-mist hover:text-nyx-moonbeam hover:bg-nyx-twilight'
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-nyx-iris/10">
        <div className="flex items-center justify-between">
          <p className="text-nyx-mist/50 text-[11px]">Nyx v1.0.0</p>
          <a
            href="https://github.com/LeSpookyHacker/nyx"
            target="_blank"
            rel="noopener noreferrer"
            className="text-nyx-mist/30 hover:text-nyx-mist/60 transition-colors"
            title="View on GitHub"
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
          </a>
        </div>
        <p className="text-nyx-mist/30 text-[10px]">goddess of night</p>
      </div>
    </aside>
  )
}
