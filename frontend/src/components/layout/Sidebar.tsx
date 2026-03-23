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
        <p className="text-nyx-mist/50 text-[11px]">Nyx v1.0.0</p>
        <p className="text-nyx-mist/30 text-[10px]">goddess of night</p>
      </div>
    </aside>
  )
}
