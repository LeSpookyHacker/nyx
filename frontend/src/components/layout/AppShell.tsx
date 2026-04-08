import { Suspense } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import TopBar from './TopBar'

export default function AppShell() {
  return (
    <div className="flex h-screen bg-nyx-void overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">
          <Suspense fallback={<div className="flex items-center justify-center h-64"><div className="text-nyx-mist animate-pulse">Loading...</div></div>}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  )
}
