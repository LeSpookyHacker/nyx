import { useState, type ElementType } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AreaChart, Area, BarChart, Bar, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid,
} from 'recharts'
import { DollarSign, Zap, TrendingDown, Wand2 } from 'lucide-react'
import { aiCostsApi } from '../api/aiCosts'
import { SEV_COLORS } from '../constants/theme'
import LoadingSkeleton from '../components/ui/LoadingSkeleton'
import type { AiCostsTopRemediation, AiCostsByModel } from '../types'

const PERIODS = [7, 30, 90, 180, 365] as const
type Period = typeof PERIODS[number]

function KpiCard({ label, value, icon: Icon, color }: {
  label: string; value: string; icon: ElementType; color: string
}) {
  return (
    <div className="nyx-card p-5">
      <div className="flex items-center justify-between mb-3">
        <p className="text-nyx-mist text-sm">{label}</p>
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
          <Icon size={16} className="text-white" />
        </div>
      </div>
      <p className="text-3xl font-bold text-nyx-moonbeam">{value}</p>
    </div>
  )
}

function formatUsd(value: number): string {
  if (value === 0) return '$0.00'
  if (value < 0.01) return `$${value.toFixed(4)}`
  return `$${value.toFixed(2)}`
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return n.toLocaleString()
}

const MODEL_COLORS = ['#7c3aed', '#6366f1', '#8b5cf6', '#a78bfa']

/** AI token consumption and estimated spend, matching Tank's /usage dashboard. */
export default function AiCostsPage() {
  const [days, setDays] = useState<Period>(30)

  const { data, isLoading } = useQuery({
    queryKey: ['ai-costs', days],
    queryFn: () => aiCostsApi.getData(days),
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSkeleton lines={5} />
      </div>
    )
  }

  if (!data || data.total_remediations === 0) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="nyx-card p-10 max-w-xl text-center space-y-4">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-nyx-iris/20 flex items-center justify-center">
            <DollarSign size={32} className="text-nyx-amethyst" />
          </div>
          <h2 className="text-2xl font-semibold text-nyx-moonbeam">No AI spend yet</h2>
          <p className="text-nyx-mist text-sm leading-relaxed">
            Token usage appears here once AI-generated remediations have been requested.
            Open a finding and click <strong className="text-nyx-moonbeam">Generate Fix</strong> to get started.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header + period selector */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-nyx-moonbeam">AI Costs</h1>
          <p className="text-nyx-mist text-sm mt-0.5">{data.pricing_note}</p>
        </div>
        <div className="flex gap-1.5">
          {PERIODS.map((p) => (
            <button
              key={p}
              onClick={() => setDays(p)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                days === p
                  ? 'bg-nyx-eclipse text-nyx-moonbeam border border-nyx-iris/30'
                  : 'text-nyx-mist hover:text-nyx-moonbeam hover:bg-nyx-twilight'
              }`}
            >
              {p}d
            </button>
          ))}
        </div>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          label="Estimated Spend"
          value={formatUsd(data.estimated_total_cost_usd)}
          icon={DollarSign}
          color="bg-nyx-iris"
        />
        <KpiCard
          label="Total Tokens"
          value={formatTokens(data.total_tokens)}
          icon={Zap}
          color="bg-nyx-stardust"
        />
        <KpiCard
          label="Avg Cost / Fix"
          value={formatUsd(data.avg_cost_per_fix_usd)}
          icon={TrendingDown}
          color="bg-indigo-600"
        />
        <KpiCard
          label="Remediations"
          value={data.total_remediations.toLocaleString()}
          icon={Wand2}
          color="bg-violet-700"
        />
      </div>

      {/* Daily cost chart */}
      <div className="nyx-card p-5">
        <h3 className="text-nyx-moonbeam font-semibold mb-4">Daily Estimated Spend</h3>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={data.daily}>
            <defs>
              <linearGradient id="costGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#7c3aed" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1a1a35" />
            <XAxis dataKey="date" tick={{ fill: '#a78bfa', fontSize: 10 }} />
            <YAxis
              tick={{ fill: '#a78bfa', fontSize: 10 }}
              width={52}
              tickFormatter={(v: number) => `$${v.toFixed(3)}`}
            />
            <Tooltip
              contentStyle={{ background: '#0d0d1a', border: '1px solid #4f46e5', borderRadius: 8 }}
              labelStyle={{ color: '#ede9fe' }}
              itemStyle={{ color: '#c4b5fd' }}
              formatter={(v: number) => [formatUsd(v), 'Est. cost']}
            />
            <Area
              type="monotone"
              dataKey="estimated_cost_usd"
              stroke="#7c3aed"
              fill="url(#costGrad)"
              strokeWidth={2}
              name="Est. cost"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Token volume chart */}
      <div className="nyx-card p-5">
        <h3 className="text-nyx-moonbeam font-semibold mb-4">Daily Token Volume</h3>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={data.daily}>
            <defs>
              <linearGradient id="inGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#6366f1" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="outGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22c55e" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1a1a35" />
            <XAxis dataKey="date" tick={{ fill: '#a78bfa', fontSize: 10 }} />
            <YAxis tick={{ fill: '#a78bfa', fontSize: 10 }} width={42} tickFormatter={formatTokens} />
            <Tooltip
              contentStyle={{ background: '#0d0d1a', border: '1px solid #4f46e5', borderRadius: 8 }}
              labelStyle={{ color: '#ede9fe' }}
              itemStyle={{ color: '#c4b5fd' }}
              formatter={(v: number) => [formatTokens(v)]}
            />
            <Area type="monotone" dataKey="input_tokens" stroke="#6366f1" fill="url(#inGrad)" strokeWidth={2} name="Input" />
            <Area type="monotone" dataKey="output_tokens" stroke="#22c55e" fill="url(#outGrad)" strokeWidth={2} name="Output" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* By-model breakdown */}
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">By Model</h3>
          {data.by_model.length === 0 ? (
            <p className="text-nyx-mist text-sm">No model data available.</p>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={120}>
                <BarChart data={data.by_model} layout="vertical" margin={{ left: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a1a35" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#a78bfa', fontSize: 10 }} tickFormatter={formatTokens} />
                  <YAxis type="category" dataKey="model" tick={{ fill: '#a78bfa', fontSize: 10 }} width={120} />
                  <Tooltip
                    contentStyle={{ background: '#0d0d1a', border: '1px solid #4f46e5', borderRadius: 8 }}
                    labelStyle={{ color: '#ede9fe' }}
                    itemStyle={{ color: '#c4b5fd' }}
                    formatter={(v: number) => [formatTokens(v)]}
                  />
                  <Bar dataKey="total_tokens" radius={[0, 4, 4, 0]} name="Total tokens">
                    {data.by_model.map((_: AiCostsByModel, i: number) => (
                      <Cell key={i} fill={MODEL_COLORS[i % MODEL_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <table className="w-full text-sm mt-4">
                <thead>
                  <tr className="text-nyx-mist text-xs uppercase tracking-wide border-b border-nyx-iris/20">
                    <th className="pb-2 text-left">Model</th>
                    <th className="pb-2 text-right">Input</th>
                    <th className="pb-2 text-right">Output</th>
                    <th className="pb-2 text-right">Fixes</th>
                    <th className="pb-2 text-right">Est. cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-nyx-iris/10">
                  {data.by_model.map((m: AiCostsByModel) => (
                    <tr key={m.model} className="text-nyx-mist hover:bg-nyx-twilight/30 transition-colors">
                      <td className="py-2 font-mono text-nyx-lavender text-xs">{m.model}</td>
                      <td className="py-2 text-right">{formatTokens(m.input_tokens)}</td>
                      <td className="py-2 text-right">{formatTokens(m.output_tokens)}</td>
                      <td className="py-2 text-right">{m.remediations}</td>
                      <td className="py-2 text-right text-nyx-moonbeam">{formatUsd(m.estimated_cost_usd)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>

        {/* Totals breakdown */}
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">Token Summary</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-nyx-mist text-sm">Input tokens</span>
              <span className="text-nyx-moonbeam font-semibold">{formatTokens(data.total_input_tokens)}</span>
            </div>
            <div className="w-full bg-nyx-twilight rounded-full h-2">
              <div
                className="bg-indigo-500 h-2 rounded-full"
                style={{ width: data.total_tokens > 0 ? `${(data.total_input_tokens / data.total_tokens) * 100}%` : '0%' }}
              />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-nyx-mist text-sm">Output tokens</span>
              <span className="text-nyx-moonbeam font-semibold">{formatTokens(data.total_output_tokens)}</span>
            </div>
            <div className="w-full bg-nyx-twilight rounded-full h-2">
              <div
                className="bg-emerald-500 h-2 rounded-full"
                style={{ width: data.total_tokens > 0 ? `${(data.total_output_tokens / data.total_tokens) * 100}%` : '0%' }}
              />
            </div>
            <div className="border-t border-nyx-iris/20 pt-4 space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-nyx-mist">Avg tokens / fix</span>
                <span className="text-nyx-moonbeam font-semibold">{formatTokens(data.avg_tokens_per_fix)}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-nyx-mist">Period</span>
                <span className="text-nyx-moonbeam font-semibold">{data.period_days} days</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Top remediations by cost */}
      {data.top_remediations_by_cost.length > 0 && (
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">Top Remediations by Cost</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-nyx-mist text-xs uppercase tracking-wide border-b border-nyx-iris/20">
                  <th className="pb-2 text-left">Finding</th>
                  <th className="pb-2 text-left">Severity</th>
                  <th className="pb-2 text-left">Status</th>
                  <th className="pb-2 text-right">Input</th>
                  <th className="pb-2 text-right">Output</th>
                  <th className="pb-2 text-right">Est. cost</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-nyx-iris/10">
                {data.top_remediations_by_cost.map((r: AiCostsTopRemediation) => (
                  <tr key={r.remediation_id} className="hover:bg-nyx-twilight/30 transition-colors">
                    <td className="py-2.5 text-nyx-moonbeam max-w-xs truncate pr-4">
                      {r.confidence_flagged && (
                        <span className="inline-block mr-1.5 text-yellow-400 text-[10px] uppercase font-bold">⚠</span>
                      )}
                      {r.finding_title}
                    </td>
                    <td className="py-2.5">
                      <span className={`text-xs font-semibold ${SEV_COLORS[r.severity] || 'text-nyx-mist'}`}>
                        {r.severity}
                      </span>
                    </td>
                    <td className="py-2.5 text-nyx-mist text-xs">{r.status.replace(/_/g, ' ')}</td>
                    <td className="py-2.5 text-right text-nyx-mist">{formatTokens(r.input_tokens)}</td>
                    <td className="py-2.5 text-right text-nyx-mist">{formatTokens(r.output_tokens)}</td>
                    <td className="py-2.5 text-right text-nyx-moonbeam font-semibold">{formatUsd(r.estimated_cost_usd)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
