import { useState, useMemo } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTargets } from '../../api/targets'
import { useRuns } from '../../api/runs'
import { useAutoRefresh } from '../../hooks/useAutoRefresh'
import { Button } from '../shared/Button'
import { RunsTable } from './RunsTable'

const STATUS_OPTIONS = ['all', 'running', 'pending', 'completed', 'failed'] as const

const COMMON_RUNNERS = ['all', 'asnmap', 'subfinder', 'crtsh', 'dnstwist', 'certstream'] as const

type StatusFilter = (typeof STATUS_OPTIONS)[number]
type RunnerFilter = (typeof COMMON_RUNNERS)[number]

export function RunsView() {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [runnerFilter, setRunnerFilter] = useState<RunnerFilter>('all')
  const [targetFilter, setTargetFilter] = useState<string>('all')
  const { autoRefreshEnabled, toggleAutoRefresh } = useAutoRefresh(true, 5000)

  const baseParams = {
    target_id: targetFilter !== 'all' ? targetFilter : undefined,
    source: runnerFilter !== 'all' ? runnerFilter : undefined,
    status: statusFilter !== 'all' ? statusFilter : undefined,
    limit: 50,
    offset: 0,
  }

  const { data: visibleRuns } = useRuns(baseParams)
  const hasActiveRuns = useMemo(
    () => visibleRuns?.some(r => r.status === 'running' || r.status === 'pending') ?? false,
    [visibleRuns]
  )

  const shouldRefetch = autoRefreshEnabled && hasActiveRuns

  const queryClient = useQueryClient()
  queryClient.setQueryDefaults(['runs'], {
    refetchInterval: shouldRefetch ? 5000 : false,
  })

  const { data: targets } = useTargets()
  const targetOptions = useMemo(
    () => targets?.map(t => t.id) ?? [],
    [targets]
  )

  return (
    <div className="flex flex-col h-full">
      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3 border-b border-hairline bg-canvas-soft px-4 py-3">
        {/* Status pills */}
        <div className="flex items-center gap-1">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute mr-2">Status</span>
          {STATUS_OPTIONS.map(s => (
            <Button
              key={s}
              variant={statusFilter === s ? 'primary' : 'outline'}
              onClick={() => setStatusFilter(s)}
              className="px-2.5 py-1 text-xs"
            >
              {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
            </Button>
          ))}
        </div>

        {/* Divider */}
        <div className="h-6 w-px bg-hairline" />

        {/* Target dropdown */}
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Target</span>
          <select
            value={targetFilter}
            onChange={e => setTargetFilter(e.target.value)}
            className="rounded-sm border border-hairline bg-canvas px-2 py-1 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="all">All targets</option>
            {targetOptions.map(id => (
              <option key={id} value={id}>{id}</option>
            ))}
          </select>
        </div>

        {/* Runner dropdown */}
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Runner</span>
          <select
            value={runnerFilter}
            onChange={e => setRunnerFilter(e.target.value as RunnerFilter)}
            className="rounded-sm border border-hairline bg-canvas px-2 py-1 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {COMMON_RUNNERS.map(r => (
              <option key={r} value={r}>
                {r === 'all' ? 'All runners' : r}
              </option>
            ))}
          </select>
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Auto-refresh toggle */}
        <Button
          variant={autoRefreshEnabled ? 'primary' : 'outline'}
          onClick={toggleAutoRefresh}
          className="px-2.5 py-1 text-xs"
        >
          {autoRefreshEnabled ? 'Auto-refresh ON' : 'Auto-refresh OFF'}
        </Button>
      </div>

      {/* Runs Table */}
      <div className="flex-1 overflow-auto">
        <RunsTable
          targetId={targetFilter !== 'all' ? targetFilter : undefined}
          source={runnerFilter !== 'all' ? runnerFilter : undefined}
          status={statusFilter !== 'all' ? statusFilter : undefined}
        />
      </div>
    </div>
  )
}
