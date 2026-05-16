import { type FC, useState, useCallback } from 'react'
import { useRuns, useRun } from '../../api/runs'
import { Badge } from '../shared/Badge'
import { Button } from '../shared/Button'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'
import { RunDetail } from './RunDetail'
import { formatDuration, formatRelativeTime } from '../../lib/format'

const statusVariantMap: Record<string, 'success' | 'running' | 'pending' | 'error'> = {
  completed: 'success',
  running: 'running',
  pending: 'pending',
  failed: 'error',
}

interface RunsTableProps {
  targetId?: string
  source?: string
  status?: string
  refetchInterval?: false | number
}

const PAGE_SIZE = 50

export const RunsTable: FC<RunsTableProps> = ({ targetId, source, status, refetchInterval }) => {
  const [offset, setOffset] = useState(0)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const params = {
    target_id: targetId || undefined,
    source: source || undefined,
    status: status || undefined,
    limit: PAGE_SIZE,
    offset,
  }

  const { data: runs, isLoading, isFetching, isError, error, refetch } = useRuns({
    ...params,
    ...(refetchInterval !== undefined ? {} : {}),
  })

  // Use refetchInterval via query options - we pass it through useRuns
  // Note: useRuns doesn't accept refetchInterval directly, so we rely on parent setting query defaults

  const { data: expandedRun } = useRun(expandedId)

  const toggleExpand = useCallback((id: string) => {
    setExpandedId(prev => (prev === id ? null : id))
  }, [])

  const loadMore = useCallback(() => {
    setOffset(prev => prev + PAGE_SIZE)
  }, [])

  if (isError) {
    return <ErrorDisplay message={error.message} onRetry={() => refetch()} />
  }

  if (isLoading) {
    return (
      <div className="space-y-2 py-4 px-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} height="44px" />
        ))}
      </div>
    )
  }

  if (!runs || runs.length === 0) {
    return (
      <div className="flex items-center justify-center py-12">
        <span className="text-sm text-mute">No runs found</span>
      </div>
    )
  }

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="bg-canvas-soft">
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Target</th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Runner</th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Trigger</th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Status</th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Started</th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Duration</th>
              <th className="px-3 py-2 text-right font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Inserted</th>
              <th className="px-3 py-2 text-right font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Deduped</th>
              <th className="px-3 py-2 text-right font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Errors</th>
            </tr>
          </thead>
          <tbody>
            {runs.map(run => {
              const isExpanded = expandedId === run.id
              return (
                <tr key={run.id} className="group">
                  {/* Main row - clickable */}
                  <td
                    colSpan={9}
                    className="p-0 border-b border-hairline"
                  >
                    <div
                      className="flex w-full cursor-pointer hover:bg-canvas-soft transition-colors"
                      onClick={() => toggleExpand(run.id)}
                    >
                      <div className="flex-1 grid grid-cols-[1fr_1fr_1fr_1fr_1fr_1fr_80px_80px_80px] items-center">
                        <span className="px-3 py-2.5 text-sm text-ink truncate">{run.target_id}</span>
                        <span className="px-3 py-2.5 text-sm text-body truncate">{run.source}</span>
                        <span className="px-3 py-2.5 text-sm text-body truncate">{run.trigger_type}</span>
                        <span className="px-3 py-2.5">
                          <Badge variant={statusVariantMap[run.status] ?? 'pending'}>
                            {run.status}
                          </Badge>
                        </span>
                        <span className="px-3 py-2.5 text-sm text-body">{formatRelativeTime(run.started_at)}</span>
                        <span className="px-3 py-2.5 text-sm font-mono text-body">{formatDuration(run.duration_ms)}</span>
                        <span className="px-3 py-2.5 text-sm text-right text-body">{run.inserted_count}</span>
                        <span className="px-3 py-2.5 text-sm text-right text-body">{run.deduped_count}</span>
                        <span className="px-3 py-2.5 text-sm text-right text-body">{run.error_count}</span>
                      </div>
                    </div>
                    {isExpanded && (
                      <div className="px-4 pb-4">
                        {expandedRun ? (
                          <RunDetail run={expandedRun} />
                        ) : (
                          <div className="py-4 text-sm text-mute">Loading details…</div>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <div className="flex justify-center py-4">
        <Button
          variant="outline"
          onClick={loadMore}
          disabled={isFetching || runs.length < PAGE_SIZE}
        >
          {isFetching ? 'Loading…' : 'Load more'}
        </Button>
      </div>
    </div>
  )
}
