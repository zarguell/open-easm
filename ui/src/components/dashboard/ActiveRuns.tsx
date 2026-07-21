import { type FC, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useRuns } from '../../api/runs'
import { Card } from '../shared/Card'
import { Badge } from '../shared/Badge'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { formatRelativeTime } from '../../lib/format'

function statusToBadgeVariant(status: string): 'success' | 'error' | 'warning' | 'running' | 'pending' {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'running') return 'running'
  return 'pending'
}

export const ActiveRuns: FC<{ refetchInterval: false | number }> = ({ refetchInterval }) => {
  const queryClient = useQueryClient()
  const { data: runningRuns, isError: isRunningErr, error: runningErr, refetch: refetchRunning } = useRuns({ status: 'running', limit: 10 })
  const { data: pendingRuns, isError: isPendingErr, error: pendingErr, refetch: refetchPending } = useRuns({ status: 'pending', limit: 10 })

  useEffect(() => {
    if (!refetchInterval) return
    const id = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: ['runs'] })
    }, refetchInterval)
    return () => { clearInterval(id); }
  }, [refetchInterval, queryClient])

  if (isRunningErr || isPendingErr) {
    const message = runningErr?.message ?? pendingErr?.message ?? 'Failed to load runs'
    return (
      <Card>
        <h3 className="text-sm font-semibold text-ink mb-3">Active Runs</h3>
        <ErrorDisplay message={message} onRetry={() => { refetchRunning(); refetchPending() }} />
      </Card>
    )
  }

  const runs = [...(runningRuns ?? []), ...(pendingRuns ?? [])]

  return (
    <Card>
      <h3 className="text-sm font-semibold text-ink mb-3">Active Runs</h3>
      {runs.length === 0 ? (
        <p className="text-sm text-mute">No active runs</p>
      ) : (
        <ul className="space-y-2">
          {runs.map(run => (
            <li key={run.id} className="flex items-center justify-between gap-3 py-1">
              <div className="flex items-center gap-3 min-w-0">
                <span className="text-sm font-mono text-body truncate">{run.source}</span>
                <Badge variant={statusToBadgeVariant(run.status)}>{run.status}</Badge>
              </div>
              <span className="text-xs font-mono text-mute whitespace-nowrap">
                {formatRelativeTime(run.started_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
