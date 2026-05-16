import { type FC } from 'react'
import { useTargets } from '../../api/targets'
import { Badge } from '../shared/Badge'
import { Card } from '../shared/Card'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'

const statusVariant = (status?: string): 'success' | 'error' | 'warning' | 'running' | 'pending' => {
  if (!status) return 'pending'
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'running') return 'running'
  return 'pending'
}

export const TargetCards: FC = () => {
  const { data: targets, isLoading, isError, error, refetch } = useTargets()

  if (isError) {
    return <ErrorDisplay message={error.message} onRetry={() => refetch()} />
  }

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Array.from({ length: 2 }).map((_, i) => (
          <Card key={i}>
            <div className="space-y-3">
              <Skeleton width="120px" height="20px" />
              <Skeleton height="40px" />
            </div>
          </Card>
        ))}
      </div>
    )
  }

  if (!targets || targets.length === 0) {
    return (
      <div className="text-sm text-mute py-4">No targets configured</div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {targets.map((target) => (
        <Card key={target.id}>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold text-ink">{target.name}</h3>
            <div className="flex items-center gap-2">
              <Badge variant="pending">{target.type}</Badge>
              {target.enabled ? (
                <span className="inline-flex items-center gap-1 text-[11px] font-mono text-statusSuccess" style={{ color: '#00d992' }}>
                  <span className="h-2 w-2 rounded-full" style={{ backgroundColor: '#00d992' }} />
                  Enabled
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[11px] font-mono text-mute">
                  <span className="h-2 w-2 rounded-full bg-mute" />
                  Disabled
                </span>
              )}
            </div>
          </div>
          <div className="space-y-2">
            {Object.entries(target.runners).map(([runnerName, runner]) => (
              <div
                key={runnerName}
                className="flex items-center justify-between rounded border border-hairline px-3 py-2"
              >
                <span className="font-mono text-xs text-body">{runnerName}</span>
                <div className="flex items-center gap-2">
                  {runner.schedule && (
                    <span className="font-mono text-[11px] text-mute">{runner.schedule}</span>
                  )}
                  {runner.last_run_status && (
                    <Badge variant={statusVariant(runner.last_run_status)}>
                      {runner.last_run_status}
                    </Badge>
                  )}
                  {!runner.last_run_status && (
                    <Badge variant="pending">no run</Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  )
}
