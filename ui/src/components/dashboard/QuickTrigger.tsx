import { type FC } from 'react'
import { useTargets } from '../../api/targets'
import { useTriggerRun } from '../../api/runs'
import { Card } from '../shared/Card'
import { Button } from '../shared/Button'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { LoadingSpinner } from '../shared/LoadingSpinner'

export const QuickTrigger: FC = () => {
  const { data: targets, isLoading, isError, error, refetch } = useTargets()
  const triggerRun = useTriggerRun()

  if (isError) {
    return (
      <Card>
        <h3 className="text-sm font-semibold text-ink mb-4">Quick Trigger</h3>
        <ErrorDisplay message={error.message} onRetry={() => refetch()} />
      </Card>
    )
  }

  if (isLoading) {
    return (
      <Card>
        <h3 className="text-sm font-semibold text-ink mb-4">Quick Trigger</h3>
        <LoadingSpinner className="py-8" />
      </Card>
    )
  }

  return (
    <Card>
      <h3 className="text-sm font-semibold text-ink mb-4">Quick Trigger</h3>
      {!targets || targets.length === 0 ? (
        <p className="text-sm text-mute">No targets configured</p>
      ) : (
        <div className="space-y-4">
          {targets
            .filter(t => t.enabled)
            .map(target => {
              const enabledRunners = Object.entries(target.runners)
                .filter(([, info]) => info.enabled)

              if (enabledRunners.length === 0) return null

              return (
                <div key={target.id}>
                  <h4 className="text-xs font-semibold text-mute uppercase tracking-wider mb-2">
                    {target.name}
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {enabledRunners.map(([runnerName]) => (
                      <Button
                        key={runnerName}
                        variant="outline"
                        className="text-xs px-3 py-1"
                        disabled={triggerRun.isPending}
                        onClick={() =>
                          { triggerRun.mutate({ targetId: target.id, runner: runnerName }); }
                        }
                      >
                        {runnerName}
                      </Button>
                    ))}
                  </div>
                </div>
              )
            })}
        </div>
      )}
    </Card>
  )
}
