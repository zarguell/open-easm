import { useState } from 'react'
import { useTargets } from '../../api/targets'
import { TargetCards } from './TargetCards'
import { PivotQueueTable } from './PivotQueueTable'
import { CascadeVisualization } from './CascadeVisualization'
import { ErrorDisplay } from '../shared/ErrorDisplay'

export function TargetsView() {
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null)
  const { data: targets, isError, error, refetch } = useTargets()

  if (isError) {
    return <ErrorDisplay message={error.message} onRetry={() => refetch()} />
  }

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold text-ink">Targets & Pivots</h1>

      <section>
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
          Configured Targets
        </span>
        <div className="mt-2">
          <TargetCards />
        </div>
      </section>

      <section>
        <div className="flex items-center justify-between">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
            Discovery Cascade
          </span>
          {targets && targets.length > 0 && (
            <select
              value={selectedTargetId ?? ''}
              onChange={(e) => setSelectedTargetId(e.target.value || null)}
              className="rounded-md border border-hairline bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="">Select target...</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          )}
        </div>
        <div className="mt-2">
          <CascadeVisualization selectedTargetId={selectedTargetId} />
        </div>
      </section>

      <section>
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
          Pivot Queue
        </span>
        <div className="mt-2">
          <PivotQueueTable />
        </div>
      </section>
    </div>
  )
}
