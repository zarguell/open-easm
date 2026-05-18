import { type FC } from 'react'
import { Activity, Clock3 } from 'lucide-react'
import { useAssetChanges } from '../../api/assets'
import { formatDateTime } from '../../lib/format'

interface AssetChangeTimelineProps {
  entityId: string
}

interface AssetChangeItem {
  id?: string
  change_type: string
  observed_at: string | null
  summary?: string | null
  source?: string | null
}

export const AssetChangeTimeline: FC<AssetChangeTimelineProps> = ({ entityId }) => {
  const { data, isLoading, error } = useAssetChanges({ entity_id: entityId, limit: 50 })
  const changes = ((data?.changes ?? []) as AssetChangeItem[])

  if (isLoading) {
    return <div className="rounded-md border border-hairline bg-canvas-soft px-3 py-4 text-sm text-mute">Loading changes...</div>
  }

  if (error) {
    return <div className="rounded-md border border-hairline px-3 py-4 text-sm text-red-400">Unable to load changes</div>
  }

  if (changes.length === 0) {
    return (
      <div className="rounded-md border border-hairline bg-canvas-soft px-3 py-4 text-sm text-mute">
        No change history recorded
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {changes.map((change, index) => (
        <div key={change.id ?? `${change.change_type}-${change.observed_at}-${index}`} className="relative pl-5">
          <span className="absolute left-0 top-1.5 h-2 w-2 rounded-full bg-primary" />
          {index < changes.length - 1 && <span className="absolute left-[3px] top-4 h-[calc(100%+4px)] w-px bg-hairline" />}
          <div className="rounded-md border border-hairline bg-canvas px-3 py-2">
            <div className="flex min-w-0 items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate font-mono text-xs font-semibold uppercase tracking-wider text-ink">
                  {change.change_type}
                </div>
                {change.summary && <div className="mt-1 break-words text-sm text-body">{change.summary}</div>}
              </div>
              {change.source && (
                <span className="shrink-0 rounded-sm border border-hairline bg-canvas-soft px-2 py-0.5 font-mono text-[11px] text-mute">
                  {change.source}
                </span>
              )}
            </div>
            <div className="mt-2 flex items-center gap-1.5 text-xs text-mute">
              {change.observed_at ? <Clock3 className="h-3 w-3" /> : <Activity className="h-3 w-3" />}
              {formatDateTime(change.observed_at)}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
