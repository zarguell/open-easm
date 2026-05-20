import { type FC, useMemo } from 'react'
import { useEntities } from '../../api/entities'
import { Card } from '../shared/Card'
import { EntityTypeBadge } from '../shared/Badge'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'
import { getEntityColor } from '../../lib/entity-colors'
import { truncateMiddle } from '../../lib/format'

const TYPES_TO_TRACK = ['ip', 'hostname', 'domain', 'certificate'] as const

export const NewThisWeek: FC = () => {
  const sevenDaysAgo = useMemo(() => {
    const d = new Date()
    d.setDate(d.getDate() - 7)
    return d.toISOString()
  }, [])

  const { data, isLoading, isError, error, refetch } = useEntities({
    first_seen_since: sevenDaysAgo,
    limit: 50,
  })

  if (isError) {
    return <ErrorDisplay message={error.message} onRetry={() => refetch()} />
  }

  const entities = data?.pages.flatMap((p) => p.entities) ?? []

  const countsByType = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const e of entities) {
      counts[e.entity_type] = (counts[e.entity_type] ?? 0) + 1
    }
    return counts
  }, [entities])

  const totalNew = entities.length
  const recent = entities.slice(0, 10)

  return (
    <Card className="space-y-4">
      <div>
        <h2 className="text-sm font-semibold text-ink">New This Week</h2>
        <p className="mt-1 text-xs text-mute">
          {totalNew} entities discovered in the last 7 days
        </p>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} height="20px" />
          ))}
        </div>
      ) : (
        <>
          {totalNew === 0 ? (
            <p className="text-sm text-mute">No new entities this week</p>
          ) : (
            <>
              <div className="flex flex-wrap gap-2">
                {TYPES_TO_TRACK.map((type) => {
                  const count = countsByType[type] ?? 0
                  if (count === 0) return null
                  const color = getEntityColor(type)
                  return (
                    <span
                      key={type}
                      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-xs font-semibold"
                      style={{ backgroundColor: `${color}1f`, color }}
                    >
                      {type === 'ip' ? 'IP' : type.charAt(0).toUpperCase() + type.slice(1)}
                      <span className="font-bold">{count}</span>
                    </span>
                  )
                })}
              </div>

              <ul className="space-y-0 divide-y divide-hairline">
                {recent.map((entity) => (
                  <li
                    key={entity.id}
                    className="flex items-center justify-between gap-3 py-2 px-1 hover:bg-canvas-soft rounded-sm transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <EntityTypeBadge entityType={entity.entity_type} />
                      <span className="text-sm font-mono text-body truncate">
                        {truncateMiddle(entity.entity_value, 40)}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </>
      )}
    </Card>
  )
}
