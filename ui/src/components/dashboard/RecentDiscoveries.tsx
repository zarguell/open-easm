import { type FC, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useEntities } from '../../api/entities'
import { Card } from '../shared/Card'
import { EntityTypeBadge } from '../shared/Badge'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'
import { formatRelativeTime, truncateMiddle } from '../../lib/format'

export const RecentDiscoveries: FC<{ refetchInterval: false | number }> = ({ refetchInterval }) => {
  const queryClient = useQueryClient()
  const { data: entitiesData, isLoading, isError, error, refetch } = useEntities({ limit: 20 })

  useEffect(() => {
    if (!refetchInterval) return
    const id = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: ['entities'] })
    }, refetchInterval)
    return () => { clearInterval(id); }
  }, [refetchInterval, queryClient])

  if (isError) {
    return (
      <Card>
        <h3 className="text-sm font-semibold text-ink mb-3">Recent Discoveries</h3>
        <ErrorDisplay message={error.message} onRetry={() => refetch()} />
      </Card>
    )
  }

  const entities = entitiesData?.pages.flatMap(page => page.entities) ?? []

  if (isLoading) {
    return (
      <Card>
        <h3 className="text-sm font-semibold text-ink mb-3">Recent Discoveries</h3>
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <Skeleton width="50px" height="20px" />
                <Skeleton width="180px" height="16px" />
              </div>
              <Skeleton width="60px" height="14px" />
            </div>
          ))}
        </div>
      </Card>
    )
  }

  return (
    <Card>
      <h3 className="text-sm font-semibold text-ink mb-3">Recent Discoveries</h3>
      {entities.length === 0 ? (
        <p className="text-sm text-mute">No entities discovered yet</p>
      ) : (
        <ul className="space-y-0 divide-y divide-hairline">
          {entities.map(entity => (
            <li key={entity.id} className="flex items-center justify-between gap-3 py-2 px-1 hover:bg-canvas-soft rounded-sm transition-colors">
              <div className="flex items-center gap-3 min-w-0">
                <EntityTypeBadge entityType={entity.entity_type} />
                <span className="text-sm font-mono text-body truncate">
                  {truncateMiddle(entity.entity_value, 48)}
                </span>
              </div>
              <span className="text-xs font-mono text-mute whitespace-nowrap">
                {formatRelativeTime(entity.first_seen_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
