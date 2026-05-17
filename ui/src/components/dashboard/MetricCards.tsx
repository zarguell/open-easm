import { type FC } from 'react'
import { useEntityCounts } from '../../api/entities'
import { MetricCard } from '../shared/Card'
import { getEntityColor, getEntityLabel } from '../../lib/entity-colors'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'

const DASHBOARD_ENTITY_TYPES = ['domain', 'ip', 'hostname', 'certificate'] as const

export const MetricCards: FC = () => {
  const { data, isLoading, isError, error, refetch } = useEntityCounts()

  if (isError) {
    return <ErrorDisplay message={error.message} onRetry={() => refetch()} />
  }

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {DASHBOARD_ENTITY_TYPES.map((type) => (
          <div key={type} className="rounded-md border border-hairline bg-canvas p-6 flex flex-col gap-1">
            <Skeleton width="60px" height="12px" />
            <Skeleton width="40px" height="32px" />
          </div>
        ))}
      </div>
    )
  }

  const counts = data?.counts ?? {}

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {DASHBOARD_ENTITY_TYPES.map(type => (
        <MetricCard
          key={type}
          label={getEntityLabel(type)}
          value={counts[type] ?? 0}
          color={getEntityColor(type)}
        />
      ))}
    </div>
  )
}
