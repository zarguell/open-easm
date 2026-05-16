import { type FC, useMemo } from 'react'
import { useEntities } from '../../api/entities'
import { CascadeStep } from '../shared/CascadeStep'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { LoadingSpinner } from '../shared/LoadingSpinner'
import { ENTITY_TYPES } from '../../DESIGN_TOKENS'

interface CascadeVisualizationProps {
  selectedTargetId: string | null
}

export const CascadeVisualization: FC<CascadeVisualizationProps> = ({ selectedTargetId }) => {
  const { data: entitiesData, isLoading, isError, error, refetch } = useEntities({
    target_id: selectedTargetId ?? undefined,
    limit: 500,
  })

  const countsByType = useMemo(() => {
    const counts: Record<string, number> = {}
    if (!entitiesData?.pages) return counts
    for (const page of entitiesData.pages) {
      for (const entity of page.entities) {
        const t = entity.entity_type.toLowerCase()
        counts[t] = (counts[t] ?? 0) + 1
      }
    }
    return counts
  }, [entitiesData])

  if (!selectedTargetId) {
    return (
      <div className="flex items-center justify-center py-8 text-sm text-mute">
        Select a target to view cascade
      </div>
    )
  }

  if (isLoading) {
    return <LoadingSpinner size="md" className="py-8" />
  }

  if (isError) {
    return <ErrorDisplay message={error.message} onRetry={() => refetch()} />
  }

  return (
    <div className="flex items-center gap-0 overflow-x-auto py-4">
      {ENTITY_TYPES.map((entityType, idx) => (
        <CascadeStep
          key={entityType}
          entityType={entityType}
          count={countsByType[entityType] ?? null}
          isLast={idx === ENTITY_TYPES.length - 1}
        />
      ))}
    </div>
  )
}
