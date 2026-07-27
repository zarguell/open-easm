import { type FC, useMemo } from 'react'
import { useEntities } from '../../api/entities'
import { useTarget } from '../../api/targets'
import { CascadeStep } from '../shared/CascadeStep'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { LoadingSpinner } from '../shared/LoadingSpinner'
import { ENTITY_TYPES } from '../../DESIGN_TOKENS'

interface CascadeVisualizationProps {
  selectedTargetId: string | null
}

export const CascadeVisualization: FC<CascadeVisualizationProps> = ({ selectedTargetId }) => {
  const { data: targetData } = useTarget(selectedTargetId)
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

  const pivots = targetData?.pivot?.allowed_pivots

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
    <div className="flex flex-col gap-3 py-4">
      <div className="flex items-center gap-0 overflow-x-auto">
        {ENTITY_TYPES.map((entityType, idx) => (
          <CascadeStep
            key={entityType}
            entityType={entityType}
            count={countsByType[entityType] ?? null}
            isLast={idx === ENTITY_TYPES.length - 1}
          />
        ))}
      </div>
      {pivots && pivots.length > 0 && (
        <div className="flex flex-wrap gap-2 px-1">
          {pivots.map(p => (
            <span
              key={`${p.from}→${p.to}→${p.via}`}
              className="inline-flex items-center gap-1.5 font-mono text-[11px] text-primary px-2.5 py-1 rounded-md bg-primary/5 border border-primary/10"
            >
              <span className="text-mute lowercase">{p.from}</span>
              <svg className="w-3 h-3 text-primary/40 shrink-0" viewBox="0 0 12 12" fill="none">
                <path d="M2 6h8M8 3l3 3-3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span className="font-semibold">{p.via}</span>
              <svg className="w-3 h-3 text-primary/40 shrink-0" viewBox="0 0 12 12" fill="none">
                <path d="M2 6h8M8 3l3 3-3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <span className="text-mute lowercase">{p.to}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
