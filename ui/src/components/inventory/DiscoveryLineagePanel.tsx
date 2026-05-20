import { type FC } from 'react'
import { useEntityLineage } from '../../api/entities'
import { getEntityColor, getEntityBgColor, getEntityLabel } from '../../lib/entity-colors'
import { Skeleton } from '../shared/Skeleton'
import { colors } from '../../DESIGN_TOKENS'

interface DiscoveryLineagePanelProps {
  entityId: string
}

const EntityNode: FC<{
  entityType: string
  entityValue: string
  discoveredBy: string | null
  isTarget?: boolean
}> = ({ entityType, entityValue, discoveredBy, isTarget }) => {
  const color = getEntityColor(entityType)
  const bgColor = getEntityBgColor(entityType)

  return (
    <div
      className="relative rounded-sm border px-3 py-2.5"
      style={{
        borderColor: isTarget ? color : colors.hairline,
        backgroundColor: isTarget ? bgColor : colors.canvasSoft,
      }}
    >
      {isTarget && (
        <div
          className="absolute top-0 left-0 right-0 h-[2px] rounded-t-sm"
          style={{ backgroundColor: color }}
        />
      )}
      <div className="flex items-center gap-2">
        <span
          className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider"
          style={{ backgroundColor: bgColor, color }}
        >
          {getEntityLabel(entityType)}
        </span>
        {isTarget && (
          <span
            className="inline-flex items-center rounded-full px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider"
            style={{ backgroundColor: `${colors.primary}1f`, color: colors.primary }}
          >
            target
          </span>
        )}
      </div>
      <div className="mt-1.5 break-all font-mono text-[12px] font-semibold text-ink">
        {entityValue}
      </div>
      {discoveredBy && (
        <div className="mt-1 font-mono text-[10px] text-mute">
          discovered by: {discoveredBy}
        </div>
      )}
    </div>
  )
}

const Connector: FC<{
  relationshipType: string
  runner: string | null
}> = ({ relationshipType, runner }) => (
  <div className="flex items-start gap-3 py-0.5">
    <div className="flex flex-col items-center">
      <div className="h-2 w-px" style={{ backgroundColor: colors.hairlineSoft }} />
      <div className="h-2.5 w-2.5 rounded-full border" style={{ borderColor: colors.hairlineSoft, backgroundColor: colors.canvas }}>
        <svg className="h-2.5 w-2.5" viewBox="0 0 10 10" fill="none">
          <path d="M5 1v7M2 5l3 3 3-3" stroke={colors.hairlineSoft} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      <div className="h-2 w-px" style={{ backgroundColor: colors.hairlineSoft }} />
    </div>
    <div className="flex flex-col gap-0.5 pt-0.5">
      <span
        className="font-mono text-[10px] font-semibold uppercase tracking-wider"
        style={{ color: colors.mute }}
      >
        {relationshipType.replace(/_/g, ' ')}
      </span>
      {runner && (
        <span className="font-mono text-[9px] text-mute">{runner}</span>
      )}
    </div>
  </div>
)

export const DiscoveryLineagePanel: FC<DiscoveryLineagePanelProps> = ({ entityId }) => {
  const { data, isLoading, error } = useEntityLineage(entityId)

  if (isLoading) {
    return (
      <div className="space-y-3 py-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} height="56px" />
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-sm border border-hairline bg-canvas-soft px-3 py-3 text-sm text-red-400">
        Failed to load lineage: {error.message}
      </div>
    )
  }

  if (!data) return null

  const { entity, ancestors } = data
  const chain = [...ancestors].reverse()

  if (chain.length === 0) {
    return (
      <div className="space-y-3">
        <EntityNode
          entityType={entity.entity_type}
          entityValue={entity.entity_value}
          discoveredBy={entity.discovered_by}
          isTarget
        />
        {entity.discovered_by ? (
          <p className="text-sm text-mute">
            Directly discovered by <span className="font-mono text-ink">{entity.discovered_by}</span>
          </p>
        ) : (
          <p className="text-sm text-mute">Seed entity with no ancestors.</p>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-0">
      {chain.map((ancestor, i) => (
        <div key={ancestor.entity.id}>
          <EntityNode
            entityType={ancestor.entity.entity_type}
            entityValue={ancestor.entity.entity_value}
            discoveredBy={ancestor.entity.discovered_by}
          />
          <Connector
            relationshipType={ancestor.relationship.type}
            runner={ancestor.relationship.runner}
          />
        </div>
      ))}
      <EntityNode
        entityType={entity.entity_type}
        entityValue={entity.entity_value}
        discoveredBy={entity.discovered_by}
        isTarget
      />
    </div>
  )
}
