import { type FC, useState } from 'react'
import { useEntity, useEntityRelationships } from '../../api/entities'
import { EntityTypeBadge } from '../shared/Badge'
import { Badge } from '../shared/Badge'
import { formatDateTime } from '../../lib/format'
import { getEntityColor } from '../../lib/entity-colors'
import { ChevronDown, ChevronRight } from 'lucide-react'

interface EntityDetailProps {
  entityId: string
}

export const EntityDetail: FC<EntityDetailProps> = ({ entityId }) => {
  const { data: entity, isLoading, error } = useEntity(entityId)
  const { data: relationshipsData } = useEntityRelationships(entityId)
  const [attributesOpen, setAttributesOpen] = useState(false)

  if (isLoading) {
    return <div className="text-sm text-mute">Loading...</div>
  }

  if (error) {
    return <div className="text-sm text-red-400">Error: {error.message}</div>
  }

  if (!entity) {
    return <div className="text-sm text-mute">Entity not found</div>
  }

  const relationships = relationshipsData?.relationships ?? []

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <EntityTypeBadge entityType={entity.entity_type} />
        <div className="font-mono text-base text-ink break-all">{entity.entity_value}</div>
        {entity.is_first_discovery && (
          <Badge variant="success">First Discovery</Badge>
        )}
      </div>

      <div className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-mute">Target</span>
          <span className="font-mono text-ink">{entity.target_id}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-mute">First Seen</span>
          <span className="text-ink">{formatDateTime(entity.first_seen_at)}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-mute">Last Seen</span>
          <span className="text-ink">{formatDateTime(entity.last_seen_at)}</span>
        </div>
      </div>

      {relationships.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-mute uppercase tracking-wider">
            Relationships ({relationships.length})
          </h3>
          <div className="space-y-1">
            {relationships.map((rel) => (
              <div
                key={rel.id}
                className="flex items-center gap-2 rounded bg-canvas-soft px-3 py-2 text-xs"
              >
                <span
                  className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider"
                  style={{
                    backgroundColor: `${getEntityColor(rel.relationship_type)}1f`,
                    color: getEntityColor(rel.relationship_type),
                  }}
                >
                  {rel.relationship_type}
                </span>
                <span className="text-body font-mono truncate">
                  {rel.source_entity_id === entityId
                    ? rel.target_entity_id
                    : rel.source_entity_id}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {entity.attributes && Object.keys(entity.attributes).length > 0 && (
        <div className="space-y-2">
          <button
            onClick={() => setAttributesOpen(!attributesOpen)}
            className="flex items-center gap-1 text-xs font-semibold text-mute uppercase tracking-wider hover:text-ink transition-colors cursor-pointer"
          >
            {attributesOpen ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
            Attributes
          </button>
          {attributesOpen && (
            <pre className="rounded bg-canvas-soft p-3 text-xs text-body font-mono overflow-auto max-h-64">
              {JSON.stringify(entity.attributes, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}
