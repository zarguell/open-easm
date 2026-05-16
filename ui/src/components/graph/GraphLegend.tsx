import { ENTITY_TYPES, type EntityType } from '../../DESIGN_TOKENS'
import { getEntityColor, getEntityLabel } from '../../lib/entity-colors'

export function GraphLegend() {
  return (
    <div className="absolute top-4 right-4 bg-canvas border border-hairline rounded-md p-3 z-10">
      <div className="space-y-1.5">
        {ENTITY_TYPES.map((type: EntityType) => (
          <div key={type} className="flex items-center gap-2">
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ backgroundColor: getEntityColor(type) }}
            />
            <span className="text-sm text-body">{getEntityLabel(type)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
