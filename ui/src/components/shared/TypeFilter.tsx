import { type FC } from 'react'
import { ENTITY_TYPES, ENTITY_LABELS } from '../../DESIGN_TOKENS'
import { getEntityColor } from '../../lib/entity-colors'

interface TypeFilterProps {
  selected: string | null
  onSelect: (type: string | null) => void
  counts?: Record<string, number>
}

export const TypeFilter: FC<TypeFilterProps> = ({ selected, onSelect, counts }) => (
  <div className="flex flex-wrap gap-2">
    <button
      onClick={() => { onSelect(null); }}
      className={`rounded-full px-3 py-1 text-sm font-medium transition-colors ${
        selected === null ? 'bg-primary text-on-primary' : 'bg-canvas-soft text-body hover:text-ink'
      }`}
    >
      All{counts ? ` (${Object.values(counts).reduce((a, b) => a + b, 0)})` : ''}
    </button>
    {ENTITY_TYPES.map((type) => {
      const color = getEntityColor(type)
      const label = ENTITY_LABELS[type]
      const count = counts?.[type]
      return (
        <button
          key={type}
          onClick={() => { onSelect(type); }}
          className={`rounded-full px-3 py-1 text-sm font-medium transition-colors ${selected === type ? 'text-ink-strong' : 'text-body hover:text-ink'}`}
          style={selected === type ? { backgroundColor: `${color}1f`, borderColor: color } : undefined}
        >
          {label}{count !== undefined ? ` (${count})` : ''}
        </button>
      )
    })}
  </div>
)
