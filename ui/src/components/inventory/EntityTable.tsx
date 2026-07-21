import { type FC } from 'react'
import { EntityTypeBadge } from '../shared/Badge'
import { formatRelativeTime } from '../../lib/format'
import { truncateMiddle } from '../../lib/format'
import type { Entity } from '../../api/entities'

interface EntityTableProps {
  entities: Entity[]
  hasNextPage: boolean
  isFetchingNextPage: boolean
  onLoadMore: () => void
  onSelectEntity: (id: string) => void
  selectedEntityId: string | null
}

export const EntityTable: FC<EntityTableProps> = ({
  entities,
  hasNextPage,
  isFetchingNextPage,
  onLoadMore,
  onSelectEntity,
  selectedEntityId,
}) => {
  if (entities.length === 0) {
    return (
      <div className="flex items-center justify-center py-20 text-sm text-mute">
        No entities found
      </div>
    )
  }

  return (
    <div>
      <table className="w-full">
        <thead>
          <tr className="bg-canvas-soft">
            <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
              Type
            </th>
            <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
              Value
            </th>
            <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
              Target
            </th>
            <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
              First Seen
            </th>
            <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
              Last Seen
            </th>
          </tr>
        </thead>
        <tbody>
          {entities.map((entity) => (
            <tr
              key={entity.id}
              onClick={() => { onSelectEntity(entity.id); }}
              className={`border-b border-hairline cursor-pointer transition-colors hover:bg-canvas-soft ${
                selectedEntityId === entity.id ? 'bg-canvas-soft' : ''
              }`}
            >
              <td className="px-4 py-2">
                <EntityTypeBadge entityType={entity.entity_type} />
              </td>
              <td className="px-4 py-2 font-mono text-sm text-ink">
                {truncateMiddle(entity.entity_value, 60)}
              </td>
              <td className="px-4 py-2 text-sm text-body">
                {truncateMiddle(entity.target_id, 16)}
              </td>
              <td className="px-4 py-2 text-sm text-body">
                {formatRelativeTime(entity.first_seen_at)}
              </td>
              <td className="px-4 py-2 text-sm text-body">
                {formatRelativeTime(entity.last_seen_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {hasNextPage && (
        <div className="flex justify-center py-4">
          <button
            onClick={onLoadMore}
            disabled={isFetchingNextPage}
            className="rounded-md border border-hairline bg-canvas-soft px-4 py-2 text-sm text-body hover:text-ink transition-colors disabled:opacity-50 cursor-pointer"
          >
            {isFetchingNextPage ? 'Loading...' : 'Load more'}
          </button>
        </div>
      )}
    </div>
  )
}
