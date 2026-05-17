import { useState, useMemo } from 'react'
import { useEntities } from '../../api/entities'
import { useDebounce } from '../../hooks/useDebounce'
import { TypeFilter } from '../shared/TypeFilter'
import { SearchInput } from '../shared/SearchInput'
import { SlideOver } from '../shared/SlideOver'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'
import { EntityTable } from './EntityTable'
import { EntityDetail } from './EntityDetail'

export function InventoryView() {
  const [entityType, setEntityType] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const debouncedSearch = useDebounce(searchQuery)
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null)

  const {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isLoading,
    isError,
    error,
    refetch,
  } = useEntities({
    entity_type: entityType ?? undefined,
    limit: 50,
  })

  const allEntities = useMemo(() => {
    const pages = data?.pages ?? []
    return pages.flatMap((page) => page.entities)
  }, [data?.pages])

  const filteredEntities = useMemo(() => {
    if (!debouncedSearch) return allEntities
    const lower = debouncedSearch.toLowerCase()
    return allEntities.filter((e) =>
      e.entity_value.toLowerCase().includes(lower),
    )
  }, [allEntities, debouncedSearch])

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const e of allEntities) {
      c[e.entity_type] = (c[e.entity_type] ?? 0) + 1
    }
    return c
  }, [allEntities])

  return (
    <div className="flex h-full">
      <div className="flex-1 flex flex-col min-w-0 p-6 gap-4">
        <TypeFilter selected={entityType} onSelect={setEntityType} counts={counts} />

        <SearchInput
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search entities..."
          className="max-w-md"
        />

        <div className="flex-1 min-h-0">
          {isError && (
            <ErrorDisplay message={error.message} onRetry={() => refetch()} />
          )}
          {isLoading && !isError && (
            <div className="space-y-3 py-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} height="40px" />
              ))}
            </div>
          )}
          {!isLoading && !isError && (
            <EntityTable
              entities={filteredEntities}
              hasNextPage={hasNextPage ?? false}
              isFetchingNextPage={isFetchingNextPage}
              onLoadMore={fetchNextPage}
              onSelectEntity={setSelectedEntityId}
              selectedEntityId={selectedEntityId}
            />
          )}
        </div>
      </div>

      <SlideOver
        open={selectedEntityId !== null}
        onClose={() => setSelectedEntityId(null)}
        title="Entity Detail"
      >
        {selectedEntityId && <EntityDetail entityId={selectedEntityId} onNavigate={setSelectedEntityId} />}
      </SlideOver>
    </div>
  )
}
