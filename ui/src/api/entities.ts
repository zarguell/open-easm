import { useQuery, useInfiniteQuery } from '@tanstack/react-query'
import api from './client'

export interface Entity {
  id: string
  org_id: string
  target_id: string
  entity_type: string
  entity_value: string
  attributes: Record<string, unknown>
  first_seen_at: string
  last_seen_at: string
  is_first_discovery: boolean
}

export interface EntityDetail extends Entity {
  raw_event_ids: string[]
}

export interface Relationship {
  id: string
  source_entity_id: string
  target_entity_id: string
  relationship_type: string
  relationship_source: string
  first_seen_at: string
  source_entity_value: string
  source_entity_type: string
  target_entity_value: string
  target_entity_type: string
}

export interface EntitiesResponse {
  entities: Entity[]
  next_cursor: string | null
  total_count: number
}

export function useEntities(params: {
  target_id?: string
  entity_type?: string
  first_seen_since?: string
  last_seen_before?: string
  q?: string
  limit?: number
  cursor?: string
}) {
  return useInfiniteQuery({
    queryKey: ['entities', params],
    queryFn: async ({ pageParam }) => {
      const searchParams: Record<string, string> = {}
      if (params.target_id) searchParams.target_id = params.target_id
      if (params.entity_type) searchParams.entity_type = params.entity_type
      if (params.first_seen_since) searchParams.first_seen_since = params.first_seen_since
      if (params.last_seen_before) searchParams.last_seen_before = params.last_seen_before
      if (params.q) searchParams.q = params.q
      searchParams.limit = String(params.limit ?? 50)
      if (pageParam) searchParams.cursor = pageParam as string
      return api.get('entities', { searchParams }).json<EntitiesResponse>()
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  })
}

export function useEntityCounts(targetId?: string) {
  return useQuery({
    queryKey: ['entity-counts', targetId],
    queryFn: () => {
      const searchParams: Record<string, string> = {}
      if (targetId) searchParams.target_id = targetId
      return api.get('entities/counts', { searchParams }).json<{ counts: Record<string, number> }>()
    },
  })
}

export function useEntity(entityId: string | null) {
  return useQuery({
    queryKey: ['entity', entityId],
    queryFn: () => api.get(`entities/${entityId}`).json<EntityDetail>(),
    enabled: entityId !== null,
  })
}

export function useEntityRelationships(entityId: string | null) {
  return useQuery({
    queryKey: ['entity-relationships', entityId],
    queryFn: () =>
      api.get(`entities/${entityId}/relationships`).json<{ relationships: Relationship[] }>(),
    enabled: entityId !== null,
  })
}

export interface LineageEntity {
  id: string
  entity_type: string
  entity_value: string
  discovered_by: string | null
  first_seen_at: string | null
}

export interface LineageRelationship {
  type: string
  runner: string | null
}

export interface LineageAncestor {
  entity: LineageEntity
  connects_to_entity_id: string
  relationship: LineageRelationship
  depth: number
}

export interface LineageResponse {
  entity: LineageEntity
  ancestors: LineageAncestor[]
}

export function useEntityLineage(entityId: string | null) {
  return useQuery({
    queryKey: ['entity-lineage', entityId],
    queryFn: () => api.get(`entities/${entityId}/lineage`).json<LineageResponse>(),
    enabled: entityId !== null,
  })
}
