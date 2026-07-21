import { useQuery } from '@tanstack/react-query'
import api from './client'
import type { Entity } from './entities'

export interface Relationship {
  id: string
  source_entity_id: string
  target_entity_id: string
  relationship_type: string
  relationship_source: string
  first_seen_at: string
}

export interface GraphData {
  target_id: string
  max_depth: number
  nodes: (Entity & { depth: number })[]
  edges: Relationship[]
}

export function useGraph(targetId: string | null, depth = 3) {
  return useQuery({
    queryKey: ['graph', targetId, depth],
    queryFn: () =>
      api
        .get(`graph/${targetId}`, { searchParams: { depth: String(depth) } })
        .json<GraphData>(),
    enabled: targetId !== null,
  })
}
