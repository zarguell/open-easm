import { useQuery } from '@tanstack/react-query'
import api from './client'
import type { PaginatedResponse } from '../lib/types'

export interface EventSummary {
  id: string
  target_id: string
  source: string
  event_type: string
  entity_type: string
  entity_value: string
  attributes: Record<string, unknown>
  timestamp: string
}

export interface EventsResponse {
  events: EventSummary[]
  next_cursor: string | null
  total: number
}

export function useEvents(params: {
  target_id?: string
  source?: string
  start?: string
  end?: string
  limit?: number
  cursor?: string
}) {
  return useQuery({
    queryKey: ['events', params],
    queryFn: async () => {
      const searchParams: Record<string, string> = {}
      if (params.target_id) searchParams.target_id = params.target_id
      if (params.source) searchParams.source = params.source
      if (params.start) searchParams.start = params.start
      if (params.end) searchParams.end = params.end
      searchParams.limit = String(params.limit ?? 50)
      if (params.cursor) searchParams.cursor = params.cursor
      const resp = await api.get('events', { searchParams }).json<PaginatedResponse<EventSummary>>()
      return { events: resp.items, next_cursor: resp.next_cursor, total: resp.total }
    },
  })
}
