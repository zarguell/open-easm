import { useQuery } from '@tanstack/react-query'
import api from './client'

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
    queryFn: () => {
      const searchParams: Record<string, string> = {}
      if (params.target_id) searchParams.target_id = params.target_id
      if (params.source) searchParams.source = params.source
      if (params.start) searchParams.start = params.start
      if (params.end) searchParams.end = params.end
      searchParams.limit = String(params.limit ?? 50)
      if (params.cursor) searchParams.cursor = params.cursor
      return api.get('events', { searchParams }).json<EventsResponse>()
    },
  })
}
