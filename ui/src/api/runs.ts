import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from './client'
import type { PaginatedResponse } from '../lib/types'

export interface RunSummary {
  id: string
  target_id: string
  source: string
  trigger_type: string
  status: string
  scheduled_for: string | null
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
  inserted_count: number
  deduped_count: number
  error_count: number
}

export interface RunDetail extends RunSummary {
  error_message: string | null
  logs: string | null
  metadata: Record<string, unknown>
}

export function useRuns(params: {
  target_id?: string
  source?: string
  status?: string
  trigger_type?: string
  start?: string
  end?: string
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: ['runs', params],
    queryFn: async () => {
      const searchParams: Record<string, string> = {}
      if (params.target_id) searchParams.target_id = params.target_id
      if (params.source) searchParams.source = params.source
      if (params.status) searchParams.status = params.status
      if (params.trigger_type) searchParams.trigger_type = params.trigger_type
      if (params.start) searchParams.start = params.start
      if (params.end) searchParams.end = params.end
      searchParams.limit = String(params.limit ?? 50)
      searchParams.offset = String(params.offset ?? 0)
      const resp = await api.get('runs', { searchParams }).json<PaginatedResponse<RunSummary>>()
      return resp.items
    },
  })
}

export function useRun(runId: string | null) {
  return useQuery({
    queryKey: ['run', runId],
    queryFn: () => api.get(`runs/${runId}`).json<RunDetail>(),
    enabled: runId !== null,
  })
}

export function useTriggerRun() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ targetId, runner }: { targetId: string; runner: string }) =>
      api
        .post(`runs/${targetId}/${runner}`)
        .json<{ run_id: string; status: string; message: string }>(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['runs'] })
    },
  })
}
