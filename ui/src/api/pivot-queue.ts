import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from './client'

export interface PivotJob {
  id: string
  org_id: string
  target_id: string
  entity_type: string
  entity_value: string
  entity_id: string
  pivot_type: string
  depth: number
  parent_entity_id: string | null
  discovery_session_id: string | null
  status: string
  enqueued_at: string
  started_at: string | null
  completed_at: string | null
  run_id: string | null
  error_message: string | null
  skip_reason: string | null
}

export interface PivotQueueResponse {
  jobs: PivotJob[]
  next_cursor: string | null
}

export interface PivotQueueParams {
  status?: string
  target_id?: string
  entity_type?: string
  pivot_type?: string
  limit?: number
  cursor?: string
}

export interface TriggerPivotRequest {
  target_id: string
  entity_type: string
  entity_value: string
  pivot_type: string
  org_id?: string
  depth?: number
}

export function usePivotQueue(params: PivotQueueParams = {}) {
  return useQuery({
    queryKey: ['pivot-queue', params],
    queryFn: () => {
      const searchParams: Record<string, string> = {}
      if (params.status) searchParams.status = params.status
      if (params.target_id) searchParams.target_id = params.target_id
      if (params.entity_type) searchParams.entity_type = params.entity_type
      if (params.pivot_type) searchParams.pivot_type = params.pivot_type
      searchParams.limit = String(params.limit ?? 50)
      if (params.cursor) searchParams.cursor = params.cursor
      return api.get('pivot-queue', { searchParams }).json<PivotQueueResponse>()
    },
  })
}

export function useTriggerPivot() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (req: TriggerPivotRequest) =>
      api.post('pivot-queue/trigger', { json: req }).json<{ job_id: string; status: string }>(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pivot-queue'] }),
  })
}

export function useRetryPivot() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (jobId: string) =>
      api.post(`pivot-queue/${jobId}/retry`).json<{ job_id: string; status: string }>(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pivot-queue'] }),
  })
}
