import { useQuery } from '@tanstack/react-query'
import api from './client'

export interface RunnerInfo {
  enabled: boolean
  schedule: string | null
  last_run_id?: string
  last_run_status?: string
}

export interface TargetSummary {
  id: string
  name: string
  type: string
  enabled: boolean
  labels: Record<string, string>
  runners: Record<string, RunnerInfo>
}

export function useTargets() {
  return useQuery({
    queryKey: ['targets'],
    queryFn: () => api.get('targets').json<TargetSummary[]>(),
  })
}

export function useTarget(targetId: string | null) {
  return useQuery({
    queryKey: ['target', targetId],
    queryFn: () =>
      api
        .get(`targets/${targetId}`)
        .json<TargetSummary & { match_rules: Record<string, unknown>; runners: Record<string, unknown> }>(),
    enabled: targetId !== null,
  })
}
