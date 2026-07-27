import { useQuery } from '@tanstack/react-query'
import api from './client'
import type { PaginatedResponse } from '../lib/types'

export interface AssetInventoryItem {
  entity_id: string
  org_id: string
  target_id: string
  entity_type: string
  entity_value: string
  first_seen_at: string | null
  last_seen_at: string | null
  confidence_score: number | null
  confidence_level: string | null
  risk_score: number | null
  risk_level: string | null
  feed_eligible: boolean
  sources: string[]
  evidence_count: number
}

export interface AssetChangeEvent {
  id: string
  org_id: string
  target_id: string
  entity_id: string
  change_type: string
  summary: string
  before_state: Record<string, unknown>
  after_state: Record<string, unknown>
  evidence: unknown[]
  source: string
  observed_at: string | null
  created_at: string | null
}

export interface AssetInventoryParams {
  target_id?: string
  confidence_level?: string
  risk_level?: string
  feed_eligible?: boolean
  limit?: number
  offset?: number
}

export interface AssetChangesParams {
  target_id?: string
  entity_id?: string
  limit?: number
  offset?: number
}

export interface AssetInventoryResponse {
  assets: AssetInventoryItem[]
  total_count: number
}

export interface AssetChangesResponse {
  changes: AssetChangeEvent[]
}

function cleanParams(params: Record<string, string | number | boolean | undefined>) {
  const searchParams: Record<string, string> = {}
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) searchParams[key] = String(value)
  }
  return searchParams
}

export function useAssetInventory(params: AssetInventoryParams = {}) {
  return useQuery({
    queryKey: ['asset-inventory', params],
    queryFn: async () => {
      const resp = await api
        .get('assets/inventory', {
          searchParams: cleanParams({
            target_id: params.target_id,
            confidence_level: params.confidence_level,
            risk_level: params.risk_level,
            feed_eligible: params.feed_eligible,
            limit: params.limit ?? 100,
            offset: params.offset ?? 0,
          }),
        })
        .json<PaginatedResponse<AssetInventoryItem>>()
      return { assets: resp.items, total_count: resp.total }
    },
  })
}

export function useAssetChanges(params: AssetChangesParams = {}) {
  return useQuery({
    queryKey: ['asset-changes', params],
    queryFn: () =>
      api
        .get('assets/changes', {
          searchParams: cleanParams({
            target_id: params.target_id,
            entity_id: params.entity_id,
            limit: params.limit ?? 100,
            offset: params.offset ?? 0,
          }),
        })
        .json<AssetChangesResponse>(),
  })
}

export function assetExportPath(targetId?: string) {
  const search = targetId ? `?target_id=${encodeURIComponent(targetId)}` : ''
  return `/api/assets/export.ndjson${search}`
}
