import { useQuery } from '@tanstack/react-query'
import api from './client'
import type { PaginatedResponse } from '../lib/types'

export interface CertificateInventoryItem {
  entity_id: string
  fingerprint_sha256: string | null
  subject_cn: string | null
  issuer_organization: string | null
  not_before: string | null
  not_after: string | null
  validity_state: string | null
  deployment_state: string | null
  observed_endpoints: unknown[]
  risk: string | null
  reasons: string[]
  strength: string | null
  san_dns_names: string[]
  subject_source: 'cn' | 'san'
}

export interface CertificateSummary {
  total: number
  by_risk: Record<string, number>
  by_deployment_state: Record<string, number>
  by_issuer_organization: Record<string, number>
}

export interface CertificateInventoryParams {
  target_id?: string
  deployment_state?: string
  risk?: string
  limit?: number
  offset?: number
}

export interface CertificateInventoryResponse {
  certificates: CertificateInventoryItem[]
  total: number
}

function cleanParams(params: Record<string, string | number | undefined>) {
  const searchParams: Record<string, string> = {}
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) searchParams[key] = String(value)
  }
  return searchParams
}

export function useCertificateInventory(params: CertificateInventoryParams = {}) {
  return useQuery({
    queryKey: ['certificate-inventory', params],
    queryFn: async () => {
      const resp = await api
        .get('certificates/inventory', {
          searchParams: cleanParams({
            target_id: params.target_id,
            deployment_state: params.deployment_state,
            risk: params.risk,
            limit: params.limit ?? 100,
            offset: params.offset ?? 0,
          }),
        })
        .json<PaginatedResponse<CertificateInventoryItem>>()
      return { certificates: resp.items, total: resp.total }
    },
  })
}

export function useCertificateSummary(targetId?: string) {
  return useQuery({
    queryKey: ['certificate-summary', targetId],
    queryFn: () =>
      api
        .get('certificates/summary', {
          searchParams: cleanParams({ target_id: targetId }),
        })
        .json<CertificateSummary>(),
  })
}
