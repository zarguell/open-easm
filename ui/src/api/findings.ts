import { useState, useEffect, useCallback } from 'react'
import ky from 'ky'

const api = ky.create({
  prefix: '/api',
  headers: { Accept: 'application/json' },
  timeout: 30_000,
})

export interface Finding {
  id: string
  org_id: string
  target_id: string
  rule_id: string
  risk: string
  headline: string
  description: string
  entity_ids: string[]
  evidence: Record<string, unknown>
  status: string
  first_seen_at: string | null
  last_seen_at: string | null
  created_at: string | null
}

export interface FindingsResponse {
  findings: Finding[]
}

export interface FindingsParams {
  target_id?: string
  risk?: string
  status?: string
  rule_id?: string
  q?: string
  limit?: number
  offset?: number
}

export function useFindings(params: FindingsParams) {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchFindings = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const searchParams: Record<string, string> = {}
      if (params.target_id) searchParams.target_id = params.target_id
      if (params.risk) searchParams.risk = params.risk
      if (params.status) searchParams.status = params.status
      if (params.rule_id) searchParams.rule_id = params.rule_id
      if (params.q) searchParams.q = params.q
      searchParams.limit = String(params.limit ?? 50)
      searchParams.offset = String(params.offset ?? 0)
      const data = await api.get('findings', { searchParams }).json<FindingsResponse>()
      setFindings(data.findings)
    } catch (e: any) {
      setError(e.message ?? 'Failed to fetch findings')
    } finally {
      setLoading(false)
    }
  }, [params.target_id, params.risk, params.status, params.rule_id, params.q, params.limit, params.offset])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  return { findings, loading, error, refetch: fetchFindings }
}

export async function patchFindingStatus(id: string, status: string): Promise<Finding> {
  return api.patch(`findings/${id}`, { json: { status } }).json<Finding>()
}
