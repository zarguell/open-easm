import api from './client'

export interface AlertRule {
  name: string
  description?: string
  enabled: boolean
  condition: string
  severity: string
}

export interface AlertFeedEntry {
  id: string
  rule_name: string
  severity: string
  title: string
  detail: string
  entity_id?: string
  created_at: string
  acknowledged: boolean
}

export interface AlertFeedParams {
  risk?: string
  status?: string
}

export const getAlertRules = () => api.get('alerts/rules').json<AlertRule[]>()
export const getAlertFeed = (params?: AlertFeedParams) => {
  const searchParams: Record<string, string> = {}
  if (params?.risk) searchParams.risk = params.risk
  if (params?.status) searchParams.status = params.status
  return api.get('alerts/feed', { searchParams }).json<AlertFeedEntry[]>()
}
export const acknowledgeFinding = (id: string) =>
  api.patch(`alerts/feed/${id}`).json<{ status: string }>()
