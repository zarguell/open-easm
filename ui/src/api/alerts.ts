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

export const getAlertRules = () => api.get('alerts/rules').json<AlertRule[]>()
export const getAlertFeed = () => api.get('alerts/feed').json<AlertFeedEntry[]>()
export const acknowledgeFinding = (id: string) =>
  api.patch(`alerts/feed/${id}`).json<{ status: string }>()
