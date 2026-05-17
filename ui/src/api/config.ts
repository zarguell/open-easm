import api from './client'

export interface ConfigData {
  targets: Array<Record<string, unknown>>
  saas_providers?: Record<string, unknown>
  alerts?: Record<string, unknown>
}

export const getConfig = () => api.get('config').json<ConfigData>()
export const updateConfig = (body: Partial<ConfigData>) =>
  api.put('config', { json: body }).json<{ status: string }>()
export const reloadConfig = () => api.post('config/reload').json<{ status: string }>()
