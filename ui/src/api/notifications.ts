import api from './client'

export interface NotificationChannel {
  name: string
  type: string
  enabled: boolean
  min_severity: string
}

export interface ChannelsResponse {
  channels: NotificationChannel[]
}

export async function fetchChannels(): Promise<ChannelsResponse> {
  return api.get('notifications/channels').json<ChannelsResponse>()
}

export async function sendTestNotification(channelName: string): Promise<{ status: string; channel: string }> {
  return api.post('notifications/test', { json: { channel_name: channelName } }).json()
}
