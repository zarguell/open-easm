import { useState, useEffect, useCallback } from 'react'
import { Bell, Send, Loader2, CheckCircle2, XCircle, Radio } from 'lucide-react'
import {
  fetchChannels,
  sendTestNotification,
  type NotificationChannel,
} from '../../api/notifications'

type TestStatus = 'idle' | 'loading' | 'success' | 'error'

export function NotificationSettings() {
  const [channels, setChannels] = useState<NotificationChannel[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [testStatus, setTestStatus] = useState<Record<string, TestStatus>>({})
  const [testError, setTestError] = useState<Record<string, string>>({})

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchChannels()
      setChannels(data.channels)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load channels')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const handleTest = async (channelName: string) => {
    setTestStatus((s) => ({ ...s, [channelName]: 'loading' }))
    setTestError((e) => ({ ...e, [channelName]: '' }))
    try {
      await sendTestNotification(channelName)
      setTestStatus((s) => ({ ...s, [channelName]: 'success' }))
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Test failed'
      setTestStatus((s) => ({ ...s, [channelName]: 'error' }))
      setTestError((e) => ({ ...e, [channelName]: msg }))
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-mute text-sm">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>Loading channels...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-2">
        <p className="text-red-500 text-sm">{error}</p>
        <button
          onClick={load}
          className="text-sm text-primary hover:underline cursor-pointer"
        >
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Bell className="w-5 h-5 text-primary" />
        <h1 className="text-lg font-semibold text-ink">Notification Channels</h1>
      </div>

      {channels.length === 0 ? (
        <div className="rounded-xl border border-hairline bg-canvas-elevated p-8 text-center">
          <Radio className="w-10 h-10 text-mute mx-auto mb-3" />
          <p className="text-mute text-sm">No notification channels configured.</p>
          <p className="text-mute text-xs mt-2">
            Add channels under the <code className="text-primary bg-canvas-soft px-1.5 py-0.5 rounded text-[11px] font-mono">notifications:</code> section in{' '}
            <code className="text-primary bg-canvas-soft px-1.5 py-0.5 rounded text-[11px] font-mono">config.yaml</code>, then reload config.
          </p>
        </div>
      ) : (
        <div className="rounded-xl border border-hairline bg-canvas-elevated overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-hairline text-left text-[11px] font-semibold uppercase tracking-wider text-mute">
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Enabled</th>
                  <th className="px-4 py-3">Min Severity</th>
                  <th className="px-4 py-3 text-right">Test</th>
                </tr>
              </thead>
              <tbody>
                {channels.map((ch) => {
                  const status = testStatus[ch.name] ?? 'idle'
                  const err = testError[ch.name] ?? ''
                  return (
                    <tr
                      key={ch.name}
                      className="border-b border-hairline last:border-b-0 hover:bg-canvas-soft transition-colors"
                    >
                      <td className="px-4 py-3">
                        <span className="font-mono text-ink font-medium">{ch.name}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1.5 rounded-md bg-canvas-soft px-2 py-0.5 text-xs font-mono text-body">
                          {ch.type}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {ch.enabled ? (
                          <span className="inline-flex items-center gap-1 text-statusSuccess text-xs font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-statusSuccess" />
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-mute text-xs font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-mute" />
                            Disabled
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-body capitalize text-xs">{ch.min_severity}</span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {status === 'error' && err && (
                            <span className="text-[11px] text-red-400 max-w-[200px] truncate" title={err}>
                              {err}
                            </span>
                          )}
                          {status === 'success' && (
                            <CheckCircle2 className="w-4 h-4 text-statusSuccess" />
                          )}
                          <button
                            onClick={() => handleTest(ch.name)}
                            disabled={status === 'loading' || !ch.enabled}
                            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer ${
                              !ch.enabled
                                ? 'text-mute bg-canvas-soft opacity-50 cursor-not-allowed'
                                : status === 'loading'
                                  ? 'text-mute bg-canvas-soft cursor-wait'
                                  : 'text-primary bg-canvas-soft hover:bg-primary hover:text-onPrimary'
                            }`}
                            title={!ch.enabled ? 'Channel is disabled' : 'Send test notification'}
                          >
                            {status === 'loading' ? (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            ) : status === 'success' ? (
                              <CheckCircle2 className="w-3 h-3" />
                            ) : status === 'error' ? (
                              <XCircle className="w-3 h-3" />
                            ) : (
                              <Send className="w-3 h-3" />
                            )}
                            Test
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {channels.length > 0 && (
        <p className="text-mute text-xs">
          To add or modify channels, edit the{' '}
          <code className="text-primary bg-canvas-soft px-1.5 py-0.5 rounded text-[11px] font-mono">notifications:</code>{' '}
          section in <code className="text-primary bg-canvas-soft px-1.5 py-0.5 rounded text-[11px] font-mono">config.yaml</code> and reload.
        </p>
      )}
    </div>
  )
}
