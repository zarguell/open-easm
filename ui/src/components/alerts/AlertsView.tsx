import { useState, useEffect, useCallback } from 'react'
import { Bell, CheckCircle, AlertTriangle, Info, Shield } from 'lucide-react'
import {
  getAlertRules,
  getAlertFeed,
  acknowledgeFinding,
  type AlertRule,
  type AlertFeedEntry,
} from '../../api/alerts'

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function severityColor(severity: string) {
  switch (severity) {
    case 'high':
      return 'bg-red-100 text-red-700'
    case 'medium':
      return 'bg-amber-100 text-amber-700'
    default:
      return 'bg-slate-100 text-slate-600'
  }
}

function severityIcon(severity: string) {
  switch (severity) {
    case 'high':
      return <AlertTriangle className="w-4 h-4 text-red-600" />
    case 'medium':
      return <Shield className="w-4 h-4 text-amber-500" />
    default:
      return <Info className="w-4 h-4 text-slate-400" />
  }
}

function formatTime(iso: string) {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

/* ------------------------------------------------------------------ */
/*  Feed tab                                                          */
/* ------------------------------------------------------------------ */
function FeedTab() {
  const [feed, setFeed] = useState<AlertFeedEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchFeed = useCallback(() => {
    setLoading(true)
    setError(null)
    getAlertFeed()
      .then(setFeed)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    fetchFeed()
  }, [fetchFeed])

  const handleAck = async (id: string) => {
    await acknowledgeFinding(id)
    setFeed((prev) =>
      prev.map((f) => (f.id === id ? { ...f, acknowledged: true } : f)),
    )
  }

  if (loading) return <p className="text-mute">Loading feed...</p>
  if (error) return <p className="text-red-500 text-sm">{error}</p>

  if (feed.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-mute">
        <Bell className="w-8 h-8 mb-2" />
        <p className="text-sm">No alerts yet</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {feed.map((entry) => (
        <div
          key={entry.id}
          className="rounded-xl border border-hairline bg-surface p-4 shadow-sm flex items-start gap-3"
        >
          <div className="shrink-0 mt-0.5">{severityIcon(entry.severity)}</div>

          <div className="flex-1 min-w-0 space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-ink">{entry.title}</span>
              <span
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${severityColor(entry.severity)}`}
              >
                {entry.severity}
              </span>
            </div>
            {entry.detail && <p className="text-xs text-mute">{entry.detail}</p>}
            <div className="flex items-center gap-3 text-[11px] text-mute">
              <span>{entry.rule_name}</span>
              <span>{formatTime(entry.created_at)}</span>
            </div>
          </div>

          <button
            onClick={() => handleAck(entry.id)}
            disabled={entry.acknowledged}
            className={`shrink-0 flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-colors cursor-pointer ${
              entry.acknowledged
                ? 'text-green-600 bg-green-50'
                : 'text-mute hover:bg-canvas-soft hover:text-ink'
            }`}
            title={entry.acknowledged ? 'Acknowledged' : 'Acknowledge'}
          >
            <CheckCircle className="w-3.5 h-3.5" />
            {entry.acknowledged ? 'Done' : 'Ack'}
          </button>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Rules tab                                                         */
/* ------------------------------------------------------------------ */
function RulesTab() {
  const [rules, setRules] = useState<AlertRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    getAlertRules()
      .then(setRules)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <p className="text-mute">Loading rules...</p>
  if (error) return <p className="text-red-500 text-sm">{error}</p>

  if (rules.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-mute">
        <Shield className="w-8 h-8 mb-2" />
        <p className="text-sm">No alert rules configured</p>
        <p className="text-xs mt-1">Add rules via config.yaml or the Config Editor</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {rules.map((rule, idx) => (
        <div
          key={idx}
          className="rounded-xl border border-hairline bg-surface p-4 shadow-sm flex items-center gap-4"
        >
          <div className="flex-1 min-w-0 space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-ink">{rule.name}</span>
              <span
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${severityColor(rule.severity)}`}
              >
                {rule.severity}
              </span>
            </div>
            {rule.description && (
              <p className="text-xs text-mute">{rule.description}</p>
            )}
            <p className="font-mono text-[11px] text-mute">{rule.condition}</p>
          </div>

          <div className="shrink-0 flex items-center gap-1.5">
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                rule.enabled ? 'bg-green-500' : 'bg-slate-300'
              }`}
            />
            <span className="text-xs text-mute">
              {rule.enabled ? 'Active' : 'Disabled'}
            </span>
          </div>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Main component                                                    */
/* ------------------------------------------------------------------ */
export function AlertsView() {
  const [tab, setTab] = useState<'feed' | 'rules'>('feed')

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold text-ink">Alerts</h1>

      {/* tabs */}
      <div className="flex gap-1 border-b border-hairline">
        {(['feed', 'rules'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium transition-colors cursor-pointer ${
              tab === t
                ? 'text-primary border-b-2 border-primary'
                : 'text-mute hover:text-ink'
            }`}
          >
            {t === 'feed' ? 'Notification Feed' : 'Alert Rules'}
          </button>
        ))}
      </div>

      {tab === 'feed' ? <FeedTab /> : <RulesTab />}
    </div>
  )
}
