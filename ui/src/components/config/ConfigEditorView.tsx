import { useState, useEffect, useCallback } from 'react'
import { Save, ChevronDown, ChevronRight, Loader2 } from 'lucide-react'
import { getConfig, updateConfig, reloadConfig, type ConfigData } from '../../api/config'

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v))
}


function Field({
  label,
  value,
  onChange,
  multiline = false,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  multiline?: boolean
}) {
  const cls =
    'w-full rounded-md border border-hairline bg-canvas px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-primary'
  return (
    <label className="block space-y-1">
      <span className="text-xs font-medium text-mute">{label}</span>
      {multiline ? (
        <textarea className={cls} rows={3} value={value} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input className={cls} value={value} onChange={(e) => onChange(e.target.value)} />
      )}
    </label>
  )
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${
        checked ? 'bg-primary' : 'bg-hairline'
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${
          checked ? 'translate-x-4' : 'translate-x-0'
        }`}
      />
    </button>
  )
}


export function ConfigEditorView() {
  const [config, setConfig] = useState<ConfigData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [collapsed, setCollapsed] = useState<Record<number, boolean>>({})

  const fetchConfig = useCallback(() => {
    setLoading(true)
    setError(null)
    getConfig()
      .then(setConfig)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    fetchConfig()
  }, [fetchConfig])

  const updateTarget = useCallback(
    (idx: number, patch: Record<string, unknown>) => {
      if (!config) return
      const next = clone(config)
      Object.assign(next.targets[idx] as Record<string, unknown>, patch)
      setConfig(next)
    },
    [config],
  )

  const updateNested = useCallback(
    (idx: number, key: string, patch: Record<string, unknown>) => {
      if (!config) return
      const next = clone(config)
      const target = next.targets[idx] as Record<string, Record<string, unknown>>
      target[key] = { ...(target[key] as Record<string, unknown>), ...patch }
      setConfig(next)
    },
    [config],
  )

  const updateRunnerField = useCallback(
    (targetIdx: number, runner: string, field: string, value: unknown) => {
      if (!config) return
      const next = clone(config)
      const target = next.targets[targetIdx] as Record<string, Record<string, Record<string, unknown>>>
      const runners = { ...(target.runners as Record<string, Record<string, unknown>>) }
      runners[runner] = { ...runners[runner], [field]: value }
      target.runners = runners
      setConfig(next)
    },
    [config],
  )

  const updatePivot = useCallback(
    (targetIdx: number, patch: Record<string, unknown>) => {
      if (!config) return
      const next = clone(config)
      const target = next.targets[targetIdx] as Record<string, Record<string, unknown>>
      target.pivot = { ...(target.pivot as Record<string, unknown>), ...patch }
      setConfig(next)
    },
    [config],
  )

  const handleSave = async () => {
    if (!config) return
    setSaving(true)
    try {
      await updateConfig(config)
      await reloadConfig()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <p className="text-mute">Loading config...</p>
  }

  if (error && !config) {
    return (
      <div className="space-y-2">
        <p className="text-red-500 text-sm">{error}</p>
        <button
          onClick={fetchConfig}
          className="text-sm text-primary hover:underline cursor-pointer"
        >
          Retry
        </button>
      </div>
    )
  }

  if (!config) return null

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-ink">Config Editor</h1>
        <button
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50 cursor-pointer"
        >
          {saving ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Save className="w-4 h-4" />
          )}
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>

      {error && <p className="text-red-500 text-sm">{error}</p>}

      <section>
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
          Targets
        </span>
        <div className="mt-2 space-y-4">
          {config.targets.map((raw, idx) => {
            const t = raw as Record<string, unknown>
            const matchRules = (t.match_rules ?? {}) as Record<string, unknown>
            const runners = (t.runners ?? {}) as Record<string, Record<string, unknown>>
            const pivot = (t.pivot ?? {}) as Record<string, unknown>
            const allowedPivots = (pivot.allowed_pivots ?? []) as Array<Record<string, unknown>>
            const isCollapsed = collapsed[idx] ?? false

            return (
              <div
                key={idx}
                className="rounded-xl border border-hairline bg-surface p-4 shadow-sm space-y-4"
              >
                <button
                  className="flex items-center gap-2 w-full text-left cursor-pointer"
                  onClick={() => setCollapsed((c) => ({ ...c, [idx]: !c[idx] }))}
                >
                  {isCollapsed ? (
                    <ChevronRight className="w-4 h-4 text-mute shrink-0" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-mute shrink-0" />
                  )}
                  <span className="font-medium text-ink">
                    {String(t.name ?? t.id ?? `Target ${idx + 1}`)}
                  </span>
                  <span className="text-xs text-mute ml-auto">{String(t.type ?? '')}</span>
                </button>

                {!isCollapsed && (
                  <>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Field label="ID" value={String(t.id ?? '')} onChange={(v) => updateTarget(idx, { id: v })} />
                      <Field label="Name" value={String(t.name ?? '')} onChange={(v) => updateTarget(idx, { name: v })} />
                      <Field label="Type" value={String(t.type ?? '')} onChange={(v) => updateTarget(idx, { type: v })} />
                    </div>

                    <div className="flex items-center gap-3">
                      <Toggle
                        checked={!!t.enabled}
                        onChange={(v) => updateTarget(idx, { enabled: v })}
                      />
                      <span className="text-sm text-ink">Enabled</span>
                    </div>

                    <div className="space-y-2">
                      <span className="text-xs font-semibold text-mute uppercase tracking-wide">
                        Match Rules
                      </span>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <Field
                          label="Domains (comma-separated)"
                          value={(matchRules.domains as string[] ?? []).join(', ')}
                          onChange={(v) =>
                            updateNested(idx, 'match_rules', {
                              domains: v.split(',').map((s) => s.trim()).filter(Boolean),
                            })
                          }
                        />
                        <Field
                          label="Keywords (comma-separated)"
                          value={(matchRules.keywords as string[] ?? []).join(', ')}
                          onChange={(v) =>
                            updateNested(idx, 'match_rules', {
                              keywords: v.split(',').map((s) => s.trim()).filter(Boolean),
                            })
                          }
                        />
                        <Field
                          label="ASNs (comma-separated)"
                          value={(matchRules.asns as string[] ?? []).join(', ')}
                          onChange={(v) =>
                            updateNested(idx, 'match_rules', {
                              asns: v.split(',').map((s) => s.trim()).filter(Boolean),
                            })
                          }
                        />
                        <Field
                          label="IP Ranges (comma-separated)"
                          value={(matchRules.ip_ranges as string[] ?? []).join(', ')}
                          onChange={(v) =>
                            updateNested(idx, 'match_rules', {
                              ip_ranges: v.split(',').map((s) => s.trim()).filter(Boolean),
                            })
                          }
                        />
                      </div>
                    </div>

                    <div className="space-y-2">
                      <span className="text-xs font-semibold text-mute uppercase tracking-wide">
                        Runners
                      </span>
                      <div className="space-y-3">
                        {Object.entries(runners).map(([name, cfg]) => (
                          <div
                            key={name}
                            className="rounded-lg border border-hairline bg-canvas p-3 space-y-2"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-sm font-medium text-ink">{name}</span>
                              <Toggle
                                checked={!!cfg.enabled}
                                onChange={(v) => updateRunnerField(idx, name, 'enabled', v)}
                              />
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              <Field
                                label="Schedule"
                                value={String(cfg.schedule ?? '')}
                                onChange={(v) => updateRunnerField(idx, name, 'schedule', v)}
                              />
                              <Field
                                label="Mode / Args"
                                value={String(cfg.mode ?? cfg.args ?? '')}
                                onChange={(v) => {
                                  const key = cfg.mode !== undefined ? 'mode' : 'args'
                                  updateRunnerField(idx, name, key, v)
                                }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <span className="text-xs font-semibold text-mute uppercase tracking-wide">
                        Pivots
                      </span>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-2">
                        <Field
                          label="Enabled"
                          value={String(pivot.enabled ?? 'true')}
                          onChange={(v) => updatePivot(idx, { enabled: v === 'true' })}
                        />
                        <Field
                          label="Max Depth"
                          value={String(pivot.max_depth ?? '')}
                          onChange={(v) => updatePivot(idx, { max_depth: Number(v) || 0 })}
                        />
                        <Field
                          label="Max Concurrent"
                          value={String(pivot.max_concurrent ?? '')}
                          onChange={(v) => updatePivot(idx, { max_concurrent: Number(v) || 0 })}
                        />
                      </div>

                      {allowedPivots.length > 0 && (
                        <div className="overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="text-left text-xs text-mute">
                                <th className="pb-1 pr-4 font-medium">From</th>
                                <th className="pb-1 pr-4 font-medium">To</th>
                                <th className="pb-1 font-medium">Via</th>
                              </tr>
                            </thead>
                            <tbody>
                              {allowedPivots.map((p, pi) => (
                                <tr key={pi} className="border-t border-hairline">
                                  <td className="py-1 pr-4 text-ink">{String(p.from ?? '')}</td>
                                  <td className="py-1 pr-4 text-ink">{String(p.to ?? '')}</td>
                                  <td className="py-1 text-ink">{String(p.via ?? '')}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            )
          })}
        </div>
      </section>
    </div>
  )
}
