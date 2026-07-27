import { useState, useMemo, useEffect } from 'react'
import { Filter, RefreshCw, ChevronLeft, ChevronRight, X } from 'lucide-react'
import { useFindings, usePatchFindingStatus, getFinding, listFindingRules } from '../../api/findings'
import type { Finding } from '../../api/findings'
import { SearchInput } from '../shared/SearchInput'
import { useDebounce } from '../../hooks/useDebounce'
import { formatRelativeTime, truncateMiddle } from '../../lib/format'
import { selectClass } from '../../lib/styles'
import { colors } from '../../DESIGN_TOKENS'

const riskLevels = ['', 'critical', 'high', 'medium', 'low']
const statusOptions = ['', 'open', 'acknowledged', 'resolved', 'false_positive']
const PAGE_SIZE = 25

function levelLabel(level: string) {
  if (!level) return 'All'
  return `${level.charAt(0).toUpperCase()}${level.slice(1).replace('_', ' ')}`
}

const riskColorMap: Record<string, { bg: string; text: string }> = {
  critical: { bg: `${colors.statusError}1f`, text: colors.statusError },
  high: { bg: `${colors.statusWarning}1f`, text: colors.statusWarning },
  medium: { bg: '#eab3081f', text: '#eab308' },
  low: { bg: `${colors.statusSuccess}1f`, text: colors.statusSuccess },
}

const fallbackRisk = { bg: '#6b72801f', text: '#6b7280' }

function riskBadgeColor(risk: string) {
  return riskColorMap[risk] ?? fallbackRisk
}

const statusColorMap: Record<string, { bg: string; text: string }> = {
  open: { bg: `${colors.statusRunning}1f`, text: colors.statusRunning },
  acknowledged: { bg: '#eab3081f', text: '#eab308' },
  resolved: { bg: `${colors.statusSuccess}1f`, text: colors.statusSuccess },
  false_positive: { bg: '#6b72801f', text: '#6b7280' },
}

const fallbackStatus = { bg: '#6b72801f', text: '#6b7280' }

function statusBadgeColor(status: string) {
  return statusColorMap[status] ?? fallbackStatus
}

export function FindingsView() {
  const [searchQuery, setSearchQuery] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [ruleFilter, setRuleFilter] = useState('')
  const [page, setPage] = useState(0)
  const [ruleOptions, setRuleOptions] = useState<string[]>([''])
  const [detail, setDetail] = useState<Finding | null>(null)
  const debouncedSearch = useDebounce(searchQuery)

  useEffect(() => {
    listFindingRules().then(rules => { setRuleOptions(['', ...rules]); }).catch(() => {})
  }, [])

  const params = useMemo(
    () => ({
      risk: riskFilter || undefined,
      status: statusFilter || undefined,
      rule_id: ruleFilter || undefined,
      q: debouncedSearch || undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    }),
    [riskFilter, statusFilter, ruleFilter, debouncedSearch, page]
  )

  const { data, isLoading, isError, error, refetch } = useFindings(params)
  const findings = data?.findings ?? []

  const patchMutation = usePatchFindingStatus()

  const handleStatusChange = (id: string, newStatus: string) => {
    patchMutation.mutate({ id, status: newStatus })
    if (detail?.id === id) setDetail({ ...detail, status: newStatus })
  }

  const handleRiskChange = (v: string) => { setRiskFilter(v); setPage(0) }
  const handleStatusChangeFilter = (v: string) => { setStatusFilter(v); setPage(0) }
  const handleRuleChange = (v: string) => { setRuleFilter(v); setPage(0) }
  const handleSearchChange = (v: string) => { setSearchQuery(v); setPage(0) }

  const openDetail = async (f: Finding) => {
    try {
      const d = await getFinding(f.id)
      setDetail(d)
    } catch {
      setDetail(f)
    }
  }

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-primary">
            Correlation Engine
          </div>
          <h1 className="mt-1 text-xl font-semibold leading-7 text-ink">Findings</h1>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isLoading}
          className="inline-flex items-center gap-2 rounded-sm border border-hairline bg-canvas px-4 py-2 text-sm font-semibold text-ink hover:opacity-90 transition-colors disabled:opacity-50 cursor-pointer"
        >
          <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="grid gap-3 rounded-md border border-hairline bg-canvas p-4 lg:grid-cols-[minmax(260px,1fr)_160px_160px_180px]">
        <SearchInput
          value={searchQuery}
          onChange={(e) => { handleSearchChange(e.target.value); }}
          placeholder="Search findings..."
          className="min-w-0"
        />
        <label className="grid gap-1">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Type</span>
          <select className={selectClass} value={ruleFilter} onChange={(e) => { handleRuleChange(e.target.value); }}>
            {ruleOptions.map((r) => (
              <option key={r || 'all'} value={r}>{r ? r.replace(/_/g, ' ') : 'All'}</option>
            ))}
          </select>
        </label>
        <label className="grid gap-1">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Risk</span>
          <select className={selectClass} value={riskFilter} onChange={(e) => { handleRiskChange(e.target.value); }}>
            {riskLevels.map((level) => (
              <option key={level || 'all'} value={level}>{levelLabel(level)}</option>
            ))}
          </select>
        </label>
        <label className="grid gap-1">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Status</span>
          <select className={selectClass} value={statusFilter} onChange={(e) => { handleStatusChangeFilter(e.target.value); }}>
            {statusOptions.map((s) => (
              <option key={s || 'all'} value={s}>{levelLabel(s)}</option>
            ))}
          </select>
        </label>
      </div>

      {/* Split: findings list + detail panel */}
      <div className="flex flex-1 gap-4 min-h-0">
        {/* List */}
        <div className="flex min-h-0 flex-1 flex-col gap-3 min-w-0">
          <div className="flex items-center justify-between gap-3 text-sm">
            <div className="flex items-center gap-2 text-mute">
              <Filter className="h-4 w-4" />
              <span>Showing <span className="font-mono text-ink">{findings.length}</span> findings</span>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => { setPage(p => Math.max(0, p - 1)); }} disabled={page === 0}
                className="p-1 rounded border border-hairline text-mute hover:text-ink disabled:opacity-30 cursor-pointer">
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-xs text-mute font-mono">Page {page + 1}</span>
              <button onClick={() => { setPage(p => p + 1); }} disabled={findings.length < PAGE_SIZE}
                className="p-1 rounded border border-hairline text-mute hover:text-ink disabled:opacity-30 cursor-pointer">
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>

          {isError && <p className="text-red-500 text-sm">{error?.message ?? 'Unknown error'}</p>}
          {isLoading && !isError && <p className="text-mute text-sm">Loading findings...</p>}
          {!isLoading && !isError && findings.length === 0 && (
            <div className="flex items-center justify-center py-20 text-sm text-mute">No findings match the current filters</div>
          )}
          {!isLoading && !isError && findings.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-canvas-soft">
                    <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">Headline</th>
                    <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">Risk</th>
                    <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">Rule</th>
                    <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">Status</th>
                    <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">Created</th>
                    <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute"></th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map(f => {
                    const riskStyle = riskBadgeColor(f.risk)
                    const statusStyle = statusBadgeColor(f.status)
                    const isSelected = detail?.id === f.id
                    return (
                      <tr key={f.id} className={`border-b border-hairline transition-colors cursor-pointer ${isSelected ? 'bg-primary/5' : 'hover:bg-canvas-soft'}`}
                          onClick={() => openDetail(f)}>
                        <td className="px-4 py-2 text-sm text-ink max-w-xs truncate">{f.headline}</td>
                        <td className="px-4 py-2">
                          <span className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase"
                                style={{ backgroundColor: riskStyle.bg, color: riskStyle.text }}>{f.risk}</span>
                        </td>
                        <td className="px-4 py-2 font-mono text-xs text-mute">{truncateMiddle(f.rule_id, 24)}</td>
                        <td className="px-4 py-2">
                          <span className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase"
                                style={{ backgroundColor: statusStyle.bg, color: statusStyle.text }}>{f.status.replace('_', ' ')}</span>
                        </td>
                        <td className="px-4 py-2 text-sm text-mute">{f.created_at ? formatRelativeTime(f.created_at) : ''}</td>
                        <td className="px-4 py-2">
                          <select value={f.status} onClick={e => { e.stopPropagation(); }}
                            onChange={e => handleStatusChange(f.id, e.target.value)}
                            className="rounded-sm border border-hairline bg-canvas-soft px-2 py-1 text-xs text-ink focus:outline-none focus:ring-1 focus:ring-primary cursor-pointer">
                            <option value="open">Open</option>
                            <option value="acknowledged">Acknowledged</option>
                            <option value="resolved">Resolved</option>
                            <option value="false_positive">False Positive</option>
                          </select>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Detail Panel */}
        {detail && (
          <div className="w-96 shrink-0 border-l border-hairline pl-4 overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Finding Detail</span>
              <button onClick={() => { setDetail(null); }} className="p-1 text-mute hover:text-ink cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <p className="text-sm text-ink font-medium leading-snug">{detail.headline}</p>
              </div>
              {detail.entity_ids && detail.entity_ids.length > 0 && (
                <div>
                  <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute block mb-1">Affected Asset</span>
                  <div className="flex flex-col gap-1">
                    {detail.entity_ids.map(eid => (
                      <span key={eid} className="font-mono text-xs text-primary bg-primary/5 px-2 py-1 rounded-md truncate">{eid}</span>
                    ))}
                  </div>
                </div>
              )}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <span className="text-mute block">Rule</span>
                  <span className="font-mono text-ink">{detail.rule_id}</span>
                </div>
                <div>
                  <span className="text-mute block">Risk</span>
                  <span className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase"
                        style={{ backgroundColor: riskBadgeColor(detail.risk).bg, color: riskBadgeColor(detail.risk).text }}>{detail.risk}</span>
                </div>
                <div>
                  <span className="text-mute block">Status</span>
                  <span className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase"
                        style={{ backgroundColor: statusBadgeColor(detail.status).bg, color: statusBadgeColor(detail.status).text }}>{detail.status.replace('_', ' ')}</span>
                </div>
                <div>
                  <span className="text-mute block">Confidence</span>
                  <span className="text-ink">{detail.confidence_level ?? 'unknown'}</span>
                </div>
              </div>
              {detail.evidence && (
                <div>
                  <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute block mb-1">Evidence</span>
                  <pre className="text-xs text-mute bg-canvas-soft rounded-md p-3 overflow-x-auto whitespace-pre-wrap max-h-96">
                    {JSON.stringify(detail.evidence, null, 2)}
                  </pre>
                </div>
              )}
              {detail.description && (
                <div>
                  <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute block mb-1">Description</span>
                  <p className="text-sm text-body">{detail.description}</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
