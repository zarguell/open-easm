import { useState, useMemo } from 'react'
import { Filter, RefreshCw, ChevronLeft, ChevronRight } from 'lucide-react'
import { useFindings, patchFindingStatus } from '../../api/findings'
import { SearchInput } from '../shared/SearchInput'
import { useDebounce } from '../../hooks/useDebounce'
import { formatRelativeTime, truncateMiddle } from '../../lib/format'

const riskLevels = ['', 'critical', 'high', 'medium', 'low']
const statusOptions = ['', 'open', 'acknowledged', 'resolved', 'false_positive']
const PAGE_SIZE = 25

const selectClass =
  'h-10 rounded-sm border border-hairline bg-canvas-soft px-3 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-primary'

function levelLabel(level: string) {
  if (!level) return 'All'
  return `${level.charAt(0).toUpperCase()}${level.slice(1).replace('_', ' ')}`
}

function riskBadgeColor(risk: string) {
  switch (risk) {
    case 'critical':
      return { bg: '#ef44441f', text: '#ef4444' }
    case 'high':
      return { bg: '#f973161f', text: '#f97316' }
    case 'medium':
      return { bg: '#eab3081f', text: '#eab308' }
    case 'low':
      return { bg: '#22c55e1f', text: '#22c55e' }
    default:
      return { bg: '#6b72801f', text: '#6b7280' }
  }
}

function statusBadgeColor(status: string) {
  switch (status) {
    case 'open':
      return { bg: '#3b82f61f', text: '#3b82f6' }
    case 'acknowledged':
      return { bg: '#eab3081f', text: '#eab308' }
    case 'resolved':
      return { bg: '#22c55e1f', text: '#22c55e' }
    case 'false_positive':
      return { bg: '#6b72801f', text: '#6b7280' }
    default:
      return { bg: '#6b72801f', text: '#6b7280' }
  }
}

export function FindingsView() {
  const [searchQuery, setSearchQuery] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(0)
  const debouncedSearch = useDebounce(searchQuery)

  const params = useMemo(
    () => ({
      risk: riskFilter || undefined,
      status: statusFilter || undefined,
      q: debouncedSearch || undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    }),
    [riskFilter, statusFilter, debouncedSearch, page]
  )

  const { findings, loading, error, refetch } = useFindings(params)

  const handleStatusChange = async (id: string, newStatus: string) => {
    await patchFindingStatus(id, newStatus)
    refetch()
  }

  const handleRiskChange = (v: string) => { setRiskFilter(v); setPage(0) }
  const handleStatusChangeFilter = (v: string) => { setStatusFilter(v); setPage(0) }
  const handleSearchChange = (v: string) => { setSearchQuery(v); setPage(0) }

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-primary">
            Correlation Engine
          </div>
          <h1 className="mt-1 text-xl font-semibold leading-7 text-ink">Findings</h1>
        </div>
        <button
          onClick={() => refetch()}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-sm border border-hairline bg-canvas px-4 py-2 text-sm font-semibold text-ink hover:opacity-90 transition-colors disabled:opacity-50 cursor-pointer"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      <div className="grid gap-3 rounded-md border border-hairline bg-canvas p-4 lg:grid-cols-[minmax(260px,1fr)_160px_180px]">
        <SearchInput
          value={searchQuery}
          onChange={(e) => handleSearchChange(e.target.value)}
          placeholder="Search findings..."
          className="min-w-0"
        />
        <label className="grid gap-1">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Risk</span>
          <select className={selectClass} value={riskFilter} onChange={(e) => handleRiskChange(e.target.value)}>
            {riskLevels.map((level) => (
              <option key={level || 'all'} value={level}>
                {levelLabel(level)}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-1">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Status</span>
          <select className={selectClass} value={statusFilter} onChange={(e) => handleStatusChangeFilter(e.target.value)}>
            {statusOptions.map((s) => (
              <option key={s || 'all'} value={s}>
                {levelLabel(s)}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="flex min-h-0 flex-1 flex-col gap-3">
        <div className="flex items-center justify-between gap-3 text-sm">
          <div className="flex items-center gap-2 text-mute">
            <Filter className="h-4 w-4" />
            <span>
              Showing <span className="font-mono text-ink">{findings.length}</span> findings
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-1 rounded border border-hairline text-mute hover:text-ink disabled:opacity-30 cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-xs text-mute font-mono">Page {page + 1}</span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={findings.length < PAGE_SIZE}
              className="p-1 rounded border border-hairline text-mute hover:text-ink disabled:opacity-30 cursor-pointer"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {error && <p className="text-red-500 text-sm">{error}</p>}
        {loading && !error && (
          <p className="text-mute text-sm">Loading findings...</p>
        )}
        {!loading && !error && findings.length === 0 && (
          <div className="flex items-center justify-center py-20 text-sm text-mute">
            No findings match the current filters
          </div>
        )}
        {!loading && !error && findings.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-canvas-soft">
                  <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                    Headline
                  </th>
                  <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                    Risk
                  </th>
                  <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                    Rule ID
                  </th>
                  <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                    Status
                  </th>
                  <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                    Created
                  </th>
                  <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => {
                  const riskStyle = riskBadgeColor(f.risk)
                  const statusStyle = statusBadgeColor(f.status)
                  return (
                    <tr
                      key={f.id}
                      className="border-b border-hairline hover:bg-canvas-soft transition-colors"
                    >
                      <td className="px-4 py-2 text-sm text-ink max-w-xs truncate">
                        {f.headline}
                      </td>
                      <td className="px-4 py-2">
                        <span
                          className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase"
                          style={{ backgroundColor: riskStyle.bg, color: riskStyle.text }}
                        >
                          {f.risk}
                        </span>
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-mute">
                        {truncateMiddle(f.rule_id, 30)}
                      </td>
                      <td className="px-4 py-2">
                        <span
                          className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase"
                          style={{ backgroundColor: statusStyle.bg, color: statusStyle.text }}
                        >
                          {f.status.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-sm text-mute">
                        {formatRelativeTime(f.created_at)}
                      </td>
                      <td className="px-4 py-2">
                        <select
                          value={f.status}
                          onChange={(e) => handleStatusChange(f.id, e.target.value)}
                          className="rounded-sm border border-hairline bg-canvas-soft px-2 py-1 text-xs text-ink focus:outline-none focus:ring-1 focus:ring-primary cursor-pointer"
                        >
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
    </div>
  )
}
