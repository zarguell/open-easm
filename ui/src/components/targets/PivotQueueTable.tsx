import { type FC, useState } from 'react'
import { usePivotQueue, useTriggerPivot, useRetryPivot } from '../../api/pivot-queue'
import { EntityTypeBadge, Badge } from '../shared/Badge'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'
import { formatRelativeTime } from '../../lib/format'
import { truncateMiddle } from '../../lib/format'

const statusVariant = (status: string): 'success' | 'error' | 'warning' | 'running' | 'pending' => {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'running') return 'running'
  if (status === 'pending') return 'pending'
  return 'pending'
}

const STATUS_OPTIONS = ['', 'pending', 'running', 'completed', 'failed'] as const

const PIVOT_TYPES = [
  'dns_resolve', 'reverse_dns', 'domain_extract', 'geoip_enrich',
  'tls_cert_grab', 'dns_mail_records', 'crtsh_search', 'subdomain_enum',
  'subdomain_takeover', 'passive_dns', 'rdap_lookup', 'reverse_whois',
  'domain_rdap', 'shodan_enrich', 'abuseipdb_enrich', 'greynoise_enrich',
  'urlscan_enrich', 'censys_enrich', 'cpe_vuln_enrich',
] as const

const ENTITY_TYPES = ['asn', 'ip_range', 'ip', 'hostname', 'domain', 'certificate', 'org'] as const

export const PivotQueueTable: FC = () => {
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [entityTypeFilter, setEntityTypeFilter] = useState<string>('')
  const [pivotTypeFilter, setPivotTypeFilter] = useState<string>('')
  const [showTrigger, setShowTrigger] = useState(false)
  const { data, isLoading, isError, error, refetch } = usePivotQueue({
    status: statusFilter || undefined,
    entity_type: entityTypeFilter || undefined,
    pivot_type: pivotTypeFilter || undefined,
    limit: 50,
  })

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        {STATUS_OPTIONS.map((opt) => (
          <button
            key={opt}
            onClick={() => setStatusFilter(opt)}
            className={`rounded-full px-3 py-1 font-mono text-[11px] tracking-wider uppercase transition-colors cursor-pointer ${
              statusFilter === opt
                ? 'bg-canvas-soft text-ink'
                : 'text-mute hover:text-ink'
            }`}
          >
            {opt || 'all'}
          </button>
        ))}
        <select
          value={entityTypeFilter}
          onChange={(e) => setEntityTypeFilter(e.target.value)}
          className="rounded border border-hairline bg-canvas-soft px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-ink"
          aria-label="Filter by entity type"
        >
          <option value="">all entities</option>
          {ENTITY_TYPES.map((type) => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>
        <select
          value={pivotTypeFilter}
          onChange={(e) => setPivotTypeFilter(e.target.value)}
          className="max-w-56 rounded border border-hairline bg-canvas-soft px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-ink"
          aria-label="Filter by pivot type"
        >
          <option value="">all pivots</option>
          {PIVOT_TYPES.map((type) => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>
        <div className="flex-1" />
        <button
          onClick={() => setShowTrigger(!showTrigger)}
          className="rounded px-3 py-1 font-mono text-[11px] tracking-wider uppercase bg-teal-600 text-white hover:bg-teal-500 transition-colors cursor-pointer"
        >
          {showTrigger ? 'Cancel' : 'Trigger Pivot'}
        </button>
      </div>

      {showTrigger && (
        <TriggerForm onClose={() => setShowTrigger(false)} onSubmitted={() => { setShowTrigger(false); refetch() }} />
      )}

      {isError && (
        <ErrorDisplay message={error.message} onRetry={() => refetch()} />
      )}

      {isLoading && !isError && (
        <div className="space-y-2 py-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} height="36px" />
          ))}
        </div>
      )}

      {!isLoading && !isError && data && data.jobs.length === 0 && (
        <div className="text-sm text-mute py-4">No pivot queue jobs found</div>
      )}

      {data && data.jobs.length > 0 && (
        <table className="w-full">
          <thead>
            <tr className="bg-canvas-soft">
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Entity Type
              </th>
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Value
              </th>
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Pivot Type
              </th>
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Status
              </th>
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Depth
              </th>
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Enqueued
              </th>
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Completed
              </th>
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Reason
              </th>
              <th className="px-4 py-2 text-left font-mono text-[11px] uppercase tracking-wider text-mute">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {data.jobs.map((job) => (
              <tr
                key={job.id}
                className="border-b border-hairline transition-colors hover:bg-canvas-soft"
              >
                <td className="px-4 py-2">
                  <EntityTypeBadge entityType={job.entity_type} />
                </td>
                <td className="px-4 py-2 font-mono text-sm text-ink">
                  {truncateMiddle(job.entity_value, 50)}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-body">
                  {job.pivot_type}
                </td>
                <td className="px-4 py-2">
                  <Badge variant={statusVariant(job.status)}>{job.status}</Badge>
                </td>
                <td className="px-4 py-2 font-mono text-sm text-body">
                  {job.depth}
                </td>
                <td className="px-4 py-2 text-sm text-body">
                  {formatRelativeTime(job.enqueued_at)}
                </td>
                <td className="px-4 py-2 text-sm text-body">
                  {formatRelativeTime(job.completed_at)}
                </td>
                <td className="px-4 py-2 text-xs text-body max-w-64">
                  {job.error_message || job.skip_reason ? (
                    <span className="line-clamp-2" title={job.error_message ?? job.skip_reason ?? undefined}>
                      {job.error_message ?? job.skip_reason}
                    </span>
                  ) : (
                    <span className="text-mute">-</span>
                  )}
                </td>
                <td className="px-4 py-2">
                  {(job.status === 'failed' || job.status === 'completed') && (
                    <RetryButton jobId={job.id} />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const RetryButton: FC<{ jobId: string }> = ({ jobId }) => {
  const retry = useRetryPivot()
  return (
    <button
      onClick={() => retry.mutate(jobId)}
      disabled={retry.isPending}
      className="rounded px-2 py-0.5 font-mono text-[10px] tracking-wider uppercase bg-canvas-soft text-mute hover:text-ink transition-colors cursor-pointer disabled:opacity-50"
    >
      {retry.isPending ? '...' : 'retry'}
    </button>
  )
}

const TriggerForm: FC<{ onClose: () => void; onSubmitted: () => void }> = ({ onClose, onSubmitted }) => {
  const [entityType, setEntityType] = useState('domain')
  const [entityValue, setEntityValue] = useState('')
  const [pivotType, setPivotType] = useState('domain_rdap')
  const [targetId, setTargetId] = useState('')
  const trigger = useTriggerPivot()

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    trigger.mutate(
      { target_id: targetId, entity_type: entityType, entity_value: entityValue, pivot_type: pivotType },
      { onSuccess: onSubmitted },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="mb-4 p-3 bg-canvas-soft rounded-lg space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <label className="block text-[11px] font-mono uppercase tracking-wider text-mute mb-1">Target ID</label>
          <input
            type="text"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            required
            className="w-full bg-canvas border border-hairline rounded px-3 py-1.5 text-sm font-mono text-ink"
            placeholder="e.g. contoso"
          />
        </div>
        <div>
          <label className="block text-[11px] font-mono uppercase tracking-wider text-mute mb-1">Entity Type</label>
          <select
            value={entityType}
            onChange={(e) => setEntityType(e.target.value)}
            className="w-full bg-canvas border border-hairline rounded px-3 py-1.5 text-sm font-mono text-ink"
          >
            {ENTITY_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-[11px] font-mono uppercase tracking-wider text-mute mb-1">Entity Value</label>
          <input
            type="text"
            value={entityValue}
            onChange={(e) => setEntityValue(e.target.value)}
            required
            className="w-full bg-canvas border border-hairline rounded px-3 py-1.5 text-sm font-mono text-ink"
            placeholder="e.g. example.com"
          />
        </div>
        <div>
          <label className="block text-[11px] font-mono uppercase tracking-wider text-mute mb-1">Pivot Type</label>
          <select
            value={pivotType}
            onChange={(e) => setPivotType(e.target.value)}
            className="w-full bg-canvas border border-hairline rounded px-3 py-1.5 text-sm font-mono text-ink"
          >
            {PIVOT_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={trigger.isPending}
          className="rounded px-4 py-1.5 font-mono text-[11px] tracking-wider uppercase bg-teal-600 text-white hover:bg-teal-500 transition-colors cursor-pointer disabled:opacity-50"
        >
          {trigger.isPending ? 'Triggering...' : 'Trigger'}
        </button>
        <button
          type="button"
          onClick={onClose}
          className="rounded px-4 py-1.5 font-mono text-[11px] tracking-wider uppercase text-mute hover:text-ink transition-colors cursor-pointer"
        >
          Cancel
        </button>
        {trigger.isError && (
          <span className="text-xs text-red-400">{trigger.error.message}</span>
        )}
      </div>
    </form>
  )
}
