import { type FC, useState } from 'react'
import { usePivotQueue } from '../../api/pivot-queue'
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

export const PivotQueueTable: FC = () => {
  const [statusFilter, setStatusFilter] = useState<string>('')
  const { data, isLoading, isError, error, refetch } = usePivotQueue({
    status: statusFilter || undefined,
    limit: 50,
  })

  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
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
      </div>

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
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
