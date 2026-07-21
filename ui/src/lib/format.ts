export function formatDuration(ms: number | null): string {
  if (ms === null || ms === undefined) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  const minutes = Math.floor(ms / 60_000)
  const seconds = Math.floor((ms % 60_000) / 1000)
  return `${minutes}m ${seconds}s`
}

export function formatRelativeTime(isoDate: string | null): string {
  if (!isoDate) return '—'
  const date = new Date(isoDate)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return 'just now'
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  const diffDay = Math.floor(diffHr / 24)
  if (diffDay < 30) return `${diffDay}d ago`
  return date.toLocaleDateString()
}

export function formatDateTime(isoDate: string | null): string {
  if (!isoDate) return '—'
  return new Date(isoDate).toLocaleString()
}

export function truncateMiddle(s: string, maxLen = 40): string {
  if (s.length <= maxLen) return s
  const half = Math.floor(maxLen / 2) - 1
  return s.slice(0, half) + '…' + s.slice(-half)
}
