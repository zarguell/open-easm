import { type FC } from 'react'
import { useAssetInventory } from '../../api/assets'
import { Card } from '../shared/Card'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'

const riskTone = (riskLevel: string): string => {
  if (riskLevel === 'critical') return '#ef4444'
  if (riskLevel === 'high') return '#f59e0b'
  return '#00d992'
}

const OverviewMetric: FC<{ label: string; value: number; tone?: string }> = ({ label, value, tone }) => (
  <div className="rounded-md border border-hairline bg-canvas-soft px-4 py-3">
    <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-mute">{label}</div>
    <div className="mt-2 font-mono text-2xl font-semibold leading-7 text-ink-strong" style={tone ? { color: tone } : undefined}>
      {value}
    </div>
  </div>
)

export const AssetRiskOverview: FC = () => {
  const { data, isLoading, isError, error, refetch } = useAssetInventory({ limit: 500 })

  if (isError) {
    return <ErrorDisplay message={error.message} onRetry={() => refetch()} />
  }

  if (isLoading) {
    return (
      <Card className="space-y-4">
        <Skeleton width="140px" height="14px" />
        <div className="grid grid-cols-2 gap-3">
          {Array.from({ length: 4 }).map((_, index) => (
            <Skeleton key={index} height="74px" />
          ))}
        </div>
      </Card>
    )
  }

  const assets = data?.assets ?? []
  const profiled = data?.total_count ?? assets.length
  const feedEligible = assets.filter((asset) => asset.feed_eligible).length
  const critical = assets.filter((asset) => asset.risk_level === 'critical').length
  const high = assets.filter((asset) => asset.risk_level === 'high').length

  return (
    <Card className="space-y-4">
      <div>
        <h2 className="text-sm font-semibold text-ink">Asset Risk Overview</h2>
        <p className="mt-1 text-xs text-mute">Risk counts from the latest 500 assets; profiled total is exact.</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <OverviewMetric label="Profiled" value={profiled} />
        <OverviewMetric label="Feed Eligible" value={feedEligible} />
        <OverviewMetric label="Critical" value={critical} tone={riskTone('critical')} />
        <OverviewMetric label="High" value={high} tone={riskTone('high')} />
      </div>
    </Card>
  )
}
