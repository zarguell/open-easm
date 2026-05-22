import { type FC, type ReactNode } from 'react'
import { CheckCircle2, CircleDashed, Database, ShieldAlert, SignalHigh } from 'lucide-react'
import { EntityTypeBadge } from '../shared/Badge'
import { Card } from '../shared/Card'
import { formatDateTime } from '../../lib/format'
import { colors } from '../../DESIGN_TOKENS'
import { AssetChangeTimeline } from './AssetChangeTimeline'
import type { AssetInventoryItem } from '../../api/assets'

interface AssetDetailPanelProps {
  asset: AssetInventoryItem
}

function metricColor(kind: 'confidence' | 'risk', level?: string | null) {
  const normal = (level ?? '').toLowerCase()
  if (kind === 'confidence') {
    if (normal === 'high') return colors.primarySoft
    if (normal === 'medium') return colors.statusWarning
    if (normal === 'low') return colors.statusRunning
    return colors.mute
  }
  if (normal === 'critical' || normal === 'high') return colors.statusError
  if (normal === 'medium') return colors.statusWarning
  if (normal === 'low') return colors.statusRunning
  return colors.mute
}

function MetricPanel({
  label,
  value,
  level,
  icon,
  color,
}: {
  label: string
  value: number | null | undefined
  level: string | null | undefined
  icon: ReactNode
  color: string
}) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">{label}</span>
        <span style={{ color }}>{icon}</span>
      </div>
      <div className="mt-3 flex items-end gap-2">
        <span className="font-mono text-2xl font-semibold leading-none text-ink-strong">{value == null ? '-' : Math.round(value)}</span>
        <span className="pb-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider" style={{ color }}>
          {level ?? 'unknown'}
        </span>
      </div>
    </Card>
  )
}

export const AssetDetailPanel: FC<AssetDetailPanelProps> = ({ asset }) => {
  const feedColor = asset.feed_eligible ? colors.primarySoft : colors.mute

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <EntityTypeBadge entityType={asset.entity_type} />
        <div className="break-all font-mono text-base text-ink">{asset.entity_value}</div>
        <div className="grid gap-2 text-sm">
          <div className="flex min-w-0 justify-between gap-3">
            <span className="shrink-0 text-mute">Target</span>
            <span className="truncate font-mono text-ink" title={asset.target_id}>{asset.target_id}</span>
          </div>
          <div className="flex min-w-0 justify-between gap-3">
            <span className="shrink-0 text-mute">Entity ID</span>
            <span className="truncate font-mono text-ink" title={asset.entity_id}>{asset.entity_id}</span>
          </div>
          <div className="flex justify-between gap-3">
            <span className="text-mute">First Seen</span>
            <span className="text-right text-ink">{formatDateTime(asset.first_seen_at)}</span>
          </div>
          <div className="flex justify-between gap-3">
            <span className="text-mute">Last Seen</span>
            <span className="text-right text-ink">{formatDateTime(asset.last_seen_at)}</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <MetricPanel
          label="Confidence"
          value={asset.confidence_score}
          level={asset.confidence_level}
          color={metricColor('confidence', asset.confidence_level)}
          icon={<SignalHigh className="h-4 w-4" />}
        />
        <MetricPanel
          label="Risk"
          value={asset.risk_score}
          level={asset.risk_level}
          color={metricColor('risk', asset.risk_level)}
          icon={<ShieldAlert className="h-4 w-4" />}
        />
      </div>

      <Card className="space-y-4 p-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Evidence</div>
            <div className="mt-1 font-mono text-xl font-semibold text-ink-strong">{asset.evidence_count ?? 0}</div>
          </div>
          <Database className="h-4 w-4 text-mute" />
        </div>
        <div className="flex flex-wrap gap-1">
          {(asset.sources ?? []).length === 0 && <span className="text-sm text-mute">No sources recorded</span>}
          {(asset.sources ?? []).map((source) => (
            <span
              key={source}
              className="max-w-full truncate rounded-sm border border-hairline bg-canvas-soft px-2 py-1 font-mono text-[11px] text-body"
              title={source}
            >
              {source}
            </span>
          ))}
        </div>
        <div className="flex items-center gap-2 border-t border-hairline pt-3 text-sm" style={{ color: feedColor }}>
          {asset.feed_eligible ? <CheckCircle2 className="h-4 w-4" /> : <CircleDashed className="h-4 w-4" />}
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider">
            {asset.feed_eligible ? 'Feed eligible' : 'Not feed eligible'}
          </span>
        </div>
      </Card>

      <section className="space-y-3">
        <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Change History</h3>
        <AssetChangeTimeline entityId={asset.entity_id} />
      </section>
    </div>
  )
}
