import { type FC } from 'react'
import { CheckCircle2, CircleDashed } from 'lucide-react'
import { EntityTypeBadge } from '../shared/Badge'
import { formatRelativeTime, truncateMiddle } from '../../lib/format'
import { colors } from '../../DESIGN_TOKENS'
import type { AssetInventoryItem } from '../../api/assets'

interface AssetInventoryTableProps {
  assets: AssetInventoryItem[]
  selectedEntityId: string | null
  onSelectAsset: (asset: AssetInventoryItem) => void
}

const levelStyles = {
  confidence: {
    high: { color: colors.primarySoft, bg: `${colors.primary}1f` },
    medium: { color: colors.statusWarning, bg: `${colors.statusWarning}1f` },
    low: { color: colors.statusRunning, bg: `${colors.statusRunning}1f` },
    unknown: { color: colors.mute, bg: `${colors.statusPending}1f` },
  },
  risk: {
    critical: { color: colors.statusError, bg: `${colors.statusError}29` },
    high: { color: colors.statusError, bg: `${colors.statusError}1f` },
    medium: { color: colors.statusWarning, bg: `${colors.statusWarning}1f` },
    low: { color: colors.statusRunning, bg: `${colors.statusRunning}1f` },
    unknown: { color: colors.mute, bg: `${colors.statusPending}1f` },
  },
} as const

function normalLevel(value: string | null | undefined) {
  return (value ?? 'unknown').toLowerCase()
}

function LevelBadge({
  type,
  level,
  score,
}: {
  type: 'confidence' | 'risk'
  level?: string | null
  score?: number | null
}) {
  const key = normalLevel(level)
  const style =
    type === 'confidence'
      ? levelStyles.confidence[key as keyof typeof levelStyles.confidence] ?? levelStyles.confidence.unknown
      : levelStyles.risk[key as keyof typeof levelStyles.risk] ?? levelStyles.risk.unknown

  return (
    <span
      className="inline-flex max-w-full items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider"
      style={{ backgroundColor: style.bg, color: style.color }}
      title={score == null ? undefined : `${level ?? 'unknown'} (${score})`}
    >
      <span className="truncate">{level ?? 'unknown'}</span>
      {score != null && <span className="text-[10px] opacity-80">{Math.round(score)}</span>}
    </span>
  )
}

export const AssetInventoryTable: FC<AssetInventoryTableProps> = ({
  assets,
  selectedEntityId,
  onSelectAsset,
}) => {
  if (assets.length === 0) {
    return (
      <div className="flex items-center justify-center rounded-md border border-hairline py-20 text-sm text-mute">
        No assets found
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-md border border-hairline">
      <table className="min-w-[1040px] w-full">
        <thead>
          <tr className="bg-canvas-soft">
            <th className="px-4 py-3 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
              Asset
            </th>
            <th className="px-4 py-3 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
              Confidence
            </th>
            <th className="px-4 py-3 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
              Risk
            </th>
            <th className="px-4 py-3 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
              Sources
            </th>
            <th className="px-4 py-3 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
              Evidence
            </th>
            <th className="px-4 py-3 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
              Feed
            </th>
            <th className="px-4 py-3 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
              Last Seen
            </th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => {
            const selected = selectedEntityId === asset.entity_id
            return (
              <tr
                key={asset.entity_id}
                onClick={() => onSelectAsset(asset)}
                className={`cursor-pointer border-t border-hairline text-sm transition-colors hover:bg-canvas-soft ${
                  selected ? 'bg-canvas-soft' : 'bg-canvas'
                }`}
              >
                <td className="max-w-[360px] px-4 py-3 align-top">
                  <div className="flex min-w-0 items-start gap-3">
                    <EntityTypeBadge entityType={asset.entity_type} className="shrink-0" />
                    <div className="min-w-0">
                      <div className="truncate font-mono text-sm text-ink" title={asset.entity_value}>
                        {truncateMiddle(asset.entity_value, 72)}
                      </div>
                      <div className="mt-1 truncate font-mono text-[11px] text-mute" title={asset.target_id}>
                        {asset.target_id}
                      </div>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3 align-top">
                  <LevelBadge type="confidence" level={asset.confidence_level} score={asset.confidence_score} />
                </td>
                <td className="px-4 py-3 align-top">
                  <LevelBadge type="risk" level={asset.risk_level} score={asset.risk_score} />
                </td>
                <td className="max-w-[220px] px-4 py-3 align-top">
                  <div className="flex flex-wrap gap-1">
                    {(asset.sources ?? []).slice(0, 3).map((source) => (
                      <span
                        key={source}
                        className="max-w-[120px] truncate rounded-sm border border-hairline bg-canvas-soft px-2 py-0.5 font-mono text-[11px] text-body"
                        title={source}
                      >
                        {source}
                      </span>
                    ))}
                    {(asset.sources ?? []).length > 3 && (
                      <span className="rounded-sm border border-hairline bg-canvas-soft px-2 py-0.5 font-mono text-[11px] text-mute">
                        +{asset.sources.length - 3}
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 align-top font-mono text-sm text-body">
                  {asset.evidence_count ?? 0}
                </td>
                <td className="px-4 py-3 align-top">
                  <span
                    className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider ${
                      asset.feed_eligible ? 'text-primary' : 'text-mute'
                    }`}
                    style={{
                      backgroundColor: asset.feed_eligible ? `${colors.primary}1f` : `${colors.statusPending}1f`,
                    }}
                  >
                    {asset.feed_eligible ? <CheckCircle2 className="h-3 w-3" /> : <CircleDashed className="h-3 w-3" />}
                    {asset.feed_eligible ? 'eligible' : 'held'}
                  </span>
                </td>
                <td className="whitespace-nowrap px-4 py-3 align-top text-sm text-body">
                  {formatRelativeTime(asset.last_seen_at)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
