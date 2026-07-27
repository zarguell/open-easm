import { type FC, useState } from 'react'
import { useEntity, useEntityRelationships } from '../../api/entities'
import { EntityTypeBadge } from '../shared/Badge'
import { Badge } from '../shared/Badge'
import { SlideOver } from '../shared/SlideOver'
import { formatDateTime } from '../../lib/format'
import { getEntityColor, getEntityBgColor } from '../../lib/entity-colors'
import { ChevronDown, ChevronRight, GitBranch } from 'lucide-react'
import { StructuredAttributes } from './AttributeRenderers'
import { DiscoveryLineagePanel } from './DiscoveryLineagePanel'

interface EntityDetailProps {
  entityId: string
  onNavigate?: (entityId: string) => void
}

type UnknownRecord = Record<string, unknown>

const isRecord = (value: unknown): value is UnknownRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const readRecord = (record: UnknownRecord | undefined, key: string): UnknownRecord | undefined => {
  const value = record?.[key]
  return isRecord(value) ? value : undefined
}

const readText = (record: UnknownRecord | undefined, key: string): string | undefined => {
  const value = record?.[key]
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return undefined
}

const readScore = (record: UnknownRecord | undefined, key: string): string | undefined => {
  const value = record?.[key]
  if (typeof value === 'number' && Number.isFinite(value)) return String(Math.round(value))
  if (typeof value === 'string' && value.trim()) return value
  return undefined
}

const titleize = (value: string | undefined): string =>
  value ? value.replace(/_/g, ' ') : 'unknown'

const ProfileStat: FC<{ label: string; value: string; tone?: string }> = ({ label, value, tone }) => (
  <div className="rounded-md border border-hairline bg-canvas-soft px-3 py-2">
    <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-mute">{label}</div>
    <div className="mt-1 text-sm font-semibold text-ink" style={tone ? { color: tone } : undefined}>
      {value}
    </div>
  </div>
)

const riskTone = (level: string | undefined): string | undefined => {
  if (level === 'critical' || level === 'high') return '#ef4444'
  if (level === 'medium') return '#f59e0b'
  if (level === 'low' || level === 'info') return '#00d992'
  return undefined
}

const AssetProfileSummary: FC<{ profile: UnknownRecord }> = ({ profile }) => {
  const confidence = readRecord(profile, 'confidence')
  const risk = readRecord(profile, 'risk')
  const confidenceLevel = readText(confidence, 'level')
  const confidenceScore = readScore(confidence, 'score')
  const riskLevel = readText(risk, 'level')
  const riskScore = readScore(risk, 'score')

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-semibold text-mute uppercase tracking-wider">Asset Profile</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <ProfileStat
          label="Confidence"
          value={`${titleize(confidenceLevel)}${confidenceScore ? ` / ${confidenceScore}` : ''}`}
        />
        <ProfileStat
          label="Risk"
          value={`${titleize(riskLevel)}${riskScore ? ` / ${riskScore}` : ''}`}
          tone={riskTone(riskLevel)}
        />
      </div>
    </div>
  )
}

const CertificateProfileSummary: FC<{ profile: UnknownRecord }> = ({ profile }) => {
  const analysis = readRecord(profile, 'analysis')
  const issuer = readRecord(profile, 'issuer')
  const deployment = readRecord(profile, 'deployment')
  const risk = readText(analysis, 'risk') ?? readText(profile, 'risk')
  const validityState = readText(analysis, 'validity_state') ?? readText(profile, 'validity_state')
  const deploymentState =
    readText(analysis, 'deployment_state') ??
    readText(deployment, 'state') ??
    readText(profile, 'deployment_state')
  const issuerOrganization = readText(issuer, 'organization')

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-semibold text-mute uppercase tracking-wider">Certificate Profile</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <ProfileStat label="Risk" value={titleize(risk)} tone={riskTone(risk)} />
        <ProfileStat label="Validity" value={titleize(validityState)} />
        <ProfileStat label="Deployment" value={titleize(deploymentState)} />
        <ProfileStat label="Issuer Org" value={issuerOrganization ?? 'unknown'} />
      </div>
    </div>
  )
}

export const EntityDetail: FC<EntityDetailProps> = ({ entityId, onNavigate }) => {
  const { data: entity, isLoading, error } = useEntity(entityId)
  const { data: relationshipsData } = useEntityRelationships(entityId)
  const [attributesOpen, setAttributesOpen] = useState(false)
  const [lineageOpen, setLineageOpen] = useState(false)

  if (isLoading) {
    return <div className="text-sm text-mute">Loading...</div>
  }

  if (error) {
    return <div className="text-sm text-red-400">Error: {error.message}</div>
  }

  if (!entity) {
    return <div className="text-sm text-mute">Entity not found</div>
  }

  const relationships = relationshipsData?.relationships ?? []
  const attributes = isRecord(entity.attributes) ? entity.attributes : undefined
  const assetProfile = readRecord(attributes, 'asset_profile')
  const certificateProfile = readRecord(attributes, 'certificate_profile')

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <EntityTypeBadge entityType={entity.entity_type} />
          <button
            onClick={() => { setLineageOpen(true); }}
            className="inline-flex items-center gap-1 rounded-full border border-hairline bg-canvas-soft px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-mute hover:text-ink hover:border-hairline-soft transition-colors cursor-pointer"
          >
            <GitBranch className="h-3 w-3" />
            Lineage
          </button>
        </div>
        <div className="font-mono text-base text-ink break-all">{entity.entity_value}</div>
        {entity.is_first_discovery && (
          <Badge variant="success">First Discovery</Badge>
        )}
      </div>

      <div className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-mute">Target</span>
          <span className="font-mono text-ink">{entity.target_id}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-mute">First Seen</span>
          <span className="text-ink">{formatDateTime(entity.first_seen_at)}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-mute">Last Seen</span>
          <span className="text-ink">{formatDateTime(entity.last_seen_at)}</span>
        </div>
      </div>

      {relationships.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-mute uppercase tracking-wider">
            Relationships ({relationships.length})
          </h3>
          <div className="space-y-1">
            {relationships.map((rel) => {
              const isSource = rel.source_entity_id === entityId
              const relatedEntityId = isSource ? rel.target_entity_id : rel.source_entity_id
              const relatedEntityValue = isSource ? rel.target_entity_value : rel.source_entity_value
              const relatedEntityType = isSource ? rel.target_entity_type : rel.source_entity_type
              const relatedColor = getEntityColor(relatedEntityType)

              return (
                <div
                  key={rel.id}
                  className="flex items-center gap-2 rounded bg-canvas-soft px-3 py-2 text-xs"
                >
                  <span
                    className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider"
                    style={{
                      backgroundColor: `${getEntityColor(rel.relationship_type)}1f`,
                      color: getEntityColor(rel.relationship_type),
                    }}
                  >
                    {rel.relationship_type}
                  </span>
                  <span
                    className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider"
                    style={{
                      backgroundColor: getEntityBgColor(relatedEntityType),
                      color: relatedColor,
                    }}
                  >
                    {relatedEntityType}
                  </span>
                  <span
                    className={`text-body font-mono truncate ${onNavigate ? 'cursor-pointer hover:text-ink underline decoration-dotted underline-offset-2' : ''}`}
                    onClick={onNavigate ? () => { onNavigate(relatedEntityId); } : undefined}
                    role={onNavigate ? 'button' : undefined}
                    tabIndex={onNavigate ? 0 : undefined}
                    onKeyDown={onNavigate ? (e) => { if (e.key === 'Enter') onNavigate(relatedEntityId) } : undefined}
                  >
                    {relatedEntityValue}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {assetProfile && <AssetProfileSummary profile={assetProfile} />}

      {certificateProfile && <CertificateProfileSummary profile={certificateProfile} />}

      {attributes && <StructuredAttributes attributes={attributes} />}

      {entity.attributes && Object.keys(entity.attributes).length > 0 && (
        <div className="space-y-2">
          <button
            onClick={() => { setAttributesOpen(!attributesOpen); }}
            className="flex items-center gap-1 text-xs font-semibold text-mute uppercase tracking-wider hover:text-ink transition-colors cursor-pointer"
          >
            {attributesOpen ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
            Raw Attributes
          </button>
          {attributesOpen && (
            <pre className="rounded bg-canvas-soft p-3 text-xs text-body font-mono overflow-auto max-h-64">
              {JSON.stringify(entity.attributes, null, 2)}
            </pre>
          )}
        </div>
      )}

      <SlideOver
        open={lineageOpen}
        onClose={() => { setLineageOpen(false); }}
        title="Discovery Lineage"
      >
        <DiscoveryLineagePanel entityId={entityId} />
      </SlideOver>
    </div>
  )
}
