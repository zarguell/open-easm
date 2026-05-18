import { type FC } from 'react'
import { Badge } from '../shared/Badge'
import { colors } from '../../DESIGN_TOKENS'
import { formatDateTime, truncateMiddle } from '../../lib/format'
import type { CertificateInventoryItem } from '../../api/certificates'

interface CertificateDetailPanelProps {
  certificate: CertificateInventoryItem
}

const riskVariant: Record<string, 'success' | 'error' | 'warning' | 'running' | 'pending'> = {
  critical: 'error',
  high: 'warning',
  medium: 'running',
  low: 'success',
  info: 'pending',
}

function display(value: string | null | undefined): string {
  return value || 'unknown'
}

function endpointLabel(endpoint: unknown): string {
  if (!endpoint || typeof endpoint !== 'object') return String(endpoint ?? 'unknown')
  const record = endpoint as Record<string, unknown>
  const hostname = typeof record.hostname === 'string' ? record.hostname : 'unknown-host'
  const port = typeof record.port === 'number' || typeof record.port === 'string' ? String(record.port) : '443'
  return `${hostname}:${port}`
}

export const CertificateDetailPanel: FC<CertificateDetailPanelProps> = ({ certificate }) => {
  const endpoints = Array.isArray(certificate.observed_endpoints) ? certificate.observed_endpoints : []
  const reasons = Array.isArray(certificate.reasons) ? certificate.reasons : []

  return (
    <div className="space-y-5">
      <section className="space-y-2">
        <div
          className="inline-flex rounded-full px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider"
          style={{ backgroundColor: `${colors.entityCertificate}1f`, color: colors.entityCertificate }}
        >
          Certificate
        </div>
        <h2 className="break-words text-base font-semibold text-ink">
          {certificate.subject_cn || 'Unknown subject'}
        </h2>
        <p className="break-all font-mono text-xs text-mute" title={certificate.fingerprint_sha256 ?? undefined}>
          {truncateMiddle(certificate.fingerprint_sha256 || certificate.entity_id, 72)}
        </p>
      </section>

      <section className="grid grid-cols-2 gap-2">
        <DetailStat label="Risk">
          <Badge variant={riskVariant[certificate.risk ?? ''] ?? 'pending'}>{display(certificate.risk)}</Badge>
        </DetailStat>
        <DetailStat label="Strength">{display(certificate.strength)}</DetailStat>
        <DetailStat label="Validity">{display(certificate.validity_state)}</DetailStat>
        <DetailStat label="Deployment">{display(certificate.deployment_state)}</DetailStat>
      </section>

      <section className="space-y-3 border-t border-hairline pt-4">
        <SectionTitle title="Issuer" />
        <div className="text-sm text-body">{certificate.issuer_organization || 'unknown'}</div>
      </section>

      <section className="space-y-3 border-t border-hairline pt-4">
        <SectionTitle title="Lifecycle" />
        <dl className="grid grid-cols-[104px_1fr] gap-x-3 gap-y-2 text-sm">
          <dt className="font-mono text-[11px] uppercase tracking-wider text-mute">Not Before</dt>
          <dd className="font-mono text-xs text-body">{formatDateTime(certificate.not_before ?? null)}</dd>
          <dt className="font-mono text-[11px] uppercase tracking-wider text-mute">Not After</dt>
          <dd className="font-mono text-xs text-body">{formatDateTime(certificate.not_after ?? null)}</dd>
        </dl>
      </section>

      <section className="space-y-3 border-t border-hairline pt-4">
        <SectionTitle title="Risk Reasons" />
        {reasons.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {reasons.map((reason) => (
              <span
                key={String(reason)}
                className="rounded-sm border border-hairline bg-canvas-soft px-2 py-1 font-mono text-[11px] text-body"
              >
                {String(reason)}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-mute">No reasons reported</p>
        )}
      </section>

      <section className="space-y-3 border-t border-hairline pt-4">
        <SectionTitle title="Observed Endpoints" />
        {endpoints.length > 0 ? (
          <div className="space-y-2">
            {endpoints.map((endpoint, index) => (
              <div
                key={`${endpointLabel(endpoint)}-${index}`}
                className="rounded-sm border border-hairline bg-canvas-soft px-3 py-2 font-mono text-xs text-ink"
              >
                {endpointLabel(endpoint)}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-mute">No live endpoints observed</p>
        )}
      </section>
    </div>
  )
}

interface DetailStatProps {
  label: string
  children: React.ReactNode
}

const DetailStat: FC<DetailStatProps> = ({ label, children }) => (
  <div className="rounded-sm border border-hairline bg-canvas-soft p-3">
    <div className="mb-1 font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">{label}</div>
    <div className="text-sm font-semibold text-ink">{children}</div>
  </div>
)

const SectionTitle: FC<{ title: string }> = ({ title }) => (
  <h3 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">{title}</h3>
)
