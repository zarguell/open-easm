import { type FC } from 'react'
import { Badge } from '../shared/Badge'
import { Button } from '../shared/Button'
import { colors } from '../../DESIGN_TOKENS'
import { formatDateTime, truncateMiddle } from '../../lib/format'
import type { CertificateInventoryItem } from '../../api/certificates'

interface CertificateInventoryTableProps {
  certificates: CertificateInventoryItem[]
  selectedEntityId: string | null
  isFetching?: boolean
  hasMore?: boolean
  onLoadMore?: () => void
  onSelectCertificate: (certificate: CertificateInventoryItem) => void
}

const riskVariant: Record<string, 'success' | 'error' | 'warning' | 'running' | 'pending'> = {
  critical: 'error',
  high: 'warning',
  medium: 'running',
  low: 'success',
  info: 'pending',
}

const validityVariant: Record<string, 'success' | 'error' | 'warning' | 'running' | 'pending'> = {
  expired: 'error',
  expiring_soon: 'warning',
  valid: 'success',
  unknown: 'pending',
}

function badgeVariant(value: string | null | undefined, map: typeof riskVariant) {
  if (!value) return 'pending'
  return map[value] ?? 'pending'
}

function display(value: string | null | undefined): string {
  return value || 'unknown'
}

export const CertificateInventoryTable: FC<CertificateInventoryTableProps> = ({
  certificates,
  selectedEntityId,
  isFetching = false,
  hasMore = false,
  onLoadMore,
  onSelectCertificate,
}) => {
  if (certificates.length === 0) {
    return (
      <div className="flex items-center justify-center border border-hairline bg-canvas py-16 text-sm text-mute">
        No certificates found
      </div>
    )
  }

  return (
    <div className="border border-hairline bg-canvas">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[980px]">
          <thead>
            <tr className="bg-canvas-soft">
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
                Subject / Fingerprint
              </th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
                Issuer
              </th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
                Risk
              </th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
                Validity
              </th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
                Deployment
              </th>
              <th className="px-3 py-2 text-left font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
                Not After
              </th>
            </tr>
          </thead>
          <tbody>
            {certificates.map((certificate) => {
              const isSelected = selectedEntityId === certificate.entity_id
              return (
                <tr
                  key={certificate.entity_id}
                  onClick={() => onSelectCertificate(certificate)}
                  className={`border-t border-hairline cursor-pointer transition-colors hover:bg-canvas-soft ${
                    isSelected ? 'bg-canvas-soft' : ''
                  }`}
                >
                  <td className="px-3 py-2.5 align-top">
                    <div className="flex min-w-0 flex-col gap-1">
                      <span className="text-sm font-semibold text-ink">
                        {certificate.subject_cn || 'Unknown subject'}
                        {certificate.subject_source === 'san' && (
                          <span className="ml-1.5 font-mono text-[10px] font-normal uppercase tracking-wider text-mute">
                            SAN
                          </span>
                        )}
                      </span>
                      <span className="font-mono text-[11px] text-mute">
                        {truncateMiddle(certificate.fingerprint_sha256 || certificate.entity_id, 34)}
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5 align-top text-sm text-body">
                    {truncateMiddle(certificate.issuer_organization || 'unknown', 28)}
                  </td>
                  <td className="px-3 py-2.5 align-top">
                    <Badge variant={badgeVariant(certificate.risk, riskVariant)}>{display(certificate.risk)}</Badge>
                  </td>
                  <td className="px-3 py-2.5 align-top">
                    <Badge variant={badgeVariant(certificate.validity_state, validityVariant)}>
                      {display(certificate.validity_state)}
                    </Badge>
                  </td>
                  <td className="px-3 py-2.5 align-top">
                    <span
                      className="inline-flex rounded-full px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider"
                      style={{ backgroundColor: `${colors.entityCertificate}1f`, color: colors.entityCertificate }}
                    >
                      {display(certificate.deployment_state)}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 align-top font-mono text-xs text-body">
                    {formatDateTime(certificate.not_after ?? null)}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {hasMore && onLoadMore && (
        <div className="flex justify-center border-t border-hairline py-3">
          <Button variant="outline" onClick={onLoadMore} disabled={isFetching}>
            {isFetching ? 'Loading...' : 'Load more'}
          </Button>
        </div>
      )}
    </div>
  )
}
