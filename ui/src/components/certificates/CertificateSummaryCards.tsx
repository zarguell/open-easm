import { type FC } from 'react'
import { MetricCard } from '../shared/Card'
import { colors } from '../../DESIGN_TOKENS'

type CertificateSummary = {
  total?: number
  by_risk?: Record<string, number>
  by_deployment_state?: Record<string, number>
}

interface CertificateSummaryCardsProps {
  summary?: CertificateSummary
  isLoading?: boolean
}

function count(summary: CertificateSummary | undefined, group: 'by_risk' | 'by_deployment_state', key: string): number {
  return summary?.[group]?.[key] ?? 0
}

export const CertificateSummaryCards: FC<CertificateSummaryCardsProps> = ({ summary, isLoading = false }) => {
  const total = isLoading ? '...' : (summary?.total ?? 0)
  const critical = isLoading ? '...' : count(summary, 'by_risk', 'critical')
  const high = isLoading ? '...' : count(summary, 'by_risk', 'high')
  const deployed = isLoading ? '...' : count(summary, 'by_deployment_state', 'deployed')

  return (
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
      <MetricCard label="Certificates" value={total} color={colors.entityCertificate} className="p-4" />
      <MetricCard label="Critical Risk" value={critical} color={colors.statusError} className="p-4" />
      <MetricCard label="High Risk" value={high} color={colors.statusWarning} className="p-4" />
      <MetricCard label="Deployed / Observed" value={deployed} color={colors.primary} className="p-4" />
    </div>
  )
}
