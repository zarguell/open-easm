import { useMemo, useState } from 'react'
import { Filter } from 'lucide-react'
import { useCertificateInventory, useCertificateSummary, type CertificateInventoryItem } from '../../api/certificates'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'
import { SlideOver } from '../shared/SlideOver'
import { CertificateDetailPanel } from './CertificateDetailPanel'
import { CertificateInventoryTable } from './CertificateInventoryTable'
import { CertificateSummaryCards } from './CertificateSummaryCards'

const RISK_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']
const DEPLOYMENT_OPTIONS = ['deployed', 'ct_only', 'unobserved_candidate']

export function CertificateInventoryView() {
  const [risk, setRisk] = useState('')
  const [deploymentState, setDeploymentState] = useState('')
  const [selectedCertificate, setSelectedCertificate] = useState<CertificateInventoryItem | null>(null)

  const inventoryParams = useMemo(
    () => ({
      risk: risk || undefined,
      deployment_state: deploymentState || undefined,
      limit: 100,
    }),
    [deploymentState, risk],
  )

  const {
    data: inventory,
    isLoading: inventoryLoading,
    isFetching,
    isError: inventoryError,
    error: inventoryErrorDetail,
    refetch: refetchInventory,
  } = useCertificateInventory(inventoryParams)

  const {
    data: summary,
    isLoading: summaryLoading,
    isError: summaryError,
    error: summaryErrorDetail,
    refetch: refetchSummary,
  } = useCertificateSummary()

  const certificates = inventory?.certificates ?? []
  const selectedEntityId = selectedCertificate?.entity_id ?? null

  function retry() {
    refetchInventory()
    refetchSummary()
  }

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
              Certificate Lifecycle
            </div>
            <h1 className="mt-1 text-xl font-semibold text-ink">Certificate Inventory</h1>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Filter className="h-4 w-4 text-mute" />
            <FilterSelect label="Risk" value={risk} options={RISK_OPTIONS} onChange={setRisk} />
            <FilterSelect
              label="Deployment"
              value={deploymentState}
              options={DEPLOYMENT_OPTIONS}
              onChange={setDeploymentState}
            />
          </div>
        </div>

        <CertificateSummaryCards summary={summary} isLoading={summaryLoading} />

        <div className="min-h-0 flex-1">
          {(inventoryError || summaryError) && (
            <ErrorDisplay
              message={inventoryErrorDetail?.message || summaryErrorDetail?.message || 'Unable to load certificates'}
              onRetry={retry}
            />
          )}

          {inventoryLoading && !inventoryError && (
            <div className="space-y-2 border border-hairline bg-canvas p-3">
              {Array.from({ length: 8 }).map((_, index) => (
                <Skeleton key={index} height="42px" />
              ))}
            </div>
          )}

          {!inventoryLoading && !inventoryError && (
            <CertificateInventoryTable
              certificates={certificates}
              selectedEntityId={selectedEntityId}
              isFetching={isFetching}
              onSelectCertificate={setSelectedCertificate}
            />
          )}
        </div>
      </div>

      <SlideOver
        open={selectedCertificate !== null}
        onClose={() => setSelectedCertificate(null)}
        title="Certificate Detail"
      >
        {selectedCertificate && <CertificateDetailPanel certificate={selectedCertificate} />}
      </SlideOver>
    </div>
  )
}

interface FilterSelectProps {
  label: string
  value: string
  options: string[]
  onChange: (value: string) => void
}

function FilterSelect({ label, value, options, onChange }: FilterSelectProps) {
  return (
    <label className="flex items-center gap-2">
      <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 rounded-sm border border-hairline bg-canvas px-2 font-mono text-xs text-body outline-none transition-colors hover:border-hairline-soft focus:border-primary"
      >
        <option value="">All</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  )
}
