import { useMemo, useState } from 'react'
import { Filter, RefreshCw } from 'lucide-react'
import { useAssetInventory } from '../../api/assets'
import { useDebounce } from '../../hooks/useDebounce'
import { SearchInput } from '../shared/SearchInput'
import { SlideOver } from '../shared/SlideOver'
import { ErrorDisplay } from '../shared/ErrorDisplay'
import { Skeleton } from '../shared/Skeleton'
import { Button } from '../shared/Button'
import { AssetInventoryTable } from './AssetInventoryTable'
import { AssetDetailPanel } from './AssetDetailPanel'
import { AssetExportPanel } from './AssetExportPanel'
import type { AssetInventoryItem } from '../../api/assets'

const confidenceLevels = ['', 'high', 'medium', 'low']
const riskLevels = ['', 'critical', 'high', 'medium', 'low']
const feedStates = [
  { label: 'All feed states', value: '' },
  { label: 'Eligible', value: 'true' },
  { label: 'Held', value: 'false' },
]

const selectClass =
  'h-10 rounded-sm border border-hairline bg-canvas-soft px-3 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-primary'

function levelLabel(level: string) {
  if (!level) return 'All levels'
  return `${level.charAt(0).toUpperCase()}${level.slice(1)}`
}

export function AssetInventoryView() {
  const [searchQuery, setSearchQuery] = useState('')
  const [confidenceLevel, setConfidenceLevel] = useState('')
  const [riskLevel, setRiskLevel] = useState('')
  const [feedEligible, setFeedEligible] = useState('')
  const [selectedAsset, setSelectedAsset] = useState<AssetInventoryItem | null>(null)
  const debouncedSearch = useDebounce(searchQuery)

  const inventoryParams = useMemo(
    () => ({
      confidence_level: confidenceLevel || undefined,
      risk_level: riskLevel || undefined,
      feed_eligible: feedEligible === '' ? undefined : feedEligible === 'true',
      limit: 500,
    }),
    [confidenceLevel, feedEligible, riskLevel],
  )

  const { data, isLoading, isError, error, refetch, isFetching } = useAssetInventory(inventoryParams)
  const assets = (data?.assets ?? []) as AssetInventoryItem[]

  const filteredAssets = useMemo(() => {
    if (!debouncedSearch.trim()) return assets
    const lower = debouncedSearch.trim().toLowerCase()
    return assets.filter((asset) => asset.entity_value.toLowerCase().includes(lower))
  }, [assets, debouncedSearch])

  const eligibleCount = useMemo(
    () => assets.filter((asset) => asset.feed_eligible).length,
    [assets],
  )

  const selectedAssetFromResults = useMemo(() => {
    if (!selectedAsset) return null
    return assets.find((asset) => asset.entity_id === selectedAsset.entity_id) ?? selectedAsset
  }, [assets, selectedAsset])

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col gap-4 p-6">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div className="min-w-0">
            <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-primary">
              Asset Inventory
            </div>
            <h1 className="mt-1 text-xl font-semibold leading-7 text-ink">Profiled assets</h1>
          </div>
          <Button variant="outline" className="gap-2 self-start lg:self-auto" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>

        <AssetExportPanel eligibleCount={eligibleCount} totalCount={assets.length} />

        <div className="grid gap-3 rounded-md border border-hairline bg-canvas p-4 lg:grid-cols-[minmax(260px,1fr)_160px_160px_170px]">
          <SearchInput
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search entity value..."
            className="min-w-0"
          />
          <label className="grid gap-1">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Confidence</span>
            <select className={selectClass} value={confidenceLevel} onChange={(e) => setConfidenceLevel(e.target.value)}>
              {confidenceLevels.map((level) => (
                <option key={level || 'all'} value={level}>
                  {levelLabel(level)}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Risk</span>
            <select className={selectClass} value={riskLevel} onChange={(e) => setRiskLevel(e.target.value)}>
              {riskLevels.map((level) => (
                <option key={level || 'all'} value={level}>
                  {levelLabel(level)}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">Feed</span>
            <select className={selectClass} value={feedEligible} onChange={(e) => setFeedEligible(e.target.value)}>
              {feedStates.map((state) => (
                <option key={state.value || 'all'} value={state.value}>
                  {state.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="flex min-h-0 flex-1 flex-col gap-3">
          <div className="flex items-center justify-between gap-3 text-sm">
            <div className="flex items-center gap-2 text-mute">
              <Filter className="h-4 w-4" />
              <span>
                Showing <span className="font-mono text-ink">{filteredAssets.length}</span> of{' '}
                <span className="font-mono text-ink">{assets.length}</span>
              </span>
            </div>
          </div>

          {isError && <ErrorDisplay message={error.message} onRetry={() => refetch()} />}
          {isLoading && !isError && (
            <div className="space-y-3 py-2">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} height="44px" />
              ))}
            </div>
          )}
          {!isLoading && !isError && (
            <AssetInventoryTable
              assets={filteredAssets}
              selectedEntityId={selectedAssetFromResults?.entity_id ?? null}
              onSelectAsset={setSelectedAsset}
            />
          )}
        </div>
      </div>

      <SlideOver
        open={selectedAssetFromResults !== null}
        onClose={() => setSelectedAsset(null)}
        title="Asset Detail"
      >
        {selectedAssetFromResults && <AssetDetailPanel asset={selectedAssetFromResults} />}
      </SlideOver>
    </div>
  )
}
