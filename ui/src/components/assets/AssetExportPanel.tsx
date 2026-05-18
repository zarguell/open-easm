import { type FC } from 'react'
import { Download, ExternalLink } from 'lucide-react'
import { assetExportPath } from '../../api/assets'
import { Button } from '../shared/Button'

interface AssetExportPanelProps {
  eligibleCount: number
  totalCount: number
}

export const AssetExportPanel: FC<AssetExportPanelProps> = ({ eligibleCount, totalCount }) => {
  const exportPath = assetExportPath()

  return (
    <div className="flex flex-col gap-3 rounded-md border border-hairline bg-canvas p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <div className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
          Source-of-truth feed
        </div>
        <div className="mt-1 text-sm text-body">
          <span className="font-mono text-ink">{eligibleCount}</span> eligible of{' '}
          <span className="font-mono text-ink">{totalCount}</span> profiled assets
        </div>
      </div>
      <div className="flex shrink-0 flex-wrap gap-2">
        <Button variant="outline" className="gap-2" onClick={() => window.open(exportPath, '_blank', 'noopener,noreferrer')}>
          <ExternalLink className="h-4 w-4" />
          Preview Feed
        </Button>
        <Button
          variant="primary"
          className="gap-2"
          type="button"
          onClick={() => {
            const link = document.createElement('a')
            link.href = exportPath
            link.download = 'open-easm-assets.ndjson'
            link.click()
          }}
        >
          <Download className="h-4 w-4" />
          Export NDJSON
        </Button>
      </div>
    </div>
  )
}
