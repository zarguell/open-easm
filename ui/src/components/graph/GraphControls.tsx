import { ZoomIn, ZoomOut, RotateCcw } from 'lucide-react'
import { colors } from '../../DESIGN_TOKENS'

interface GraphControlsProps {
  depth: number
  onDepthChange: (d: number) => void
  onZoomIn: () => void
  onZoomOut: () => void
  onZoomReset: () => void
}

export function GraphControls({ depth, onDepthChange, onZoomIn, onZoomOut, onZoomReset }: GraphControlsProps) {
  return (
    <div className="absolute bottom-4 left-4 bg-canvas border border-hairline rounded-md p-3 z-10 flex items-end gap-4">
      <div className="flex items-center gap-1">
        <button
          onClick={onZoomOut}
          className="p-1.5 rounded hover:bg-canvas-soft text-mute hover:text-ink transition-colors cursor-pointer"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={onZoomReset}
          className="p-1.5 rounded hover:bg-canvas-soft text-mute hover:text-ink transition-colors cursor-pointer"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
        <button
          onClick={onZoomIn}
          className="p-1.5 rounded hover:bg-canvas-soft text-mute hover:text-ink transition-colors cursor-pointer"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
      </div>

      <div className="flex items-center gap-2">
        <label className="text-xs text-mute whitespace-nowrap">Depth</label>
        <input
          type="range"
          min={1}
          max={10}
          value={depth}
          onChange={(e) => onDepthChange(Number(e.target.value))}
          className="w-20 h-1 rounded-full appearance-none cursor-pointer"
          style={{
            backgroundColor: colors.hairline,
            accentColor: colors.primary,
          }}
        />
        <span className="text-xs font-mono text-ink w-4 text-center">{depth}</span>
      </div>
    </div>
  )
}
