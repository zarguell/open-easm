import { type FC } from 'react'
import type { RunDetail as RunDetailType } from '../../api/runs'

interface RunDetailProps {
  run: RunDetailType
}

export const RunDetail: FC<RunDetailProps> = ({ run }) => (
  <div className="rounded-md bg-canvas-soft p-4 space-y-3">
    {run.error_message && (
      <div>
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-statusError">
          Error
        </span>
        <p className="mt-1 text-sm text-statusError">{run.error_message}</p>
      </div>
    )}
    {run.metadata && Object.keys(run.metadata).length > 0 && (
      <div>
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">
          Metadata
        </span>
        <pre className="mt-1 overflow-x-auto rounded-sm bg-canvas p-3 font-mono text-xs text-body">
          {JSON.stringify(run.metadata, null, 2)}
        </pre>
      </div>
    )}
  </div>
)
