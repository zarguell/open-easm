import { useState, type FC } from 'react'
import type { RunDetail as RunDetailType } from '../../api/runs'

interface RunDetailProps {
  run: RunDetailType
}

export const RunDetail: FC<RunDetailProps> = ({ run }) => {
  const [showLogs, setShowLogs] = useState(false)

  return (
    <div className="rounded-md bg-canvas-soft p-4 space-y-3">
      {run.error_message && (
        <div>
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-statusError">
            Error
          </span>
          <p className="mt-1 text-sm text-statusError">{run.error_message}</p>
        </div>
      )}
      {run.logs && (
        <div>
          <button
            type="button"
            onClick={() => setShowLogs(!showLogs)}
            className="font-mono text-[11px] font-semibold uppercase tracking-wider text-accent hover:text-accent-light transition-colors"
          >
            {showLogs ? 'Hide Logs' : 'Show Logs'}
          </button>
          {showLogs && (
            <pre className="mt-3 rounded-lg bg-[#1a1a2e] p-3 max-h-96 overflow-auto font-mono text-sm text-gray-300">
              {run.logs}
            </pre>
          )}
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
}
