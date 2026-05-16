import { type FC } from 'react'
import { getEntityColor, getEntityLabel } from '../../lib/entity-colors'

interface CascadeStepProps {
  entityType: string
  count: number | null
  isLast: boolean
}

export const CascadeStep: FC<CascadeStepProps> = ({ entityType, count, isLast }) => {
  const color = getEntityColor(entityType)
  const label = getEntityLabel(entityType)

  return (
    <div className="flex items-center">
      <div
        className="flex flex-col items-center gap-1 rounded-md border border-hairline px-4 py-3"
        style={{ minWidth: 80 }}
      >
        <div
          className="h-3 w-3 rounded-full"
          style={{ backgroundColor: color }}
        />
        <span className="font-mono text-[11px] font-semibold tracking-wider text-ink">
          {label}
        </span>
        {count !== null && (
          <span className="font-mono text-sm text-body">{count}</span>
        )}
        {count === null && (
          <span className="font-mono text-sm text-mute">?</span>
        )}
      </div>
      {!isLast && (
        <div className="flex items-center px-2">
          <div className="h-px w-6 bg-hairline-soft" />
          <svg
            className="h-3 w-3 text-hairline-soft shrink-0"
            viewBox="0 0 12 12"
            fill="none"
          >
            <path
              d="M2 6h8M8 3l3 3-3 3"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      )}
    </div>
  )
}
