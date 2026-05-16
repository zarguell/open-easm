import { type FC, type ReactNode } from 'react'

interface CardProps {
  children: ReactNode
  className?: string
  style?: React.CSSProperties
}

export const Card: FC<CardProps> = ({ children, className = '', style }) => (
  <div className={`rounded-md border border-hairline bg-canvas p-6 ${className}`} style={style}>
    {children}
  </div>
)

interface MetricCardProps {
  label: string
  value: number | string
  color?: string
  className?: string
}

export const MetricCard: FC<MetricCardProps> = ({ label, value, color, className = '' }) => (
  <Card className={`flex flex-col gap-1 ${className}`}>
    <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">{label}</span>
    <span className="font-mono text-[32px] font-semibold leading-9" style={color ? { color } : undefined}>
      {value}
    </span>
  </Card>
)
