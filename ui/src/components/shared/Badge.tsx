import { type FC } from 'react'
import { colors } from '../../DESIGN_TOKENS'
import { getEntityColor, getEntityLabel } from '../../lib/entity-colors'

type BadgeVariant = 'success' | 'error' | 'warning' | 'running' | 'pending'

const variantStyles: Record<BadgeVariant, { bg: string; text: string }> = {
  success: { bg: `${colors.statusSuccess}1f`, text: colors.statusSuccess },
  error: { bg: `${colors.statusError}1f`, text: colors.statusError },
  warning: { bg: `${colors.statusWarning}1f`, text: colors.statusWarning },
  running: { bg: `${colors.statusRunning}1f`, text: colors.statusRunning },
  pending: { bg: `${colors.statusPending}1f`, text: colors.statusPending },
}

interface BadgeProps {
  variant: BadgeVariant
  children: React.ReactNode
  className?: string
}

export const Badge: FC<BadgeProps> = ({ variant, children, className = '' }) => {
  const style = variantStyles[variant]
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[11px] font-semibold tracking-wider uppercase ${className}`}
      style={{ backgroundColor: style.bg, color: style.text }}
    >
      {children}
    </span>
  )
}

interface EntityTypeBadgeProps {
  entityType: string
  className?: string
}

export const EntityTypeBadge: FC<EntityTypeBadgeProps> = ({ entityType, className = '' }) => {
  const color = getEntityColor(entityType)
  const label = getEntityLabel(entityType)
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[11px] font-semibold tracking-wider ${className}`}
      style={{ backgroundColor: `${color}1f`, color }}
    >
      {label}
    </span>
  )
}
