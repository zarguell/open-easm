import { type FC, type ButtonHTMLAttributes } from 'react'
import { colors } from '../../DESIGN_TOKENS'

type ButtonVariant = 'primary' | 'outline' | 'ghost' | 'danger'

const variantStyles: Record<ButtonVariant, React.CSSProperties> = {
  primary: { backgroundColor: colors.primary, color: colors.onPrimary },
  outline: { backgroundColor: colors.canvas, color: colors.ink, borderColor: colors.hairline },
  ghost: { backgroundColor: 'transparent', color: colors.primarySoft },
  danger: { backgroundColor: colors.statusError, color: colors.inkStrong },
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
}

export const Button: FC<ButtonProps> = ({ variant = 'primary', className = '', style, ...props }) => {
  const variantStyle = variantStyles[variant]
  return (
    <button
      className={`inline-flex items-center justify-center rounded-sm px-4 py-2 text-sm font-semibold leading-5 transition-colors hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
      style={{ ...variantStyle, border: variant === 'outline' ? '1px solid' : 'none', ...style }}
      {...props}
    />
  )
}
