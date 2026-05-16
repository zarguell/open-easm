import { type FC } from 'react'

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

const sizeMap = { sm: 'w-4 h-4', md: 'w-6 h-6', lg: 'w-12 h-12' } as const

export const LoadingSpinner: FC<LoadingSpinnerProps> = ({ size = 'md', className = '' }) => (
  <div className={`flex items-center justify-center ${className}`}>
    <div
      className={`${sizeMap[size]} border-2 border-hairline border-t-primary rounded-full animate-spin`}
    />
  </div>
)
