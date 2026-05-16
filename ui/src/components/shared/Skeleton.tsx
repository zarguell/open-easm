import { type FC } from 'react'

interface SkeletonProps {
  width?: string
  height?: string
  className?: string
}

export const Skeleton: FC<SkeletonProps> = ({ width, height, className = '' }) => (
  <div
    className={`animate-pulse bg-canvas-soft rounded ${className}`}
    style={{ width: width ?? '100%', height: height ?? '20px' }}
  />
)
