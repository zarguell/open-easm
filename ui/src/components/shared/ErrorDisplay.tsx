import { type FC } from 'react'
import { AlertCircle } from 'lucide-react'
import { Button } from './Button'

interface ErrorDisplayProps {
  message: string
  onRetry?: () => void
}

export const ErrorDisplay: FC<ErrorDisplayProps> = ({ message, onRetry }) => (
  <div className="flex flex-col items-center justify-center gap-3 py-12">
    <AlertCircle className="w-8 h-8 text-statusError" />
    <p className="text-sm text-statusError text-center max-w-md">{message}</p>
    {onRetry && (
      <Button variant="outline" onClick={onRetry} className="text-xs mt-2">
        Retry
      </Button>
    )}
  </div>
)
