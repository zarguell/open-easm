import { useState, useCallback } from 'react'

export function useAutoRefresh(defaultEnabled = false, intervalMs = 5000) {
  const [enabled, setEnabled] = useState(defaultEnabled)
  const toggle = useCallback(() => { setEnabled(prev => !prev); }, [])
  const refetchInterval: number | false = enabled ? intervalMs : false
  return {
    autoRefreshEnabled: enabled,
    toggleAutoRefresh: toggle,
    refetchInterval,
  }
}
