import { useState, useCallback } from 'react'

export function useAutoRefresh(defaultEnabled: boolean = false, intervalMs: number = 5000) {
  const [enabled, setEnabled] = useState(defaultEnabled)
  const toggle = useCallback(() => setEnabled(prev => !prev), [])
  return {
    autoRefreshEnabled: enabled,
    toggleAutoRefresh: toggle,
    refetchInterval: (enabled ? intervalMs : false) as false | number,
  }
}
