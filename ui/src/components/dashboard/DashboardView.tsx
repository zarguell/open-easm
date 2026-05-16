import { useAutoRefresh } from '../../hooks/useAutoRefresh'
import { MetricCards } from './MetricCards'
import { ActiveRuns } from './ActiveRuns'
import { RecentDiscoveries } from './RecentDiscoveries'
import { QuickTrigger } from './QuickTrigger'
import { Button } from '../shared/Button'

export function DashboardView() {
  const { autoRefreshEnabled, toggleAutoRefresh, refetchInterval } = useAutoRefresh(false, 5000)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-ink">Dashboard</h1>
        <Button variant="ghost" className="text-xs" onClick={toggleAutoRefresh}>
          {autoRefreshEnabled ? 'Auto-refresh: ON' : 'Auto-refresh: OFF'}
        </Button>
      </div>

      <MetricCards />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-6">
          <ActiveRuns refetchInterval={refetchInterval} />
          <RecentDiscoveries refetchInterval={refetchInterval} />
        </div>
        <div>
          <QuickTrigger />
        </div>
      </div>
    </div>
  )
}
