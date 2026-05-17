import { Routes, Route } from "react-router";
import { AppShell } from "./components/layout/AppShell";
import { DashboardView } from "./components/dashboard/DashboardView";
import { InventoryView } from "./components/inventory/InventoryView";
import { GraphView } from "./components/graph/GraphView";
import { RunsView } from "./components/runs/RunsView";
import { TargetsView } from "./components/targets/TargetsView";
import { ConfigEditorView } from "./components/config/ConfigEditorView";
import { AlertsView } from "./components/alerts/AlertsView";
import { GeoMap } from "./components/GeoMap";

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<DashboardView />} />
        <Route path="inventory" element={<InventoryView />} />
        <Route path="graph" element={<GraphView />} />
        <Route path="runs" element={<RunsView />} />
        <Route path="targets" element={<TargetsView />} />
        <Route path="config" element={<ConfigEditorView />} />
        <Route path="alerts" element={<AlertsView />} />
        <Route path="geo" element={<GeoMap />} />
      </Route>
    </Routes>
  );
}
