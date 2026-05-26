import { Routes, Route, Navigate } from "react-router";
import { AppShell } from "./components/layout/AppShell";
import { DashboardView } from "./components/dashboard/DashboardView";
import { AssetInventoryView } from "./components/assets/AssetInventoryView";
import { InventoryView } from "./components/inventory/InventoryView";
import { CertificateInventoryView } from "./components/certificates/CertificateInventoryView";
import { GraphView } from "./components/graph/GraphView";
import { RunsView } from "./components/runs/RunsView";
import { TargetsView } from "./components/targets/TargetsView";
import { ConfigEditorView } from "./components/config/ConfigEditorView";
import { AlertsView } from "./components/alerts/AlertsView";
import { FindingsView } from "./components/findings/FindingsView";
import { GeoMap } from "./components/GeoMap";
import { NotificationSettings } from "./components/settings/NotificationSettings";
import { LoginPage } from "./components/auth/LoginPage";
import { RegisterPage } from "./components/auth/RegisterPage";
import { useAuth } from "./hooks/useAuth";

function ProtectedRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-canvas">
        <div className="text-muted">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<DashboardView />} />
        <Route path="assets" element={<AssetInventoryView />} />
        <Route path="inventory" element={<InventoryView />} />
        <Route path="certificates" element={<CertificateInventoryView />} />
        <Route path="graph" element={<GraphView />} />
        <Route path="runs" element={<RunsView />} />
        <Route path="targets" element={<TargetsView />} />
        <Route path="config" element={<ConfigEditorView />} />
        <Route path="alerts" element={<AlertsView />} />
        <Route path="findings" element={<FindingsView />} />
        <Route path="notifications" element={<NotificationSettings />} />
        <Route path="geo" element={<GeoMap />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/*" element={<ProtectedRoutes />} />
    </Routes>
  );
}
