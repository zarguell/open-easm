import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router";
import { AppShell } from "./components/layout/AppShell";
import { LoginPage } from "./components/auth/LoginPage";
import { RegisterPage } from "./components/auth/RegisterPage";
import { useAuth } from "./hooks/useAuth";

const Dashboard = lazy(() => import("./components/dashboard/DashboardView").then(m => ({ default: m.DashboardView })));
const AssetInventoryView = lazy(() => import("./components/assets/AssetInventoryView").then(m => ({ default: m.AssetInventoryView })));
const InventoryView = lazy(() => import("./components/inventory/InventoryView").then(m => ({ default: m.InventoryView })));
const CertificateInventoryView = lazy(() => import("./components/certificates/CertificateInventoryView").then(m => ({ default: m.CertificateInventoryView })));
const GraphView = lazy(() => import("./components/graph/GraphView").then(m => ({ default: m.GraphView })));
const RunsView = lazy(() => import("./components/runs/RunsView").then(m => ({ default: m.RunsView })));
const TargetsView = lazy(() => import("./components/targets/TargetsView").then(m => ({ default: m.TargetsView })));
const ConfigEditorView = lazy(() => import("./components/config/ConfigEditorView").then(m => ({ default: m.ConfigEditorView })));
const AlertsView = lazy(() => import("./components/alerts/AlertsView").then(m => ({ default: m.AlertsView })));
const FindingsView = lazy(() => import("./components/findings/FindingsView").then(m => ({ default: m.FindingsView })));
const GeoMap = lazy(() => import("./components/GeoMap").then(m => ({ default: m.GeoMap })));
const NotificationSettings = lazy(() => import("./components/settings/NotificationSettings").then(m => ({ default: m.NotificationSettings })));
const UsersView = lazy(() => import("./components/admin/UsersView").then(m => ({ default: m.UsersView })));

function ProtectedRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-canvas">
        <div className="text-mute">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <Suspense fallback={
      <div className="flex h-screen items-center justify-center text-ink-mute">
        Loading...
      </div>
    }>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Dashboard />} />
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
          <Route path="users" element={<UsersView />} />
        </Route>
      </Routes>
    </Suspense>
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
