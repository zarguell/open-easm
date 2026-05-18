import { useLocation } from "react-router";
import { Search, Menu } from "lucide-react";

interface TopBarProps {
  onMobileMenuToggle: () => void;
}

const routeLabels: Record<string, string> = {
  "/": "Dashboard",
  "/assets": "Asset Inventory",
  "/inventory": "Inventory",
  "/certificates": "Certificates",
  "/graph": "Graph Explorer",
  "/runs": "Runs",
  "/targets": "Targets & Pivots",
  "/config": "Config",
  "/alerts": "Alerts",
  "/geo": "Geo Map",
};

export function TopBar({ onMobileMenuToggle }: TopBarProps) {
  const location = useLocation();
  const breadcrumb = routeLabels[location.pathname] ?? "EASM";

  return (
    <header className="flex items-center justify-between h-14 px-lg bg-canvas border-b border-hairline shrink-0">
      <div className="flex items-center gap-3">
        <button
          onClick={onMobileMenuToggle}
          className="p-1.5 text-mute hover:text-ink transition-colors md:hidden cursor-pointer"
          aria-label="Toggle menu"
        >
          <Menu className="w-5 h-5" />
        </button>
        <span className="text-sm font-medium text-ink">{breadcrumb}</span>
      </div>

      <div className="flex items-center gap-2 bg-canvas-soft rounded-md px-3 py-1.5 text-mute">
        <Search className="w-4 h-4" />
        <input
          type="text"
          placeholder="Search…"
          className="bg-transparent border-none outline-none text-sm text-ink placeholder:text-mute w-32 sm:w-48"
        />
      </div>
    </header>
  );
}
