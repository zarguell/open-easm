import { useLocation, useNavigate } from "react-router";
import {
  LayoutDashboard,
  List,
  Share2,
  Play,
  Target,
  Globe,
  Settings,
  Bell,
  PanelLeftClose,
  PanelLeftOpen,
  Shield,
  X,
} from "lucide-react";

interface SidebarProps {
  expanded: boolean;
  onToggle: () => void;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

const navItems = [
  { icon: LayoutDashboard, label: "Dashboard", path: "/" },
  { icon: List, label: "Inventory", path: "/inventory" },
  { icon: Share2, label: "Graph Explorer", path: "/graph" },
  { icon: Play, label: "Runs", path: "/runs" },
  { icon: Target, label: "Targets & Pivots", path: "/targets" },
  { icon: Settings, label: "Config", path: "/config" },
  { icon: Bell, label: "Alerts", path: "/alerts" },
  { icon: Globe, label: "Geo Map", path: "/geo" },
] as const;

export function Sidebar({ expanded, onToggle, mobileOpen, onMobileClose }: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();

  const handleNav = (path: string) => {
    navigate(path);
    onMobileClose();
  };

  return (
    <>
      {/* mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={onMobileClose}
        />
      )}

      {/* mobile sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col bg-canvas border-r border-hairline transition-transform duration-200 md:hidden ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        } w-[240px]`}
      >
        <div className="flex items-center justify-between h-14 px-4 border-b border-hairline">
          <span className="text-lg font-bold text-ink tracking-wide">EASM</span>
          <button
            onClick={onMobileClose}
            className="p-1 text-mute hover:text-ink transition-colors cursor-pointer"
            aria-label="Close sidebar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="flex-1 py-2 flex flex-col gap-0.5 px-2">
          {navItems.map(({ icon: Icon, label, path }) => {
            const isActive =
              path === "/"
                ? location.pathname === "/"
                : location.pathname.startsWith(path);

            return (
              <button
                key={path}
                onClick={() => handleNav(path)}
                className={`flex items-center gap-3 px-3 py-2 rounded-md transition-colors cursor-pointer ${
                  isActive
                    ? "bg-canvas-soft text-primary border-l-2 border-primary"
                    : "text-mute hover:bg-canvas-soft hover:text-ink"
                }`}
                title={label}
              >
                <Icon className="w-5 h-5 shrink-0" />
                <span className="text-sm truncate">{label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      {/* tablet sidebar */}
      <aside className="hidden md:flex lg:hidden flex-col bg-canvas border-r border-hairline shrink-0 w-16">
        <div className="flex items-center h-14 px-4 border-b border-hairline">
          <Shield className="w-5 h-5 text-primary mx-auto" />
        </div>

        <nav className="flex-1 py-2 flex flex-col gap-0.5 px-2">
          {navItems.map(({ icon: Icon, label, path }) => {
            const isActive =
              path === "/"
                ? location.pathname === "/"
                : location.pathname.startsWith(path);

            return (
              <button
                key={path}
                onClick={() => handleNav(path)}
                className={`flex items-center justify-center px-0 py-2 rounded-md transition-colors cursor-pointer ${
                  isActive
                    ? "bg-canvas-soft text-primary border-l-2 border-primary"
                    : "text-mute hover:bg-canvas-soft hover:text-ink"
                }`}
                title={label}
              >
                <Icon className="w-5 h-5 shrink-0" />
              </button>
            );
          })}
        </nav>
      </aside>

      {/* desktop sidebar */}
      <aside
        className={`hidden lg:flex flex-col bg-canvas border-r border-hairline shrink-0 transition-[width] duration-200 ${
          expanded ? "w-[240px]" : "w-16"
        }`}
      >
        <div className="flex items-center h-14 px-4 border-b border-hairline">
          {expanded ? (
            <span className="text-lg font-bold text-ink tracking-wide">EASM</span>
          ) : (
            <Shield className="w-5 h-5 text-primary mx-auto" />
          )}
        </div>

        <nav className="flex-1 py-2 flex flex-col gap-0.5 px-2">
          {navItems.map(({ icon: Icon, label, path }) => {
            const isActive =
              path === "/"
                ? location.pathname === "/"
                : location.pathname.startsWith(path);

            return (
              <button
                key={path}
                onClick={() => handleNav(path)}
                className={`flex items-center gap-3 rounded-md transition-colors cursor-pointer ${
                  expanded ? "px-3 py-2" : "px-0 py-2 justify-center"
                } ${
                  isActive
                    ? "bg-canvas-soft text-primary border-l-2 border-primary"
                    : "text-mute hover:bg-canvas-soft hover:text-ink"
                }`}
                title={label}
              >
                <Icon className="w-5 h-5 shrink-0" />
                {expanded && (
                  <span className="text-sm truncate">{label}</span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="border-t border-hairline p-2">
          <button
            onClick={onToggle}
            className={`flex items-center gap-3 rounded-md px-3 py-2 text-mute hover:bg-canvas-soft hover:text-ink transition-colors w-full cursor-pointer ${
              !expanded && "justify-center px-0"
            }`}
            title={expanded ? "Collapse sidebar" : "Expand sidebar"}
          >
            {expanded ? (
              <PanelLeftClose className="w-5 h-5 shrink-0" />
            ) : (
              <PanelLeftOpen className="w-5 h-5 shrink-0" />
            )}
            {expanded && (
              <span className="text-sm">Collapse</span>
            )}
          </button>
        </div>
      </aside>
    </>
  );
}
