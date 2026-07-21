import { useState, useEffect, useRef } from "react";
import { useLocation, useNavigate } from "react-router";
import { Search, Menu } from "lucide-react";
import { getEntityColor } from "../../lib/entity-colors";

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
  "/findings": "Findings",
  "/geo": "Geo Map",
};

interface SearchResult {
  id: string;
  entity_type: string;
  entity_value: string;
  target_id: string;
}

export function TopBar({ onMobileMenuToggle }: TopBarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const breadcrumb = routeLabels[location.pathname] ?? "EASM";

  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (query.length < 2) {
      setResults([]);
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const resp = await fetch(
          `/api/entities?q=${encodeURIComponent(query)}&limit=10`
        );
        const data = await resp.json();
        setResults(data.entities ?? []);
        setShowDropdown(true);
      } catch {
        setResults([]);
      }
    }, 300);
    return () => { clearTimeout(timer); };
  }, [query]);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target as Node)
      ) {
        setShowDropdown(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => { document.removeEventListener("mousedown", handleClickOutside); };
  }, []);

  const handleSelect = (result: SearchResult) => {
    setShowDropdown(false);
    setQuery("");
    navigate(`/inventory?entityType=${result.entity_type}`);
  };

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

      <div className="relative" ref={dropdownRef}>
        <div className="flex items-center gap-2 bg-canvas-soft rounded-md px-3 py-1.5 text-mute">
          <Search className="w-4 h-4" />
          <input
            type="text"
            placeholder="Search…"
            value={query}
            onChange={(e) => { setQuery(e.target.value); }}
            onFocus={() => results.length > 0 && setShowDropdown(true)}
            className="bg-transparent border-none outline-none text-sm text-ink placeholder:text-mute w-32 sm:w-48"
          />
        </div>

        {showDropdown && results.length > 0 && (
          <div className="absolute right-0 top-full mt-1 w-80 max-h-80 overflow-y-auto rounded-md border border-hairline bg-canvas shadow-lg z-50">
            {results.map((r) => {
              const color = getEntityColor(r.entity_type);
              return (
                <button
                  key={r.id}
                  onClick={() => { handleSelect(r); }}
                  className="flex items-center gap-3 w-full px-3 py-2 text-left hover:bg-canvas-soft transition-colors cursor-pointer"
                >
                  <span
                    className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider uppercase shrink-0"
                    style={{
                      backgroundColor: `${color}1f`,
                      color,
                    }}
                  >
                    {r.entity_type}
                  </span>
                  <span className="font-mono text-sm text-ink truncate">
                    {r.entity_value}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </header>
  );
}
