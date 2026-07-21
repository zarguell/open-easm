import { useEffect, useRef, useState } from "react";
import maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import ky from "ky";

interface IpEntity {
  id: string;
  entity_type: string;
  entity_value: string;
  attributes: string | {
    geo?: {
      city?: string;
      country_code?: string;
      country_name?: string;
      latitude?: number;
      longitude?: number;
    };
    [key: string]: unknown;
  };
}

function getGeoAttrs(entity: IpEntity) {
  const attrs = typeof entity.attributes === "string"
    ? JSON.parse(entity.attributes)
    : entity.attributes;
  return attrs.geo;
}

export function GeoMap() {
  const mapContainer = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const [ips, setIps] = useState<IpEntity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchIps() {
      try {
        const resp = await ky
          .get("/api/entities", { searchParams: { entity_type: "ip", limit: "5000" } })
          .json<{ entities: IpEntity[] }>();
        setIps(resp.entities);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to fetch IPs");
      } finally {
        setLoading(false);
      }
    }
    fetchIps();
  }, []);

  useEffect(() => {
    if (!mapContainer.current || mapRef.current) return;

    const map = new maplibregl.Map({
      container: mapContainer.current,
      style: {
        version: 8,
        sources: {
          osm: {
            type: "raster",
            tiles: ["https://tile.openstreetmap.org/{z}/{x}/{y}.png"],
            tileSize: 256,
            attribution: "&copy; OpenStreetMap contributors",
          },
        },
        layers: [{ id: "osm", type: "raster", source: "osm" }],
      },
      center: [0, 20],
      zoom: 2,
    });

    map.addControl(new maplibregl.NavigationControl(), "top-right");
    mapRef.current = map;

    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!mapRef.current || loading || ips.length === 0) return;

    const map = mapRef.current;
    const geoIps = ips.filter(
      (ip) => getGeoAttrs(ip)?.latitude && getGeoAttrs(ip)?.longitude
    );

    if (geoIps.length === 0) return;

    const bounds = new maplibregl.LngLatBounds();

    for (const ip of geoIps) {
      const { latitude, longitude, city, country_name } = getGeoAttrs(ip)!;
      const lngLat = new maplibregl.LngLat(longitude!, latitude!);

      const el = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = ip.entity_value;
      el.appendChild(strong);
      const br = document.createElement("br");
      el.appendChild(br);
      const locationText = document.createTextNode(
        `${city ? `${city}, ` : ""}${country_name || ""}`
      );
      el.appendChild(locationText);
      const popup = new maplibregl.Popup({ offset: 25 }).setDOMContent(el);

      new maplibregl.Marker({ color: "#3b82f6" })
        .setLngLat(lngLat)
        .setPopup(popup)
        .addTo(map);

      bounds.extend(lngLat);
    }

    map.fitBounds(bounds, { padding: 50, maxZoom: 10 });
  }, [ips, loading]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-hairline">
        <h1 className="text-lg font-semibold text-ink">Geo Map</h1>
        <span className="text-sm text-mute">
          {loading ? "Loading..." : `${ips.filter((ip) => getGeoAttrs(ip)?.latitude).length} IPs located`}
        </span>
      </div>
      {error && (
        <div className="px-4 py-2 bg-red-900/30 text-red-300 text-sm">{error}</div>
      )}
      <div ref={mapContainer} className="flex-1 min-h-[500px]" />
    </div>
  );
}
