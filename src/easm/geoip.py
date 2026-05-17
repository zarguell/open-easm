from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "GeoLite2-City.mmdb"


@dataclass
class GeoIpResult:
    city: str | None
    country_code: str | None
    country_name: str | None
    latitude: float | None
    longitude: float | None
    asn: int | None = None
    asn_org: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "city": self.city,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "asn_org": self.asn_org,
        }


class GeoIpLookup:
    def __init__(self, reader: Any = None, db_path: str | Path | None = None):
        self._reader = reader
        self._owns_reader = False
        if reader is None:
            path = Path(db_path) if db_path else _DEFAULT_DB_PATH
            if path.exists():
                try:
                    import maxminddb

                    self._reader = maxminddb.Reader(str(path))
                    self._owns_reader = True
                except Exception:
                    logger.warning("Failed to open GeoLite2 database at %s", path)
            else:
                logger.info("GeoLite2 database not found at %s, geo-IP lookups disabled", path)

    def lookup(self, ip: str) -> GeoIpResult | None:
        if self._reader is None:
            return None
        try:
            result = self._reader.get(ip)
        except Exception:
            return None
        if result is None:
            return None

        city = None
        if "city" in result:
            city = result["city"].get("names", {}).get("en")

        country_code = None
        country_name = None
        if "country" in result:
            country_code = result["country"].get("iso_code")
            country_name = result["country"].get("names", {}).get("en")

        lat = None
        lon = None
        if "location" in result:
            lat = result["location"].get("latitude")
            lon = result["location"].get("longitude")

        return GeoIpResult(
            city=city,
            country_code=country_code,
            country_name=country_name,
            latitude=lat,
            longitude=lon,
        )

    def close(self):
        if self._owns_reader and self._reader:
            self._reader.close()
