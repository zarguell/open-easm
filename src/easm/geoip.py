from __future__ import annotations

import logging
import shutil
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "GeoLite2-City.mmdb"
_GEOIP_DB_URL = "https://github.com/zarguell/TA-geoip/raw/refs/heads/master/bin/GeoLite2-City.mmdb"
_MAX_AGE_DAYS = 30


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


def download_geoip_db(url: str = _GEOIP_DB_URL, dest: Path | None = None) -> Path | None:
    """Download GeoLite2 City database. Returns path on success, None on failure."""
    if dest is None:
        dest = _DEFAULT_DB_PATH
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        logger.info("downloading GeoLite2 database from %s", url)
        with urllib.request.urlopen(url, timeout=120) as resp:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                shutil.copyfileobj(resp, tmp)
                tmp_path = Path(tmp.name)

        shutil.move(str(tmp_path), str(dest))
        dest.chmod(0o644)
        logger.info("GeoLite2 database downloaded to %s (%d bytes)", dest, dest.stat().st_size)
        return dest
    except (urllib.error.URLError, OSError, shutil.Error) as e:
        logger.warning(
            "failed to download GeoLite2 database from %s",
            url, exc_info=True, extra={"error": str(e)},
        )
        return None


def geoip_db_needs_refresh(path: Path, max_age_days: int = _MAX_AGE_DAYS) -> bool:
    """Check if the GeoLite2 database is missing or older than max_age_days."""
    if not path.exists():
        return True
    age = datetime.now(UTC) - datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    return age > timedelta(days=max_age_days)


class GeoIpLookup:
    def __init__(self, reader: Any = None, db_path: str | Path | None = None, auto_download: bool = True):
        self._reader = reader
        self._owns_reader = False
        if reader is None:
            path = Path(db_path) if db_path else _DEFAULT_DB_PATH

            if not path.exists() and auto_download:
                download_geoip_db(dest=path)

            if path.exists():
                try:
                    import maxminddb

                    self._reader = maxminddb.Reader(str(path))
                    self._owns_reader = True
                except (OSError, ValueError) as e:
                    logger.warning(
                        "Failed to open GeoLite2 database at %s",
                        path, extra={"error": str(e)},
                    )
            else:
                logger.info("GeoLite2 database not found at %s, geo-IP lookups disabled", path)

    def lookup(self, ip: str) -> GeoIpResult | None:
        if self._reader is None:
            return None
        try:
            result = self._reader.get(ip)
        except (KeyError, ValueError, TypeError) as e:
            logger.debug("GeoIP lookup failed for %s", ip, extra={"error": str(e)})
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


def ensure_geoip_db(max_age_days: int = _MAX_AGE_DAYS, url: str = _GEOIP_DB_URL) -> Path | None:
    """Ensure the GeoLite2 database exists and is fresh. Call at startup."""
    if geoip_db_needs_refresh(_DEFAULT_DB_PATH, max_age_days):
        return download_geoip_db(url=url, dest=_DEFAULT_DB_PATH)
    return _DEFAULT_DB_PATH if _DEFAULT_DB_PATH.exists() else None
