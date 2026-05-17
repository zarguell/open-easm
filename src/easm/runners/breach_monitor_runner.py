from __future__ import annotations

import json
import logging
import uuid
from base64 import b64encode

import httpx

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount"
DEHASHED_API = "https://api.dehashed.com/search"


class BreachMonitorRunner(ApiRunner):
    source_name = "breach_monitor"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        sources: list[str] = cfg.get("sources", ["hibp"])
        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        inserted = deduped = errors = 0

        try:
            if "hibp" in sources:
                ins, ded, err = await self._check_hibp(http, target, run_id)
                inserted += ins
                deduped += ded
                errors += err

            if "dehashed" in sources:
                ins, ded, err = await self._check_dehashed(http, target, run_id)
                inserted += ins
                deduped += ded
                errors += err
        finally:
            if not self._http_client:
                await http.aclose()

        return inserted, deduped, errors

    async def _check_hibp(
        self,
        http: httpx.AsyncClient,
        target: TargetConfig,
        run_id: uuid.UUID,
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        api_key: str | None = cfg.get("hibp_api_key")
        inserted = deduped = errors = 0

        emails: set[str] = set()
        for domain in target.match_rules.domains:
            emails.add(f"admin@{domain}")
            emails.add(f"security@{domain}")
            emails.add(f"noreply@{domain}")

        for email in emails:
            headers: dict[str, str] = {}
            if api_key:
                headers["hibp-api-key"] = api_key
            headers["user-agent"] = "open-easm/1.0"

            try:
                resp = await http.get(f"{HIBP_API}/{email}", headers=headers)
                if resp.status_code == 404:
                    continue
                if resp.status_code == 429:
                    logger.warning("HIBP rate limited, sleeping")
                    continue
                if resp.status_code != 200:
                    logger.warning("HIBP returned %d for %s", resp.status_code, email)
                    continue

                breaches = resp.json()
                for breach in breaches:
                    raw = {
                        "source": "hibp",
                        "email": email,
                        "breach_name": breach.get("Name", ""),
                        "breach_date": breach.get("BreachDate", ""),
                        "data_classes": breach.get("DataClasses", []),
                        "description": breach.get("Description", ""),
                        "domain": breach.get("Domain", ""),
                    }
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
            except Exception as e:
                errors += 1
                logger.warning("HIBP error for %s: %s", email, e)

        return inserted, deduped, errors

    async def _check_dehashed(
        self,
        http: httpx.AsyncClient,
        target: TargetConfig,
        run_id: uuid.UUID,
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        api_key: str | None = cfg.get("dehashed_api_key")
        dehashed_email: str | None = cfg.get("dehashed_email")
        inserted = deduped = errors = 0

        if not api_key or not dehashed_email:
            logger.warning("Dehashed requires both api_key and email configured")
            return 0, 0, 0

        auth = b64encode(f"{dehashed_email}:{api_key}".encode()).decode()
        headers = {"Accept": "application/json", "Authorization": f"Basic {auth}"}

        queries: list[str] = []
        for domain in target.match_rules.domains:
            queries.append(f"domain:{domain}")
        for email_domain in target.match_rules.domains:
            queries.append(f"email:*@{email_domain}")

        for query in queries:
            try:
                resp = await http.get(DEHASHED_API, params={"query": query, "size": 100}, headers=headers)
                if resp.status_code != 200:
                    logger.warning("Dehashed returned %d for query: %s", resp.status_code, query)
                    continue

                data = resp.json()
                for entry in data.get("entries", []):
                    raw = {
                        "source": "dehashed",
                        "query": query,
                        "email": entry.get("email", ""),
                        "password": entry.get("password", ""),
                        "username": entry.get("username", ""),
                        "hashed_password": entry.get("hashed_password", ""),
                        "database_name": entry.get("database_name", ""),
                        "ip_address": entry.get("ip_address", ""),
                        "name": entry.get("name", ""),
                    }
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
            except Exception as e:
                errors += 1
                logger.warning("Dehashed error for query %s: %s", query, e)

        return inserted, deduped, errors
