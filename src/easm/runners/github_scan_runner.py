from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass

import httpx

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"


class GithubScanRunner(ApiRunner):
    source_name = "github_scan"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        http = self._http_client or httpx.AsyncClient(timeout=60.0)
        inserted = deduped = errors = 0

        kw_engine = KeywordEngine(target)

        try:
            ins, ded, err = await self._run_gitleaks(target, run_id)
            inserted += ins
            deduped += ded
            errors += err

            if target.match_rules.domains or target.match_rules.keywords:
                ins, ded, err = await self._run_github_search(http, kw_engine, target, run_id)
                inserted += ins
                deduped += ded
                errors += err
        finally:
            if not self._http_client:
                await http.aclose()

        return inserted, deduped, errors

    async def _run_gitleaks(
        self, target: TargetConfig, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            cmd = ["gitleaks", "detect", "--no-git", "--source", domain, "--report-format", "json"]
            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=120)
            if not ok:
                if "binary not found" in stderr:
                    logger.warning("gitleaks binary not found, skipping gitleaks scan")
                    return inserted, deduped, errors
                logger.warning("gitleaks error for %s: %s", domain, stderr[:200])
                errors += 1
                continue

            try:
                findings = json.loads(stdout)
                if isinstance(findings, list):
                    for f in findings:
                        raw = {
                            "source": "gitleaks",
                            "repository": f.get("Repo", ""),
                            "file": f.get("File", ""),
                            "line": f.get("Line", 0),
                            "commit": f.get("Commit", ""),
                            "secret": f.get("Secret", ""),
                            "match": f.get("Match", ""),
                            "domain": domain,
                            "severity": f.get("Severity", "high"),
                        }
                        result = await self.store.insert_raw_event(
                            target.org_id, target.id, self.source_name, raw, run_id,
                        )
                        if result:
                            inserted += 1
                        else:
                            deduped += 1
            except json.JSONDecodeError:
                errors += 1

        return inserted, deduped, errors

    async def _run_github_search(
        self,
        http: httpx.AsyncClient,
        kw_engine: KeywordEngine,
        target: TargetConfig,
        run_id: uuid.UUID,
    ) -> tuple[int, int, int]:
        inserted = deduped = errors = 0

        github_token: str | None = self.get_runner_config(target).get("github_token")
        headers = {"Accept": "application/vnd.github.v3.text-match+json"}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        queries: list[str] = []

        for domain in target.match_rules.domains:
            queries.append(f"org:{domain} password")
            queries.append(f"org:{domain} secret")
            queries.append(f"org:{domain} key")

        for keyword in target.match_rules.keywords:
            quoted = f'"{keyword}"'
            queries.append(quoted)

        for query in queries:
            try:
                resp = await http.get(
                    GITHUB_SEARCH_URL,
                    params={"q": query, "per_page": 50},
                    headers=headers,
                )
                if resp.status_code == 403:
                    logger.warning("GitHub API rate limited on query: %s", query)
                    continue
                if resp.status_code != 200:
                    logger.warning("GitHub API returned %d for query: %s", resp.status_code, query)
                    continue

                data = resp.json()
                for item in data.get("items", []):
                    text_matches = item.get("text_matches", [])
                    fragments = [m.get("fragment", "") for m in text_matches]

                    matched_keywords: list[dict] = []
                    for frag in fragments:
                        m = kw_engine.match(frag)
                        for match in m:
                            matched_keywords.append({
                                "keyword": match.keyword,
                                "match_type": match.match_type,
                                "severity": match.severity,
                            })

                    raw = {
                        "source": "github_search",
                        "repository": item.get("repository", {}).get("full_name", ""),
                        "file_path": item.get("path", ""),
                        "file_url": item.get("html_url", ""),
                        "query": query,
                        "matched_keywords": matched_keywords,
                        "fragments": fragments,
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
                logger.warning("GitHub search error for query %s: %s", query, e)

        return inserted, deduped, errors
