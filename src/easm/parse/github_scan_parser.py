from __future__ import annotations

from easm.parse.base import BaseParser, ParseResult, EntityCandidate


class GithubScanParser(BaseParser):
    source_name = "github_scan"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        source = raw.get("source", "")
        repository = raw.get("repository", "")
        file_path = raw.get("file_path", "") or raw.get("file", "")

        if not source or not repository:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no source or repository")

        entities: list[EntityCandidate] = []

        if source == "gitleaks":
            entities.append(EntityCandidate(
                entity_type="finding",
                value=f"gitleaks-{repository}-{file_path}-{raw.get('line', 0)}",
                attributes={
                    "source": "gitleaks",
                    "repository": repository,
                    "file_path": file_path,
                    "line": raw.get("line", 0),
                    "commit": raw.get("commit", ""),
                    "secret_type": raw.get("secret", ""),
                    "severity": raw.get("severity", "high"),
                    "domain": raw.get("domain", ""),
                    "source_type": "github_scan",
                },
            ))
        elif source == "github_search":
            matches = raw.get("matched_keywords", [])
            if not matches:
                return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no keyword matches")

            for m in matches:
                finding_id = f"github-{repository}-{file_path}-{m.get('keyword', 'unknown')}"
                entities.append(EntityCandidate(
                    entity_type="finding",
                    value=finding_id,
                    attributes={
                        "source": "github_search",
                        "repository": repository,
                        "file_path": file_path,
                        "file_url": raw.get("file_url", ""),
                        "query": raw.get("query", ""),
                        "matched_keyword": m.get("keyword", ""),
                        "match_type": m.get("match_type", ""),
                        "severity": m.get("severity", "medium"),
                        "source_type": "github_scan",
                    },
                ))
        else:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error=f"unknown source: {source}")

        return ParseResult(entities=entities, relationships=[])
