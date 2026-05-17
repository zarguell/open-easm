from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class UrlScanParser(BaseParser):
    source_name = "urlscan"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        domain = raw.get("domain", "").strip()
        urlscan = raw.get("urlscan")
        if not domain or not urlscan:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing domain or urlscan data",
            )

        normalized_domain = normalize_entity_value("domain", domain)
        results_raw = urlscan.get("results", [])
        malicious_count = sum(1 for r in results_raw if r.get("is_malicious"))
        malicious_urls = [
            r.get("page_url", "") for r in results_raw if r.get("is_malicious")
        ]

        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="domain",
                    value=normalized_domain,
                    attributes={
                        "source": "urlscan",
                        "threat_intel": {
                            "urlscan": {
                                "total_results": urlscan.get("total_results", 0),
                                "malicious_count": malicious_count,
                                "results": [
                                    {
                                        "page_url": r.get("page_url", ""),
                                        "ip": r.get("ip", ""),
                                        "domain": r.get("domain", ""),
                                        "is_malicious": r.get("is_malicious", False),
                                        "screenshot_url": r.get("screenshot_url"),
                                    }
                                    for r in results_raw
                                ],
                                "malicious_urls": malicious_urls,
                            }
                        },
                    },
                ),
            ],
            relationships=[],
        )
