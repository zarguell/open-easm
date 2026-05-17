from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class CloudBucketParser(BaseParser):
    source_name = "cloud_enum"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        bucket_url = raw.get("bucket_url", "").strip()
        provider = raw.get("provider", "").strip()
        if not bucket_url or not provider:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing bucket_url or provider",
            )

        # Strip path component for GCS-style URLs (e.g. storage.googleapis.com/bucket)
        hostname = bucket_url.split("/")[0]
        normalized_url = normalize_entity_value("domain", hostname)
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="domain",
                    value=normalized_url,
                    attributes={
                        "source": "cloud_enum",
                        "cloud_provider": provider,
                        "bucket_name": raw.get("bucket_name", ""),
                        "public_access": raw.get("public_access", False),
                        "public_list": raw.get("public_list", False),
                        "status_code": raw.get("status_code"),
                    },
                ),
            ],
            relationships=[],
        )
