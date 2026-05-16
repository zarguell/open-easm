import tldextract
from easm.pivot.handlers.base import PivotHandler


class DomainExtractHandler(PivotHandler):
    pivot_type = "domain_extract"
    source_name = "domain_extract"

    async def execute(self, job: dict, pool) -> list[dict]:
        hostname = job["entity_value"]
        extracted = tldextract.extract(hostname)
        apex = f"{extracted.domain}.{extracted.suffix}".lower()
        if apex == hostname.lower():
            return []
        return [{"domain": apex, "source_hostname": hostname}]
