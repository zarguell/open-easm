from __future__ import annotations

import logging

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

TAKEOVER_FINGERPRINTS = {
    "github.io": "github_pages",
    "herokuapp.com": "heroku",
    "s3.amazonaws.com": "aws_s3",
    "azurewebsites.net": "azure_app",
    "cloudfront.net": "aws_cloudfront",
    "surge.sh": "surge",
    "bitbucket.io": "bitbucket",
    "netlify.app": "netlify",
    "firebaseapp.com": "firebase",
    "ghost.io": "ghost",
}


class SubdomainTakeoverHandler(PivotHandler):
    pivot_type = "subdomain_takeover"
    source_name = "takeover"

    async def execute(self, job: dict, pool) -> list[dict]:
        hostname = job["entity_value"]
        try:
            vulnerable = []
            for pattern, service in TAKEOVER_FINGERPRINTS.items():
                if pattern in hostname.lower():
                    vulnerable.append({"pattern": pattern, "service": service})
            return [{"hostname": hostname, "takeover_check": {
                "fingerprint_matches": vulnerable,
                "takeover_risk": len(vulnerable) > 0,
            }}]
        except Exception as e:
            logger.debug("Takeover check failed for %s: %s", hostname, e)
            return [{"hostname": hostname, "message": f"takeover check failed: {e}"}]
