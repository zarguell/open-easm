"""Legal disclaimer terms text and versioning."""

from __future__ import annotations

import hashlib

TERMS_VERSION = "en-2026-05-21"

LEGAL_WARNING_TEXT = """\
RESPONSIBLE USE DISCLAIMER AND TERMS OF USE — OpenEASM

OpenEASM is an External Attack Surface Management tool designed to help
organizations identify their public internet-facing exposure.

The tool performs limited, non-exploitative technical checks including DNS
analysis, TLS/SSL inspection, HTTP header review, open port identification,
service and version detection, and passive correlation with publicly known
vulnerabilities (CVEs).

OpenEASM does NOT perform:
- Exploitation of vulnerabilities
- Brute-force attacks
- Denial-of-service attacks
- Authentication bypass
- Data modification or unauthorized extraction
- Any offensive security operation

By using OpenEASM, I acknowledge:
1. I am solely responsible for the domains, subdomains, IP addresses, and
   services I submit for analysis.
2. I have explicit authorization, a legitimate right, or a lawful security
   purpose to analyze the resources I submit.
3. Analyzing systems without authorization may constitute a criminal offense
   under applicable law, including but not limited to the Computer Fraud and
   Abuse Act (CFAA), the EU Directive on Attacks Against Information Systems,
   and equivalent national legislation.
4. The results are based on publicly observable information and passive
   correlation; they do not constitute proof of exploitation.
5. Detected software versions may differ from actual versions due to backported
   security patches applied by operating system distributors.

By accepting these terms, I confirm that I have read, understood, and agree to
use OpenEASM only in a lawful, authorized, and defensive capacity.
""".strip()


def terms_hash() -> str:
    """SHA-256 hash of the current terms text."""
    return hashlib.sha256(LEGAL_WARNING_TEXT.encode("utf-8")).hexdigest()


def legal_payload() -> dict:
    """Return the full legal payload for the API."""
    return {
        "app": "OpenEASM",
        "version": TERMS_VERSION,
        "hash": terms_hash(),
        "text": LEGAL_WARNING_TEXT,
        "blocking": True,
        "requires_acceptance": True,
    }
