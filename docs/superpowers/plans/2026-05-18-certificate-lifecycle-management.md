# Certificate Lifecycle Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn certificate data from passive CT logs and live TLS observations into a certificate lifecycle inventory that distinguishes deployed risk from CT-only risk, tracks CA/issuer inventory, and flags weak, expired, expiring, unobserved, and mismatched certificates.

**Architecture:** Keep certificates as existing `certificate` entities, but normalize all certificate-producing schemas into a shared `certificate_profile` attribute shape. Add a small certificate analysis layer that derives deployment state, validity state, crypto strength, CA inventory fields, and lifecycle findings from the entity graph. Expose the derived inventory through store/API methods so UI/reporting can consume it without duplicating certificate logic.

**Tech Stack:** Python 3.14, asyncpg/Postgres JSONB, pytest/pytest-asyncio, `cryptography`, FastAPI, Docker Compose test harness.

**Standards Notes:** Certificate policy thresholds should be centralized and source-backed. As of May 18, 2026, CA/Browser Forum Baseline Requirements list a 200-day maximum validity period for TLS Subscriber Certificates issued on or after March 15, 2026; do not hardcode this in scattered tests or UI code. References: [CA/B Forum latest Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/requirements/), [Mozilla on 1024-bit RSA deprecation](https://blog.mozilla.org/security/2014/09/08/phasing-out-certificates-with-1024-bit-rsa-keys/).

**Constraints:**
- Do not make commits.
- Do not run active scans against public targets while implementing or testing.
- Live TLS behavior must be covered with fixtures or monkeypatched raw handler results.
- Keep the canonical backend gate: `docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test`.

---

## Scope

This plan builds a backend-first certificate lifecycle capability:

- Normalize certificate profiles from `crtsh`, `certstream`, and `tls_cert`.
- Distinguish `deployed`, `ct_only`, `unobserved_candidate`, and `replaced_or_not_deployed` states.
- Rank expired deployed certificates higher than expired CT-only certificates.
- Detect weak or suspicious certificate attributes: weak key size, weak signature/hash algorithm, CA/basic-constraints oddities, missing SANs, hostname mismatch, abnormal validity period, self-signed, and untrusted/unknown issuer markers where data is available.
- Inventory issuing CAs and issuer organizations.
- Produce explicit findings and an API-ready inventory.

Out of scope for this first implementation:

- Browser trust-store verification against Mozilla/Apple/Microsoft root programs.
- OCSP/CRL revocation checking.
- ACME renewal automation.
- UI screens beyond returning API-ready data.

---

## Current State Summary

Relevant existing files:

- `src/easm/runners/schemas.py`
  - `crtsh(raw)` creates certificate entities from CT data but only stores issuer id and dates.
  - `certstream(raw)` creates certificate entities from stream data but does not normalize fields consistently.
  - `tls_cert(raw)` creates certificate entities from a live endpoint and records `grabbed_from`.
- `src/easm/pivot/handlers.py`
  - `tls_cert_grab(job, pool)` fetches a deployed leaf certificate but currently extracts only a narrow set of fields.
- `correlations/stale_certificate.yaml`
  - Currently checks regexes against `entity_value`, so it cannot reliably detect expiration from certificate dates.
- `src/easm/store.py`
  - Stores certificate attributes in `entities.attributes`; no dedicated certificate inventory query exists.
- `src/easm/api/routes/`
  - No certificate inventory endpoint exists yet.

Important existing behavior:

- Certificate entity values are normalized by hashing in `src/easm/entity_store.py`.
- Attributes are deep-merged, so profile updates must merge lists without silently replacing important observations.

---

## Target Data Model

All certificate-producing schemas should attach this common shape under `attributes["certificate_profile"]`:

```python
{
    "fingerprint_sha256": "hex-or-empty",
    "serial_number": "hex-or-empty",
    "subject": {"common_name": "www.example.com", "raw": {}},
    "issuer": {
        "common_name": "Example Issuing CA",
        "organization": "Example CA Inc.",
        "name_id": "crtsh issuer id when available",
        "raw": {},
    },
    "san_dns_names": ["www.example.com", "api.example.com"],
    "not_before": "2026-01-01T00:00:00+00:00",
    "not_after": "2026-06-01T00:00:00+00:00",
    "validity_days": 151,
    "public_key": {
        "algorithm": "RSA",
        "size_bits": 2048,
        "curve": "",
    },
    "signature": {
        "algorithm": "sha256WithRSAEncryption",
        "hash_algorithm": "sha256",
    },
    "x509": {
        "version": 3,
        "is_ca": False,
        "basic_constraints": {"ca": False, "path_length": None},
        "key_usage": [],
        "extended_key_usage": [],
    },
    "sources": ["crtsh", "tls_cert"],
    "ct": {
        "seen": True,
        "first_seen_at": "",
        "last_seen_at": "",
    },
    "deployment": {
        "state": "deployed",
        "last_observed_at": "2026-05-18T12:00:00+00:00",
        "observed_endpoints": [
            {"hostname": "www.example.com", "port": 443, "source": "tls_cert"}
        ],
    },
    "analysis": {
        "validity_state": "valid",
        "days_until_expiry": 14,
        "strength": "strong",
        "risk": "medium",
        "reasons": ["expires_within_30_days"],
    },
}
```

Deployment states:

- `deployed`: physically observed from `tls_cert`.
- `ct_only`: known only from `crtsh` or `certstream`.
- `unobserved_candidate`: CT cert is currently valid and matches in-scope names but no matching deployed leaf has been observed.
- `replaced_or_not_deployed`: CT cert is expired or older and no live endpoint currently presents it.

---

## File Structure

Create:

- `src/easm/certificates/__init__.py` - package marker and public exports.
- `src/easm/certificates/profile.py` - profile normalization helpers and datetime parsing.
- `src/easm/certificates/analysis.py` - derives lifecycle state, strength, risk, and reasons.
- `src/easm/certificates/findings.py` - converts certificate inventory rows into `Finding` objects.
- `src/easm/api/routes/certificates.py` - certificate inventory and summary endpoints.
- `tests/test_certificates/test_profile.py` - unit tests for profile normalization.
- `tests/test_certificates/test_analysis.py` - unit tests for state/risk derivation.
- `tests/test_certificates/test_findings.py` - DB-backed finding generation tests.
- `tests/test_api/test_certificates.py` - API response tests.

Modify:

- `src/easm/runners/schemas.py` - use shared certificate profile helpers in `crtsh`, `certstream`, and `tls_cert`.
- `src/easm/pivot/handlers.py` - extract deeper X.509 fields in `tls_cert_grab`.
- `src/easm/store.py` - add `list_certificate_inventory()` and `summarize_certificate_inventory()`.
- `src/easm/api/app.py` - include certificate router.
- `correlations/stale_certificate.yaml` - either retire or narrow to compatibility after explicit finding generation exists.
- `AGENTS.md` - document certificate profile invariants.

---

## Task 1: Add Certificate Profile Normalization

**Files:**
- Create: `src/easm/certificates/__init__.py`
- Create: `src/easm/certificates/profile.py`
- Create: `tests/test_certificates/test_profile.py`

- [ ] **Step 1: Write failing profile tests**

Create `tests/test_certificates/test_profile.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from easm.certificates.profile import (
    build_certificate_profile,
    merge_certificate_profiles,
    parse_cert_datetime,
)


def test_parse_cert_datetime_accepts_date_and_iso_strings() -> None:
    assert parse_cert_datetime("2026-05-01").isoformat() == "2026-05-01T00:00:00+00:00"
    assert parse_cert_datetime("2026-05-01T12:30:00Z").isoformat() == "2026-05-01T12:30:00+00:00"


def test_build_profile_normalizes_ct_certificate() -> None:
    profile = build_certificate_profile(
        source="crtsh",
        raw={
            "fingerprint": "ABCD",
            "serial_number": "01",
            "issuer_name_id": "123",
            "not_before": "2026-01-01",
            "not_after": "2026-06-01",
            "name_value": "www.example.invalid\napi.example.invalid",
        },
        observed_at=datetime(2026, 5, 18, tzinfo=UTC),
    )

    assert profile["fingerprint_sha256"] == "abcd"
    assert profile["issuer"]["name_id"] == "123"
    assert profile["san_dns_names"] == ["api.example.invalid", "www.example.invalid"]
    assert profile["ct"]["seen"] is True
    assert profile["deployment"]["state"] == "ct_only"
    assert profile["validity_days"] == 151


def test_build_profile_marks_tls_observation_deployed() -> None:
    profile = build_certificate_profile(
        source="tls_cert",
        raw={
            "hostname": "www.example.invalid",
            "port": 443,
            "cert": {
                "fingerprint_sha256": "abcd",
                "subject_cn": "www.example.invalid",
                "issuer_cn": "Example Issuing CA",
                "issuer_org": "Example CA",
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2026-06-01T00:00:00+00:00",
                "san_dns_names": ["www.example.invalid"],
            },
        },
        observed_at=datetime(2026, 5, 18, tzinfo=UTC),
    )

    assert profile["deployment"]["state"] == "deployed"
    assert profile["deployment"]["observed_endpoints"] == [
        {"hostname": "www.example.invalid", "port": 443, "source": "tls_cert"}
    ]
    assert profile["sources"] == ["tls_cert"]


def test_merge_profiles_keeps_deployed_state_over_ct_only() -> None:
    ct_profile = build_certificate_profile(
        source="crtsh",
        raw={"fingerprint": "abcd", "name_value": "www.example.invalid", "not_after": "2026-06-01"},
        observed_at=datetime(2026, 5, 1, tzinfo=UTC),
    )
    live_profile = build_certificate_profile(
        source="tls_cert",
        raw={
            "hostname": "www.example.invalid",
            "port": 443,
            "cert": {"fingerprint_sha256": "abcd", "not_after": "2026-06-01"},
        },
        observed_at=datetime(2026, 5, 18, tzinfo=UTC),
    )

    merged = merge_certificate_profiles(ct_profile, live_profile)

    assert merged["deployment"]["state"] == "deployed"
    assert merged["sources"] == ["crtsh", "tls_cert"]
    assert merged["ct"]["seen"] is True
```

- [ ] **Step 2: Verify tests fail**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_certificates/test_profile.py"
```

Expected:

```text
ModuleNotFoundError: No module named 'easm.certificates'
```

- [ ] **Step 3: Implement profile helpers**

Create `src/easm/certificates/__init__.py`:

```python
from easm.certificates.analysis import analyze_certificate_profile
from easm.certificates.profile import build_certificate_profile, merge_certificate_profiles

__all__ = [
    "analyze_certificate_profile",
    "build_certificate_profile",
    "merge_certificate_profiles",
]
```

Create `src/easm/certificates/profile.py` with these public functions:

```python
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def parse_cert_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    if len(text) == 10:
        text = f"{text}T00:00:00+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
```

Also implement:

```python
def build_certificate_profile(
    *,
    source: str,
    raw: dict[str, Any],
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    ...


def merge_certificate_profiles(
    existing: dict[str, Any] | None,
    incoming: dict[str, Any],
) -> dict[str, Any]:
    ...
```

Implementation rules:

- Lowercase `fingerprint` and `fingerprint_sha256`.
- Sort and dedupe SAN DNS names.
- Use `deployment.state = "deployed"` only for `source == "tls_cert"`.
- Use `ct.seen = True` for `source in {"crtsh", "certstream"}`.
- Merge `sources`, `san_dns_names`, and `observed_endpoints` as sorted unique lists.
- Preserve deployed state when merging CT and live profiles.

- [ ] **Step 4: Verify profile tests pass**

Run the same focused test command.

Expected:

```text
4 passed
```

---

## Task 2: Add Certificate Analysis And Risk Ranking

**Files:**
- Create: `src/easm/certificates/analysis.py`
- Create: `tests/test_certificates/test_analysis.py`

- [ ] **Step 1: Write failing analysis tests**

Create `tests/test_certificates/test_analysis.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from easm.certificates.analysis import analyze_certificate_profile


NOW = datetime(2026, 5, 18, tzinfo=UTC)


def test_expired_deployed_certificate_is_critical() -> None:
    analysis = analyze_certificate_profile(
        {
            "not_after": "2026-05-01T00:00:00+00:00",
            "deployment": {"state": "deployed", "observed_endpoints": [{"hostname": "app.example.invalid", "port": 443}]},
            "public_key": {"algorithm": "RSA", "size_bits": 2048},
            "signature": {"hash_algorithm": "sha256"},
        },
        now=NOW,
    )

    assert analysis["validity_state"] == "expired"
    assert analysis["risk"] == "critical"
    assert "expired_deployed" in analysis["reasons"]


def test_expired_ct_only_certificate_is_lower_than_deployed() -> None:
    analysis = analyze_certificate_profile(
        {
            "not_after": "2026-05-01T00:00:00+00:00",
            "deployment": {"state": "ct_only", "observed_endpoints": []},
            "public_key": {"algorithm": "RSA", "size_bits": 2048},
            "signature": {"hash_algorithm": "sha256"},
        },
        now=NOW,
    )

    assert analysis["validity_state"] == "expired"
    assert analysis["risk"] == "medium"
    assert "expired_ct_only" in analysis["reasons"]


def test_unobserved_valid_ct_certificate_is_candidate() -> None:
    analysis = analyze_certificate_profile(
        {
            "not_after": "2026-06-15T00:00:00+00:00",
            "deployment": {"state": "ct_only", "observed_endpoints": []},
            "ct": {"seen": True},
            "public_key": {"algorithm": "RSA", "size_bits": 2048},
            "signature": {"hash_algorithm": "sha256"},
        },
        now=NOW,
    )

    assert analysis["deployment_state"] == "unobserved_candidate"
    assert analysis["risk"] == "info"
    assert "valid_ct_only_not_observed" in analysis["reasons"]


def test_weak_crypto_is_high_risk_when_deployed() -> None:
    analysis = analyze_certificate_profile(
        {
            "not_after": "2026-08-01T00:00:00+00:00",
            "deployment": {"state": "deployed", "observed_endpoints": [{"hostname": "app.example.invalid", "port": 443}]},
            "public_key": {"algorithm": "RSA", "size_bits": 1024},
            "signature": {"hash_algorithm": "sha1"},
        },
        now=NOW,
    )

    assert analysis["strength"] == "weak"
    assert analysis["risk"] == "high"
    assert "rsa_key_too_small" in analysis["reasons"]
    assert "weak_signature_hash" in analysis["reasons"]
```

- [ ] **Step 2: Verify tests fail**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_certificates/test_analysis.py"
```

Expected:

```text
ModuleNotFoundError or ImportError for analyze_certificate_profile
```

- [ ] **Step 3: Implement analysis**

Implement `analyze_certificate_profile(profile, now=None) -> dict[str, Any]` in `src/easm/certificates/analysis.py`.

Required rules:

- `expired_deployed` -> `risk = "critical"`.
- `expired_ct_only` -> `risk = "medium"`.
- `expires_within_7_days` on deployed -> at least `high`.
- `expires_within_30_days` on deployed -> at least `medium`.
- `ct_only` and currently valid -> `deployment_state = "unobserved_candidate"` and `risk = "info"`.
- RSA key below 2048 bits -> `strength = "weak"`, deployed risk at least `high`.
- Signature hash in `{"md5", "sha1"}` -> `strength = "weak"`, deployed risk at least `high`.
- Missing `not_after` -> `validity_state = "unknown"` and `risk = "info"` unless crypto or deployment reasons raise it.

- [ ] **Step 4: Verify analysis tests pass**

Run the same focused test command.

Expected:

```text
4 passed
```

---

## Task 3: Normalize Certificate-Producing Schemas

**Files:**
- Modify: `src/easm/runners/schemas.py`
- Modify: `tests/test_schemas.py`

- [ ] **Step 1: Add failing schema tests**

Append tests to `tests/test_schemas.py`:

```python
def test_tls_cert_schema_adds_certificate_profile_deployment_state():
    from easm.runners.schemas import tls_cert

    entities, rels = tls_cert({
        "hostname": "app.example.invalid",
        "port": 443,
        "cert": {
            "fingerprint_sha256": "ABCDEF",
            "subject_cn": "app.example.invalid",
            "issuer_cn": "Example CA",
            "issuer_org": "Example Org",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2026-06-01T00:00:00+00:00",
            "san_dns_names": ["app.example.invalid"],
            "public_key_algorithm": "RSA",
            "public_key_size_bits": 2048,
            "signature_hash_algorithm": "sha256",
        },
    })

    cert = next(e for e in entities if e.entity_type == "certificate")
    profile = cert.attributes["certificate_profile"]
    assert profile["fingerprint_sha256"] == "abcdef"
    assert profile["deployment"]["state"] == "deployed"
    assert profile["analysis"]["risk"] == "medium"
    assert any(r.relationship_type == "deployed_on" for r in rels)


def test_crtsh_schema_adds_ct_only_certificate_profile():
    from easm.runners.schemas import crtsh

    entities, _ = crtsh({
        "name_value": "app.example.invalid",
        "issuer_name_id": "example-ca",
        "not_before": "2026-01-01",
        "not_after": "2026-06-01",
        "serial_number": "01",
        "fingerprint": "ABCDEF",
    })

    cert = next(e for e in entities if e.entity_type == "certificate")
    profile = cert.attributes["certificate_profile"]
    assert profile["deployment"]["state"] == "ct_only"
    assert profile["ct"]["seen"] is True
```

- [ ] **Step 2: Verify tests fail**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_schemas.py"
```

Expected:

```text
KeyError: 'certificate_profile'
```

- [ ] **Step 3: Update schemas**

In `src/easm/runners/schemas.py`:

- Import `datetime`, `UTC`, `build_certificate_profile`, `merge_certificate_profiles`, and `analyze_certificate_profile`.
- In `crtsh(raw)`, attach:

```python
profile = build_certificate_profile(source="crtsh", raw=raw, observed_at=datetime.now(UTC))
profile["analysis"] = analyze_certificate_profile(profile)
attrs = {
    "source": "crtsh",
    "issuer_name_id": raw.get("issuer_name_id", ""),
    "not_before": raw.get("not_before", ""),
    "not_after": raw.get("not_after", ""),
    "certificate_profile": profile,
}
```

- In `certstream(raw)`, attach `certificate_profile` using `source="certstream"`.
- In `tls_cert(raw)`, attach `certificate_profile` using `source="tls_cert"`.
- Change the live endpoint relationship from only `issued_for` to include:

```python
RelationshipCandidate("hostname", nh, "certificate", cert_val, "deployed_on", "pivot")
```

Keep existing `issued_for` or `san_contains` relationships if tests rely on them.

- [ ] **Step 4: Verify schema tests pass**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_schemas.py tests/test_schema_contracts.py"
```

Expected:

```text
passed
```

---

## Task 4: Extract Deeper X.509 Attributes From Live TLS

**Files:**
- Modify: `src/easm/pivot/handlers.py`
- Create: `tests/test_certificates/test_tls_cert_extraction.py`

- [ ] **Step 1: Write fixture-backed extraction tests**

Create `tests/test_certificates/test_tls_cert_extraction.py` with a test that monkeypatches socket/TLS or, preferably, factors pure extraction into `_certificate_to_raw_dict(cert, hostname, port)` and tests it with a generated `cryptography.x509.Certificate`.

Required assertions:

```python
assert raw["cert"]["public_key_algorithm"] == "RSA"
assert raw["cert"]["public_key_size_bits"] == 2048
assert raw["cert"]["signature_hash_algorithm"] == "sha256"
assert raw["cert"]["is_ca"] is False
assert raw["cert"]["key_usage"] == ["digital_signature", "key_encipherment"]
assert raw["cert"]["extended_key_usage"] == ["server_auth"]
```

- [ ] **Step 2: Verify tests fail**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_certificates/test_tls_cert_extraction.py"
```

Expected:

```text
ImportError for _certificate_to_raw_dict or missing keys
```

- [ ] **Step 3: Implement pure extraction helper**

In `src/easm/pivot/handlers.py`, add:

```python
def _certificate_to_raw_dict(cert: x509.Certificate, hostname: str, port: int) -> dict[str, Any]:
    ...
```

It must extract:

- subject CN
- issuer CN and organization
- serial number
- validity dates
- SHA-256 fingerprint
- SAN DNS names
- public key algorithm and size/curve
- signature algorithm and hash
- basic constraints CA flag
- key usage
- extended key usage

Then make `tls_cert_grab()` return `[ _certificate_to_raw_dict(cert, hostname, port) ]`.

- [ ] **Step 4: Verify extraction tests pass**

Run the focused test command.

Expected:

```text
passed
```

---

## Task 5: Add Certificate Inventory Store Queries

**Files:**
- Modify: `src/easm/store.py`
- Create: `tests/test_certificates/test_inventory_store.py`

- [ ] **Step 1: Write failing DB tests**

Create tests that insert certificate entities with `certificate_profile` attributes and assert sorted inventory output:

```python
@pytest.mark.asyncio
@pytest.mark.db
async def test_list_certificate_inventory_prioritizes_deployed_expired(store):
    await store.upsert_entity(
        "default",
        "target-1",
        "certificate",
        "deployed-expired",
        {
            "certificate_profile": {
                "fingerprint_sha256": "deployed-expired",
                "issuer": {"organization": "Example CA"},
                "deployment": {"state": "deployed", "observed_endpoints": [{"hostname": "app.example.invalid", "port": 443}]},
                "analysis": {"risk": "critical", "validity_state": "expired", "reasons": ["expired_deployed"]},
                "not_after": "2026-05-01T00:00:00+00:00",
            }
        },
    )
    await store.upsert_entity(
        "default",
        "target-1",
        "certificate",
        "ct-expired",
        {
            "certificate_profile": {
                "fingerprint_sha256": "ct-expired",
                "issuer": {"organization": "Example CA"},
                "deployment": {"state": "ct_only", "observed_endpoints": []},
                "analysis": {"risk": "medium", "validity_state": "expired", "reasons": ["expired_ct_only"]},
                "not_after": "2026-05-01T00:00:00+00:00",
            }
        },
    )

    rows = await store.list_certificate_inventory(target_id="target-1")

    assert [r["risk"] for r in rows] == ["critical", "medium"]
    assert rows[0]["deployment_state"] == "deployed"
```

- [ ] **Step 2: Verify tests fail**

Expected:

```text
AttributeError: 'Store' object has no attribute 'list_certificate_inventory'
```

- [ ] **Step 3: Implement store queries**

Add methods to `Store`:

```python
async def list_certificate_inventory(
    self,
    target_id: str | None = None,
    org_id: str = "default",
    deployment_state: str | None = None,
    risk: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    ...


async def summarize_certificate_inventory(
    self,
    target_id: str | None = None,
    org_id: str = "default",
) -> dict[str, Any]:
    ...
```

The inventory rows should include:

- `entity_id`
- `fingerprint_sha256`
- `subject_cn`
- `issuer_organization`
- `not_before`
- `not_after`
- `validity_state`
- `deployment_state`
- `observed_endpoints`
- `risk`
- `reasons`
- `strength`

Sort by risk order `critical`, `high`, `medium`, `low`, `info`, then `not_after`.

- [ ] **Step 4: Verify store tests pass**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_certificates/test_inventory_store.py"
```

Expected:

```text
passed
```

---

## Task 6: Generate Certificate Lifecycle Findings

**Files:**
- Create: `src/easm/certificates/findings.py`
- Create: `tests/test_certificates/test_findings.py`

- [ ] **Step 1: Write failing finding tests**

Test conversion from inventory rows to findings:

```python
def test_deployed_expired_finding_is_critical():
    findings = certificate_inventory_to_findings(
        org_id="default",
        target_id="target-1",
        rows=[{
            "entity_id": "00000000-0000-0000-0000-000000000001",
            "fingerprint_sha256": "abcd",
            "deployment_state": "deployed",
            "risk": "critical",
            "validity_state": "expired",
            "observed_endpoints": [{"hostname": "app.example.invalid", "port": 443}],
            "reasons": ["expired_deployed"],
        }],
    )

    assert findings[0].rule_id == "certificate_deployed_expired"
    assert findings[0].risk.value == "critical"
    assert "app.example.invalid:443" in findings[0].headline


def test_ct_only_expired_finding_is_medium():
    findings = certificate_inventory_to_findings(
        org_id="default",
        target_id="target-1",
        rows=[{
            "entity_id": "00000000-0000-0000-0000-000000000002",
            "fingerprint_sha256": "dcba",
            "deployment_state": "ct_only",
            "risk": "medium",
            "validity_state": "expired",
            "observed_endpoints": [],
            "reasons": ["expired_ct_only"],
        }],
    )

    assert findings[0].rule_id == "certificate_ct_only_expired"
    assert findings[0].risk.value == "medium"
```

- [ ] **Step 2: Verify tests fail**

Expected:

```text
ModuleNotFoundError or ImportError
```

- [ ] **Step 3: Implement finding conversion**

Create:

```python
def certificate_inventory_to_findings(
    *,
    org_id: str,
    target_id: str,
    rows: list[dict[str, Any]],
) -> list[Finding]:
    ...
```

Finding rule ids:

- `certificate_deployed_expired`
- `certificate_deployed_expiring_soon`
- `certificate_weak_crypto_deployed`
- `certificate_ct_only_expired`
- `certificate_unobserved_candidate`

- [ ] **Step 4: Verify finding tests pass**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_certificates/test_findings.py"
```

Expected:

```text
passed
```

---

## Task 7: Add Certificate Inventory API

**Files:**
- Create: `src/easm/api/routes/certificates.py`
- Modify: `src/easm/api/app.py`
- Create: `tests/test_api/test_certificates.py`

- [ ] **Step 1: Write failing API tests**

Create tests for:

- `GET /api/certificates/inventory`
- `GET /api/certificates/summary`
- filters: `target_id`, `deployment_state`, `risk`

Expected inventory response item:

```json
{
  "entity_id": "uuid",
  "fingerprint_sha256": "abcd",
  "subject_cn": "app.example.invalid",
  "issuer_organization": "Example CA",
  "not_after": "2026-06-01T00:00:00+00:00",
  "deployment_state": "deployed",
  "validity_state": "valid",
  "strength": "strong",
  "risk": "medium",
  "reasons": ["expires_within_30_days"],
  "observed_endpoints": [{"hostname": "app.example.invalid", "port": 443}]
}
```

- [ ] **Step 2: Verify API tests fail with 404**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_api/test_certificates.py"
```

Expected:

```text
assert 404 == 200
```

- [ ] **Step 3: Implement router**

Create routes:

```python
@router.get("/certificates/inventory")
async def list_certificate_inventory(...):
    ...


@router.get("/certificates/summary")
async def summarize_certificate_inventory(...):
    ...
```

Register in `src/easm/api/app.py`.

- [ ] **Step 4: Verify API tests pass**

Run focused API tests.

Expected:

```text
passed
```

---

## Task 8: Add Offline End-To-End Certificate Lifecycle Test

**Files:**
- Create: `tests/test_certificates/test_certificate_lifecycle_flow.py`

- [ ] **Step 1: Write DB-backed flow test**

The flow test should:

1. Insert a CT-only expired certificate entity.
2. Insert a live TLS deployed expired certificate entity.
3. Insert a live TLS deployed weak certificate entity.
4. Call `store.list_certificate_inventory()`.
5. Convert rows to findings with `certificate_inventory_to_findings()`.
6. Assert deployed expired outranks CT-only expired.

- [ ] **Step 2: Run focused flow test**

Run:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_certificates/test_certificate_lifecycle_flow.py"
```

Expected:

```text
passed
```

---

## Task 9: Documentation And Agent Guidance

**Files:**
- Modify: `AGENTS.md`
- Create: `docs/certificate-lifecycle-management.md`

- [ ] **Step 1: Document invariants**

Add to `AGENTS.md`:

```markdown
## Certificate Lifecycle

- Certificate-producing schemas must attach `attributes.certificate_profile`.
- CT-only certificates are not equivalent to deployed certificates.
- A physically observed expired certificate is higher risk than an expired CT-only certificate.
- Do not represent raw CT observations as deployed unless `tls_cert` or another live observation proves it.
- Certificate policy thresholds belong in `src/easm/certificates/analysis.py`, not scattered through API/UI tests.
```

- [ ] **Step 2: Add operator docs**

Create `docs/certificate-lifecycle-management.md` describing:

- data sources (`crtsh`, `certstream`, `tls_cert`)
- deployment states
- risk scoring
- CA inventory fields
- safe simulation/testing guidance

---

## Final Verification

- [ ] Run focused certificate suite:

```powershell
docker compose -f docker-compose.test.yml run --rm test sh -c "alembic upgrade head && python -m pytest -q tests/test_certificates tests/test_schemas.py tests/test_api/test_certificates.py"
```

- [ ] Run canonical backend gate:

```powershell
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test
```

- [ ] Clean Docker resources:

```powershell
docker compose -f docker-compose.test.yml down
```

---

## Subagent Ownership Map

Use disjoint workers:

1. **Worker A: Profile Normalization**
   - Owns `src/easm/certificates/profile.py`
   - Owns `tests/test_certificates/test_profile.py`

2. **Worker B: Analysis And Risk**
   - Owns `src/easm/certificates/analysis.py`
   - Owns `tests/test_certificates/test_analysis.py`

3. **Worker C: Schema Integration**
   - Owns `src/easm/runners/schemas.py`
   - Owns `tests/test_schemas.py`
   - Starts after Workers A and B.

4. **Worker D: X.509 Extraction**
   - Owns `src/easm/pivot/handlers.py`
   - Owns `tests/test_certificates/test_tls_cert_extraction.py`

5. **Worker E: Store/API Inventory**
   - Owns `src/easm/store.py`
   - Owns `src/easm/api/routes/certificates.py`
   - Owns `src/easm/api/app.py`
   - Owns `tests/test_certificates/test_inventory_store.py`
   - Owns `tests/test_api/test_certificates.py`

6. **Worker F: Findings And Flow**
   - Owns `src/easm/certificates/findings.py`
   - Owns `tests/test_certificates/test_findings.py`
   - Owns `tests/test_certificates/test_certificate_lifecycle_flow.py`

7. **Worker G: Docs**
   - Owns `AGENTS.md`
   - Owns `docs/certificate-lifecycle-management.md`

---

## Self-Review

- The plan directly covers deployed-vs-CT-only risk differentiation.
- It adds CA/issuer inventory fields without requiring a new database table.
- It keeps active TLS probing out of tests by using pure extraction helpers and fixture-like raw payloads.
- It avoids pretending CT observations are deployed observations.
- It keeps policy thresholds centralized so current CA/B Forum changes can be updated in one file.
- The first useful deliverable is backend-only and testable; UI can be planned afterward using the new API.
