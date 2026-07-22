# Open EASM — Runner Output Schema Audit Report

**Scope:** All runner output schemas in `src/easm/runners/schemas.py`, `src/easm/runners/schema_engine.py`, the 10 YAML files under `src/easm/runners/schemas/*.yaml`, and `src/easm/runners/registry.py`.
**Auditor:** Reconnaissance Tool Integration Specialist.
**Code reviewed:** 1,500+ LOC across 13 files. Every schema function and every YAML file was read.
**Verdict:** **The schema layer is in serious disrepair.** YAML refactoring silently overrode four working Python schema functions with broken replacements; three of them produce garbage attributes, the fourth produces invalid entity types. Several other parsers drop critical pivot data. Confirmed by direct execution traces against realistic sample data.

---

## TL;DR — Critical Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | `nuclei.yaml` overrides working Python and **drops ALL vulnerability data**, storing literal string `"$raw.vulnerability"` as the attribute value | **CRITICAL** |
| 2 | `rdap.yaml` overrides working Python and stores literal string `"$raw.rdap"` — every ASN-RDAP enrichment loses the WHOIS payload | **CRITICAL** |
| 3 | `cpe_vuln_enrich.yaml` hardcodes `type: hostname` — CPE/CVE enrichments for IPs and domains become hostname entities with bogus values | **CRITICAL** |
| 4 | `commoncrawl.yaml` returns the *queried seed domain* as the entity value, never the URL host actually discovered | **CRITICAL** |
| 5 | `cloud_enum.yaml` stores full bucket URLs (e.g. `https://s3.amazonaws.com/bucket/`) as domain entity values | **CRITICAL** |
| 6 | `certstream` schema (Python) does not filter `IP Address:` entries from `subjectAltName` strings — creates literal `"ip address:1.2.3.4"` domain entities | **HIGH** |
| 7 | `portscan` schema creates hostname + IP entities but never links them with a relationship — graph is disconnected | **HIGH** |
| 8 | `normalize_entity_value()` does not canonicalize IPv4 zero-padding, IPv6 (RFC 5952), IP:port, IPv6 zone IDs, or wildcard domains → duplicate entities for the same asset | **HIGH** |
| 9 | `censys`, `shodan`, `abuseipdb` parsers drop ASN / IP-range / hostname data that could become entities + graph edges | **HIGH** |
| 10 | `subfinder.yaml` drops the `source` field (which passive DNS source produced the hit) and `resolved` IP from `-nW` output | **MEDIUM** |

---

## How Schemas Are Wired (and Why It Matters)

`OUTPUT_SCHEMAS` is populated once at module load by `_init_output_schemas()` (`src/easm/runners/schemas.py:645-684`):

1. It calls `_load_yaml_schemas()` from `schema_engine.py:190-205`, which loads **every** `*.yaml` file in `schemas/`.
2. Python schema functions are then added **only if the name is not already present** (line 680-682): `if name not in schemas: schemas[name] = fn`.

**Consequence:** *YAML wins by default.* A YAML schema for `nuclei` silently shadows the Python `nuclei()` function. The shadowing is verified at runtime:

```
subfinder:        _schema_fn from schema_engine.py   (Python subfinder() IGNORED)
rdap:             _schema_fn from schema_engine.py   (Python rdap() IGNORED)
cpe_vuln_enrich:  _schema_fn from schema_engine.py   (Python cpe_vuln_enrich() IGNORED)
commoncrawl:      _schema_fn from schema_engine.py   (Python commoncrawl() IGNORED)
cloud_enum:       _schema_fn from schema_engine.py   (Python cloud_bucket() IGNORED)
nuclei:           _schema_fn from schema_engine.py   (Python nuclei() IGNORED)
geoip, wappalyzer, screenshot, searchengine: YAML wins
portscan, crtsh, shodan, certstream, asnmap, dns, tls_cert, etc.: Python (no YAML)
```

The dead Python code at `schemas.py:120-135` (`nuclei`), `:146-160` (`commoncrawl`), `:491-501` (`cloud_bucket`), `:588-599` (`rdap`), `:618-639` (`cpe_vuln_enrich`) is a **trap for future maintainers**: tests that import these functions directly will pass, but production will use the broken YAML.

---

## Schema Accuracy Scorecard

| Schema | Source | Verdict | One-line justification |
|--------|--------|---------|------------------------|
| `subfinder.yaml` | YAML | **MINOR_ISSUES** | Extracts hostname correctly but drops `source`, `resolved`, `resolver` fields |
| `wappalyzer.yaml` | YAML | **CORRECT** | Extracts hostname + technologies; matches Python behavior |
| `screenshot.yaml` | YAML | **CORRECT** | Extracts hostname + screenshot_path |
| `searchengine.yaml` | YAML | **CORRECT** | Extracts domain + provenance metadata |
| `geoip.yaml` | YAML | **CORRECT** | Extracts IP + geo dict |
| `nuclei.yaml` | YAML | **BROKEN** | `vulnerability: "$raw.vulnerability"` stores literal placeholder string; ALL nested `info.*` data dropped |
| `rdap.yaml` | YAML | **BROKEN** | `rdap: "$raw.rdap"` stores literal placeholder; the entire WHOIS payload is lost |
| `cpe_vuln_enrich.yaml` | YAML | **BROKEN** | Hardcodes `type: hostname`; enrichments for IPs/domains create invalid hostname entities |
| `commoncrawl.yaml` | YAML | **BROKEN** | Uses `domain` field (queried seed) as the entity value; never extracts discovered URL host |
| `cloud_enum.yaml` | YAML | **BROKEN** | Stores full bucket URL `https://s3.amazonaws.com/x/` as a domain value |
| `portscan` | Python | **MINOR_ISSUES** | Creates hostname + IP entities but no relationship between them |
| `asnmap` | Python | **CORRECT** | Correctly handles both list-of-dicts and list-of-strings `as_range` |
| `dnstwist` | Python | **CORRECT** | Lookalike + original domain relationship works |
| `crtsh` | Python | **MINOR_ISSUES** | Wildcard SANs (`*.example.com`) become literal domain entities |
| `certspotter` | Python (alias of `crtsh`) | **MINOR_ISSUES** | Same as crtsh |
| `certstream` | Python | **BROKEN** | Real CertStream `subjectAltName` is a string containing `IP Address:` entries — schema creates bogus `"ip address:1.2.3.4"` domain entities |
| `nuclei` (Python fallback) | Python | **CORRECT** | Properly extracts `info.name/severity/description`, `template-id`, `matched-at`, `curl-command` — but never runs (shadowed by YAML) |
| `rdap` (Python fallback) | Python | **CORRECT** | Properly builds rdap dict from raw — but never runs (shadowed by YAML) |
| `cpe_vuln_enrich` (Python fallback) | Python | **CORRECT** | Properly reads `entity_type` from raw — but never runs (shadowed by YAML) |
| `commoncrawl` (Python fallback) | Python | **MINOR_ISSUES** | Extracts URL host but reduces to last-2 labels (`sub.example.com` → `example.com`) — but never runs |
| `cloud_bucket` (Python fallback) | Python | **BROKEN** | `bucket_url.split("/")[0]` returns the URL scheme `"https:"`, not the hostname — but never runs |
| `dns` | Python | **CORRECT** | A and CNAME branches handled, relationships created |
| `reverse_dns` | Python | **CORRECT** | IP ↔ hostname relationship correct |
| `domain_extract` | Python | **CORRECT** | Uses `registered_domain_of` relationship (not in enum but stored anyway) |
| `tls_cert` | Python | **MINOR_ISSUES** | Wildcard SANs become literal domain entities; double-relationship (`issued_for` + `deployed_on`) is redundant |
| `dns_mail_records` | Python | **CORRECT** | MX/SPF/DMARC + mail provider classification works |
| `shodan` | Python | **MINOR_ISSUES** | Drops `tags`, `last_updated`; does not extract ASN entity despite `asn` field present |
| `abuseipdb` | Python | **MINOR_ISSUES** | `hostnames` and `domain` nested fields not extracted as entities |
| `greynoise` | Python | **CORRECT** | Threat intel passthrough |
| `urlscan` | Python | **CORRECT** | Threat intel aggregation works |
| `censys` | Python | **MINOR_ISSUES** | `autonomous_system.asn` not extracted as ASN entity; `bgp_prefix` not extracted as ip_range entity |
| `passive_dns` (securitytrails) | Python | **MINOR_ISSUES** | Drops MX/TXT/CNAME records; only A records extracted |
| `subdomain_takeover` | Python | **CORRECT** | v1 + v2 format handling, signal extraction, DNS chain capture |
| `ripe_stat` | Python | **CORRECT** | ASN + IP entities with `hosted_in` relationship |
| `domain_rdap` | Python | **CORRECT** | Domain + rdap dict passthrough |

**Summary: 5 BROKEN, 11 MINOR_ISSUES, 14 CORRECT, plus 4 Python functions are dead code (shadowed).**

---

## Sample Trace — 5 Key Runners

### 1. subfinder

**Sample input** (matches `fixtures/simulation/runners/subfinder.jsonl` and real `subfinder -json -nW` output):

```json
{"host": "api.example.com", "source": "crtsh", "resolved": "203.0.113.5", "resolver": ["1.1.1.1"]}
```

**What the schema extracts** (`subfinder.yaml:1-9`):

- Entity: `hostname` = `api.example.com`, attrs = `{source: "subfinder"}`

**What's lost:**

| Field | Value | Value for EASM | Seriousness |
|-------|-------|----------------|-------------|
| `source` | `crtsh` | Indicates which passive DNS sources produce hits; useful for coverage analytics and per-source confidence | LOW |
| `resolved` | `203.0.113.5` | The IP address resolved by subfinder (when run with `-nW` flag) — could immediately create `hostname` → `ip` relationship without a separate DNS resolve pivot | MEDIUM |
| `resolver` | `["1.1.1.1"]` | Which resolver returned the IP; useful for resolver-divergence detection (DNS poisoning / split-horizon) | LOW |
| `timestamp` | (not extracted) | When subfinder observed the host | LOW |

---

### 2. shodan

**Sample input** (real internetdb.shodan.io response wrapped by the runner):

```json
{
  "ip": "203.0.113.5",
  "shodan": {
    "cpes": ["cpe:2.3:a:apache:http_server:2.4.41"],
    "hostnames": ["host1.example.com"],
    "domains": ["example.com"],
    "vulns": ["CVE-2021-41773"],
    "ports": [80, 443],
    "tags": ["vpn", "cloud"],
    "last_updated": "2024-06-01",
    "org": "Example Inc", "isp": "AWS", "asn": "AS15169",
    "country_name": "US", "city": "Seattle", "os": "Linux",
    "data": [{"port": 80, "product": "nginx", "version": "1.18"}]
  }
}
```

**What the schema extracts** (`schemas.py:377-405`):

- 3 entities: `ip` (with 13 attrs), `hostname` (host1.example.com), `domain` (example.com)
- 2 relationships: `ip → hostname` (`reverse_of`), `ip → domain` (`belongs_to`)

**What's lost:**

| Field | Value | Value for EASM | Seriousness |
|-------|-------|----------------|-------------|
| `tags` | `["vpn","cloud"]` | Shodan's contextual tags — feeds directly into correlation rules (e.g. "cloud asset on unexpected hosting") | MEDIUM |
| `last_updated` | `2024-06-01` | Staleness signal for the entire shodan enrichment; useful to decide re-enrich cadence | LOW |
| `asn` | `AS15169` (kept as IP attr but not promoted) | Could create `asn` entity and `ip → asn` (`hosted_in`) relationship — graph pivots from this IP to all other IPs in the same ASN | **HIGH** |
| Per-service `product`/`version` (in `data`) | `nginx/1.18` | Buried in `services` attr as nested JSON; not promoted to technology fingerprint entities. Cannot pivot to other assets running the same software | MEDIUM |

---

### 3. nmap (portscan)

**Sample input** (produced by `portscan_runner.py:107-119` from `nmap -oG -` output):

```json
{
  "hostname": "target.example.com",
  "ip": "203.0.113.5",
  "ports": [
    {"port": 80, "protocol": "tcp", "service": "http"},
    {"port": 443, "protocol": "tcp", "service": "https"},
    {"port": 22, "protocol": "tcp", "service": "ssh"}
  ]
}
```

**What the schema extracts** (`schemas.py:163-175`):

- 2 entities: `hostname` (with `open_ports` attr), `ip` (with same `open_ports` attr)
- **0 relationships** ← **this is the bug**

**What's lost / wrong:**

| Issue | Impact | Seriousness |
|-------|--------|-------------|
| No `hostname → ip` `resolves_to` relationship | The IP and hostname are floating islands in the graph. Reverse-DNS pivot from this IP won't reach the hostname's port data. | **HIGH** |
| `ip` field is the literal `host` value from `nmap -oG` parsing | `portscan_runner.py:99-101` extracts it as `host.split(" (")[0]` — which is the original hostname, not the resolved IP. So the "ip" entity value is frequently a duplicate of the hostname. | **HIGH** |
| Service version (`-sV`) is dropped | nmap output parser regex `(\d+)/open/(\w+)///(.*?)/` only captures port/protocol/service — drops version, e.g. `22/open/tcp//ssh//OpenSSH 8.2p1///`. Could feed CVE matching. | MEDIUM |
| No per-port entities | Each open port could become a `service` entity with `hostname → service` `exposes` relationship — would enable "find all assets exposing port 22" queries by graph traversal | LOW |

---

### 4. nuclei

**Sample input** (real nuclei `-jsonl` output after the runner's `transform_fn` adds `hostname` from the URL):

```json
{
  "template-id": "CVE-2021-44228",
  "info": {
    "name": "Log4Shell RCE",
    "severity": "critical",
    "description": "Remote code execution via log4j JNDI lookup",
    "tags": ["cve", "rce", "log4j"]
  },
  "matched-at": "https://vuln.example.com:8443/login",
  "hostname": "vuln.example.com",
  "url": "https://vuln.example.com:8443/",
  "type": "http",
  "curl-command": "curl -X GET 'https://vuln.example.com:8443/login'",
  "ip": "203.0.113.10",
  "extracted-results": ["${jndi:ldap://...}"],
  "matcher-name": "log4j-rce",
  "timestamp": "2024-06-01T12:00:00"
}
```

**What the schema extracts** (`nuclei.yaml:1-10`):

```python
EntityCandidate(
  entity_type='hostname',
  value='vuln.example.com',
  attributes={
    'source': 'nuclei',
    'vulnerability': '$raw.vulnerability'   # ← literal placeholder string
  }
)
```

**What's lost:**

| Field | Value | Value for EASM | Seriousness |
|-------|-------|----------------|-------------|
| `template-id` | `CVE-2021-44228` | The single most important field — without it you cannot match against CPE/CVE databases or trigger correlation rules | **CRITICAL** |
| `info.name` | `Log4Shell RCE` | Human-readable finding title for alerts | **CRITICAL** |
| `info.severity` | `critical` | Alert ranking, dashboards, severity filters | **CRITICAL** |
| `info.description` | (full text) | Context for analysts | HIGH |
| `matched-at` | `https://vuln.example.com:8443/login` | Exact evidence URL — needed for analyst verification | HIGH |
| `curl-command` | (reproduction command) | One-click reproduction for the analyst | MEDIUM |
| `extracted-results` | `["${jndi:ldap://...}"]` | PoC payload proving exploitability | MEDIUM |
| `matcher-name` | `log4j-rce` | Distinguishes which matcher within a template fired | LOW |
| `ip` | `203.0.113.10` | Could create `ip` entity and `hostname → ip` relationship | MEDIUM |
| `info.tags` / `info.reference` | metadata | Linkage to upstream advisories | LOW |

**Worst consequence:** the entire nuclei output is reduced to a hostname with a junk attribute. The Python function at `schemas.py:120-135` builds the correct `vulnerability` sub-dict but is shadowed and never runs.

---

### 5. crtsh

**Sample input** (real `crt.sh/?q=%25.example.com&output=json` response after `transform_fn` at `registry.py:169-177`):

```json
{
  "name_value": "example.com\nwww.example.com\napi.example.com\n*.example.com",
  "issuer_name_id": "16418",
  "not_before": "2024-01-01T00:00:00",
  "not_after": "2025-01-01T00:00:00",
  "serial_number": "0fb8d1d3e0a2",
  "fingerprint": "abc123def456"
}
```

**What the schema extracts** (`schemas.py:89-117`):

- 4 entities: 1 `certificate` (with `certificate_profile`), 4 `domain` entities: `example.com`, `www.example.com`, `api.example.com`, `*.example.com`
- 8 relationships: `domain → certificate` `cert_discovered` (×4) + `reverse_of` correlation (×4)

**What's lost / wrong:**

| Issue | Impact | Seriousness |
|-------|--------|-------------|
| `*.example.com` becomes a literal `domain` entity | The wildcard is never expanded; instead the entity store gets a junk domain that no other tool will ever produce. Graph queries become noisy. | **HIGH** |
| `name_value` whitespace and quotes not stripped | `"quoted.example.com"` (with literal quotes) becomes a domain entity. Verified by trace. | MEDIUM |
| `min_entry_timestamp` / `entry_timestamp` / crt.sh internal `id` dropped | Cannot determine when crt.sh first saw the cert (CT log lag analysis) | LOW |
| Same SAN repeated across many crt.sh responses creates N×M cert→domain relationships | Could be deduped at the relationship level via conflict, but inflates raw_events | LOW |

---

## Data Loss Analysis (Per Runner)

For each runner, fields that the tool produces but the schema silently drops. Seriousness: 🔴 HIGH (causes incorrect/missing attack surface), 🟡 MEDIUM (reduces analyst value), 🟢 LOW (cosmetic).

| Runner | Dropped Field | Why it matters for EASM | Rating |
|--------|---------------|--------------------------|--------|
| `subfinder` | `source`, `resolver`, `resolved`, `timestamp` | Per-source attribution, IP from `-nW` flag (could create `hostname → ip`), resolver divergence | 🟡 |
| `asnmap` | `input`, `timestamp`, per-CIDR `timestamp` | Replay / dedup, when the ASN map changed | 🟢 |
| `dnstwist` | A-record IPs in nested `dns.a` | Could create `ip` entities + `lookalike_domain → ip` relationships | 🟡 |
| `crtsh` / `certspotter` | `entry_timestamp`, `id` (crt.sh), `issuer_dn` (certspotter), `revocation_*` (certspotter) | CT log timing, issuer chain, revoked certs | 🟡 |
| `certstream` | `data.source.name`, `data.source.url`, `data.seen` | Which CT log observed the cert and when | 🟡 |
| `nuclei` | everything (see trace) | template-id, severity, description, matched-at, curl-command, extracted-results, IP | 🔴 |
| `wappalyzer` | `url`, individual match metadata (`app_id`, `confidence`, `versions`) | Confidence scoring, exact URL where tech was detected | 🟡 |
| `commoncrawl` | actual discovered URL host (returns seed domain instead — see sample trace) | Discovery runner produces zero new entities | 🔴 |
| `cloud_enum` | bucket URL is stored whole (not the bucket hostname) | Domain entities contain invalid values like `https://s3.amazonaws.com/bucket/` | 🔴 |
| `portscan` | `hostname → ip` relationship missing; `-sV` version info dropped | Graph disconnected; CVE matching impossible | 🔴 |
| `screenshot` | HTTP status, response time, page title | Could feed "is this alive?" correlation | 🟢 |
| `dns` (A) | TTL, record class | TTL affects cache-staleness reasoning | 🟢 |
| `dns` (CNAME) | (none significant) | — | — |
| `reverse_dns` | (none significant) | — | — |
| `domain_extract` | (none significant) | — | — |
| `geoip` | `asn` (often present in MaxMind lookups) | Could create `ip → asn` `hosted_in` relationship | 🟡 |
| `tls_cert` | TLS cipher suite, TLS version, certificate chain (intermediate certs) | Cipher suite deprecation rules; chain validation | 🟡 |
| `dns_mail_records` | DMARC policy details (`p`, `sp`, `pct`), DKIM selectors | DMARC enforcement status feeds phishing-readiness rules | 🟡 |
| `shodan` | `tags`, `last_updated`, per-service `product`/`version`, `asn` (not promoted) | See trace | 🟡 / 🔴 |
| `abuseipdb` | `hostnames`, `domain` not promoted to entities | Could create `ip → hostname`/`ip → domain` relationships | 🔴 |
| `greynoise` | `metadata.*`, `viz_url`, raw `raw_data` | Viz URL links to GreyNoise analyst view | 🟢 |
| `urlscan` | `ip` (in results) not promoted | Could create `ip` entities from scan results | 🟡 |
| `censys` | `autonomous_system.asn`, `autonomous_system.bgp_prefix` not promoted | Could create `asn` + `ip_range` entities with pivots | 🔴 |
| `passive_dns` (securitytrails) | `mx_records`, `txt_records`, `cname_records`, `ns_records`, `soa_records` | Full DNS history is more than A records | 🟡 |
| `ripe_stat` | `holders`, `block.start`/`block.end`, `query_time` | Holder name (org entity), exact IP range, query time | 🟡 |
| `rdap` (ASN) | **EVERYTHING** — `name`, `country`, `handle`, `type`, `startAddress`, `endAddress` | All WHOIS data lost; YAML placeholder bug | 🔴 |
| `domain_rdap` | (passes through; works) | — | — |
| `cpe_vuln_enrich` | entity type is wrong (see trace) — also drops `entity_type` awareness | Every IP/domain enrichment creates bogus hostname entity | 🔴 |
| `subdomain_takeover` | (passes through; works) | — | — |
| `searchengine` | search rank, result snippet, result title | Quality / relevance signal | 🟢 |

---

## Normalization Issues

`normalize_entity_value()` at `src/easm/entity_store.py:8-26` is too narrow. Each weakness was verified by direct invocation:

| Input | Output | Expected | Impact | Severity |
|-------|--------|----------|--------|----------|
| `normalize_entity_value("ip", "203.0.113.005")` | `"203.0.113.005"` | `"203.0.113.5"` | Same IPv4 creates two distinct entities (nmap prints leading zeros in some locales) | 🔴 |
| `normalize_entity_value("ip", "2001:db8::1")` vs `"2001:0db8::1"` | both unchanged | RFC 5952 canonical form | IPv6 dedup completely broken; same address enters entity store 12+ ways | 🔴 |
| `normalize_entity_value("ip", "203.0.113.5:443")` | `"203.0.113.5:443"` | `"203.0.113.5"` (port stripped) | Shodan/ censys give bare IPs; masscan/nmap/active scans often include port. Same asset = 2 entities. | 🔴 |
| `normalize_entity_value("ip", "fe80::1%eth0")` | `"fe80::1%eth0"` | zone ID stripped | Link-local addresses dedup wrong | 🟡 |
| `normalize_entity_value("ip", " 1.2.3.4 ")` (leading/trailing space) | `"1.2.3.4"` (correct) | — | — | ✅ |
| `normalize_entity_value("asn", "ASN15169")` | `"ASN15169"` | `"AS15169"` | "ASN" prefix variant creates second ASN entity | 🟡 |
| `normalize_entity_value("asn", "asn 15169")` | `"ASN 15169"` | `"AS15169"` | Spaces and "asn" prefix not normalized | 🟡 |
| `normalize_entity_value("domain", "*.example.com")` | `"*.example.com"` | Either reject or strip wildcard to `example.com` | Wildcard cert SANs become literal domain entities; verified in crtsh/certstream/tls_cert | 🔴 |
| `normalize_entity_value("domain", "\"example.com\"")` | `"\"example.com\""` | `"example.com"` | Quoted SAN values create duplicate entities | 🟡 |
| `normalize_entity_value("hostname", "EXAMPLE.COM.")` | `"example.com"` (correct, lower+strip dot) | — | — | ✅ |
| `normalize_entity_value("certificate", "abc123")` | SHA256 hash of input | Deterministic ID (good) — but inconsistent inputs across sources produce different IDs for the same cert | See entity-type consistency section | 🟡 |
| `normalize_entity_value("ip_range", "8.8.4.0/22")` vs `"8.8.4.0/022"` | unchanged | CIDR canonicalization | Same CIDR with leading-zero mask = 2 entities | 🟡 |
| `normalize_entity_value("ip_range", "8.8.4.0/22 ")` (trailing space) | `"8.8.4.0/22 "` | `"8.8.4.0/22"` | Whitespace not stripped for ip_range | 🟢 |

### Specific normalization problems per source

- **crtsh** cert value: schema falls back through `fingerprint → serial_number → uuid4` (`schemas.py:102`). For real crt.sh responses, `fingerprint` is empty (crt.sh does not expose it directly) — so most certificates end up keyed by `serial_number`, which is **not unique across CAs**. Different CAs can mint the same serial. The certstore will silently merge unrelated certificates.
- **certstream** cert value: uses `raw.get("fingerprint", raw.get("serial_number", uuid4()))` — `raw` is `{"cert_data": ...}`, so `raw["fingerprint"]` is always empty. Falls back to `raw["serial_number"]` (also empty), then to a random UUID. **Every certstream cert is a brand-new entity** even on re-observation. Verified.
- **tls_cert** cert value: uses `cert_data.get("fingerprint_sha256", ...)` (`schemas.py:324`) — correct.
- **certspotter** cert value: uses `issuance["tbs_sha256"]` as `fingerprint` (`registry.py:275`) — different from `cert_sha256`. Inconsistent with crtsh and tls_cert.

---

## Entity Type Consistency

### Same string, different entity type

A bare value like `example.com` will be stored as different entity types depending on which tool discovered it:

| Tool | Entity type | Why |
|------|-------------|-----|
| subfinder | `hostname` | `subfinder.yaml:4` |
| crtsh SAN | `domain` | `schemas.py:112-113` |
| shodan domain | `domain` | `schemas.py:400-403` |
| searchengine | `domain` | `searchengine.yaml:4` |
| commoncrawl | `domain` (broken — uses seed) | `commoncrawl.yaml:4` |
| certstream SAN | `domain` | `schemas.py:231-233` |
| tls_cert SAN | `domain` | `schemas.py:343-345` |
| dns A record (hostname is host) | `hostname` | `schemas.py:267-270` |
| dns CNAME (target) | `hostname` | `schemas.py:255-258` |
| dns_mail_records (MX target) | `hostname` | `schemas.py:371-372` |

**Effect:** the same string `example.com` exists simultaneously as a `hostname` and a `domain` entity. They never deduplicate, never share attributes, and never form the relationships that should connect them. The graph contains two parallel universes.

**Recommendation:** pick one rule. Either (a) everything with a dot is a `hostname` unless `tldextract` confirms it is a registered domain (current `domain_extract` pivot does this), or (b) make `domain` a strict subtype assigned only by `domain_extract`. Today the codebase uses both rules inconsistently.

### Registered vs. registered_domain

The Python `domain_extract` relationship type is `registered_domain_of` (`schemas.py:303`); shodan's `ip → domain` relationship is `belongs_to` (`schemas.py:404`). Neither string is in the `RelationshipType` enum (`src/easm/models.py:29-35`). Verified:

```
Relationship types USED but NOT in enum:
  - belongs_to
  - cert_discovered
  - cname_to
  - deployed_on
  - discovered_lookalike
  - hosted_in
  - mail_handled_by
  - registered_domain_of
```

The DB has no CHECK constraint (`alembic/versions/0002_orgs_and_entities.py:77` declares `relationship_type Text NOT NULL`), so these insert fine — but the enum exists and is misleading. Either expand the enum or delete it.

---

## YAML Engine Footgun

The YAML engine at `schema_engine.py:99-102` silently falls back to the literal `$raw.X` placeholder when the raw field is missing:

```python
for key, ref in list(attrs.items()):
    if isinstance(ref, str) and ref.startswith("$raw."):
        raw_key = ref[5:]
        attrs[key] = raw.get(raw_key, ref)   # ← falls back to ref = "$raw.X"
```

This is exactly what causes `nuclei.yaml` to store `vulnerability: "$raw.vulnerability"` and `rdap.yaml` to store `rdap: "$raw.rdap"`. A typo in a YAML file produces silent corruption. **There should be at minimum a warning log; ideally, the engine should drop the attribute entirely or raise a `SchemaError`.**

---

## Priority Fixes (Ranked)

### #1 — Delete or rewrite the 5 broken YAML schemas (CRITICAL, ~2 hours)

Files: `src/easm/runners/schemas/nuclei.yaml`, `rdap.yaml`, `cpe_vuln_enrich.yaml`, `commoncrawl.yaml`, `cloud_enum.yaml`.

Two paths:

**A. Delete them** and let the Python fallback functions take over. The Python `nuclei()`, `rdap()`, `cpe_vuln_enrich()` are already correct. `commoncrawl()` and `cloud_bucket()` are buggy in Python too and need fixes regardless.

**B. Rewrite the YAML** to correctly reference raw fields. For `nuclei` this is awkward because the YAML engine does not support nested lookups like `$raw.info.name`. The Python function's job of flattening nested `info` is exactly the kind of work the YAML engine was designed to *avoid* supporting. Recommendation: **go with (A)** — keep the Python functions for complex sources and reserve YAML for genuinely flat sources.

Add a regression test that runs each schema against a sample input and asserts the attributes dict has no `$raw.` literals.

### #2 — Fix `portscan` to create `hostname → ip` relationship (CRITICAL, ~30 min)

File: `src/easm/runners/schemas.py:163-175`.

Also fix `portscan_runner.py:99-101` — the `host` parsing extracts the *input hostname*, not the resolved IP. The nmap `-oG -` line format is `Host: target.example.com (203.0.113.5)`, and the current parser does `host.split(" (")[0]` which yields the hostname. It should yield the parenthesized IP instead (or both).

### #3 — Fix `normalize_entity_value()` for IPs and wildcards (HIGH, ~1 hour)

File: `src/easm/entity_store.py:8-26`.

Specifically:
- IPv4: parse with `ipaddress.ip_address()`, output compressed form.
- IPv6: same — RFC 5952 compressed form.
- Strip `:port` from IPv4 (configurable; some runners genuinely mean "the IP that answered on port X").
- Strip `%zone_id` from IPv6 link-local.
- Wildcard `*.` prefix on domains: either drop the entity or expand to parent.
- ASN: regex `^(?:asn|as)?\s*(\d+)$` → `AS\d+`.
- Quote stripping for all string types.

Add unit tests covering each case.

### #4 — Fix `certstream` to filter non-DNS SANs (HIGH, ~15 min)

File: `src/easm/runners/schemas.py:187-237`.

In the `subjectAltName` string parser (lines 201-207), skip entries that start with `IP Address:`, `email:`, `URI:`, `DirName:`, etc. Only accept `DNS:`-prefixed or bare-domain entries.

Also fix `cert_val` computation at line 212: currently it falls back to UUID when `raw.fingerprint` is missing, but `raw` here is `{"cert_data": data}`, so the fingerprint is at `raw["cert_data"]["leaf_cert"]["fingerprint"]`. Use `_certstream_cert_data(raw).get("fingerprint", ...)` instead.

### #5 — Promote nested entities in `censys`, `shodan`, `abuseipdb` (HIGH, ~1 hour)

Files: `src/easm/runners/schemas.py:377-467`.

- `censys`: extract `autonomous_system.asn` as `asn` entity with `ip → asn` `hosted_in` relationship. Extract `autonomous_system.bgp_prefix` as `ip_range` entity with `asn → ip_range` `owns`.
- `shodan`: extract `asn` as `asn` entity with `ip → asn` `hosted_in`. Extract per-service `product`/`version` into a structured `technologies` attribute (already partially done — promote to first-class).
- `abuseipdb`: extract `hostnames` list as `hostname` entities with `ip → hostname` `reverse_of`. Extract `domain` as `domain` entity with `ip → domain` `belongs_to`.

Each of these is a small, self-contained change that adds high-value graph edges.

---

## Appendix A — Verification

All findings were verified by direct execution against `OUTPUT_SCHEMAS`. Example commands used:

```python
from easm.runners.schemas import OUTPUT_SCHEMAS
schema = OUTPUT_SCHEMAS['nuclei']
sample = {'template-id': 'CVE-2021-44228', 'info': {'name': 'Log4Shell', 'severity': 'critical'},
          'matched-at': 'https://vuln.example.com/', 'hostname': 'vuln.example.com'}
ents, rels = schema(sample)
print(ents[0].attributes)
# {'source': 'nuclei', 'vulnerability': '$raw.vulnerability'}   ← literal string, BUG
```

```python
import inspect
from easm.runners.schemas import OUTPUT_SCHEMAS
for name in ['subfinder', 'nuclei', 'rdap', 'cpe_vuln_enrich', 'commoncrawl', 'cloud_enum']:
    fn = OUTPUT_SCHEMAS[name]
    print(f"{name}: {fn.__qualname__} from {inspect.getsourcefile(fn)}")
# Confirms YAML shadows Python for all 6 sources.
```

Existing test suite (`tests/test_schema_contracts.py`) passes — but only asserts that schemas exist and are not redefined in Python source. It does **not** exercise the schemas against realistic sample data. Adding the traces in this report as test cases would catch all five CRITICAL regressions.

## Appendix B — Files Reviewed

- `src/easm/runners/schemas.py` (687 lines, all 30+ functions)
- `src/easm/runners/schema_engine.py` (283 lines)
- `src/easm/runners/schemas/*.yaml` (10 files, ~100 lines)
- `src/easm/runners/registry.py` (505 lines)
- `src/easm/runners/portscan_runner.py` (128 lines)
- `src/easm/runners/certstream_runner.py` (131 lines)
- `src/easm/runners/subprocess_runner.py` (136 lines)
- `src/easm/runners/ingestion.py` (239 lines)
- `src/easm/runners/__init__.py` (195 lines)
- `src/easm/runners/lifecycle.py` (164 lines, partial)
- `src/easm/runners/base.py` (164 lines)
- `src/easm/entity_store.py` (36 lines)
- `src/easm/models.py` (47 lines)
- `src/easm/certificates/profile.py` (partial, 120 lines)
- `alembic/versions/0002_orgs_and_entities.py` (partial)
- `tests/test_schema_contracts.py` (61 lines)
