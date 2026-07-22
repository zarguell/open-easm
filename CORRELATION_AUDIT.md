# Open EASM Correlation Rules — Detection Engineering Audit

**Scope:** 9 YAML rules in `correlations/` + supporting engine (`src/easm/correlation/`).
**Lens:** Detection-engineering signal/noise. Would a Fortune-500 SOC act on these findings, or mute the source?
**Verdict:** **The engine is structurally incapable of producing high-fidelity ASM signal.** Of 9 rules, 1 is intentionally disabled, 1 is a no-op (path bug), 1 is fully duplicate logic, 1 fires on every entity of a type, and the rest use regex matching that nukes precision. Estimated signal-to-noise ratio across the population of rules as deployed: **< 1:20**.

---

## Executive Summary

The correlation engine is a thin SQL-builder wrapped around three Pydantic models (`CollectCondition`, `AggregationConfig`, `AnalysisStep`). It collects entities via parameterized SQL, groups them by a single field, applies a count threshold, and emits a `Finding`. That is the entire capability surface.

### Fundamental structural problems

1. **No finding deduplication.** `findings` table (`alembic/versions/0005_findings.py:21-36`) has only `id` as PRIMARY KEY. There is **no** uniqueness constraint on `(rule_id, target_id, entity_ids)` or `(rule_id, target_id, headline)`. `FindingStore.create_finding` (`src/easm/stores/finding_store.py:91-113`) is a plain `INSERT`. Rules are evaluated on **every pivot cycle** (`src/easm/tasks/pivot.py:312-332`). Result: the same finding is re-inserted on every pivot run for the lifetime of the entity. With cron schedules of every 5–60 minutes, a single stale dev host will produce **dozens of duplicate findings per day**. This is the single largest noise source in the product.

2. **`UNIQUE` analysis method is dead code.** `AnalysisMethod.UNIQUE` is declared in the enum (`src/easm/correlation/rule.py:17`) but `CorrelationEngine._analyze` (`src/easm/correlation/engine.py:175-184`) only branches on `THRESHOLD`. A rule author who writes `method: unique` gets silent no-op behavior.

3. **No per-rule enable/disable.** The loader (`src/easm/correlation/loader.py:28-40`) globs every `*.yaml` in the directory. There is no `enabled: false` field on `CorrelationRule`. The only way to disable a rule is to mutate the `entity_type` to a sentinel that never matches (as `email_in_breach.yaml:13` does with `__disabled_breach_monitor_no_email_entities__`). This is a hack, not a feature.

4. **Two parallel finding pipelines, one set of UI surfaces.** YAML rules run via `CorrelationEngine.evaluate_rules`. Certificate findings separately run via `certificates/findings.py::certificate_inventory_to_findings`, producing rule IDs like `certificate_deployed_expired`, `certificate_deployed_expiring_soon`, `certificate_weak_crypto_deployed`, `certificate_ct_only_expired`, `certificate_unobserved_candidate`. The `stale_certificate.yaml` rule is a strict subset of this logic, with worse fidelity. The README still claims "7 built-in rules" — the code ships 9, two of which overlap with Python-emitted findings.

5. **Cross-entity-type correlation is impossible.** Each rule's `collect` block builds a `WHERE` clause against the single `entities` table, but the engine has no JOIN support. A rule like "domain with a cert expiring inside 7 days that also has port 443 open" cannot be expressed. Every rule operates on flat attributes of a single entity.

6. **Aggregation is single-field string keying.** `_aggregate` (`engine.py:164-173`) builds `dict[str, list[dict]]` keyed on one field. There is no composite-key grouping, no time-bucket grouping, no spatial grouping.

### Headline signal/noise table

| Rule | Actionability (1–10) | Noise | Status |
|---|---:|---|---|
| `cloud_bucket_open.yaml` | 2 | **High** | Logical error — fires on any cloud-domain hostname |
| `dev_or_test_system.yaml` | 3 | **High** | Greedy `.*dev.*` regex catches legitimate domains |
| `email_in_breach.yaml` | 0 | None | **Intentionally disabled** (sentinel value) |
| `high_risk_port_exposed.yaml` | 5 | Med | SSH 22 is not "high-risk"; misses 9200/27017/11211 |
| `known_exploited_vulnerability.yaml` | 6 | Med | Real signal but headline lacks CVE IDs |
| `outlier_country.yaml` | 0 | None (broken) | **Field-path bug** — checks wrong attribute, never fires |
| `saas_hosted_infrastructure.yaml` | 1 | **Very High** | Flags every CNAME in the org |
| `stale_certificate.yaml` | 0 | **Very High** | Fully duplicate; also matches valid certs |
| `subdomain_takeover_risk.yaml` | 6 | Med | Best of the lot; `analysis.minimum=1` is no-op |

**Aggregate actionable rule count: ~2 of 9.** Excluding disabled and broken rules, 4 rules will produce material noise volumes.

---

## Per-Rule Analysis

### 1. `cloud_bucket_open.yaml`

| Field | Assessment |
|---|---|
| **What it detects** | Per `meta.description` (lines 5–8): publicly accessible cloud storage buckets. **What it actually detects:** any hostname whose value matches `s3.amazonaws.com`, `storage.googleapis.com`, `blob.core.windows.net`, or `digitaloceanspaces.com`. |
| **Collection logic** | `entity_type = hostname` AND `entity_value ~ '.*s3\\.amazonaws\\.com'` (OR … 3 more patterns). Pure string match on the hostname. |
| **Aggregation** | `entity_value` — one finding per hostname. |
| **Analysis threshold** | **None.** No `analysis` block. Every match is a finding. |
| **Actionability** | **2/10**. A bare S3 hostname tells the defender nothing about exposure. The bucket might be private, public, request-pays, or a CNAME to a third-party bucket. |
| **Noise potential** | **High.** Every corp that uses S3 for static assets, CloudFront origins, or Kinesis endpoints will accumulate these. |
| **FP causes** | (a) Every CloudFront origin (`xxx.cloudfront.net` is exempt, but `s3.amazonaws.com` is not — and CloudFront origins are commonly written as S3 endpoints). (b) Legitimate private buckets. (c) Buckets owned by third parties that the org merely references. (d) The `cloud_bucket` schema (`schemas.py:491-501`) populates `public_access: bool` — this rule ignores that field entirely. |
| **Missing context** | Bucket name, region, ACL state ("public-read"? "public-write"?), whether the bucket is owned by the org, last-modified date, whether it's actually serving public content. |
| **Priority fix** | Add `attributes.public_access = True` exact-match condition, or delete the rule and re-emit findings from the `cloud_enum` runner's own metadata when `public_access=True` is observed. |

**File:** `correlations/cloud_bucket_open.yaml:1-22`. Note the description/name claim ("bucket exposure") does not match the SQL produced from the rule body.

---

### 2. `dev_or_test_system.yaml`

| Field | Assessment |
|---|---|
| **What it detects** | Hostnames containing `dev`, `test`, `staging`, `uat`, or `internal` (lines 14–19). |
| **Collection logic** | `entity_type = hostname` AND regex OR over 5 greedy patterns like `.*dev.*`. |
| **Aggregation** | `entity_value`. |
| **Analysis threshold** | None. |
| **Actionability** | **3/10**. "There exists a hostname with `dev` in its name" is intelligence, not a vulnerability. Actionability depends entirely on whether the host is *internal-only* or *internet-exposed* — this rule cannot tell. |
| **Noise potential** | **High.** The patterns match legitimate domains: `developer.mozilla.org`, `dev.example.com`, `test.com`, `staging-band.example.com`, `domain-dev.com`, internal.example.com (which may be a public marketing page for an "internal" product line). |
| **FP causes** | (a) Substring match — `.*test.*` matches `protest.net`, `testimony.example.com`, `latest.example.com`. (b) The rule treats any exposure of a dev hostname as bad; many dev systems are intentionally public (preview environments, beta apps). (c) No filter on whether the hostname resolves, whether it has open ports, or whether it serves anything sensitive. |
| **Missing context** | Is the host actually serving content? Is it password-protected? Is it in a private subnet? Is it owned by the org? Does the org's policy forbid public dev systems? (None of these are answerable from this rule's evidence.) |
| **Priority fix** | Tighten the regex to label boundaries (`(^|[-.])dev([-.]|$)`), exclude known-safe domains via `not_regex`, and require the hostname to also have an `open_ports` attribute (i.e., the asset actually has exposed services). |

**File:** `correlations/dev_or_test_system.yaml:1-22`.

---

### 3. `email_in_breach.yaml`

| Field | Assessment |
|---|---|
| **What it detects** | Nothing. **The rule is disabled by sentinel.** |
| **Collection logic** | `entity_type = __disabled_breach_monitor_no_email_entities__` (line 13) — a value that can never match any entity_type in the schema. |
| **Aggregation** | `entity_value` (dead code). |
| **Analysis threshold** | None. |
| **Actionability** | **0/10** (does not fire). |
| **Noise potential** | None. |
| **FP causes** | N/A. |
| **Missing context** | The comment (lines 8–9) is accurate: `breach_monitor` produces only raw events, not email-shaped entities. Until that runner is fixed to emit email entities, this rule is dead. |
| **Priority fix** | Either fix `breach_monitor` to emit `email` entities (then the rule can collect them) or delete this YAML. Disabled rules shipped in `correlations/` mislead operators into thinking breach detection is live. |

**File:** `correlations/email_in_breach.yaml:1-16`.

---

### 4. `high_risk_port_exposed.yaml`

| Field | Assessment |
|---|---|
| **What it detects** | IPs whose `attributes.open_ports` JSON contains any of: 3389 (RDP), 22 (SSH), 23 (Telnet), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis). |
| **Collection logic** | `entity_type = ip` AND regex over `attributes.open_ports` JSON text for patterns like `"port": 22`. The match works because `attributes->>'open_ports'` returns JSON like `[{"port": 22, "protocol": "tcp", "service": "ssh"}]` (see `portscan_runner.py:114-118` and `schemas.py:171`). |
| **Aggregation** | `entity_value` — one finding per IP. |
| **Analysis threshold** | None. |
| **Actionability** | **5/10.** Real signal — exposed databases/admin interfaces are a top ASM finding. But the rule does not distinguish ports or report which port, which defeats triage. |
| **Noise potential** | **Medium.** SSH on 22 is ubiquitous and almost always authorized on internet-facing hosts (jump boxes, bastions, GitHub.com, every Linux cloud image). Including 22 inflates the finding count by roughly 10×. |
| **FP causes** | (a) SSH 22 is standard practice — not high-risk by itself. (b) The rule omits the genuinely dangerous ports: Elasticsearch 9200, MongoDB 27017, Memcached 11211, Docker 2375/2376, VNC/RDP 5900, Kubernetes API 6443, NetBIOS 139/445, SMB 445, FTP 21, Rsync 873, CouchDB 5984, MongoDB 28017, Hadoop 8088/9000, RabbitMQ 5672, MongoDB 27018. (c) The headline `High-risk port exposed: {entity_value}` doesn't say *which* port, forcing a click-through to evidence. |
| **Missing context** | Which port(s), which service, whether the port is on a public IP owned by the org (vs. a third-party SaaS IP), whether Shodan/AbuseIPDB confirms exploitability. |
| **Priority fix** | (a) Drop 22 from the list or split it into a separate lower-risk rule. (b) Add 9200/27017/11211/2375/6443. (c) Put the port number in the headline — currently impossible because the engine can't enumerate matched sub-fields. Requires either a per-port rule (9 rules instead of 1) or engine support for "matched JSON array element" extraction. |

**File:** `correlations/high_risk_port_exposed.yaml:1-23`.

---

### 5. `known_exploited_vulnerability.yaml`

| Field | Assessment |
|---|---|
| **What it detects** | Any entity with `attributes.kev_count` matching `[1-9]`. |
| **Collection logic** | Single regex condition on `attributes.kev_count` (a top-level integer populated by `cpe_vuln_enrich` pivot; see `vuln_enrichment.py:83` and `schemas.py:634`). JSONB int `1` coerces to text `"1"`, which matches `[1-9]`. Counts of 10+ also match (`"10"` contains `1`). Correctly excludes `0`. |
| **Aggregation** | `entity_value`. |
| **Analysis threshold** | None. |
| **Actionability** | **6/10.** CISA KEV catalog membership is one of the strongest ASM signals available — every CVE in KEV has evidence of active exploitation. This is the single highest-signal rule in the engine. |
| **Noise potential** | **Medium.** Volume scales with org size and tech-stack age. The rule does not differentiate between 1 KEV CVE and 50; an entity with 50 KEV CVEs probably needs to be decommissioned, while 1 might be a low-priority edge service. |
| **FP causes** | Low FP — KEV membership is binary and authoritative. The bigger risk is false **negatives**: only entities that ran `cpe_vuln_enrich` (i.e., had Wappalyzer/nmap/Shodan data and the pivot fired) will have `kev_count` populated. Many hostnames never trigger the CPE pivot and will not be evaluated. |
| **Missing context** | The CVE IDs themselves (stored in `attributes.matched_cves`, never shown), the CVSS scores, the CPE/product name, the due date from CISA's KEV catalog (`kev_due_date`), whether the affected service is internet-reachable. The headline `Known exploited vulnerability found on {entity_value} ({kev_count} KEV CVE(s))` forces a click to see *what* the CVE is. |
| **Priority fix** | Surface the top CVE ID and CVSS in the headline. Since the YAML engine can't iterate matched_cves, this needs to move to a Python-side finding emitter (like `certificates/findings.py` does for certs) that produces one finding per (entity, CVE) pair with the CVE in the headline. |

**File:** `correlations/known_exploited_vulnerability.yaml:1-15`.

---

### 6. `outlier_country.yaml`

| Field | Assessment |
|---|---|
| **What it detects** | **Nothing. The rule is broken and will never fire.** |
| **Collection logic** | `entity_type = ip` AND `attributes.country_code ~ '.+'` AND `attributes.country_code !~ '^US$'` AND `!~ '^CA$'` AND `!~ '^GB$'`. The bug: the geoip schema (`schemas.py:316`) stores country data at `attributes.geo.country_code`, **not** at `attributes.country_code`. `_field_to_sql` (`engine.py:191-193`) only handles one-level `attributes.X`; it does not support `attributes.geo.country_code` nested paths. The condition resolves to `attributes->>'country_code'`, which is `NULL` for every IP entity. The regex `. ~ NULL` evaluates to FALSE in PostgreSQL, so no rows match. |
| **Aggregation** | `entity_value` (dead). |
| **Analysis threshold** | None. |
| **Actionability** | **0/10.** Even if the path bug were fixed, the rule is conceptually broken. |
| **Noise potential** | If the path were fixed: **Very High.** US/CA/GB is hardcoded. A German, Japanese, Indian, Australian, or Brazilian org would have nearly 100% of their assets flagged as "unexpected." There is no per-target allow-list of expected countries. |
| **FP causes** | (a) Path bug (currently suppressing all noise). (b) Hardcoded country list. (c) Cloud egress IPs are routinely geo-located to unexpected countries due to CDN/edge POPs. (d) Country != threat — many low-risk jurisdictions host legitimate SaaS. |
| **Missing context** | Per-target expected-country list (configurable), ASN of the hosting provider (US org using a French OVH datacenter is fine if it's a known CDN), the *type* of asset (a marketing page in Singapore is different from a database in Singapore). |
| **Priority fix** | Fix the field path first (`_field_to_sql` needs to support nested paths via `attributes->'geo'->>'country_code'`). Then make the expected-countries list a per-target config in `config.yaml`, not a hardcoded regex. Then require the IP to belong to the org's ASN inventory before flagging — third-party SaaS IPs in unusual countries are not the org's problem. |

**File:** `correlations/outlier_country.yaml:1-24`. The hardcoded allow-list (lines 18–21) is the second-worst design choice in this directory.

---

### 7. `saas_hosted_infrastructure.yaml`

| Field | Assessment |
|---|---|
| **What it detected (intent)** | Per `meta.description` (lines 5–9): hostnames served via SaaS providers like GitHub Pages, S3, Netlify, etc. |
| **What it actually detects** | **Any hostname with any CNAME target.** The regex is `.+` on `attributes.cname_target` — a non-empty string match. |
| **Collection logic** | `entity_type = hostname` AND `attributes.cname_target ~ '.+'`. |
| **Aggregation** | `entity_value`. |
| **Analysis threshold** | None. |
| **Actionability** | **1/10.** Almost every modern hostname has a CNAME (to a CDN, to a WAF, to an ALB, to a SaaS provider). This rule flags them all. The rule's own risk is `low`, which is honest, but low-risk noise still consumes SOC attention. |
| **Noise potential** | **Very High.** Will fire on essentially every CNAME-bearing hostname in the org. For a 50K-hostname org, this is tens of thousands of findings. |
| **FP causes** | (a) The regex is `.+` — no filtering by SaaS provider. (b) The `saas_providers` config block in `config.yaml.example:8-24` already classifies known SaaS providers — the rule does not consult it. (c) Hostnames pointing to `cloudfront.net` are usually intentional and properly configured, not exposures. |
| **Missing context** | Whether the SaaS provider is on the org's approved list, whether the CNAME target is currently serving the org's content, whether the upstream SaaS resource is claimed or orphaned. |
| **Priority fix** | Delete this rule, or restrict it to CNAME targets that point to *known takeover-vulnerable unclaimed* SaaS providers (overlaps with `subdomain_takeover_risk.yaml`). As-is, it's pure noise labeled as low-risk intelligence. |

**File:** `correlations/saas_hosted_infrastructure.yaml:1-20`.

---

### 8. `stale_certificate.yaml`

| Field | Assessment |
|---|---|
| **What it detects** | **Every certificate entity**, regardless of expiration status. |
| **Collection logic** | `entity_type = certificate`. No other conditions (lines 8–11). The rule does not look at `attributes.not_after`, `attributes.certificate_profile.validity_state`, or any other expiry field. A freshly issued cert with 397 days of validity triggers this rule identically to a cert that expired in 2019. |
| **Aggregation** | `entity_value`. |
| **Analysis threshold** | None. |
| **Actionability** | **0/10.** The rule is fully duplicate of the Python-side `certificates/findings.py::certificate_inventory_to_findings` (lines 12–67), which produces *correct* findings with five distinct rule IDs: `certificate_deployed_expired` (critical), `certificate_deployed_expiring_soon` (high/medium), `certificate_weak_crypto_deployed` (high), `certificate_ct_only_expired` (medium), `certificate_unobserved_candidate` (info). Those findings use real analysis: `_validity` compares `not_after` to `now` (`certificates/analysis.py:74-81`), `_crypto_strength` checks RSA key size and signature hash (`analysis.py:107-137`). |
| **Noise potential** | **Very High.** Every discovered certificate triggers this rule. For an org with CT monitoring on, that's hundreds to thousands of findings per day. Worse, because of the missing dedup constraint on the findings table, every pivot cycle re-creates all of them. |
| **FP causes** | 100% false-positive rate against valid, non-expiring certificates. |
| **Missing context** | Expiry date, deployment state (deployed vs. CT-only vs. unobserved), weak-crypto status, issuer, SANs. |
| **Priority fix** | **Delete this rule.** It is a strict subset of `certificates/findings.py` with strictly worse fidelity. Keeping it active generates noise and confuses operators who see both `stale_certificate` and `certificate_deployed_expiring_soon` findings for the same cert. |

**File:** `correlations/stale_certificate.yaml:1-14`.

---

### 9. `subdomain_takeover_risk.yaml`

| Field | Assessment |
|---|---|
| **What it detects** | Hostnames with `attributes.takeover_risk ~ '[Tt]rue'`. `takeover_risk` is a boolean populated by `subdomain_takeover` schema (`schemas.py:526, 550`) from the `takeover_detect` pivot handler (`pivot/handlers/takeover.py:351-432`). |
| **Collection logic** | `entity_type = hostname` AND regex on boolean-as-text. JSONB `true` coerces to `"true"` via `->>`, which matches `[Tt]rue`. |
| **Aggregation** | `entity_value`. |
| **Analysis threshold** | `analysis: minimum: 1` (line 22) — this is a tautology. The threshold is "at least 1 entity in the group," but groups are formed by grouping one entity's value, so every group has exactly 1 entity. The check is meaningless. |
| **Actionability** | **6/10.** Takeover risk is a legitimate high-priority ASM finding. The detection logic behind it (`pivot/handlers/takeover.py`) is genuinely sophisticated: DNS chain resolution, provider fingerprinting against 50+ services, HTTP body fingerprinting, RDAP domain-lifecycle checks. The rule itself is just the final boolean gate. |
| **Noise potential** | **Medium.** The underlying `takeover_detect` sets `takeover_risk=True` whenever *any* signal is present, including `provider:aws_cloudfront` with `claimability=conditional` (line 411 of takeover.py just appends `provider:X`; conditional providers are NOT exploitable by arbitrary parties). The YAML rule does not distinguish unclaimed (actually exploitable) from conditional (requires platform verification) from owned (not exploitable). |
| **FP causes** | (a) `claimability=conditional` and `claimability=owned` are flagged identically to `claimability=unclaimed`. Only `unclaimed` represents real takeover risk. (b) `ns_not_resolving` is appended for transient DNS failures, not just genuinely broken delegations. (c) The headline `Takeover signals on {entity_value} ({signal_count} signals)` shows a count but not *which* signals — defenders must click through to evidence to know whether it's a Heroku unclaimed or a CloudFront conditional. |
| **Missing context** | Provider name, claimability class, list of signal names (e.g., `provider_unclaimed`, `http_unclaimed`, `external_domain_not_found`), whether HTTP fingerprint confirmed the takeover (vs. just CNAME pattern match). |
| **Priority fix** | (a) Make `takeover_risk=True` only when at least one `unclaimed` signal exists (either CNAME or HTTP fingerprint). (b) Add `takeover_claimability` as an attribute and write a second higher-risk rule for `unclaimed` matches. (c) Drop the meaningless `analysis.minimum=1` block. |

**File:** `correlations/subdomain_takeover_risk.yaml:1-23`.

---

## Critical Missing Rules

These are detection patterns that every commercial ASM platform (BitSight, Randori, Censys, Microsoft Defender EASM, Intrigue, ThreatConnect) ships out of the box. The data needed to implement most of them is **already collected** by Open EASM's enrichment pipeline but not surfaced as findings.

### 1. Expired TLS certificate (deployed, on a live endpoint)

- **What it detects:** A certificate whose `not_after < now` AND that is deployed on a live HTTPS endpoint (i.e., `tls_cert_grab` confirmed it).
- **Why it matters:** This is the single most actionable ASM finding — browsers refuse the cert, customers can't transact, and the fix is mechanical (renew + redeploy). Different from the existing `stale_certificate.yaml` because it (a) requires actual expiry, not just existence, and (b) requires deployment, not just CT-log observation.
- **Effort:** **Zero new code.** `certificates/findings.py::certificate_inventory_to_findings` already emits `certificate_deployed_expired` (line 52). This rule already exists in Python; the YAML version should be deleted, and the README should advertise the Python-side rule ID.
- **Priority:** **Critical.**

### 2. Self-signed certificate on public-facing hostname

- **What it detects:** A certificate whose issuer == subject (or whose issuer is on a known self-signed list like "Kubernetes Ingress Controller Fake Certificate", "donottrustit", " Fortinet CA", "Palo Alto") AND that is deployed on a public hostname.
- **Why it matters:** Self-signed certs on public endpoints indicate misconfigured internal services exposed to the internet, failed automation, or shadow IT. Customers/browsers will get TOFU warnings.
- **Effort:** Small. Add a `self_signed: bool` field to the cert profile (`certificates/profile.py`) by comparing subject_cn/issuer_cn or fingerprint patterns. Add a Python-side emitter.
- **Priority:** **High.**

### 3. Missing SPF, DMARC, or DKIM on mail-sending domain

- **What it detects:** A domain with MX records (or sending mail) that lacks an SPF record, lacks a DMARC record, or has `dmarc_record="none"` (vs. `quarantine`/`reject`).
- **Why it matters:** Email spoofing, phishing, BEC. DMARC `p=reject` is now a hard requirement for bulk senders (Google/Yahoo February 2024 policy). This is a top-5 ASM finding for any org that sends email.
- **Effort:** **Trivial.** The data is already collected by `dns_mail_records` pivot (`schemas.py:351-374`) and stored as `attributes.spf_record`, `attributes.dmarc_record`, `attributes.mx_records`. A YAML rule with `attributes.dmarc_record` not_regex `[~.]` (or a Python emitter checking `mx_records && not dmarc_record`) closes the gap.
- **Priority:** **Critical.** This is the most embarrassing gap given the data is already there.

### 4. HSTS missing on HTTPS host

- **What it detects:** A hostname serving HTTPS that does not return a `Strict-Transport-Security` header.
- **Why it matters:** Without HSTS, users can be SSL-stripped. Baseline web-security control.
- **Effort:** Medium. Requires adding an HTTP-header probe to the `tls_cert_grab` or a new `http_headers` pivot, then a YAML rule. Currently the `takeover_detect._http_probe` collects some header info but doesn't persist the HSTS header specifically.
- **Priority:** **High.**

### 5. TLS version < 1.2 or weak cipher suite

- **What it detects:** A hostname accepting TLS 1.0/1.1, or offering RC4/3DES/NULL/EXPORT cipher suites.
- **Why it matters:** PCI DSS forbids TLS < 1.2. Modern browsers refuse TLS 1.0/1.1 (March 2020). This is a compliance blocking issue.
- **Effort:** Medium. Requires extending `tls_cert_grab` to also do a `sslscan`/`testssl.sh` invocation and persist supported protocols/ciphers. The Python `ssl` module doesn't enumerate cipher suites; needs a subprocess runner.
- **Priority:** **High.**

### 6. Login/admin page served over plain HTTP

- **What it detects:** A hostname whose HTTP response body matches login/admin page patterns AND only listens on port 80 (no 443).
- **Why it matters:** Credential disclosure over unencrypted channel.
- **Effort:** Medium. The `screenshot` runner already visits pages; the `nuclei` runner has many `http-missing-security-headers` and `http-login-page` templates. Wire nuclei findings into the correlation engine as entity attributes (`attributes.login_page_http: true`).
- **Priority:** **High.**

### 7. Open DNS/NTP/SNMP/mDNS resolver

- **What it detects:** An IP responding to DNS queries for arbitrary domains (open recursive resolver), NTP monlist responses, SNMP public community strings, or mDNS broadcasts.
- **Why it matters:** Open resolvers are abused for DDoS amplification (DNS reflection, NTP monlist, SNMP amplification). High-signal, low-FP.
- **Effort:** Small. The `portscan` runner already opens 53/123/161. Add service fingerprints (DNS recursion test, NTP monlist query) to the portscan post-processing.
- **Priority:** **High.**

### 8. CVE with known exploit mapped to discovered technology stack

- **What it detects:** A hostname running a specific CPE that has a CVE with a public exploit (Exploit-DB, Metasploit module, or nuclei template), beyond just KEV listing.
- **Why it matters:** KEV catches 0.1% of exploitable CVEs. The product already has `attributes.matched_cves` — extending the risk model to weight "CVE has public exploit" vs. "CVE is theoretical" sharply increases signal.
- **Effort:** Medium. Requires enriching the `cve_cache` table with an `exploit_available` flag (pulled from Exploit-DB or nuclei templates) and emitting findings per (entity, exploit-available CVE).
- **Priority:** **High.**

### 9. API endpoint discovered without authentication

- **What it detects:** A URL returning JSON/200 to an unauthenticated `GET` and matching API patterns (`/api/v*`, `/swagger.json`, `/openapi.json`, `/graphql`).
- **Why it matters:** Unauthorized data exposure. Common post-breach finding.
- **Effort:** Large. Requires HTTP-content crawling (not currently in the runner set) and careful rate-limiting. The `commoncrawl` runner gets URLs; the `nuclei` runner has `exposed-panels` templates. Stitching these together is non-trivial.
- **Priority:** **Medium.**

### 10. Wildcard certificate exposing internal hostnames

- **What it detects:** A certificate with `*.corp.example.com` in SANs that is deployed on a public hostname, revealing internal naming.
- **Why it matters:** Reconnaissance accelerant — attackers learn the internal hostname schema from CT logs.
- **Effort:** Small. The `tls_cert` schema already captures `san_dns_names` (`schemas.py:328, 338`). A Python-side finding emitter checking for wildcard SANs on deployed certs closes this.
- **Priority:** **Medium.**

---

## Rule Engine Limitations

Architectural constraints of the YAML-based rule engine. These are not bugs in individual rules — they are ceilings on what any YAML rule can express.

### 1. Temporal logic: **Not supported**

The engine queries the current `entities` table snapshot. There is no concept of "yesterday's state," no comparison against historical `raw_events`, no time-window semantics. A rule like "port 22 was open 7 days ago but is closed today" (drift detection) cannot be written. Likewise, "this cert has been expired for > 30 days" (vs. "this cert is expired") is not expressible — only the current state is visible. The `first_seen_at` and `last_seen_at` columns on findings are bookkeeping; they are not queryable from rule YAML.

To get temporal logic, the engine would need either (a) a `previous_value` column on entities with diff support, or (b) a time-bounded query builder (e.g., `collected_at BETWEEN $start AND $end`), neither of which exists.

### 2. Cross-entity-type correlation: **Not supported**

Every rule collects from a single SQL query against `entities` filtered by `entity_type` (typically). There is no JOIN support. The `_collect` method (`engine.py:108-162`) builds a flat `SELECT ... FROM entities WHERE ...` — no subqueries, no `EXISTS`, no `IN (SELECT … FROM relationships WHERE …)`.

This means high-value ASM rules are impossible:

- "Domain with an expiring cert **AND** port 443 open"
- "Hostname whose CNAME points to a provider **AND** HTTP returns 404 with the provider's 'bucket not found' body"
- "IP in the org's ASN **AND** country code != expected"
- "Certificate issued by Let's Encrypt **AND** hostname not in CT logs"

The `relationships` table exists and is populated (e.g., `tls_cert` emits `issued_for`, `deployed_on`, `san_contains` relations — see `schemas.py:341-347`), but the YAML rule engine never reads from it.

### 3. External data references: **Not supported**

A YAML rule can only reference entity attributes. It cannot:

- Query the `cve_cache` table for CVE details.
- Query the `kev_cache` for KEV metadata (due dates, vendor, product).
- Reference external intel feeds (Shodan CVSS, GreyNoise noise vs. riot classification).
- Look up the org's expected-country list from `config.yaml`.

The result is that rules are limited to checking the boolean/integer attributes that enrichment handlers happened to denormalize onto the entity. The `cve_cache` and `kev_cache` tables — populated at startup (`main.py:148-149`) — are invisible to the YAML engine. The Python-side finding emitters (`certificates/findings.py`) bypass this by reading whatever they want, but that path requires writing Python, defeating the YAML-configurable premise.

### 4. Risk scoring: **Static severity only**

`RiskLevel` is a 5-value enum (`rule.py:20-25`): `critical`, `high`, `medium`, `low`, `info`. A rule's risk is a single static field. The engine cannot:

- Produce a numeric risk score (e.g., "87/100") computed from matched attributes.
- Vary severity by match context (e.g., KEV with CVSS ≥ 9.0 → critical; KEV with CVSS < 7.0 → medium).
- Apply a confidence multiplier (the `confidence_score` field exists on `Finding` but is computed from `asset_profile.confidence`, not from rule logic — see `_compute_finding_confidence` at `engine.py:21-46`).

The `novelty_factor` in evidence (engine.py:64) is a multiplier (`new: 1.5`, `recent: 1.2`, `stable: 1.0`) that *could* be used to score, but it's stored in `evidence` JSON and never applied to risk. Findings are ordered by `risk DESC, created_at DESC` (`finding_store.py:166`) — a flat sort on the 5-value enum.

### 5. Other limits worth flagging

- **No `enabled` field.** `CorrelationRule` has no `enabled: bool`. Rules are disabled by file deletion or by mutating conditions to sentinels (see `email_in_breach.yaml`).
- **No per-target rule binding.** All rules run against all targets. A rule like `outlier_country` (hardcoded US/CA/GB) cannot be scoped per-target.
- **Headline format string falls back silently.** `rule.headline.format(**placeholder_data)` catches `KeyError` and returns the unformatted template (`engine.py:67-69`). A typo in a placeholder name (`{signal_count}` vs `{signals_count}`) produces findings with literal `{signal_count}` text in the headline.
- **`_field_to_sql` does not support nested JSON paths** (`engine.py:186-194`). `attributes.geo.country_code` is impossible; the rule author must use a single-level path. This is the root cause of the `outlier_country` rule's brokenness.
- **Aggregation is single-field.** `_aggregate` (`engine.py:164-173`) groups by one field. Multi-field grouping (e.g., "by domain AND by port") requires multiple rules.
- **Analysis is THRESHOLD-only.** `UNIQUE` is in the enum but `_analyze` (engine.py:175-184) only branches on `THRESHOLD`. No statistical methods (mean, stddev outlier), no set-membership checks, no boolean-AND across multiple sub-conditions on the grouped entities.

---

## Priority Fixes

Top 5 changes, ordered by signal-to-noise impact:

### 1. Add finding deduplication to the `findings` table — **Critical**

**Problem:** Every pivot cycle re-inserts every finding. With pivots running every 5–60 minutes, a single dev host generates dozens of duplicate findings per day. The findings table has no uniqueness constraint (`alembic/versions/0005_findings.py:21-36`).

**Fix:** Add a unique index on `(rule_id, target_id, headline)` or `(rule_id, target_id, entity_ids)` and change `FindingStore.create_finding` to `INSERT … ON CONFLICT (rule_id, target_id, headline) DO UPDATE SET last_seen_at = NOW(), evidence = EXCLUDED.evidence RETURNING id`. This collapses the duplicate-spew into a single row per unique finding with an updated `last_seen_at`.

**Impact:** Eliminates >90% of the alert volume from existing rules without changing detection logic.

### 2. Delete `stale_certificate.yaml` and `saas_hosted_infrastructure.yaml` — **Critical**

**Problem:** `stale_certificate.yaml` fires on every certificate entity (100% FP rate against valid certs) and is a strict subset of the Python-side `certificate_inventory_to_findings` logic. `saas_hosted_infrastructure.yaml` fires on every CNAME (essentially 100% of modern hostnames) and surfaces only `risk: low` intelligence.

**Fix:** `rm correlations/stale_certificate.yaml correlations/saas_hosted_infrastructure.yaml`. Certificate findings already come from `certificates/findings.py` with proper classification.

**Impact:** Removes the two highest-volume noise sources. Certificate findings become higher-fidelity (5 distinct rule IDs with correct risk levels instead of one flat "stale").

### 3. Fix the `outlier_country.yaml` field-path bug and add per-target country allow-lists — **High**

**Problem:** The rule never fires because `_field_to_sql` (`engine.py:186-194`) cannot resolve nested JSON paths like `attributes.geo.country_code`. Even if it did, US/CA/GB is hardcoded, making the rule unusable for non-North-American orgs.

**Fix:** (a) Extend `_field_to_sql` to walk dotted JSON paths: `attributes.geo.country_code` → `attributes->'geo'->>'country_code'`. (b) Replace the hardcoded `^US$|^CA$|^GB$` regex with a per-target `expected_countries` list in `config.yaml`. (c) Only evaluate the rule against IPs in the org's own ASN inventory (filter by `attributes.asn` matching target's configured ASNs).

**Impact:** Turns a dead rule into a configurable, useful one. Without the per-target config, this rule should remain disabled.

### 4. Add SPF/DMARC/DKIM, HSTS, TLS-version, and self-signed-certificate Python-side finding emitters — **High**

**Problem:** The data for SPF/DMARC is already collected (`schemas.py:351-374`) but never surfaced as findings. HSTS, TLS version, and self-signed certs require small enrichments but are top-5 ASM controls. The YAML engine cannot express any of these because they need cross-field logic, regex on headers, or comparison against `now`.

**Fix:** Following the `certificates/findings.py` pattern, add Python emitters that read entity attributes and produce typed findings. Each is ~50 LOC. The hardest part (HSTS, TLS version) requires extending the `tls_cert_grab` pivot to also record response headers and negotiated protocol/cipher.

**Impact:** Closes 4 of the 10 critical-missing-rule categories with high-signal, low-FP findings.

### 5. Restructure `high_risk_port_exposed.yaml` and add takeover claimability scoping — **Medium**

**Problem:** (a) Port rule includes SSH 22 (standard practice, ~10× noise inflation) and omits the genuinely dangerous ports (9200, 27017, 11211, 2375, 6443). (b) Takeover rule fires identically for `claimability=unclaimed` (real takeover risk), `conditional` (not exploitable without platform verification), and `owned` (not exploitable at all).

**Fix:** (a) Drop port 22 or split into a `common_admin_port` rule at `risk: low`. Add 9200/27017/11211/2375/6443 to the high-risk list. Surface the matched port number in the headline by emitting per-port findings from Python (the YAML engine can't extract the matched JSON array element). (b) Gate `takeover_risk=True` on at least one `unclaimed` signal in `pivot/handlers/takeover.py:411-418` — append a `takeover_claimability` attribute and write a separate critical-risk rule for confirmed-unclaimed matches.

**Impact:** Cuts port-rule noise ~10×, sharpens takeover rule to fire only on real takeover risk.

---

*Audit performed against code as of `correlations/subdomain_takeover_risk.yaml` modified 2026-07-21. All file:line references are to that revision.*
