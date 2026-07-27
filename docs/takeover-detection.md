# Subdomain Takeover Detection

## Design

The takeover detection system evaluates every hostname against multiple independent signal sources and uses a **severity × confidence** matrix to classify findings rather than a simple binary "vulnerable/not vulnerable."

## Risk Tiers

| Tier | Detection situation | Evidence required |
|---|---|---|
| **Critical** | Dangling NS delegation — a delegated nameserver domain is expired/available | NS delegation exists; the NS hostname's domain is unregistered or the DNS service is unclaimed |
| **High** | CNAME/alias to a known third-party platform where the resource is claimable | Active DNS chain; provider identified; HTTP/TLS response matches an unclaimed fingerprint |
| **High** | DNS chain depends on an expired external domain | Full CNAME chain followed; target registrable domain is expired/available |
| **Medium** | A/AAAA record to a public IP no longer owned | Public IP classified; ASN/provider identified; no active service at the address |
| **Medium** | External MX, SPF include, DKIM, or service endpoint references an expired domain | Record points outside the organization; referenced domain is claimable |
| **Low** | Dangling CNAME but platform does not allow arbitrary claims or evidence is incomplete | DNS target is dead/generic error; no validated claimability signal |
| **Informational** | Stale/broken/private/non-routable record | No externally claimable target; mere timeout/NXDOMAIN/SERVFAIL |

## Confidence Model

```
confirmed = active DNS + validated provider fingerprint + verified claimability
likely    = active DNS + validated provider fingerprint
possible  = active DNS + external/decommissioned target, claimability unknown
hygiene   = stale or broken record with no credible external-claim path
```

## Detection Modules

Each module runs as part of the `takeover_detect` pivot on a hostname entity.

| Module | What it does |
|---|---|
| **DNS chain** | Resolves A, AAAA, CNAME (follows to terminal), NS delegation, MX. Detects loops, broken chains, and external NS delegation. |
| **Provider classification** | Maps terminal CNAME target and hostname against a curated fingerprint database of 50+ cloud/CDN/PaaS/SaaS providers with claimability metadata per provider. |
| **HTTP/TLS probe** | Lightweight HTTP/HTTPS fetch with original hostname as SNI. Captures status code, redirect chain, page title, body snippet, and TLS SAN names. Matches against HTTP response fingerprints. |
| **Domain lifecycle check** | Checks whether external target domains resolve. Future expansion: WHOIS/RDAP expiry and registration status. |

## Signal Aggregation

The correlation engine receives the `takeover_evidence` attribute on hostname entities and evaluates available signals to determine severity and confidence:

```yaml
signals:
  - ns_not_resolving
  - provider:<name>
  - provider_unclaimed
  - http_fingerprint:<name>
  - http_unclaimed
  - external_domain_not_found
```

Severity is driven by the **highest-severity signal** present. Confidence is driven by the **number and quality** of corroborating signals.

## Provider Fingerprints

The fingerprint database covers providers across five categories:

- **Cloud & CDN:** AWS S3/CloudFront, Azure App Service/CDN/Front Door, Cloudflare Pages/R2
- **Static hosting & PaaS:** GitHub Pages, Heroku, Netlify, Firebase, Vercel, Render, Fly.io, Railway, Surge, Bitbucket, Ghost, GitLab Pages, Pantheon
- **SaaS & status pages:** Shopify, ReadMe, Statuspage, Freshdesk, Zendesk, Helpscout, Intercom, Canny, Tawk
- **DNS & email:** NS1, DNSControl, CNAME.sh
- **HTTP response fingerprints:** Body and title patterns for 25+ provider-specific error/unclaimed pages

Each provider is tagged `unclaimed` (any tenant can bind the hostname), `conditional` (ownership verification required), or `owned` (not takeover-able).

## Guardrails

- Only probe hostnames belonging to org-owned zones (scope evaluator)
- Rate-limited HTTP probes via existing limiter infrastructure
- Domain checks cached on cooldown (default 168h)
- No resource is ever claimed to validate a finding — detection is entirely passive

## A/AAAA Record Rules

- Do not report "takeover confirmed" solely because an IP fails to respond
- Classify as **possible stale-IP exposure** when the address is public/external/cloud-hosted and no longer maps to an owned asset
- Raise priority if the IP serves unexpected content or the hostname has high business trust
- RFC1918, loopback, link-local, multicast, and documentation addresses are **configuration hygiene**, not takeover candidates
