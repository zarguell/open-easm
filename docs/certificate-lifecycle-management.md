# Certificate Lifecycle Management

Certificate lifecycle data is normalized into `attributes.certificate_profile` on certificate entities. Shared certificate logic lives in:

- `src/easm/certificates/profile.py` for profile construction and merge behavior.
- `src/easm/certificates/analysis.py` for deployment state, validity, crypto checks, and risk thresholds.
- `src/easm/certificates/findings.py` for turning inventory analysis into findings.

Inventory is exposed through `GET /api/certificates/inventory`. Summary counts are exposed through `GET /api/certificates/summary`.

## Data Sources

- `crtsh`: passive Certificate Transparency data from crt.sh. This proves a certificate was logged in CT, not that it is currently deployed.
- `certstream`: passive Certificate Transparency stream data. This also proves CT visibility only.
- `tls_cert`: live deployed TLS observation. This is the source that proves a certificate was physically observed on an endpoint.

Do not represent CT-only certificates as deployed unless `tls_cert` or another live observation proves deployment.

## Deployment States

The intended deployment model is:

- `deployed`: a certificate was physically observed from a live endpoint.
- `ct_only`: a certificate was observed only in Certificate Transparency data.
- `unobserved_candidate`: a currently valid CT-only certificate matches in-scope names but has not been observed live.
- `replaced_or_not_deployed`: a CT-only certificate is expired, older, or otherwise not currently observed live.

Current inventory derives `unobserved_candidate` from analysis when CT-only valid certificates have not been observed live.

## Risk Scoring

Deployment evidence changes criticality. A physically observed certificate on a live endpoint has higher confidence and usually higher operational risk than a CT-only certificate.

Examples:

- `expired_deployed`: higher risk because clients may be actively seeing an expired certificate.
- `expired_ct_only`: lower than deployed expiration because CT data alone does not prove the certificate is still served.
- `valid_ct_only_not_observed`: useful lifecycle signal for certificates that may be pending deployment, unused, or already replaced.
- `expires_within_7_days`: urgent renewal window.
- `expires_within_30_days`: near-term renewal window.
- `rsa_key_too_small`: cryptographic weakness based on public key size.
- `weak_signature_hash`: cryptographic weakness based on the certificate signature hash.

Certificate policy thresholds belong in `src/easm/certificates/analysis.py` so API, UI, and tests consume one shared interpretation.

## Inventory Fields

CA inventory fields come from the normalized issuer profile:

- issuer organization
- issuer common name
- issuer name id when available from CT data

Cryptographic inventory fields include:

- public key algorithm, key size, and curve
- signature algorithm and hash algorithm
- X.509 version, CA/basic-constraints data, key usage, and extended key usage

These fields should be read from `attributes.certificate_profile` instead of re-parsing raw source payloads in routes or UI code.

## Safe Simulation And Testing

Certificate tests must avoid public active scans and public target traffic. Use fixture raw payloads, generated certificates, or monkeypatched live-observation results.

For CT behavior, prefer fixture payloads for `crtsh` and `certstream`. For deployed behavior, use fixture or generated `tls_cert` payloads that prove live observation semantics without opening network connections.
