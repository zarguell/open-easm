# EASM Platform Maturity

These notes describe the platform direction for open-easm as a discovery and evidence system. They are intended as durable operator and developer guidance, not a changelog for a single implementation slice.

## Capability Model

open-easm produces discovery evidence, normalized assets, relationships, findings, profiles, and outbound feed records. It should help downstream systems understand what was observed, why it matters, and which evidence supports it.

In this plan, open-easm is not the authoritative source of truth for ownership or inventory. Imports from CMDBs, cloud inventories, IPAM, HR, ownership registries, or similar authoritative systems are out of scope. The platform may export discovered assets and evidence to those systems, but should not ingest ownership truth back into open-easm as part of this maturity track.

Expected capabilities include:

- Normalize runner and pivot output into deduped assets, relationships, raw evidence, and findings.
- Maintain asset profiles that summarize confidence, lifecycle, evidence, risk, and outbound feed eligibility.
- Preserve provenance from raw event through derived entity, relationship, finding, profile, and feed state.
- Track change history append-only so operators can see what changed without losing prior observations.
- Expose stable list/read workflows for API and UI consumers with predictable sorting, filtering, ordering, and pagination.
- Produce outbound feeds for downstream source-of-truth systems that need discovered assets and supporting evidence.

## Data Model

The `entities` table is the deduped asset identity layer. Changes should preserve existing entity identity semantics and avoid turning `entities` into a dumping ground for source-specific inventory records.

Entity `attributes` JSONB may hold derived structures such as:

- `asset_profile`: confidence, lifecycle, evidence, risk, and feed-readiness summary.
- `certificate_profile`: certificate-specific lifecycle and policy interpretation.
- Risk details: scores, levels, reasons, and evidence-derived context.

Raw event links are part of the audit trail. Derived records should retain enough linkage to explain which source, raw event, run, session, or pivot produced the observation.

`asset_change_events` is append-only change history. Current state belongs on the entity/profile/feed record; historical events should not be rewritten to make old facts match current facts.

Asset profile invariants:

- Confidence has a numeric score, level, and reasons.
- Lifecycle state includes timestamps such as first observed, last observed, changed, or retired when known.
- Evidence records include source, `raw_event_id`, `observed_at`, and a concise summary.
- Risk has a score, level, and reasons.
- Source-of-truth feed state records eligibility and export metadata, such as exportable status and last export details.

## API And Workflow Notes

Implementation may expose endpoints for asset profiles, asset changes, evidence drilldown, and outbound feeds. Verify local routes before documenting or depending on exact paths.

When adding or changing endpoints:

- Prefer existing route, schema, dependency, and `Store` patterns.
- Keep list endpoints deterministic under sort, order, filter, and pagination parameters.
- Add response fields only when they can be populated consistently or explicitly marked as optional.
- Keep UI API types aligned with backend schemas.
- Preserve provenance fields that help operators explain where an asset, profile, or feed record came from.

Operator workflows should support:

- Reviewing discovered assets and their confidence/risk reasons.
- Drilling from profile summary to raw evidence.
- Understanding asset lifecycle transitions over time.
- Exporting discovered assets and evidence to downstream source-of-truth systems.
- Diagnosing why an asset is or is not eligible for outbound feed export.

## Outbound Feed Guidance

Outbound feeds should carry discovered assets and evidence out of open-easm. They should be shaped for downstream authoritative systems to ingest, reconcile, or review.

Feed records should favor explainability over authority:

- What asset was discovered.
- Which evidence supports it.
- How confident open-easm is.
- What lifecycle and risk signals are known.
- Whether it is eligible for export.
- When it was exported or why it was skipped.

Do not build source-of-truth imports for CMDB, cloud, IPAM, HR, or ownership data in this plan. Ownership and authoritative inventory reconciliation should happen downstream.

## Testing Approach

Avoid active public scans in tests. Prefer fixture-backed simulation, dependency-light unit tests, and the local Docker test stack where appropriate.

Use reserved or local targets in configuration and fixtures. Tests should not require public DNS, public HTTP targets, active scanner side effects, or network-heavy behavior.

Useful verification patterns:

- Fixture ingestion for runner and pivot output.
- Schema conversion from raw evidence to entities and relationships.
- Store/API coverage for sorting, ordering, filtering, and pagination.
- Profile derivation coverage for confidence, lifecycle, evidence, risk, and feed eligibility.
- Outbound feed coverage using local fixtures and deterministic export metadata.

## Roadmap Boundaries

In scope:

- Discovery and evidence production.
- Asset profile derivation from observed evidence.
- Append-only asset change history.
- Operator-visible provenance and evidence drilldown.
- Outbound feeds for downstream source-of-truth systems.
- Stable API/UI list behavior for profiles, changes, and feeds.

Out of scope for this plan:

- Importing authoritative ownership or inventory from CMDB, cloud, IPAM, HR, or similar systems.
- Treating open-easm as the final system of record for asset ownership.
- Tests that depend on active public scanning or public target availability.
- Replacing existing store/API patterns with one-off query behavior.
