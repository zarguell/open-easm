"""Certificate inventory persistence.

Read-side queries over entities of type ``certificate``. The certificate
profile (subject, issuer, validity, deployment state, analysis) is stored
inside ``attributes.certificate_profile`` JSONB.
"""

from __future__ import annotations

import json
from typing import Any

import asyncpg

from easm.stores import BaseStore


def _json_field(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def _row_to_certificate_inventory_dict(row: asyncpg.Record) -> dict[str, Any]:
    return {
        "entity_id": str(row["entity_id"]),
        "fingerprint_sha256": row["fingerprint_sha256"],
        "subject_cn": row["subject_cn"],
        "issuer_organization": row["issuer_organization"],
        "not_before": row["not_before"],
        "not_after": row["not_after"],
        "validity_state": row["validity_state"],
        "deployment_state": row["deployment_state"],
        "observed_endpoints": _json_field(row["observed_endpoints"], []),
        "risk": row["risk"],
        "reasons": _json_field(row["reasons"], []),
        "strength": row["strength"],
        "san_dns_names": _json_field(row["san_dns_names"], []),
        "subject_source": row["subject_source"],
    }


class CertificateStore(BaseStore):
    """Read-side inventory for certificate entities."""

    async def list_certificate_inventory(
        self,
        target_id: str | None = None,
        org_id: str = "default",
        deployment_state: str | None = None,
        risk: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        conditions = ["org_id = $1", "entity_type = 'certificate'"]
        params: list[Any] = [org_id]
        idx = 2

        if target_id:
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
            idx += 1
        if deployment_state:
            conditions.append(
                "COALESCE("
                "attributes #>> '{certificate_profile,analysis,deployment_state}', "
                "attributes #>> '{certificate_profile,deployment,state}'"
                f") = ${idx}"
            )
            params.append(deployment_state)
            idx += 1
        if risk:
            conditions.append(f"attributes #>> '{{certificate_profile,analysis,risk}}' = ${idx}")
            params.append(risk)
            idx += 1

        params.extend([limit, offset])
        rows = await self._pool.fetch(
            f"""
            SELECT
                COUNT(*) OVER() AS total_count,
                id AS entity_id,
                attributes #>> '{{certificate_profile,fingerprint_sha256}}' AS fingerprint_sha256,
                COALESCE(
                    attributes #>> '{{certificate_profile,subject,common_name}}',
                    (attributes #> '{{certificate_profile,san_dns_names}}'->>0)
                ) AS subject_cn,
                attributes #> '{{certificate_profile,san_dns_names}}' AS san_dns_names,
                CASE
                    WHEN attributes #>> '{{certificate_profile,subject,common_name}}' IS NOT NULL THEN 'cn'
                    ELSE 'san'
                END AS subject_source,
                attributes #>> '{{certificate_profile,issuer,organization}}' AS issuer_organization,
                attributes #>> '{{certificate_profile,not_before}}' AS not_before,
                attributes #>> '{{certificate_profile,not_after}}' AS not_after,
                attributes #>> '{{certificate_profile,analysis,validity_state}}' AS validity_state,
                COALESCE(
                    attributes #>> '{{certificate_profile,analysis,deployment_state}}',
                    attributes #>> '{{certificate_profile,deployment,state}}'
                ) AS deployment_state,
                attributes #> '{{certificate_profile,deployment,observed_endpoints}}' AS observed_endpoints,
                attributes #>> '{{certificate_profile,analysis,risk}}' AS risk,
                attributes #> '{{certificate_profile,analysis,reasons}}' AS reasons,
                attributes #>> '{{certificate_profile,analysis,strength}}' AS strength
            FROM entities
            WHERE {' AND '.join(conditions)}
            ORDER BY
                CASE attributes #>> '{{certificate_profile,analysis,risk}}'
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END,
                (attributes #>> '{{certificate_profile,not_after}}') ASC NULLS LAST
            LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params,
        )
        total_count = rows[0]["total_count"] if rows else 0
        return {
            "certificates": [_row_to_certificate_inventory_dict(row) for row in rows],
            "total_count": total_count,
        }

    async def summarize_certificate_inventory(
        self,
        target_id: str | None = None,
        org_id: str = "default",
    ) -> dict[str, Any]:
        conditions = ["org_id = $1", "entity_type = 'certificate'"]
        params: list[Any] = [org_id]
        if target_id:
            conditions.append("target_id = $2")
            params.append(target_id)

        rows = await self._pool.fetch(
            f"""
            SELECT
                attributes #>> '{{certificate_profile,analysis,risk}}' AS risk,
                COALESCE(
                    attributes #>> '{{certificate_profile,analysis,deployment_state}}',
                    attributes #>> '{{certificate_profile,deployment,state}}'
                ) AS deployment_state,
                attributes #>> '{{certificate_profile,issuer,organization}}' AS issuer_organization
            FROM entities
            WHERE {' AND '.join(conditions)}
            """,
            *params,
        )

        summary: dict[str, Any] = {
            "total": len(rows),
            "by_risk": {},
            "by_deployment_state": {},
            "by_issuer_organization": {},
        }
        for row in rows:
            for source_key, summary_key in (
                ("risk", "by_risk"),
                ("deployment_state", "by_deployment_state"),
                ("issuer_organization", "by_issuer_organization"),
            ):
                value = row[source_key] or "unknown"
                summary[summary_key][value] = summary[summary_key].get(value, 0) + 1
        return summary
