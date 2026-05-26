"""Report generation and download API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from easm.api.deps import get_store
from easm.reports.data import gather_report_data
from easm.reports.excel_report import generate_excel_report
from easm.reports.pdf_report import generate_pdf_report
from easm.store import Store

router = APIRouter(tags=["reports"])


@router.get("/reports/{target_id}/pdf")
async def download_pdf_report(
    target_id: str,
    store: Store = Depends(get_store),
):
    data = await gather_report_data(target_id, store)
    pdf_bytes = generate_pdf_report(data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="openeasm_{target_id}.pdf"'},
    )


@router.get("/reports/{target_id}/excel")
async def download_excel_report(
    target_id: str,
    store: Store = Depends(get_store),
):
    data = await gather_report_data(target_id, store)
    xlsx_bytes = generate_excel_report(data)
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="openeasm_{target_id}.xlsx"'},
    )
