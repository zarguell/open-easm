"""PDF report generation for OpenEASM."""

from __future__ import annotations

from html import escape
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Color palette — based on our UI design tokens (DESIGN_TOKENS.ts)
# Dark terminal aesthetic with electric-teal accents.
PAGE_BG = colors.HexColor("#1a1a1a")
INK = colors.HexColor("#f2f2f2")
MUTED = colors.HexColor("#8b949e")
PRIMARY = colors.HexColor("#00d992")
PRIMARY_DEEP = colors.HexColor("#10b981")
RED = colors.HexColor("#ef4444")
RED_DARK = colors.HexColor("#991b1b")
CARD = colors.HexColor("#222222")
CARD_ALT = colors.HexColor("#2a2a2a")
BORDER = colors.HexColor("#3d3a39")
ROW_ALT = colors.HexColor("#282828")
WHITE = colors.HexColor("#ffffff")
GREEN = colors.HexColor("#00d992")
ORANGE = colors.HexColor("#f59e0b")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_pdf_report(data: dict[str, Any]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        rightMargin=1.1 * cm,
        leftMargin=1.1 * cm,
        topMargin=1.35 * cm,
        bottomMargin=1.05 * cm,
        title=f"OpenEASM Report - {data.get('target_id', 'unknown')}",
        author="OpenEASM",
    )

    styles = _styles()
    story = []
    risk = data.get("executive_risk", {})
    findings = data.get("findings", [])

    # Cover
    story.append(_cover_block(data, styles))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_kpi_cards(data, styles))
    story.append(Spacer(1, 0.2 * cm))

    # Executive summary
    story.append(Paragraph("Executive Summary", styles["Section"]))
    story.append(_callout(risk.get("board_summary", "No summary available."), styles))
    story.append(Spacer(1, 0.2 * cm))

    # Pillar table
    story.append(Paragraph("Risk by Pillar", styles["Section"]))
    story.append(_pillar_table(risk, styles))
    story.append(Spacer(1, 0.25 * cm))

    # Action plan
    story.append(Paragraph("Prioritized Action Plan", styles["Section"]))
    story.append(_actions_table(findings, styles))
    story.append(PageBreak())

    # Findings
    story.append(Paragraph("All Findings", styles["Section"]))
    story.append(_findings_table(findings, styles))
    story.append(PageBreak())

    # Exposure inventory
    story.append(Paragraph("Exposed Asset Inventory", styles["Section"]))
    story.append(_assets_table(data.get("entities", []), styles))
    story.append(PageBreak())

    # Scope and limits
    story.append(Paragraph("Scope and Limitations", styles["Section"]))
    limits = [
        ["Point", "Detail"],
        ["Nature", "Defensive external attack surface audit using publicly observable information."],
        ["Active Scanning", "Service/version/port identification only. No exploitation, brute-force, or DoS."],
        ["CVE Correlation", "Version-based correlation. A masked version should not generate false positives."],
        ["Backports", "Distributions may apply security patches without changing the upstream version number."],
        ["Responsibility", "The user must have authorization or a legitimate security purpose for analyzed resources."],
    ]
    story.append(_table(limits, [5.2 * cm, 20.3 * cm], styles=styles))

    doc.build(story)
    return buf.getvalue()


def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle("Section", parent=base["Heading2"], textColor=PRIMARY, fontSize=15, leading=18, spaceBefore=5, spaceAfter=7))
    base.add(ParagraphStyle("Body", parent=base["BodyText"], textColor=INK, fontSize=8.5, leading=12))
    base.add(ParagraphStyle("Cell", parent=base["BodyText"], textColor=INK, fontSize=6.8, leading=8.3))
    base.add(ParagraphStyle("CellSmall", parent=base["BodyText"], textColor=INK, fontSize=6.15, leading=7.35))
    base.add(ParagraphStyle("HeaderCell", parent=base["BodyText"], textColor=PRIMARY, fontSize=6.8, leading=8.2, fontName="Helvetica-Bold"))
    return base


def _cover_block(data, styles):
    target = data.get("target_id", "N/A")
    risk = data.get("executive_risk", {})
    left = [Paragraph("OPENEASM REPORT", ParagraphStyle("CoverTitle", parent=styles["Body"], fontSize=24, textColor=PRIMARY, fontName="Helvetica-Bold"))]
    right = Paragraph(
        f"<b>Target</b>: {escape(target)}<br/>"
        f"<b>Score</b>: {risk.get('overall_score', 'N/A')} / 100<br/>"
        f"<b>Posture</b>: {escape(risk.get('posture', 'N/A'))}<br/>"
        f"<b>Risk</b>: {escape(risk.get('risk_level', 'N/A'))}",
        styles["Body"],
    )
    t = Table([[left, right]], colWidths=[15.8 * cm, 9.8 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("BOX", (0, 0), (-1, -1), 0.9, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 13),
        ("RIGHTPADDING", (0, 0), (-1, -1), 13),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    return t


def _kpi_cards(data, styles):
    risk = data.get("executive_risk", {})
    findings = data.get("findings", [])
    items = [
        f"<b>Executive Score</b><br/><font size='14' color='#65000B'><b>{risk.get('overall_score', 'N/A')}/100</b></font>",
        f"<b>Technical Score</b><br/><font size='14' color='#65000B'><b>{risk.get('technical_score', 'N/A')}/1000</b></font>",
        f"<b>Surface</b><br/><font size='14' color='#65000B'><b>{data.get('ip_count', 0)} IPs</b></font>",
        f"<b>Findings</b><br/><font size='14' color='#65000B'><b>{len(findings)}</b></font>",
    ]
    row = [Paragraph(i, styles["Body"]) for i in items]
    t = Table([row], colWidths=[6.25 * cm] * 4)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _pillar_table(risk, styles):
    rows = [["Pillar", "Score", "Level", "Risk", "Findings", "Recommendation"]]
    for p in risk.get("pillars", []):
        score = p.get("score", "N/A")
        rows.append([
            p.get("label", ""),
            f"{score}/100" if score != "N/A" else "N/A",
            p.get("level", ""),
            p.get("risk", ""),
            str(p.get("findings_count", 0)),
            p.get("recommendation", ""),
        ])
    return _table(rows, [4.4 * cm, 2.6 * cm, 3.7 * cm, 4.1 * cm, 2.2 * cm, 8.5 * cm], styles=styles)


def _actions_table(findings, styles, limit=12):
    rows = [["Priority", "Severity", "Headline", "Recommendation"]]
    sorted_f = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("risk", "info"), 9))
    for f in sorted_f[:limit]:
        sev = f.get("risk", "info")
        priority = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "Info"}.get(sev, "Info")
        rows.append([priority, sev, f.get("headline", ""), f.get("description", "") or ""])
    if len(rows) == 1:
        rows.append(["Info", "info", "No findings", "No action required"])
    return _table(rows, [2.5 * cm, 2.2 * cm, 10 * cm, 10.8 * cm], small=True, styles=styles)


def _findings_table(findings, styles, limit=40):
    rows = [["Severity", "Rule", "Headline", "Status", "Confidence"]]
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("risk", "info"), 9))[:limit]:
        rows.append([f.get("risk", ""), f.get("rule_id", ""), f.get("headline", ""), f.get("status", ""), f.get("confidence_level", "")])
    if len(rows) == 1:
        rows.append(["info", "none", "No findings", "N/A", "N/A"])
    return _table(rows, [2.5 * cm, 4 * cm, 10 * cm, 3 * cm, 3 * cm], small=True, styles=styles)


def _assets_table(entities, styles, limit=50):
    rows = [["Entity", "Type", "Risk", "Confidence", "First Seen"]]
    for e in entities[:limit]:
        rows.append([
            e.get("entity_value", ""),
            e.get("entity_type", ""),
            e.get("risk_level", ""),
            e.get("confidence_level", ""),
            str(e.get("first_seen_at", ""))[:19],
        ])
    if len(rows) == 1:
        rows.append(["None", "N/A", "N/A", "N/A", "N/A"])
    return _table(rows, [8 * cm, 3 * cm, 3 * cm, 3 * cm, 5 * cm], small=True, styles=styles)


def _callout(text, styles):
    t = Table([[Paragraph(escape(text), styles["Body"])]], colWidths=[25.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD_ALT),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


def _table(data, col_widths, small=False, header=True, styles=None):
    styles = styles or _styles()
    cell_style = styles["CellSmall" if small else "Cell"]
    header_style = styles["HeaderCell"]
    converted = []
    for r, row in enumerate(data):
        new_row = []
        for value in row:
            s = header_style if header and r == 0 else cell_style
            new_row.append(Paragraph(escape(str(value if value is not None else "")), s))
        converted.append(new_row)
    t = LongTable(converted, colWidths=col_widths, repeatRows=1 if header else 0, splitByRow=1)
    ts = [
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("GRID", (0, 0), (-1, -1), 0.28, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4.3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.3),
        ("TOPPADDING", (0, 0), (-1, -1), 3.8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.8),
    ]
    if header:
        ts += [("BACKGROUND", (0, 0), (-1, 0), CARD_ALT), ("LINEBELOW", (0, 0), (-1, 0), 0.7, PRIMARY)]
    for r in range(1 if header else 0, len(data)):
        if r % 2 == 0:
            ts.append(("BACKGROUND", (0, r), (-1, r), ROW_ALT))
    t.setStyle(TableStyle(ts))
    return t
