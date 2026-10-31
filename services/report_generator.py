"""HTML and PDF report generation from real database findings."""
import os
from datetime import datetime
from xml.sax.saxutils import escape

from flask import current_app, render_template
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from database import db, utcnow
from models import Report

SEV_COLORS = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#d97706", "Low": "#0284c7"}


def build_context(scan) -> dict:
    return {
        "scan": scan,
        "findings": [v.to_dict() for v in scan.vulnerabilities],
        "counts": scan.severity_counts(),
        "generated_at": utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "colors": SEV_COLORS,
    }


def generate_html(scan) -> str:
    return render_template("report_html.html", **build_context(scan))


def _on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7390"))
    canvas.drawString(18 * mm, 10 * mm, "WebGuard AI - Confidential security assessment report")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf(scan, path: str) -> None:
    ctx = build_context(scan)
    base = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=base["Title"], fontSize=22, textColor=colors.HexColor("#14203d"), alignment=0)
    H2 = ParagraphStyle("H2", parent=base["Heading2"], textColor=colors.HexColor("#14203d"), spaceBefore=10)
    body = ParagraphStyle("B", parent=base["BodyText"], fontSize=9, leading=12)
    code = ParagraphStyle("C", parent=body, fontName="Courier", fontSize=8, leading=10,
                          backColor=colors.HexColor("#f1f3f9"), borderPadding=4)
    label = ParagraphStyle("L", parent=body, fontName="Helvetica-Bold", textColor=colors.HexColor("#14203d"))

    def P(t, s=body):
        return Paragraph(escape(str(t)), s)

    fmt = lambda d: d.strftime("%Y-%m-%d %H:%M:%S UTC") if d else "-"
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=18 * mm, title=f"WebGuard AI Report - Scan {scan.id}")
    s = [P("WebGuard AI", H1), P("Web Application Vulnerability Assessment Report", H2), Spacer(1, 6)]

    rows = [["Target URL", scan.target_url], ["Scan ID", f"#{scan.id}"], ["Scan type", scan.scan_type.title()],
            ["Started", fmt(scan.scan_start_time)], ["Completed", fmt(scan.scan_end_time)],
            ["Status", scan.scan_status], ["Pages discovered", scan.pages_discovered],
            ["Tests completed", scan.tests_completed], ["Total findings", scan.total_findings],
            ["Risk score", f"{scan.risk_score} / 100 ({scan.risk_level})"], ["Generated", ctx["generated_at"]]]
    t = Table([[P(a, label), P(b)] for a, b in rows], colWidths=[40 * mm, 130 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d5d9e6")),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1f9")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s += [t, Spacer(1, 10), P("Severity distribution", H2)]

    counts = ctx["counts"]
    st = Table([[sev, counts[sev]] for sev in ("Critical", "High", "Medium", "Low")], colWidths=[40 * mm, 25 * mm])
    style = [("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d5d9e6"))]
    for i, sev in enumerate(("Critical", "High", "Medium", "Low")):
        style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor(SEV_COLORS[sev])))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    st.setStyle(TableStyle(style))
    if scan.total_findings:
        d = Drawing(120, 110)
        pie = Pie()
        pie.x, pie.y, pie.width, pie.height = 10, 5, 100, 100
        sevs = [k for k in ("Critical", "High", "Medium", "Low") if counts[k]]
        pie.data = [counts[k] for k in sevs]
        for i, k in enumerate(sevs):
            pie.slices[i].fillColor = colors.HexColor(SEV_COLORS[k])
        d.add(pie)
        s.append(Table([[st, d]], colWidths=[80 * mm, 60 * mm]))
    else:
        s += [st, P("No findings were reported for this scan.")]

    s.append(P("Findings (prioritized)", H2))
    for f in ctx["findings"]:
        color = colors.HexColor(SEV_COLORS.get(f["severity"], "#444444"))
        head = ParagraphStyle("hd", parent=body, fontName="Helvetica-Bold", fontSize=10.5, textColor=color)
        block = [P(f"#{f['priority']}  [{f['severity']}]  {f['name']}", head)]
        meta = Table([[P("OWASP", label), P(f["owasp"]), P("Confidence", label), P(f"{f['confidence']} ({f['status']})")],
                      [P("Affected URL", label), P(f["url"]), P("Priority", label), P(f["priority_label"])]],
                     colWidths=[22 * mm, 68 * mm, 24 * mm, 56 * mm])
        meta.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, -1), (-1, -1), 0.3, colors.HexColor("#d5d9e6"))]))
        block += [meta, P("Description", label), P(f["description"]), P("Detection evidence", label), P(f["evidence"], code),
                  P("Potential impact", label), P(f["impact"]), P("Remediation", label), P(f["recommendation"]), Spacer(1, 10)]
        s.append(KeepTogether(block[:4]))
        s += block[4:]
    doc.build(s, onFirstPage=_on_page, onLaterPages=_on_page)


def save_report(scan, fmt: str):
    """Generate a report file from current DB findings, record it, return (Report, absolute path)."""
    out_dir = current_app.config["REPORTS_DIR"]
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"webguard_scan{scan.id}_{stamp}.{fmt}"
    path = os.path.join(out_dir, filename)
    if fmt == "pdf":
        generate_pdf(scan, path)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(generate_html(scan))
    rep = Report.query.filter_by(scan_id=scan.id, report_type=fmt).first()
    if rep:
        try:
            os.remove(rep.file_path)
        except OSError:
            pass
        rep.file_path, rep.generated_at = path, utcnow()
    else:
        rep = Report(scan_id=scan.id, report_type=fmt, file_path=path)
        db.session.add(rep)
    db.session.commit()
    return rep, path
