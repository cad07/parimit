#!/usr/bin/env python3
"""Build the Parimit v0.2 technical white paper from its Markdown source."""

from __future__ import annotations

import argparse
import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


NAVY = colors.HexColor("#102A43")
BLUE = colors.HexColor("#176B87")
TEAL = colors.HexColor("#0B7285")
SAFFRON = colors.HexColor("#F08C46")
INK = colors.HexColor("#243B53")
MUTED = colors.HexColor("#627D98")
PALE_BLUE = colors.HexColor("#EAF4F7")
PALE_SAFFRON = colors.HexColor("#FFF4E8")
PALE_GRAY = colors.HexColor("#F4F7FA")
LINE = colors.HexColor("#D9E2EC")
RED = colors.HexColor("#B42318")


def _placeholderize(text: str, pattern: str, render) -> tuple[str, dict[str, str]]:
    replacements: dict[str, str] = {}

    def repl(match: re.Match[str]) -> str:
        token = f"@@PARIMIT{len(replacements)}@@"
        replacements[token] = render(match)
        return token

    return re.sub(pattern, repl, text), replacements


def inline_markup(text: str) -> str:
    """Translate the small inline-Markdown subset used by the paper."""

    replacements: dict[str, str] = {}

    def stash(value: str) -> str:
        token = f"@@PARIMIT{len(replacements)}@@"
        replacements[token] = value
        return token

    text = re.sub(
        r"`([^`]+)`",
        lambda m: stash(
            f'<font name="Courier" color="#0B7285">{html.escape(m.group(1))}</font>'
        ),
        text,
    )
    text = re.sub(
        r"\[([^\]]+)\]\((https?://[^)]+)\)",
        lambda m: stash(
            f'<link href="{html.escape(m.group(2), quote=True)}" color="#176B87">'
            f"{html.escape(m.group(1))}</link>"
        ),
        text,
    )
    text = re.sub(
        r"<(https?://[^>]+)>",
        lambda m: stash(
            f'<link href="{html.escape(m.group(1), quote=True)}" color="#176B87">'
            f"{html.escape(m.group(1))}</link>"
        ),
        text,
    )
    text = re.sub(
        r"\*\*([^*]+)\*\*",
        lambda m: stash(f"<b>{html.escape(m.group(1))}</b>"),
        text,
    )
    text = re.sub(
        r"(?<!\*)\*([^*]+)\*(?!\*)",
        lambda m: stash(f"<i>{html.escape(m.group(1))}</i>"),
        text,
    )
    escaped = html.escape(text)
    # Later placeholders can contain earlier ones (for example bold text with
    # inline code). Resolve from the outside in so no internal marker leaks.
    for token, value in reversed(list(replacements.items())):
        escaped = escaped.replace(token, value)
    if "@@PARIMIT" in escaped:
        raise ValueError("Unresolved inline-markup placeholder")
    return escaped


def make_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    styles: dict[str, ParagraphStyle] = {}
    styles["body"] = ParagraphStyle(
        "Body",
        parent=base["BodyText"],
        fontName="Helvetica",
        fontSize=9.25,
        leading=13.2,
        textColor=INK,
        spaceAfter=6.5,
        allowWidows=0,
        allowOrphans=0,
        splitLongWords=True,
    )
    styles["h1"] = ParagraphStyle(
        "Heading1",
        parent=base["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=NAVY,
        spaceBefore=4,
        spaceAfter=10,
        keepWithNext=True,
    )
    styles["h2"] = ParagraphStyle(
        "Heading2",
        parent=base["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=NAVY,
        spaceBefore=8,
        spaceAfter=7,
        keepWithNext=True,
    )
    styles["h3"] = ParagraphStyle(
        "Heading3",
        parent=base["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=14,
        textColor=TEAL,
        spaceBefore=7,
        spaceAfter=4,
        keepWithNext=True,
    )
    styles["quote"] = ParagraphStyle(
        "Quote",
        parent=styles["body"],
        fontName="Helvetica-Oblique",
        fontSize=10,
        leading=14,
        leftIndent=12,
        rightIndent=8,
        borderColor=SAFFRON,
        borderWidth=0,
        borderPadding=(7, 10, 7, 12),
        backColor=PALE_SAFFRON,
        spaceBefore=5,
        spaceAfter=10,
    )
    styles["bullet"] = ParagraphStyle(
        "BulletBody",
        parent=styles["body"],
        fontSize=8.9,
        leading=12.4,
        spaceAfter=2,
    )
    styles["code"] = ParagraphStyle(
        "Code",
        parent=base["Code"],
        fontName="Courier",
        fontSize=6.9,
        leading=9.2,
        textColor=NAVY,
        leftIndent=7,
        rightIndent=7,
        borderColor=LINE,
        borderWidth=0.5,
        borderPadding=8,
        backColor=PALE_GRAY,
        spaceBefore=4,
        spaceAfter=9,
    )
    styles["table_header"] = ParagraphStyle(
        "TableHeader",
        parent=styles["body"],
        fontName="Helvetica-Bold",
        fontSize=7.6,
        leading=9.4,
        textColor=colors.white,
        spaceAfter=0,
        splitLongWords=True,
        wordWrap="CJK",
    )
    styles["table_body"] = ParagraphStyle(
        "TableBody",
        parent=styles["body"],
        fontSize=7.35,
        leading=9.5,
        spaceAfter=0,
        splitLongWords=True,
        wordWrap="CJK",
    )
    styles["caption"] = ParagraphStyle(
        "Caption",
        parent=styles["body"],
        fontSize=7.5,
        leading=9.5,
        textColor=MUTED,
        alignment=TA_CENTER,
        spaceBefore=4,
        spaceAfter=8,
    )
    styles["toc_title"] = ParagraphStyle(
        "TOCTitle",
        parent=styles["h1"],
        fontSize=19,
        leading=23,
        spaceAfter=16,
    )
    styles["toc1"] = ParagraphStyle(
        "TOC1",
        parent=styles["body"],
        fontName="Helvetica-Bold",
        fontSize=9.2,
        leading=13,
        leftIndent=0,
        firstLineIndent=0,
        textColor=NAVY,
        spaceBefore=2,
    )
    styles["toc2"] = ParagraphStyle(
        "TOC2",
        parent=styles["body"],
        fontSize=8.1,
        leading=11,
        leftIndent=12,
        firstLineIndent=0,
        textColor=MUTED,
    )
    return styles


class ArchitectureDiagram(Flowable):
    """Compact vector diagram of the proposal-only trust boundary."""

    def __init__(self, width: float):
        super().__init__()
        self.width = width
        self.height = 178

    def _box(self, canvas, x, y, w, h, fill, stroke, title, subtitle=""):
        canvas.setFillColor(fill)
        canvas.setStrokeColor(stroke)
        canvas.setLineWidth(0.8)
        canvas.roundRect(x, y, w, h, 5, fill=1, stroke=1)
        canvas.setFillColor(NAVY if fill != NAVY else colors.white)
        canvas.setFont("Helvetica-Bold", 7.8)
        canvas.drawCentredString(x + w / 2, y + h - 13, title)
        if subtitle:
            canvas.setFont("Helvetica", 6.4)
            canvas.setFillColor(MUTED if fill != NAVY else colors.HexColor("#D9EAF0"))
            canvas.drawCentredString(x + w / 2, y + 8, subtitle)

    def _arrow(self, canvas, x1, y1, x2, y2, color=TEAL):
        canvas.setStrokeColor(color)
        canvas.setFillColor(color)
        canvas.setLineWidth(1.3)
        canvas.line(x1, y1, x2, y2)
        angle_x = 4 if x2 >= x1 else -4
        if abs(x2 - x1) > abs(y2 - y1):
            canvas.line(x2, y2, x2 - angle_x, y2 + 2.5)
            canvas.line(x2, y2, x2 - angle_x, y2 - 2.5)
        else:
            direction = 4 if y2 >= y1 else -4
            canvas.line(x2, y2, x2 - 2.5, y2 - direction)
            canvas.line(x2, y2, x2 + 2.5, y2 - direction)

    def draw(self):
        c = self.canv
        w = self.width
        c.saveState()
        c.setFillColor(PALE_GRAY)
        c.roundRect(0, 0, w, self.height, 8, fill=1, stroke=0)
        c.setFillColor(MUTED)
        c.setFont("Helvetica-Bold", 7)
        c.drawString(12, self.height - 15, "UNTRUSTED INPUT")
        self._box(c, 12, self.height - 58, 105, 34, colors.white, LINE, "AI agent / AiNxt", "draft only")
        self._box(c, w - 117, self.height - 58, 105, 34, colors.white, LINE, "Keycloak", "verified identity")

        boundary_y = 48
        boundary_h = 69
        c.setFillColor(colors.white)
        c.setStrokeColor(BLUE)
        c.setLineWidth(1.5)
        c.roundRect(12, boundary_y, w - 24, boundary_h, 8, fill=1, stroke=1)
        c.setFillColor(BLUE)
        c.setFont("Helvetica-Bold", 7.2)
        c.drawString(22, boundary_y + boundary_h - 13, "PARIMIT TRUSTED PROPOSAL BOUNDARY")
        gap = 7
        box_w = (w - 60 - gap * 3) / 4
        labels = [
            ("Validate", "closed schema"),
            ("Policy", "deterministic"),
            ("Human gate", "separate role"),
            ("Evidence", "no dispatch"),
        ]
        xs = []
        for i, (title, subtitle) in enumerate(labels):
            x = 22 + i * (box_w + gap)
            xs.append(x)
            self._box(c, x, boundary_y + 10, box_w, 34, PALE_BLUE, BLUE, title, subtitle)
            if i:
                self._arrow(c, x - gap + 1, boundary_y + 27, x - 1, boundary_y + 27)

        self._arrow(c, 117, self.height - 41, xs[0] + box_w / 2, boundary_y + boundary_h)
        self._arrow(c, w - 64, self.height - 58, xs[2] + box_w / 2, boundary_y + boundary_h)

        c.setFillColor(colors.HexColor("#FFF1F0"))
        c.setStrokeColor(RED)
        c.setLineWidth(1)
        c.roundRect(70, 8, w - 140, 25, 5, fill=1, stroke=1)
        c.setFillColor(RED)
        c.setFont("Helvetica-Bold", 7.8)
        c.drawCentredString(w / 2, 18, "EXTERNAL PAYMENT EXECUTION: ABSENT")
        c.setStrokeColor(RED)
        c.setLineWidth(2.1)
        c.line(w / 2, boundary_y, w / 2, 34)
        c.line(w / 2 - 8, 39, w / 2 + 8, 39)
        c.restoreState()


class WhitePaperDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str, styles: dict[str, ParagraphStyle], **kwargs):
        super().__init__(filename, **kwargs)
        self.styles = styles
        self._bookmark_counter = 0

    def beforeDocument(self):
        super().beforeDocument()
        # multiBuild performs more than one layout pass for the table of
        # contents. Stable bookmark keys are required for convergence.
        self._bookmark_counter = 0

    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        if style_name not in {"Heading2", "Heading3"}:
            return
        level = 0 if style_name == "Heading2" else 1
        text = flowable.getPlainText()
        key = f"section-{self._bookmark_counter}"
        self._bookmark_counter += 1
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level, closed=False)
        # Keep the printed contents concise; subsections remain available in
        # the PDF outline without expanding the contents across several pages.
        if level == 0:
            self.notify("TOCEntry", (level, text, self.page, key))


def draw_cover(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)

    canvas.setFillColor(colors.HexColor("#163A59"))
    canvas.circle(width + 18 * mm, height - 20 * mm, 67 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#1D4C6D"))
    canvas.circle(width - 8 * mm, height - 20 * mm, 42 * mm, fill=1, stroke=0)
    canvas.setFillColor(SAFFRON)
    canvas.rect(0, 0, 9 * mm, height, fill=1, stroke=0)

    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(24 * mm, height - 32 * mm, "PARIMIT")
    canvas.setFillColor(colors.HexColor("#B8D8E6"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(24 * mm, height - 39 * mm, "BOUNDED AUTHORITY FOR AGENT PAYMENTS")

    title = Paragraph(
        "Parimit: A Proposal-Only<br/>Authorization Boundary<br/>for Agentic Payments",
        ParagraphStyle(
            "CoverTitle",
            fontName="Helvetica-Bold",
            fontSize=27,
            leading=31,
            textColor=colors.white,
            alignment=TA_LEFT,
        ),
    )
    title.wrapOn(canvas, 150 * mm, 80 * mm)
    title.drawOn(canvas, 24 * mm, height - 130 * mm)

    canvas.setFillColor(colors.HexColor("#B8D8E6"))
    canvas.setFont("Helvetica", 11)
    canvas.drawString(24 * mm, height - 143 * mm, "Technical White Paper v0.2")
    canvas.setFont("Helvetica", 8.8)
    canvas.drawString(
        24 * mm,
        height - 151 * mm,
        "Implementation, identity, evidence, and local AiNxt compatibility study",
    )

    pill_x, pill_y, pill_w, pill_h = 24 * mm, height - 174 * mm, 77 * mm, 14 * mm
    canvas.setFillColor(colors.HexColor("#214D68"))
    canvas.roundRect(pill_x, pill_y, pill_w, pill_h, 5, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.drawCentredString(pill_x + pill_w / 2, pill_y + 5, "IMPLEMENTATION-ALIGNED TECHNICAL ALPHA")

    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(24 * mm, 44 * mm, "Parimit Contributors")
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#B8D8E6"))
    canvas.drawString(24 * mm, 37 * mm, "29 September 2026")
    canvas.drawString(24 * mm, 30 * mm, "Open source - MIT License")

    canvas.setStrokeColor(colors.HexColor("#5E8198"))
    canvas.setLineWidth(0.7)
    canvas.line(24 * mm, 24 * mm, width - 24 * mm, 24 * mm)
    canvas.setFont("Helvetica", 6.8)
    canvas.setFillColor(colors.HexColor("#9EC5D5"))
    canvas.drawString(
        24 * mm,
        17 * mm,
        "Proposal and evidence only. No UPI, bank, PSP, wallet, or live payment connection.",
    )
    canvas.restoreState()


def draw_normal_page(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, height - 16 * mm, width - doc.rightMargin, height - 16 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica-Bold", 6.8)
    canvas.drawString(doc.leftMargin, height - 12 * mm, "PARIMIT TECHNICAL WHITE PAPER v0.2")
    canvas.setFont("Helvetica", 6.8)
    right = "IMPLEMENTATION-ALIGNED TECHNICAL ALPHA"
    canvas.drawRightString(width - doc.rightMargin, height - 12 * mm, right)

    canvas.setStrokeColor(LINE)
    canvas.line(doc.leftMargin, 14 * mm, width - doc.rightMargin, 14 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 6.8)
    canvas.drawString(doc.leftMargin, 9.5 * mm, "No payment execution capability")
    canvas.drawRightString(width - doc.rightMargin, 9.5 * mm, f"Page {doc.page}")
    canvas.restoreState()


def column_widths(column_count: int, total_width: float) -> list[float]:
    if column_count == 2:
        return [total_width * 0.31, total_width * 0.69]
    if column_count == 3:
        return [total_width * 0.28, total_width * 0.34, total_width * 0.38]
    if column_count == 4:
        return [total_width * 0.22, total_width * 0.15, total_width * 0.315, total_width * 0.315]
    return [total_width / column_count] * column_count


def build_table(rows: list[list[str]], styles, width: float) -> Table:
    column_count = max(len(row) for row in rows)
    normalized = [row + [""] * (column_count - len(row)) for row in rows]
    rendered = []
    for row_index, row in enumerate(normalized):
        style = styles["table_header"] if row_index == 0 else styles["table_body"]
        rendered.append([Paragraph(inline_markup(cell.strip()), style) for cell in row])
    table = Table(
        rendered,
        colWidths=column_widths(column_count, width),
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=1,
    )
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for row_index in range(1, len(rendered)):
        if row_index % 2 == 0:
            commands.append(("BACKGROUND", (0, row_index), (-1, row_index), PALE_GRAY))
    table.setStyle(TableStyle(commands))
    return table


def parse_markdown(source: str, styles, content_width: float) -> list:
    lines = source.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "## Abstract")
    except StopIteration as exc:
        raise ValueError("White paper source is missing the Abstract heading") from exc
    lines = lines[start:]
    story: list = []
    paragraph_lines: list[str] = []
    quote_lines: list[str] = []
    list_items: list[tuple[bool, int | None, str]] = []
    in_code = False
    code_lines: list[str] = []
    index = 0

    def flush_paragraph():
        if paragraph_lines:
            text = " ".join(part.strip() for part in paragraph_lines)
            story.append(Paragraph(inline_markup(text), styles["body"]))
            paragraph_lines.clear()

    def flush_quote():
        if quote_lines:
            text = " ".join(part.strip() for part in quote_lines)
            story.append(Paragraph(inline_markup(text), styles["quote"]))
            quote_lines.clear()

    def flush_list():
        if not list_items:
            return
        ordered = list_items[0][0]
        start_at = list_items[0][1] if ordered else None
        items = [
            ListItem(Paragraph(inline_markup(text), styles["bullet"]), leftIndent=11)
            for _, _, text in list_items
        ]
        list_kwargs = {
            "bulletType": "1" if ordered else "bullet",
            "start": start_at if ordered else "circle",
            "leftIndent": 17,
            "bulletFontName": "Helvetica-Bold",
            "bulletFontSize": 7.5,
            "bulletColor": TEAL,
            "spaceAfter": 7,
        }
        story.append(ListFlowable(items, **list_kwargs))
        list_items.clear()

    def flush_all():
        flush_paragraph()
        flush_quote()
        flush_list()

    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()

        if in_code:
            if stripped.startswith("```"):
                story.append(Preformatted("\n".join(code_lines), styles["code"]))
                code_lines.clear()
                in_code = False
            else:
                code_lines.append(raw)
            index += 1
            continue

        if stripped.startswith("```"):
            flush_all()
            in_code = True
            index += 1
            continue

        if stripped == "<!-- FIGURE:architecture -->":
            flush_all()
            story.append(ArchitectureDiagram(content_width))
            story.append(Paragraph("Figure 1. Parimit keeps external payment execution outside the shipped trust boundary.", styles["caption"]))
            index += 1
            continue

        if stripped.startswith("<!--"):
            flush_all()
            index += 1
            continue

        if stripped.startswith("## "):
            flush_all()
            title = stripped[3:]
            forced_starts = (
                "1.",
                "5.",
                "10.",
                "References",
            )
            if title.startswith(forced_starts):
                if story:
                    story.append(PageBreak())
            story.append(Paragraph(inline_markup(title), styles["h2"]))
            story.append(HRFlowable(width="100%", thickness=0.8, color=SAFFRON, spaceAfter=8))
            index += 1
            continue

        if stripped.startswith("### "):
            flush_all()
            story.append(Paragraph(inline_markup(stripped[4:]), styles["h3"]))
            index += 1
            continue

        if stripped.startswith("# "):
            flush_all()
            story.append(Paragraph(inline_markup(stripped[2:]), styles["h1"]))
            index += 1
            continue

        if stripped.startswith(">"):
            flush_paragraph()
            flush_list()
            quote_lines.append(stripped.lstrip("> "))
            index += 1
            continue

        bullet_match = re.match(r"^-\s+(.+)$", stripped)
        ordered_match = re.match(r"^\d+\.\s+(.+)$", stripped)
        if bullet_match or ordered_match:
            flush_paragraph()
            flush_quote()
            ordinal = int(stripped.split(".", 1)[0]) if ordered_match else None
            list_items.append((bool(ordered_match), ordinal, (ordered_match or bullet_match).group(1)))
            index += 1
            continue

        if list_items and raw[:1].isspace() and stripped:
            ordered, ordinal, prior_text = list_items[-1]
            list_items[-1] = (ordered, ordinal, f"{prior_text} {stripped}")
            index += 1
            continue

        if stripped.startswith("|") and index + 1 < len(lines):
            separator = lines[index + 1].strip()
            if separator.startswith("|") and re.fullmatch(r"[|:\-\s]+", separator):
                flush_all()
                rows: list[list[str]] = []
                rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
                index += 2
                while index < len(lines) and lines[index].strip().startswith("|"):
                    rows.append([cell.strip() for cell in lines[index].strip().strip("|").split("|")])
                    index += 1
                story.append(build_table(rows, styles, content_width))
                story.append(Spacer(1, 8))
                continue

        if not stripped:
            flush_all()
            index += 1
            continue

        if quote_lines:
            flush_quote()
        if list_items:
            flush_list()
        paragraph_lines.append(stripped)
        index += 1

    flush_all()
    if in_code:
        raise ValueError("Unclosed code fence in white paper source")
    return story


def build(source_path: Path, output_path: Path):
    styles = make_styles()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    width, height = A4
    left = 22 * mm
    right = 22 * mm
    top = 22 * mm
    bottom = 20 * mm
    content_width = width - left - right

    doc = WhitePaperDocTemplate(
        str(output_path),
        styles,
        pagesize=A4,
        leftMargin=left,
        rightMargin=right,
        topMargin=top,
        bottomMargin=bottom,
        title="Parimit: A Proposal-Only Authorization Boundary for Agentic Payments",
        author="Parimit Contributors",
        subject="Technical White Paper v0.2",
        keywords="Parimit, AI agents, payment proposal, authorization, AiNxt, OIDC, Keycloak",
    )

    cover_frame = Frame(0, 0, width, height, id="cover-frame", showBoundary=0)
    normal_frame = Frame(left, bottom, content_width, height - top - bottom, id="normal-frame", showBoundary=0)
    doc.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[cover_frame], onPage=draw_cover),
            PageTemplate(id="normal", frames=[normal_frame], onPage=draw_normal_page),
        ]
    )

    story: list = [NextPageTemplate("normal"), PageBreak()]
    story.append(Paragraph("Contents", styles["toc_title"]))
    story.append(
        Paragraph(
            "This paper distinguishes implementation, automated evidence, maintainer-observed live evidence, human acceptance, and external acceptance.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 6))
    toc = TableOfContents()
    toc.levelStyles = [styles["toc1"], styles["toc2"]]
    toc.dotsMinLevel = 0
    story.append(toc)
    story.append(PageBreak())
    story.extend(parse_markdown(source_path.read_text(encoding="utf-8"), styles, content_width))

    doc.multiBuild(story)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("docs/parimit-technical-white-paper-v0.2.md"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/pdf/parimit-technical-white-paper-v0.2.pdf"),
    )
    args = parser.parse_args()
    build(args.source.resolve(), args.output.resolve())
    print(args.output.resolve())


if __name__ == "__main__":
    main()
