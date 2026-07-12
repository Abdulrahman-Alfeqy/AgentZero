"""
report_generator.py — PDF compliance report builder for Agent Zero.

Generates professional PDF reports from stored incidents using ReportLab.
Never writes raw sensitive values to the report.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path


logger = logging.getLogger(__name__)

_REPORTS_DIR = Path("reports")


def _get_reportlab():
    """Lazy import of reportlab to give a clear error if missing."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            HRFlowable,
        )
        return colors, A4, getSampleStyleSheet, ParagraphStyle, cm, SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    except ImportError as exc:
        raise ImportError(
            "ReportLab is required for PDF generation. "
            "Install it with: pip install reportlab"
        ) from exc


class ReportGenerator:
    """
    Builds PDF compliance reports from incident records.

    Args:
        output_dir: Directory where generated PDF files are saved.
    """

    def __init__(self, output_dir: Path = _REPORTS_DIR) -> None:
        """Initialise the generator, creating the output directory if needed."""
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("ReportGenerator initialised, output dir: %s", self._output_dir.resolve())

    def generate(
        self,
        incidents: list,
        stats: dict,
        title: str = "Agent Zero — Compliance Report",
    ) -> Path:
        """
        Generate a PDF compliance report.

        Args:
            incidents: List of IncidentRecord objects.
            stats:     Summary stats dict from IncidentStore.get_stats().
            title:     Report title shown on the cover page.

        Returns:
            Path to the generated PDF file.

        Raises:
            ImportError: If ReportLab is not installed.
            OSError: If the file cannot be written.
        """
        colors, A4, getSampleStyleSheet, ParagraphStyle, cm, SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable = _get_reportlab()

        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        unique_id = uuid.uuid4().hex[:8]
        filename = f"compliance_report_{timestamp}_{unique_id}.pdf"
        output_path = self._output_dir / filename

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=22,
            spaceAfter=12,
            textColor=colors.HexColor("#1a1a2e"),
        )
        heading2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontSize=14,
            spaceAfter=6,
            textColor=colors.HexColor("#16213e"),
        )
        normal_style = styles["Normal"]
        normal_style.fontSize = 9

        # Severity colours
        sev_color = {
            "HIGH": colors.HexColor("#e74c3c"),
            "MEDIUM": colors.HexColor("#f39c12"),
            "LOW": colors.HexColor("#27ae60"),
        }

        story = []

        # ── Cover ────────────────────────────────────────────────────────
        story.append(Paragraph(title, title_style))
        story.append(
            Paragraph(
                f"Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                normal_style,
            )
        )
        story.append(Spacer(1, 0.5 * cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
        story.append(Spacer(1, 0.5 * cm))

        # ── Executive Summary ────────────────────────────────────────────
        story.append(Paragraph("Executive Summary", heading2_style))
        summary_data = [
            ["Metric", "Value"],
            ["Total Incidents", str(stats.get("total", 0))],
            ["High Severity", str(stats.get("high", 0))],
            ["Medium Severity", str(stats.get("medium", 0))],
            ["Low Severity", str(stats.get("low", 0))],
            ["Last Activity", stats.get("last_activity") or "—"],
        ]
        summary_table = Table(summary_data, colWidths=[8 * cm, 8 * cm])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 0.8 * cm))

        # ── Incidents ────────────────────────────────────────────────────
        story.append(Paragraph("Incident Log", heading2_style))

        if not incidents:
            story.append(Paragraph("No incidents recorded.", normal_style))
        else:
            table_data = [
                ["ID", "Timestamp", "User", "Channel", "Severity", "Risks"],
            ]
            from xml.sax.saxutils import escape
            for inc in incidents:
                table_data.append(
                    [
                        Paragraph(escape(inc.incident_id), normal_style),
                        Paragraph(escape(inc.timestamp[:19].replace("T", " ")), normal_style),
                        Paragraph(escape(inc.username or inc.user_id), normal_style),
                        Paragraph(escape(inc.channel_name or inc.channel_id), normal_style),
                        Paragraph(escape(inc.highest_severity), normal_style),
                        Paragraph(escape(str(inc.risk_count)), normal_style),
                    ]
                )

            col_widths = [3.5 * cm, 4 * cm, 3 * cm, 3 * cm, 2.2 * cm, 1.8 * cm]
            incident_table = Table(table_data, colWidths=col_widths, repeatRows=1)

            # Build row colours based on severity
            row_styles = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
            for row_idx, inc in enumerate(incidents, start=1):
                bg = sev_color.get(inc.highest_severity, colors.white)
                row_styles.append(
                    ("BACKGROUND", (4, row_idx), (4, row_idx), bg)
                )
                row_styles.append(
                    ("TEXTCOLOR", (4, row_idx), (4, row_idx), colors.white)
                )

            incident_table.setStyle(TableStyle(row_styles))
            story.append(incident_table)

        story.append(Spacer(1, 0.5 * cm))
        story.append(
            Paragraph(
                "⚠️  Confidential — For authorised personnel only. "
                "This report was generated automatically by Agent Zero.",
                ParagraphStyle(
                    "Footer",
                    parent=normal_style,
                    fontSize=7,
                    textColor=colors.grey,
                ),
            )
        )

        doc.build(story)
        logger.info("PDF report generated: %s", output_path)
        return output_path
