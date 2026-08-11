"""
Report Service for the AI Memory Forensic Investigation Assistant.

Generates a complete forensic investigation report as a PDF using
ReportLab and records report metadata inside the application database.

The report contains:

    A. Cover Page
    B. Investigation Summary
    C. Plugin Execution Summary
    D. Evidence Summary (grouped by artifact type)
    E. High Priority Findings
    F. AI Investigation Summary (from chat history)
    G. Conclusion

Author:
    FIA Development Team
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.database.repositories import (
    CaseRepository,
    ChatMessageRepository,
    MemoryDumpRepository,
    PluginExecutionRepository,
    PluginResultRepository,
)

logger = get_logger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

MALWARE_KEYWORDS = [
    "malware",
    "malfind",
    "yara",
    "trojan",
    "ransomware",
    "backdoor",
    "rootkit",
    "injected",
]

NETWORK_KEYWORDS = [
    "netscan",
    "netstat",
    "network",
    "connection",
    "socket",
    "listen",
    "connect",
    "remote",
]

SUSPICIOUS_KEYWORDS = [
    "suspicious",
    "suspect",
    "hidden",
    "unusual",
    "anomaly",
    "inject",
    "hollow",
    "unknown",
]

HIGH_CONFIDENCE_THRESHOLD = 90

PAGE_MARGIN = 2 * cm


# ==============================================================================
# Helpers
# ==============================================================================


def safe_text(value: Any) -> str:
    """
    Sanitize text for inclusion inside a ReportLab Paragraph.

    Escapes XML markup and replaces characters that cannot be encoded
    using the built-in WinAnsi font encoding.
    """

    text = str(value)

    text = (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    return text.encode("latin-1", "replace").decode("latin-1")


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds as a human-readable string.
    """

    if seconds <= 0:
        return "N/A"

    minutes = int(seconds // 60)
    remaining = int(round(seconds % 60))

    if minutes > 0:
        return f"{minutes}m {remaining}s"

    return f"{seconds:.1f}s"


def format_file_size(size_bytes: int) -> str:
    """
    Format a file size in bytes as a human-readable string.
    """

    value = float(size_bytes)

    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024

    return f"{size_bytes} B"


# ==============================================================================
# Report Service
# ==============================================================================


class ReportService:
    """
    Coordinates report data gathering, PDF generation, and metadata
    persistence.
    """

    def __init__(
        self,
        output_directory: Path | None = None,
    ) -> None:
        """
        Initialize the report service.

        Parameters
        ----------
        output_directory : Path | None
            Directory where generated PDFs are stored. Defaults to the
            configured reporting output directory.
        """

        self._output_directory = (
            output_directory
            if output_directory is not None
            else settings.reporting.output_directory
        )

        self._output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        logger.info(
            "Report Service initialized. Output: %s",
            self._output_directory,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def output_directory(self) -> Path:
        return self._output_directory

    # ------------------------------------------------------------------
    # Data Gathering
    # ------------------------------------------------------------------

    def gather_investigation_data(
        self,
        investigation_id: str,
        session: Session,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Collect every piece of data needed for a report.

        When ``session_id`` is provided, only chat messages belonging to
        that conversation session are included in the AI summary.

        Raises
        ------
        ValueError
            If the investigation does not exist.
        """

        memory_dump_repository = MemoryDumpRepository(session)
        case_repository = CaseRepository(session)
        plugin_execution_repository = PluginExecutionRepository(session)
        plugin_result_repository = PluginResultRepository(session)
        chat_message_repository = ChatMessageRepository(session)

        memory_dump = memory_dump_repository.get_by_investigation_id(
            investigation_id
        )

        if memory_dump is None:
            raise ValueError(
                f"Investigation not found: {investigation_id}"
            )

        case = (
            case_repository.get_by_id(memory_dump.case_id)
            if memory_dump.case_id
            else None
        )

        executions = plugin_execution_repository.get_by_memory_dump(
            memory_dump.id
        )

        evidence = plugin_result_repository.get_by_investigation(
            investigation_id
        )

        chat_messages = chat_message_repository.get_by_investigation(
            investigation_id,
            session_id=session_id,
        )

        successful = [
            execution
            for execution in executions
            if execution.execution_status == "completed"
        ]

        failed = [
            execution
            for execution in executions
            if execution.execution_status == "failed"
        ]

        duration = self._compute_duration(executions)

        return {
            "investigation_id": investigation_id,
            "case_name": (
                case.case_name
                if case is not None
                else investigation_id
            ),
            "investigation_status": memory_dump.status,
            "dump_filename": memory_dump.filename,
            "sha256_hash": memory_dump.sha256_hash,
            "dump_size": memory_dump.file_size,
            "generated_at": datetime.now(),
            "executions": executions,
            "evidence": evidence,
            "chat_messages": chat_messages,
            "total_plugins": len(executions),
            "successful_plugins": len(successful),
            "failed_plugins": len(failed),
            "total_evidence": len(evidence),
            "investigation_duration": duration,
        }

    @staticmethod
    def _compute_duration(
        executions: list,
    ) -> float:
        """
        Compute the investigation duration from plugin execution times.
        """

        timestamps = [
            execution.executed_at
            for execution in executions
            if execution.executed_at is not None
        ]

        if len(timestamps) < 2:
            return 0.0

        delta = max(timestamps) - min(timestamps)

        return max(0.0, delta.total_seconds())

    # ------------------------------------------------------------------
    # Report Generation
    # ------------------------------------------------------------------

    def generate(
        self,
        investigation_id: str,
        session: Session,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate a complete investigation report.

        Workflow
        --------
        1. Gather investigation data.
        2. Build the PDF document.
        3. Store the file in the reports directory.
        4. Return metadata for persistence.

        Raises
        ------
        ValueError
            If the investigation does not exist.
        """

        data = self.gather_investigation_data(
            investigation_id,
            session,
            session_id=session_id,
        )

        data["statistics"] = {
            "investigation_status": data["investigation_status"],
            "total_plugins": data["total_plugins"],
            "successful_plugins": data["successful_plugins"],
            "failed_plugins": data["failed_plugins"],
            "total_evidence": data["total_evidence"],
            "investigation_duration": data["investigation_duration"],
        }

        filename = (
            f"report_{investigation_id}_{data['generated_at']:%Y%m%d_%H%M%S}.pdf"
        )

        output_path = self._output_directory / filename

        self._build_pdf(
            data=data,
            output_path=output_path,
        )

        file_size = output_path.stat().st_size

        logger.info(
            "Report generated for investigation '%s': %s",
            investigation_id,
            output_path,
        )

        return {
            "investigation_id": investigation_id,
            "case_name": data["case_name"],
            "dump_filename": data["dump_filename"],
            "sha256_hash": data["sha256_hash"],
            "filename": filename,
            "file_path": str(output_path),
            "file_size": file_size,
            "generated_at": data["generated_at"],
            "statistics": data["statistics"],
        }

    # ------------------------------------------------------------------
    # PDF Construction
    # ------------------------------------------------------------------

    def _build_pdf(
        self,
        data: dict[str, Any],
        output_path: Path,
    ) -> None:
        """
        Compose the ReportLab document and write the PDF file.
        """

        document = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=PAGE_MARGIN,
            rightMargin=PAGE_MARGIN,
            topMargin=PAGE_MARGIN,
            bottomMargin=PAGE_MARGIN,
            title=f"Investigation Report {data['investigation_id']}",
            author="AI Memory Forensic Investigation Assistant",
            subject=f"Forensic report for {data['investigation_id']}",
        )

        story: list = []

        self._section_cover(data, story)
        story.append(PageBreak())

        self._section_investigation_summary(data, story)
        story.append(PageBreak())

        self._section_plugin_summary(data, story)
        story.append(PageBreak())

        self._section_evidence_summary(data, story)
        story.append(PageBreak())

        self._section_high_priority_findings(data, story)
        story.append(PageBreak())

        self._section_ai_summary(data, story)
        story.append(PageBreak())

        self._section_conclusion(data, story)

        document.build(
            story,
            onFirstPage=self._draw_footer,
            onLaterPages=self._draw_footer,
        )

    # ==================================================================
    # Section Builders
    # ==================================================================

    def _section_cover(
        self,
        data: dict[str, Any],
        story: list,
    ) -> None:
        """
        Build the cover page (Section A).
        """

        story.append(Spacer(1, 3.5 * cm))

        story.append(Paragraph(
            safe_text(
                settings.application.name
            ),
            self._style_cover_title,
        ))

        story.append(Spacer(1, 1.2 * cm))

        story.append(Paragraph(
            "INVESTIGATION REPORT",
            self._style_cover_subtitle,
        ))

        story.append(Spacer(1, 2.5 * cm))

        cover_rows = [
            ["Investigation ID", data["investigation_id"]],
            ["Case Name", data["case_name"]],
            [
                "Generated",
                f"{data['generated_at']:%Y-%m-%d %H:%M:%S}",
            ],
            ["Memory Dump Filename", data["dump_filename"]],
            ["SHA-256", data["sha256_hash"] or "N/A"],
            ["Dump Size", format_file_size(data["dump_size"])],
        ]

        cover_table = Table(
            cover_rows,
            colWidths=[5 * cm, 9 * cm],
        )

        cover_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0F172A")),
            ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#F1F5F9")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0F172A")),
        ]))

        story.append(cover_table)

    def _section_investigation_summary(
        self,
        data: dict[str, Any],
        story: list,
    ) -> None:
        """
        Build the investigation summary (Section B).
        """

        story.append(Paragraph(
            "Investigation Summary",
            self._style_heading,
        ))

        story.append(Spacer(1, 0.4 * cm))

        stats = data["statistics"]

        rows = [
            ["Investigation Status", stats["investigation_status"]],
            ["Total Plugins Executed", stats["total_plugins"]],
            ["Successful Plugins", stats["successful_plugins"]],
            ["Failed Plugins", stats["failed_plugins"]],
            ["Total Evidence", stats["total_evidence"]],
            [
                "Investigation Duration",
                format_duration(stats["investigation_duration"]),
            ],
        ]

        story.append(self._key_value_table(rows))

        story.append(Spacer(1, 0.6 * cm))

        story.append(Paragraph(
            (
                "This report summarizes the forensic analysis performed on "
                "the memory dump for investigation "
                f"{data['investigation_id']}. Plugin execution results, "
                "parsed evidence, high-priority findings, and AI-assisted "
                "question answering are documented in the sections below."
            ),
            self._style_body,
        ))

    def _section_plugin_summary(
        self,
        data: dict[str, Any],
        story: list,
    ) -> None:
        """
        Build the plugin execution summary table (Section C).
        """

        story.append(Paragraph(
            "Plugin Execution Summary",
            self._style_heading,
        ))

        story.append(Spacer(1, 0.4 * cm))

        executions = data["executions"]

        if not executions:

            story.append(Paragraph(
                "No plugin executions were recorded for this investigation.",
                self._style_body,
            ))

            return

        rows = [
            ["#", "Plugin", "Status", "Execution Time"],
        ]

        for index, execution in enumerate(executions, start=1):

            execution_time = (
                f"{execution.execution_time:.2f}s"
                if execution.execution_time is not None
                else "N/A"
            )

            rows.append([
                str(index),
                safe_text(execution.plugin_name),
                safe_text(execution.execution_status),
                execution_time,
            ])

        table = Table(
            rows,
            colWidths=[1.2 * cm, 6 * cm, 3.4 * cm, 3.4 * cm],
            repeatRows=1,
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#0F172A")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#F8FAFC"),
            ]),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (3, 0), (3, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0F172A")),
        ]))

        story.append(table)

        failed_count = data["statistics"]["failed_plugins"]

        if failed_count:
            story.append(Spacer(1, 0.4 * cm))
            story.append(Paragraph(
                (
                    f"{failed_count} plugin(s) failed to execute. "
                    "See the application logs for details."
                ),
                self._style_note,
            ))

    def _section_evidence_summary(
        self,
        data: dict[str, Any],
        story: list,
    ) -> None:
        """
        Build the evidence summary grouped by artifact type (Section D).
        """

        story.append(Paragraph(
            "Evidence Summary",
            self._style_heading,
        ))

        story.append(Spacer(1, 0.4 * cm))

        evidence = data["evidence"]

        if not evidence:

            story.append(Paragraph(
                "No evidence was collected for this investigation.",
                self._style_body,
            ))

            return

        grouped: dict[str, list] = {}

        for item in evidence:

            grouped.setdefault(item.artifact_type, []).append(item)

        story.append(Paragraph(
            "Evidence grouped by artifact type:",
            self._style_subheading,
        ))

        story.append(Spacer(1, 0.3 * cm))

        rows = [
            ["Artifact Type", "Count", "Confidence"],
        ]

        for artifact_type in sorted(grouped.keys()):

            items = grouped[artifact_type]

            average_confidence = int(round(
                sum(
                    item.confidence_score
                    for item in items
                ) / len(items)
            ))

            rows.append([
                safe_text(artifact_type),
                str(len(items)),
                f"{average_confidence}%",
            ])

        table = Table(
            rows,
            colWidths=[7 * cm, 3 * cm, 4 * cm],
            repeatRows=1,
        )

        table.setStyle(self._base_table_style)

        story.append(table)

        story.append(Spacer(1, 0.6 * cm))

        story.append(Paragraph(
            "Artifact breakdown:",
            self._style_subheading,
        ))

        story.append(Spacer(1, 0.3 * cm))

        for artifact_type in sorted(grouped.keys()):

            items = grouped[artifact_type]

            story.append(Paragraph(
                safe_text(artifact_type),
                self._style_list_title,
            ))

            for item in items[:30]:

                value = safe_text(item.artifact_value)

                if len(value) > 220:
                    value = value[:220] + "..."

                story.append(Paragraph(
                    f"{safe_text(item.artifact_name)} "
                    f"(confidence {item.confidence_score}%): {value}",
                    self._style_list_item,
                ))

            if len(items) > 30:
                story.append(Paragraph(
                    f"... and {len(items) - 30} more.",
                    self._style_note,
                ))

    def _section_high_priority_findings(
        self,
        data: dict[str, Any],
        story: list,
    ) -> None:
        """
        Build the high priority findings section (Section E).
        """

        story.append(Paragraph(
            "High Priority Findings",
            self._style_heading,
        ))

        story.append(Spacer(1, 0.4 * cm))

        findings = self._high_priority_findings(data["evidence"])

        if not findings:

            story.append(Paragraph(
                (
                    "No high-priority findings were identified. Evidence "
                    "confidence was below the review threshold."
                ),
                self._style_body,
            ))

            return

        categories = [
            ("High Confidence Evidence", "high_confidence"),
            ("Malware Findings", "malware"),
            ("Network Findings", "network"),
            ("Suspicious Artifacts", "suspicious"),
        ]

        for title, key in categories:

            items = findings.get(key, [])

            story.append(Paragraph(
                title,
                self._style_subheading,
            ))

            if not items:

                story.append(Paragraph(
                    "None identified.",
                    self._style_note,
                ))

                story.append(Spacer(1, 0.2 * cm))

                continue

            rows = [
                ["Plugin", "Artifact", "Confidence", "Value"],
            ]

            for item in items[:20]:

                value = safe_text(item["value"])

                if len(value) > 120:
                    value = value[:120] + "..."

                rows.append([
                    safe_text(item["plugin"]),
                    safe_text(item["artifact"]),
                    f"{item['confidence']}%",
                    value,
                ])

            table = Table(
                rows,
                colWidths=[3.4 * cm, 3.2 * cm, 1.9 * cm, 5.5 * cm],
                repeatRows=1,
            )

            table.setStyle(self._base_table_style)

            story.append(table)

            story.append(Spacer(1, 0.4 * cm))

    def _section_ai_summary(
        self,
        data: dict[str, Any],
        story: list,
    ) -> None:
        """
        Build the AI investigation summary from chat history (Section F).
        """

        story.append(Paragraph(
            "AI Investigation Summary",
            self._style_heading,
        ))

        story.append(Spacer(1, 0.4 * cm))

        messages = data["chat_messages"]

        if not messages:

            story.append(Paragraph(
                (
                    "No AI conversations were recorded for this "
                    "investigation. Use the AI Investigation assistant "
                    "to ask questions about the evidence."
                ),
                self._style_body,
            ))

            return

        exchanges = self._build_exchanges(messages)

        story.append(Paragraph(
            (
                "The investigator asked the AI assistant questions about "
                "the evidence. Each answer is grounded in retrieved "
                "forensic evidence and cites the supporting records."
            ),
            self._style_body,
        ))

        story.append(Spacer(1, 0.3 * cm))

        for index, exchange in enumerate(exchanges, start=1):

            story.append(Paragraph(
                f"Q{index}. {safe_text(exchange['question'])}",
                self._style_question,
            ))

            story.append(Spacer(1, 0.15 * cm))

            story.append(Paragraph(
                f"Answer: {safe_text(exchange['answer'])}",
                self._style_answer,
            ))

            if exchange["citations"]:

                story.append(Paragraph(
                    "Evidence citations:",
                    self._style_note_bold,
                ))

                for citation in exchange["citations"]:

                    citation_text = (
                        f"{safe_text(citation['plugin_name'] or 'unknown')} "
                        f"[confidence {citation['confidence_score']}%]"
                    )

                    story.append(Paragraph(
                        f"  - {citation_text}",
                        self._style_list_item,
                    ))

            story.append(Spacer(1, 0.4 * cm))

    def _section_conclusion(
        self,
        data: dict[str, Any],
        story: list,
    ) -> None:
        """
        Build the conclusion section (Section G).
        """

        story.append(Paragraph(
            "Conclusion",
            self._style_heading,
        ))

        story.append(Spacer(1, 0.4 * cm))

        stats = data["statistics"]

        findings = self._high_priority_findings(data["evidence"])

        finding_count = sum(
            len(items)
            for items in findings.values()
        )

        story.append(Paragraph(
            (
                f"The investigation of memory dump "
                f"{safe_text(data['dump_filename'])} "
                f"(investigation {data['investigation_id']}) executed "
                f"{stats['total_plugins']} Volatility plugin(s) "
                f"({stats['successful_plugins']} successful, "
                f"{stats['failed_plugins']} failed) and produced "
                f"{stats['total_evidence']} evidence record(s)."
            ),
            self._style_body,
        ))

        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph(
            (
                f"The analysis identified {finding_count} high-priority "
                "finding(s) including high-confidence evidence, malware "
                "indicators, network activity, and suspicious artifacts. "
                "These findings should be reviewed manually by a forensic "
                "analyst before reaching a final conclusion."
            ),
            self._style_body,
        ))

        story.append(Spacer(1, 0.3 * cm))

        ai_exchanges = self._build_exchanges(data["chat_messages"])

        story.append(Paragraph(
            (
                f"The AI investigation assistant answered {len(ai_exchanges)} "
                "question(s) during this investigation. Where evidence was "
                "insufficient, the assistant explicitly stated that the "
                "answer could not be determined from the available evidence."
            ),
            self._style_body,
        ))

        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph(
            (
                "It is recommended to treat the findings in this report as "
                "indicative rather than conclusive. Corroborate each "
                "finding with additional analysis tools and preserve the "
                "original memory dump for chain of custody."
            ),
            self._style_body,
        ))

        story.append(Spacer(1, 0.6 * cm))

        story.append(Paragraph(
            (
                f"Report generated by the AI Memory Forensic Investigation "
                f"Assistant on {data['generated_at']:%Y-%m-%d %H:%M:%S}."
            ),
            self._style_note,
        ))

    # ------------------------------------------------------------------
    # Supporting Helpers
    # ------------------------------------------------------------------

    def _high_priority_findings(
        self,
        evidence: list,
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Categorize evidence into high priority finding groups.
        """

        groups: dict[str, list[dict[str, Any]]] = {
            "high_confidence": [],
            "malware": [],
            "network": [],
            "suspicious": [],
        }

        seen: set[int] = set()

        for item in evidence:

            if item.id in seen:
                continue

            seen.add(item.id)

            plugin = (
                item.plugin_execution.plugin_name
                if item.plugin_execution is not None
                else item.artifact_name
            )

            haystack = " ".join([
                plugin or "",
                item.artifact_type,
                item.artifact_name,
                item.artifact_value,
            ]).lower()

            record = {
                "plugin": plugin or "unknown",
                "artifact": item.artifact_name,
                "value": item.artifact_value,
                "confidence": item.confidence_score,
            }

            if item.confidence_score >= HIGH_CONFIDENCE_THRESHOLD:
                groups["high_confidence"].append(record)

            if any(keyword in haystack for keyword in MALWARE_KEYWORDS):
                groups["malware"].append(record)

            if any(keyword in haystack for keyword in NETWORK_KEYWORDS):
                groups["network"].append(record)

            if any(keyword in haystack for keyword in SUSPICIOUS_KEYWORDS):
                groups["suspicious"].append(record)

        return groups

    @staticmethod
    def _build_exchanges(
        messages: list,
    ) -> list[dict[str, Any]]:
        """
        Pair user questions with assistant answers from chat history.
        """

        exchanges: list[dict[str, Any]] = []

        pending_question: str | None = None

        for message in messages:

            if message.role == "user":

                pending_question = message.content

            elif message.role == "assistant" and pending_question is not None:

                citations = []

                if message.citations:
                    try:
                        import json

                        citations = json.loads(message.citations)
                    except json.JSONDecodeError:
                        citations = []

                exchanges.append({
                    "question": pending_question,
                    "answer": message.content,
                    "citations": citations,
                })

                pending_question = None

        return exchanges

    @staticmethod
    def _key_value_table(
        rows: list[list[str]],
    ) -> Table:
        """
        Build a simple two-column key-value table.
        """

        table = Table(
            rows,
            colWidths=[7 * cm, 7 * cm],
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0F172A")),
        ]))

        return table

    @property
    def _base_table_style(self) -> TableStyle:
        """
        Shared styling for data tables.
        """

        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#0F172A")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#F8FAFC"),
            ]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0F172A")),
        ])

    # ------------------------------------------------------------------
    # Page Decorations
    # ------------------------------------------------------------------

    def _draw_footer(
        self,
        canvas,
        document,
    ) -> None:
        """
        Draw the report footer with page numbers.
        """

        canvas.saveState()

        canvas.setFont("Helvetica", 8)

        canvas.setFillColor(colors.HexColor("#64748B"))

        canvas.drawCentredString(
            A4[0] / 2,
            1 * cm,
            (
                f"Page {document.page}  ·  "
                "AI Memory Forensic Investigation Assistant"
            ),
        )

        canvas.restoreState()

    # ------------------------------------------------------------------
    # Styles
    # ------------------------------------------------------------------

    @property
    def _style_cover_title(self) -> ParagraphStyle:
        return ParagraphStyle(
            "CoverTitle",
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0F172A"),
        )

    @property
    def _style_cover_subtitle(self) -> ParagraphStyle:
        return ParagraphStyle(
            "CoverSubtitle",
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0891B2"),
        )

    @property
    def _style_heading(self) -> ParagraphStyle:
        return ParagraphStyle(
            "Heading",
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            spaceAfter=6,
            textColor=colors.HexColor("#0F172A"),
        )

    @property
    def _style_subheading(self) -> ParagraphStyle:
        return ParagraphStyle(
            "SubHeading",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            spaceBefore=10,
            spaceAfter=6,
            textColor=colors.HexColor("#0E7490"),
        )

    @property
    def _style_body(self) -> ParagraphStyle:
        return ParagraphStyle(
            "Body",
            fontName="Helvetica",
            fontSize=10,
            leading=15,
            textColor=colors.HexColor("#1E293B"),
        )

    @property
    def _style_note(self) -> ParagraphStyle:
        return ParagraphStyle(
            "Note",
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#64748B"),
        )

    @property
    def _style_note_bold(self) -> ParagraphStyle:
        return ParagraphStyle(
            "NoteBold",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#64748B"),
            spaceBefore=4,
        )

    @property
    def _style_list_title(self) -> ParagraphStyle:
        return ParagraphStyle(
            "ListTitle",
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            spaceBefore=8,
            textColor=colors.HexColor("#0F172A"),
        )

    @property
    def _style_list_item(self) -> ParagraphStyle:
        return ParagraphStyle(
            "ListItem",
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            leftIndent=8,
            textColor=colors.HexColor("#334155"),
        )

    @property
    def _style_question(self) -> ParagraphStyle:
        return ParagraphStyle(
            "Question",
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            spaceBefore=6,
            textColor=colors.HexColor("#0E7490"),
        )

    @property
    def _style_answer(self) -> ParagraphStyle:
        return ParagraphStyle(
            "Answer",
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#1E293B"),
        )


# ==============================================================================
# Singleton Instance
# ==============================================================================

report_service = ReportService()


# ==============================================================================
# Public Exports
# ==============================================================================

__all__ = [
    "ReportService",
    "report_service",
    "safe_text",
    "format_duration",
    "format_file_size",
]
