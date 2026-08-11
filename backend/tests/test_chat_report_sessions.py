"""
Report regression tests for conversation session isolation.

Requirements covered:
    G  A report for Session 1 contains only Session 1 Q&A.
    H  A report for Session 2 contains only Session 2 Q&A.
    I  Evidence/artifact sections in reports remain unchanged.
    14 The report's AI summary is scoped to the current session.
    15 Report generation does not include every message in the
       investigation when a session is active.
"""

import base64
import re
import zlib
from datetime import datetime
from pathlib import Path

from app.database.repositories import ChatMessageRepository
from app.models.chat_message import ChatMessage
from app.models.plugin_execution import PluginExecution
from app.models.plugin_result import PluginResult
from app.services.report_service import ReportService


def _decode_stream(raw: bytes) -> bytes:
    content = raw

    try:
        candidate = raw

        if candidate.endswith(b"~>"):
            candidate = candidate[:-2]

        content = base64.a85decode(candidate)
    except Exception:
        pass

    try:
        content = zlib.decompress(content)
    except Exception:
        pass

    return content


def _extract_pdf_text(pdf_path: Path) -> str:
    """Extract human-readable text from a ReportLab PDF."""

    data = pdf_path.read_bytes()

    parts: list[str] = []

    for match in re.finditer(rb"stream\r?\n", data):
        start = match.end()

        end = data.find(b"endstream", start)

        if end == -1:
            continue

        raw = data[start:end].strip(b"\r\n")

        content = _decode_stream(raw)

        for token in re.finditer(rb"\((?:[^()\\]|\\.)*\)\s*Tj", content):
            text_match = re.match(
                rb"\((.*)\)\s*Tj",
                token.group(0),
                re.S,
            )

            text = text_match.group(1)

            text = (
                text
                .replace(b"\\(", b"(")
                .replace(b"\\)", b")")
                .replace(b"\\\\", b"\\")
            )

            parts.append(text.decode("latin-1", "replace"))

    return " ".join(parts)


def _seed_report_data(session, seed_investigation):
    case, dump = seed_investigation("INV-A", "dump.raw")

    execution = PluginExecution(
        memory_dump_id=dump.id,
        plugin_name="windows.pslist",
        execution_status="completed",
        execution_time=1.5,
    )

    session.add(execution)
    session.flush()

    result = PluginResult(
        plugin_execution_id=execution.id,
        artifact_type="process",
        artifact_name="malware.exe",
        artifact_value="PID 5555 - suspicious",
        confidence_score=95,
    )

    session.add(result)

    repository = ChatMessageRepository(session)

    repository.create(
        ChatMessage(
            investigation_id="INV-A",
            session_id="s1",
            role="user",
            content="S1 question",
        )
    )
    repository.create(
        ChatMessage(
            investigation_id="INV-A",
            session_id="s1",
            role="assistant",
            content="S1 answer",
        )
    )
    repository.create(
        ChatMessage(
            investigation_id="INV-A",
            session_id="s2",
            role="user",
            content="S2 question",
        )
    )
    repository.create(
        ChatMessage(
            investigation_id="INV-A",
            session_id="s2",
            role="assistant",
            content="S2 answer",
        )
    )

    session.commit()

    return {"case": case, "dump": dump}


def _make_service(output_directory: Path) -> ReportService:
    return ReportService(output_directory=output_directory)


# ----------------------------------------------------------------------
# Data gathering scoping
# ----------------------------------------------------------------------


def test_gather_chat_messages_scoped_by_session(session, seed_investigation, tmp_path):
    _seed_report_data(session, seed_investigation)

    service = _make_service(tmp_path)

    session1 = service.gather_investigation_data(
        "INV-A",
        session,
        session_id="s1",
    )
    session2 = service.gather_investigation_data(
        "INV-A",
        session,
        session_id="s2",
    )
    unscoped = service.gather_investigation_data("INV-A", session)

    assert [
        message.content
        for message in session1["chat_messages"]
    ] == ["S1 question", "S1 answer"]

    assert [
        message.content
        for message in session2["chat_messages"]
    ] == ["S2 question", "S2 answer"]

    assert len(unscoped["chat_messages"]) == 4


# ----------------------------------------------------------------------
# PDF report scoping
# ----------------------------------------------------------------------


def test_report_for_session1_contains_only_session1(
    session,
    seed_investigation,
    tmp_path,
):
    _seed_report_data(session, seed_investigation)

    service = _make_service(tmp_path)

    generated = service.generate(
        "INV-A",
        session,
        session_id="s1",
    )

    pdf_text = _extract_pdf_text(Path(generated["file_path"]))

    assert "S1 question" in pdf_text
    assert "S1 answer" in pdf_text
    assert "S2 question" not in pdf_text
    assert "S2 answer" not in pdf_text

    # Evidence sections must remain unchanged (requirement I).
    assert "Evidence Summary" in pdf_text
    assert "malware.exe" in pdf_text


def test_report_for_session2_contains_only_session2(
    session,
    seed_investigation,
    tmp_path,
):
    _seed_report_data(session, seed_investigation)

    service = _make_service(tmp_path)

    generated = service.generate(
        "INV-A",
        session,
        session_id="s2",
    )

    pdf_text = _extract_pdf_text(Path(generated["file_path"]))

    assert "S2 question" in pdf_text
    assert "S2 answer" in pdf_text
    assert "S1 question" not in pdf_text
    assert "S1 answer" not in pdf_text

    assert "Evidence Summary" in pdf_text
    assert "malware.exe" in pdf_text


# ----------------------------------------------------------------------
# Reports API route pass-through
# ----------------------------------------------------------------------


def _fake_generate_result(tmp_path: Path) -> dict:
    return {
        "investigation_id": "INV-A",
        "case_name": "INV-A",
        "dump_filename": "dump.raw",
        "sha256_hash": None,
        "filename": "report.pdf",
        "file_path": str(tmp_path / "report.pdf"),
        "file_size": 0,
        "generated_at": datetime.now(),
        "statistics": {},
    }


def test_reports_route_passes_session_id(
    client,
    seed_investigation,
    monkeypatch,
    tmp_path,
):
    seed_investigation("INV-A")

    captured: dict = {}

    class _FakeReportService:
        def generate(self, investigation_id, db, session_id=None):
            captured["session_id"] = session_id

            return _fake_generate_result(tmp_path)

    monkeypatch.setattr(
        "app.api.routes.reports.report_service",
        _FakeReportService(),
    )

    response = client.post(
        "/reports/generate/INV-A",
        params={"session_id": "s1"},
    )

    assert response.status_code == 200
    assert captured["session_id"] == "s1"


def test_reports_route_without_session_id_stays_compatible(
    client,
    seed_investigation,
    monkeypatch,
    tmp_path,
):
    seed_investigation("INV-A")

    captured: dict = {}

    class _FakeReportService:
        def generate(self, investigation_id, db, session_id=None):
            captured["session_id"] = session_id

            return _fake_generate_result(tmp_path)

    monkeypatch.setattr(
        "app.api.routes.reports.report_service",
        _FakeReportService(),
    )

    response = client.post("/reports/generate/INV-A")

    assert response.status_code == 200
    assert captured["session_id"] is None
