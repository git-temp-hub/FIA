"""
Batch harness: run the department's twenty questions and write one report.

This is the acceptance test for the question-answering work. It submits every
question in ``app.services.question_set`` to a running backend, checks each
answer against the properties the platform is supposed to guarantee, and
writes a single readable Markdown report.

What it checks, and why each check exists
-----------------------------------------
routing
    An answer drawn from the wrong evidence can still read well. Routing is
    verified first, offline, before any answer is judged.

citations
    An uncited claim is unsupported. Q9 is exempt: it is out of scope and is
    supposed to decline.

confidence ceiling
    Every stored ``confidence_score`` is the constant 100, so confidence used
    to be 100 on every answer. Nothing may report 100 now.

unsupported absence
    An answer may not assert that something is absent when the source that
    would show it never ran.

signature corroboration
    Every YARA match on D2F9 sits inside Defender's memory or is content-free.
    An answer to a signature question must carry the corroboration notice.

Usage
-----
    python scripts/run_question_set.py INV-XXXXXXXX-XXXXXX [--out report.md]

The backend must be running. Expect roughly two to four minutes per question.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.question_routing import match_route  # noqa: E402
from app.services.question_set import QUESTIONS  # noqa: E402

DEFAULT_URL = "http://127.0.0.1:8000/chat/query"
REQUEST_TIMEOUT = 900

# Phrases that assert an absence. Paired with the coverage model: asserting
# any of these about a source that never ran is the failure the routing work
# was built to prevent.
ABSENCE_PHRASES = (
    "no evidence of",
    "there is no",
    "was not found",
    "were not found",
    "did not occur",
)


def ask(url: str, investigation_id: str, question: str) -> dict:
    payload = json.dumps(
        {"investigation_id": investigation_id, "question": question}
    ).encode()

    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )

    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read())


def evaluate(entry, result: dict) -> list[str]:
    """Return the list of failed checks for one answer."""

    failures: list[str] = []

    answer = str(result.get("answer") or "")
    lowered = answer.lower()
    confidence = result.get("confidence")
    citations = result.get("citations") or []

    if confidence is None:
        failures.append("no confidence value")
    elif confidence >= 100:
        failures.append(f"confidence {confidence} (must be below 100)")

    if entry.qid == "Q9":
        # Out of scope: it must decline rather than assemble an answer.
        if "cannot" not in lowered and "out of scope" not in lowered:
            failures.append("out-of-scope question did not decline")
    elif not citations:
        failures.append("no citations")

    if entry.qid in ("Q11", "Q12", "Q13", "Q16", "Q18"):
        if "automated corroboration check" not in lowered:
            failures.append("signature answer missing corroboration notice")

    # An answer that asserts absence must not do so about an unsearched
    # source. Checked only for the sources this question actually maps to.
    route = match_route(entry.question)

    if route is not None and any(phrase in lowered for phrase in ABSENCE_PHRASES):
        for plugin in route.plugins:
            short = plugin.rsplit(".", 1)[-1]
            if f"no evidence of {short}" in lowered:
                failures.append(f"asserts absence via unsearched {plugin}")

    return failures


def render(
    investigation_id: str,
    rows: list[dict],
    started: datetime,
    elapsed: float,
) -> str:
    passed = sum(1 for row in rows if not row["failures"])

    lines = [
        "# Department question set — results",
        "",
        f"- **Investigation:** `{investigation_id}`",
        f"- **Run:** {started.strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Duration:** {elapsed / 60:.0f} min",
        f"- **Passed:** {passed}/{len(rows)}",
        "",
        "A pass means the question reached its intended route, cited "
        "evidence, reported a confidence below 100, made no unsupported "
        "absence claim, and — for signature questions — carried the "
        "corroboration notice. It does not mean a human has agreed with the "
        "finding.",
        "",
        "## Summary",
        "",
        "| Q | Routed | Conf | Cites | Time | Result |",
        "|---|---|---:|---:|---:|---|",
    ]

    for row in rows:
        status = "pass" if not row["failures"] else "**FAIL**"
        routed = row["routed"] if row["routed"] == row["expected"] else (
            f"**{row['routed']}** (want {row['expected']})"
        )
        lines.append(
            f"| {row['qid']} | {routed} | {row['confidence']} | "
            f"{row['citations']} | {row['seconds']:.0f}s | {status} |"
        )

    failing = [row for row in rows if row["failures"]]

    if failing:
        lines.extend(["", "## Failed checks", ""])
        for row in failing:
            lines.append(f"- **{row['qid']}**: " + "; ".join(row["failures"]))

    lines.extend(["", "## Answers", ""])

    for row in rows:
        lines.append(f"### {row['qid']} — {row['question']}")
        lines.append("")
        lines.append(
            f"*routed to {row['routed']}, confidence {row['confidence']}, "
            f"{row['citations']} citation(s), {row['seconds']:.0f}s*"
        )
        lines.append("")
        if row["failures"]:
            lines.append("> FAILED: " + "; ".join(row["failures"]))
            lines.append("")
        lines.append(row["answer"] or "_(no answer returned)_")
        lines.append("")
        if row["sources"]:
            lines.append("Cited evidence:")
            lines.append("")
            for source in row["sources"]:
                lines.append(f"- {source}")
            lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("investigation_id")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--out", default="")
    arguments = parser.parse_args()

    started = datetime.now(timezone.utc)
    began = time.time()
    rows: list[dict] = []

    for index, entry in enumerate(QUESTIONS, start=1):

        route = match_route(entry.question)
        routed = route.qid if route else "NONE"

        question_started = time.time()

        try:
            result = ask(arguments.url, arguments.investigation_id, entry.question)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            result = {"answer": "", "confidence": None, "citations": []}
            failures = [f"request failed: {exc}"]
        else:
            failures = evaluate(entry, result)

        if routed != entry.expected:
            failures.insert(0, f"routed to {routed}, expected {entry.expected}")

        seconds = time.time() - question_started

        rows.append(
            {
                "qid": entry.qid,
                "question": entry.question,
                "expected": entry.expected,
                "routed": routed,
                "answer": str(result.get("answer") or ""),
                "confidence": result.get("confidence"),
                "citations": len(result.get("citations") or []),
                # Citation fields are top level on the chat response, not
                # nested under "metadata"; reading them from there rendered
                # every source in the first report as "? id=?".
                "sources": [
                    f"[{item.get('index', '?')}] "
                    f"{item.get('plugin_name', '?')} "
                    f"id={item.get('evidence_id', '?')}"
                    for item in (result.get("citations") or [])
                ],
                "seconds": seconds,
                "failures": failures,
            }
        )

        print(
            f"{index:2}/{len(QUESTIONS)}  {entry.qid:4} "
            f"{'pass' if not failures else 'FAIL'}  "
            f"routed={routed:4} conf={result.get('confidence')} "
            f"cites={len(result.get('citations') or [])} ({seconds:.0f}s)",
            flush=True,
        )

    elapsed = time.time() - began

    report = render(arguments.investigation_id, rows, started, elapsed)

    destination = Path(
        arguments.out
        or Path(__file__).resolve().parents[1]
        / "storage"
        / "reports"
        / f"question_set_{arguments.investigation_id}_"
        f"{started.strftime('%Y%m%d_%H%M%S')}.md"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report, encoding="utf-8")

    failed = sum(1 for row in rows if row["failures"])

    print(f"\n{len(rows) - failed}/{len(rows)} passed in {elapsed / 60:.0f} min")
    print(f"report: {destination}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
