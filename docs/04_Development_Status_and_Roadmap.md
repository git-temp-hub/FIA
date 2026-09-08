# Development Status & Roadmap

**FIA (Anveshak) — What Works, What's Next, and Why the Order Matters**

| | | | |
|---|---|---|---|
| **Document Code** | FIA-STA-04 | **Version** | 3.0 |
| **Status** | Active | **Date** | September 2026 |
| **Prepared By** | Project Intern | **Reviewed By** | Project Mentor |

> Updated whenever a status actually changes, and reviewed weekly — not on a fixed schedule.

---

## 1. Purpose

This document is the single place to check what actually works today, what is broken, and what happens next. It is meant to be read often and kept short — status belongs here, not scattered across the other reference documents.

## 2. Current Build Status

| Component | Status |
|---|---|
| Upload handling (streamed, 64 GB cap, extension check) | ✅ Done |
| Volatility 3 execution engine | ✅ Done |
| Plugin output parser | ✅ Done |
| Data normalizer (unified schema) | ✅ Done |
| SQLite evidence store (authoritative) | ✅ Done |
| ChromaDB vector index | ✅ Done |
| Evidence classifier / correlator | ✅ Done |
| Retrieval engine (with SQLite fallback) | ✅ Done |
| Prompt builder + system prompt | ✅ Done |
| Ollama LLM integration (qwen3:14b) | ✅ Done |
| Chat UI ↔ backend wiring | ✅ Done — verified against real DB rows (citations, confidence scoring, history persistence all confirmed) |
| Chat verified against real Volatility-derived evidence | ✅ Done — 20/20 department questions answered against `INV-20260902-C3D2F9` (66 GB dump, 326,506 evidence rows) |
| Deterministic question routing + evidence coverage model | ✅ Done |
| Confidence calibration | ✅ Done |
| YARA rule set and signature corroboration | ✅ Done |
| Known-tool signature matching | ✅ Done |
| Exact-match IOC correlation | ✅ Done |
| Integrated assessment (corpus overview + timeline) | ✅ Done |
| Batch harness for the 20-question set | ✅ Done — `backend/scripts/run_question_set.py` |
| PDF report generation | 🔶 In Progress |
| API versioning (/api/v1) | ⬜ Not Started |
| Verified end-to-end run on a real memory dump | ✅ Done — 66 GB dump, 22 plugins, 326,506 rows |
| Large-dump performance benchmarking | 🔶 Partial — real figures recorded; see Known Issues |
| Configurable plugin timeouts | ✅ Done — `analysis.plugin_timeout_seconds` |
| Remove unused LangChain dependency | ⬜ Not Started |
| Stop tracking database files in version control | ⬜ Not Started |
| Multi-user authentication / access control | ⬜ Not Started |

> The evidence classifier / correlator was originally scoped for a later phase and is already implemented — ahead of plan. Multi-user authentication is intentionally out of scope for this phase, not a gap.

## 2.1 Question-Answering Programme (Phases 1–9)

All nine phases are complete. Each was verified against `INV-20260902-C3D2F9` — a real 66 GB Windows memory dump, 22 plugins, 326,506 evidence rows — not against synthetic data.

| Phase | Work | Status |
|---|---|---|
| 1 | GPU acceleration (CUDA torch, GPU embedding) | ✅ Complete |
| 2 | Context window and structured answer format (FINDING / EVIDENCE / ASSESSMENT / GAPS) | ✅ Complete |
| 3 | YARA rule sourcing from public repositories, with provenance | ✅ Complete |
| 4 | Combined re-run of all dump-requiring work (22 plugins) | ✅ Complete |
| 5 | Deterministic question routing with the three-state coverage model | ✅ Complete |
| 6 | Known-tool signature matching (41 tools) | ✅ Complete |
| 7 | Exact-match IOC correlation; refused attribution without indicators | ✅ Complete |
| 8 | Integrated assessment: corpus overview, timeline, severity qualification | ✅ Complete |
| 9 | Batch harness over all 20 questions | ✅ Complete |

**Acceptance result:** 20/20 questions route correctly, cite evidence, and report calibrated confidence. Reports are written to `backend/storage/reports/question_set_*.md`.

A recurring lesson runs through Phases 5–9 and is worth keeping: **instructions in the prompt did not hold, and enforcement in code did.** Three separate times — YARA matches inside Defender's memory, malfind regions reported as injection, and database identifiers cited as citation numbers — the model read past explicit guidance. Each was fixed by changing what the model receives or by capping the result in code, never by rewording. New work in this area should assume the same.

### Open items

Two of the twenty questions remain open. Neither is a code defect.

| Item | Status | What it needs |
|---|---|---|
| **Q12 — APT28 attribution** | Mechanically complete, deliberately unanswered | A real indicator list from the department. The platform ships none and invents none: `backend/rules/iocs/` is empty by design, with a test asserting it stays empty. Q12 currently states that attribution cannot be performed and names the missing set as the gap. Drop a JSON file into that directory (format in its README) and it loads at answer time, no restart. |
| **Q9 — browser / M365 artifacts** | Out of scope by decision | Nothing. This requires disk and browser forensics (profile databases, cookie stores, token caches), which this platform does not collect. Q9 is routed to a declared out-of-scope route and correctly declines rather than assembling an answer from unrelated artifacts. This is the intended behaviour, not a gap to close. |

The wording of the twenty questions in `app/services/question_set.py` is derived from the department's question-to-plugin mapping, not copied from their document. Routing is keyword-driven, so a rephrasing that drops a keyword changes which evidence is searched — replace the wording with the department's exact text when it is available.

## 3. Known Issues

| Issue | Detail |
|---|---|
| Volatility CLI resolution | `vol.exe` is only discoverable on PATH when the backend's virtual environment is activated. Starting the server via the venv's interpreter directly, without activating first, silently breaks plugin execution. |
| Evidence database tracked in version control | The live SQLite and ChromaDB files currently contain real evidence data and are committed to the repository — risk of repo bloat and accidental sensitive-data commits. |
| Partial real-world performance data | Real figures now exist for `INV-20260902-C3D2F9` (66 GB): `malfind` completed in 2,352 s against a previous 1,800 s timeout, GPU indexing ran at roughly 30–38k rows/min against roughly 3.5k on CPU, and the 20-question set takes about 38 minutes end to end at 84–207 s per question. These are single-run measurements on one machine, not a benchmark suite, and figures in the planning documents remain design targets unless a measurement is cited beside them. |
| Answer latency degrades over a long batch run | Individual questions take 85–250 s. Across a full 20-question batch the later ones slow markedly on the same machine: Q20 took 207 s in one run and 693 s in the next, exceeding the then-current 600 s `LLM_TIMEOUT` and failing the batch, yet completed in 248 s when run alone immediately afterwards. The cause is host load accumulated over the run, not the question — the same effect that made the classifier timing test fail only inside the full suite. `LLM_TIMEOUT` is now 1200 s to give the tail of a batch headroom. Anything running the full set on a busy machine should expect the same degradation and size the timeout accordingly. |
| Evidence classification is quadratic in corpus size | Measured with corpus shape held constant: per-record classification cost is **0.47 / 0.97 / 1.99 ms at 5k / 10k / 20k rows** — cost per record doubles as the corpus doubles, so total cost grows with the square of the row count. Isolated to the per-record classify path: index construction is flat (~0.009 ms/record), and correlation-group size has no effect at constant total size (0.03 ms/record whether 16,000 rows share one PID or spread across 160). The earlier indexing work removed a large constant factor (~0.16 s/record before it) but not the quadratic term. The 20 ms/record ceiling asserted by `test_large_corpus_classification_cost_per_record_is_bounded` holds to roughly **200k rows**; `INV-20260902-C3D2F9` has **326,506 rows**, which is past that and is the likely explanation for observed classification slowness on real dumps. Found while converting that test from a wall-clock deadline to a rate assertion; not yet investigated or fixed. |

## 4. Immediate Priorities, In Order

> **The gating milestone in Step 1 has been met.** `INV-20260902-C3D2F9` — a 66 GB Windows dump — was carried through upload, plugin execution, parsing, normalization, storage, indexing and retrieval to cited chat answers, and the full 20-question set now runs against it. Steps 1 and 2 are complete; the original wording is kept below so the ordering and its reasoning remain legible.

1. ✅ **Run one real Windows memory dump through the complete pipeline**: upload, plugin execution, parsing, normalization, storage, retrieval, and a chat query against the resulting evidence. *This was the gating milestone; nothing after it was to start until it passed.* Passed — 22 plugins, 326,506 evidence rows.
2. ✅ Finish wiring the chat interface to the backend retrieval pipeline, verified against the real evidence produced in Step 1 — not against an empty or synthetic dataset. Verified across all 20 department questions.
3. ⬜ Finish report generation, verified against a real completed investigation.
4. 🔶 Clear the housekeeping items: remove tracked database files from git, drop the unused LangChain dependency, ~~make plugin timeouts configurable~~ (done), add API versioning.
5. ⬜ Large-dump benchmarking. Partly begun — real figures now exist (see Known Issues), and the quadratic classification cost is the first thing to investigate.

## 5. Why the Ordering Matters

It is tempting to work on visible features — a nicer chat UI, more report formatting — while the core claim of the system (that answers are grounded in real evidence) is still unverified end-to-end. Every test so far has proven the failure path works correctly: a bad input produces a clean, graceful failure. That is necessary but not sufficient. Until a real dump has been carried all the way through to a correctly cited chat answer, the system's central promise is unproven, and any work built on top of it risks being built on an assumption rather than a demonstrated fact.

> That has now happened, and the reasoning held up: almost every significant defect found in Phases 5–9 was invisible against synthetic data and only appeared against the real corpus — malfind's 8,912 undifferentiated high-severity rows, YARA matches sitting inside Defender's own memory, a persistence question answered entirely from the wrong plugin, and an LSASS question that never retrieved `lsass.exe`. The same principle applies to what is still unverified: report generation has not yet been run against a real completed investigation, and should not be called done until it has.

## 6. Forward Roadmap

Beyond the immediate priorities above, the following phases represent the intended direction of the platform. They are ordered but not scheduled — timing depends on what Step 1 above reveals.

### 6.1 Near Term

- Investigation session persistence and conversation history
- JSON/CSV export alongside PDF reporting
- Dashboard polish and multi-session support

### 6.2 Medium Term

- Timeline reconstruction across correlated evidence
- Indicator-of-compromise (IOC) extraction
- Multi-dump comparison for related investigations

### 6.3 Longer Term

- Authentication and role-based access for multi-investigator use
- Containerized deployment
- MITRE ATT&CK mapping and threat-intelligence enrichment
- Knowledge-graph-based cross-case correlation

## 7. Definition of Done for the Current Phase

The current phase is complete — not the project, just this phase — when all of the following are simultaneously true:

- A real memory dump has been analyzed end-to-end without manual intervention
- The chat interface answers a real investigation question with a correct, cited response
- A report has been generated from that real investigation
- The housekeeping items in Section 4 are cleared
