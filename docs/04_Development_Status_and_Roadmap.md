# Development Status & Roadmap

**FIA (Anveshak) — What Works, What's Next, and Why the Order Matters**

| | | | |
|---|---|---|---|
| **Document Code** | FIA-STA-04 | **Version** | 2.0 |
| **Status** | Active | **Date** | August 2026 |
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
| Chat verified against real Volatility-derived evidence | ⬜ Not Started |
| PDF report generation | 🔶 In Progress |
| API versioning (/api/v1) | ⬜ Not Started |
| Verified end-to-end run on a real memory dump | ⬜ Not Started |
| Large-dump performance benchmarking | ⬜ Not Started |
| Configurable plugin timeouts | ⬜ Not Started |
| Remove unused LangChain dependency | ⬜ Not Started |
| Stop tracking database files in version control | ⬜ Not Started |
| Multi-user authentication / access control | ⬜ Not Started |

> The evidence classifier / correlator was originally scoped for a later phase and is already implemented — ahead of plan. Multi-user authentication is intentionally out of scope for this phase, not a gap.

## 3. Known Issues

| Issue | Detail |
|---|---|
| Volatility CLI resolution | `vol.exe` is only discoverable on PATH when the backend's virtual environment is activated. Starting the server via the venv's interpreter directly, without activating first, silently breaks plugin execution. |
| Evidence database tracked in version control | The live SQLite and ChromaDB files currently contain real evidence data and are committed to the repository — risk of repo bloat and accidental sensitive-data commits. |
| No real-world performance data | Every timing figure quoted in planning documents is a design target, not a measurement. Nothing should be presented as a benchmark until a real dump has been timed end-to-end. |

## 4. Immediate Priorities, In Order

1. **Run one real Windows memory dump through the complete pipeline**: upload, plugin execution, parsing, normalization, storage, retrieval, and a chat query against the resulting evidence. Every test to date has only exercised the failure path against a placeholder file — the success path has not been observed even once. This is the gating milestone; nothing after it should start until it passes.
2. Finish wiring the chat interface to the backend retrieval pipeline, verified against the real evidence produced in Step 1 — not against an empty or synthetic dataset.
3. Finish report generation, verified against a real completed investigation.
4. Clear the housekeeping items: remove tracked database files from git, drop the unused LangChain dependency, make plugin timeouts configurable, add API versioning.
5. Only after Steps 1–4 are done: begin large-dump benchmarking and move into the next phase of feature work.

## 5. Why the Ordering Matters

It is tempting to work on visible features — a nicer chat UI, more report formatting — while the core claim of the system (that answers are grounded in real evidence) is still unverified end-to-end. Every test so far has proven the failure path works correctly: a bad input produces a clean, graceful failure. That is necessary but not sufficient. Until a real dump has been carried all the way through to a correctly cited chat answer, the system's central promise is unproven, and any work built on top of it risks being built on an assumption rather than a demonstrated fact.

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
