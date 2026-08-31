# Engineering Log

> Updated at the end of every work session — this is the daily log.

This log is built directly from `git log` and `git show --stat` for every commit since 2026-07-01 (`git log --since="2026-07-01" --all --date=short --pretty=format:"%ad | %s"`), plus a diff review of each commit's actual changes. Entries describe what was committed, not what was planned — where a gap of several days has no commits, it is noted plainly rather than filled in. The closing entry for today is based on this session's direct testing, not on git history (nothing from today has been committed yet).

---

## 2026-07-20

**Worked on:** Repository initialization — `.gitignore` and a placeholder `README.md`.
**Result:** Empty project scaffold committed. No application code yet.
**Next:** Set up the backend project skeleton.

## 2026-07-21

**Worked on:** Backend skeleton: `backend/.env.example`, `backend/configs/config.yaml`, `backend/configs/logging.yaml`, `backend/requirements.txt`, and empty `app/__init__.py` / `main.py` placeholders.
**Result:** Project structure and dependency list established. Still no functional code — configuration and scaffolding only.
**Next:** Implement the core infrastructure modules (config loading, logging, database, entry point).

> *No commits between 2026-07-21 and 2026-07-29 (8-day gap) — no activity logged.*

## 2026-07-29

Seven commits landed on this single day, each a focused, independent piece of core infrastructure:

**Worked on:** Production-grade configuration manager (`app/core/config.py`, 612 lines); centralized logging manager (`app/core/logging.py`); SQLAlchemy database manager (`app/database/database.py`); the FastAPI application entry point (`app/main.py`); initial ORM models (`Case`, `MemoryDump`, `PluginExecution`, `PluginResult`); and the Volatility memory dump manager (`app/volatility/manager.py`, `memory_dump_manager.py`).
**Result:** The backend gained a working config/logging/database/entry-point foundation, and could validate and store a memory dump for the first time. Each concern was committed separately rather than as one large drop.
**Next:** Build the RAG pipeline and plugin execution engine on top of this foundation.

## 2026-07-30

**Worked on:** A large single commit (2,661 insertions across 24 files) — the repository layer (`base_repository.py` plus case/memory-dump/plugin-execution/plugin-result repositories), an LLM manager skeleton, the evidence normalizer and Volatility JSON parser, the RAG pipeline itself (`embedding_manager.py`, `rag_pipeline.py`, `retriever.py`, `vector_store.py`), and the Volatility execution engine, plugin registry, and plugin runner.
**Result:** First working ChromaDB vector store committed (binary index files present in the diff) — a retrieval path existed end-to-end for the first time.
**Next:** Connect this backend pipeline to a real frontend and an upload workflow.

> *No commits between 2026-07-30 and 2026-08-03 (4-day gap) — no activity logged.*

## 2026-08-03

**Worked on:** Frontend project bootstrapped from scratch (Vite + React + TypeScript + Tailwind, ESLint config, routing) with a full dashboard layout — sidebar, header, dashboard cards, charts (`EvidencePieChart`, `InvestigationChart`), and placeholder pages for Evidence/Investigation/Reports/Settings/Upload. On the backend, the upload route and `investigation_service.py` were added.
**Result:** First runnable frontend (5,394 insertions, 41 files) alongside a real `/upload` endpoint on the backend.
**Next:** Wire the upload UI to the real backend endpoint and start the investigation workflow.

## 2026-08-04

**Worked on:** `investigation.py` route added on the backend; the upload route reworked; frontend upload components built (`UploadDropzone`, `UploadProgress`, `UploadActions`, `FileInformation`) and wired to `uploadService.ts` / `investigationService.ts`. Several manual test-upload files landed in `backend/storage/uploads/`, and `sample.raw` was added at the repo root.
**Result:** Upload → investigation start wired between frontend and backend for the first time.
**Next:** Finish the remaining MVP surface — chat, evidence browsing, reports, dashboard stats.

## 2026-08-05

The single largest commit in the project's history: 108 files, 9,213 insertions, titled "complete Phase 7 and finalize AI Memory Forensic Investigation Assistant MVP."

**Worked on:** Backend — chat, dashboard, evidence, rag, and reports routers all added; `prompt_builder.py` and `response_parser.py` implemented; `report_service.py` written (1,317 lines, PDF generation); `ai_investigation_service.py` added as the chat-answering service; the RAG indexing service added. Frontend — `ChatPage.tsx` (389 lines), `RagSearchPage.tsx`, and major rewrites of `EvidencePage`, `ReportsPage`, `InvestigationPage`, and `DashboardPage`, plus the full set of frontend services/types for chat, evidence, RAG, and reports. Six PDF reports and a populated `fia.db` were committed from real manual testing during this session.
**Result:** This is the commit where the platform went from disconnected pieces to a functioning end-to-end MVP — every major route and page exists after this point. No automated tests exist yet at this stage.
**Next:** Add evidence correlation/risk scoring, and start building real test coverage.

## 2026-08-11

Titled "complete V1 MVP."

**Worked on:** The evidence classifier module built from scratch — `classifier.py`, `correlation.py`, `entities.py`, `indicators.py` (457 lines), `scorer.py` — plus `risk_classification_service.py` to persist classifications onto evidence records. The first automated tests were added: `conftest.py` and five test files covering the evidence classifier and chat/report session behavior (over 2,000 lines of test code in one commit).
**Result:** Deterministic, explainable risk scoring exists and is test-covered for the first time. This commit also introduced the project's first automated test suite — before this, nothing was under test.
**Next:** Improve investigation progress reporting and indexing behavior.

## 2026-08-12

**Worked on:** `investigation.py` route reworked (198 lines changed) alongside database and indexing-service changes; two new test files added (`test_investigation_postprocessing.py`, `test_investigation_progress.py` — 930 lines combined); frontend `InvestigationPage.tsx` updated to match the new progress model.
**Result:** More granular investigation progress/status reporting, backed by new tests.
**Next:** Address performance bottlenecks in classification, indexing, and retrieval (named explicitly in the next commit's message).

> *2026-08-13: no commits — no activity logged.*

## 2026-08-14

The most structurally significant commit in the project: 49 files, 7,658 insertions, titled "optimize investigation, indexing, and evidence retrieval." This is also the most recent commit — HEAD as of this log entry.

**Worked on:** `forensic_evidence_retrieval_service.py` added (1,615 lines — the deterministic, SQLite-first retrieval layer that the current architecture is built around); `investigation_phase_tracker.py` added; the `evidence_index_state` model and repository added for incremental, crash-resumable RAG indexing; `plugin_runner.py` reworked to stream Volatility output to disk instead of buffering it in memory; `memory_dump_manager.py` extended with streamed-upload size validation. Six new large test files landed (`test_chat_fallback_sqlite.py`, `test_classifier_equivalence.py`, `test_indexing_incremental.py`, `test_plugin_runner_streaming.py`, `test_retrieval_index_acceleration.py`, `test_streaming_upload.py` — roughly 3,300 lines of new tests). Frontend theme support (`ThemeProvider.tsx`, dark/light toggle) also landed in this commit.
**Result:** This is the performance-hardening pass described in `02_System_Architecture_and_Design.md` — it's what makes SQLite-authoritative/ChromaDB-optional retrieval and bounded-memory streaming real in the code, not just a design intention.
**Next:** Run a real end-to-end investigation and finish verifying the chat and reporting paths against real evidence — the goal stated in this commit's own follow-on work, and still the standing priority as of today (see below).

> *No commits between 2026-08-14 and today, 2026-08-31 (17-day gap) — no activity logged in git. The work described below happened in this window but has not been committed.*

## 2026-08-31 — Current state

**Worked on:** No new commits in this window. This entry documents uncommitted session work rather than git history: set up the environment end-to-end on what was expected to be a fresh machine (created `backend/.env` from `.env.example` + `config.yaml`; confirmed `backend/.venv` and `frontend/node_modules` were actually already populated, not fresh); identified and fixed the `vol` PATH-activation issue reported below in *Known Issues*; started the backend and frontend and ran the full test suite (**147/147 passing**); tested the chat → retrieval → Ollama (`qwen3:14b`) chain directly against real evidence already present in `fia.db` (a test-fixture investigation, `INV-20260805-48E690`, with 10 evidence rows) and confirmed it returns correctly cited, non-fabricated answers, including full history persistence; audited the upload size limit (64 GB, `memory_dump_manager.py`) and Volatility plugin timeout (30 minutes/plugin, hardcoded, `plugin_runner.py`); consolidated project documentation into this four-document set plus this log.
**Result:** The chat pipeline — the item marked "In Progress" in the current `04_Development_Status_and_Roadmap.md` status table — was directly tested this session and works correctly end-to-end against real evidence, including citation and confidence scoring. It has **not**, however, been tested against evidence produced by a real Volatility run on a real memory dump — only against a placeholder upload (`sample.raw`, which fails all 10 plugins as expected, since it isn't a real memory image) and against pre-existing test-fixture evidence rows in the database. The single gating milestone below remains open.
**Next:** Per `04_Development_Status_and_Roadmap.md` §4 — run one real Windows memory dump through the complete pipeline (upload → plugin execution → parsing → normalization → retrieval → chat query). This remains the standing priority; nothing else should be scheduled ahead of it.

---

## Cross-check against `04_Development_Status_and_Roadmap.md`

This log agrees with `04_Development_Status_and_Roadmap.md` on the central point: **a real end-to-end run against an actual memory dump has still not happened**, and that remains the single gating item before further feature work.

One discrepancy was flagged rather than silently smoothed over: `04_Development_Status_and_Roadmap.md` §2 previously listed a single ambiguous **"Chat UI — backend wiring: 🔶 In Progress"** row. Based on direct testing performed this session (see 2026-08-31 above), the chat pipeline — frontend request shape, retrieval, prompt construction, the Ollama call, citation return, and history persistence — is functionally complete and was verified working against real evidence rows. What had *not* been verified was that same pipeline running against evidence from a genuine Volatility analysis rather than test fixtures — a narrower and different claim than "wiring in progress." `docs/04` §2 has since been split into two rows to reflect this: **"Chat UI ↔ backend wiring: ✅ Done"** (verified against real DB rows) and **"Chat verified against real Volatility-derived evidence: ⬜ Not Started"**. §4's Immediate Priorities and gating-milestone language were deliberately left unchanged — the real-memory-dump test is still the thing everything else is blocked on, and splitting the status row does not relax that.
