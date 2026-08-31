# Software Requirements Specification

**FIA (Anveshak) — AI-Powered Memory Forensic Investigation Assistant**

| | | | |
|---|---|---|---|
| **Document Code** | FIA-SRS-01 | **Version** | 2.0 |
| **Status** | Active | **Date** | August 2026 |
| **Prepared By** | Project Intern | **Reviewed By** | Project Mentor |

---

## 1. Introduction

FIA ("Anveshak") is a memory forensic investigation platform that pairs Volatility 3 with a locally-hosted language model to turn raw memory-dump analysis into a conversational, evidence-grounded investigation. This specification defines what the system must do, for whom, and how its correctness will be judged. It reflects the requirements as they stand for the current development phase, not an aspirational end state.

## 2. Problem Statement

A single Volatility plugin sweep against a modern memory image routinely produces thousands of rows spread across dozens of independent plugin outputs — process lists, network sockets, loaded modules, registry keys, injected memory regions. None of these outputs reference one another. An investigator has to hold the correlations in their head: which process opened which socket, which DLL was injected into which process, whether a suspicious handle and a suspicious network connection belong to the same actor. That correlation work is where investigation time actually goes, and it is the part existing tooling does not help with — Volatility gives you the raw facts, not the story they tell.

## 3. Objectives

The system is judged against five outcomes, in priority order:

1. Every configured Volatility plugin runs unattended against an uploaded dump, with failures isolated per-plugin rather than aborting the run.
2. Plugin output, regardless of source format, lands in one consistent evidence schema.
3. An investigator can ask a question in plain language and receive an answer grounded in that evidence — with the source plugin cited.
4. The system says so explicitly when it has no supporting evidence, rather than producing a plausible-sounding guess.
5. A completed investigation can be exported as a report without manual compilation.

## 4. Users

| Category | Who | What they need from the system |
|---|---|---|
| Primary | Digital forensic investigators, incident responders | Fast triage: which processes/connections deserve attention, with justification |
| Primary | Malware analysts | Detailed artifact relationships — process-DLL-network chains |
| Secondary | Students, SOC analysts, researchers | An approachable way to explore what a memory dump actually contains |

## 5. User Stories

| ID | Story | Priority |
|---|---|---|
| US-01 | Upload a memory dump and have analysis start without manual plugin selection | High |
| US-02 | See plugin execution progress and know if/why a plugin failed | High |
| US-03 | Ask a free-text investigation question instead of grepping plugin output | High |
| US-04 | Trust that every answer traces back to a specific artifact and plugin | High |
| US-05 | Be told plainly when there is no evidence for a claim, instead of a fabricated one | High |
| US-06 | See related evidence surfaced together (e.g. a process with its DLLs and connections) | Medium |
| US-07 | Export a report that summarizes the investigation without rebuilding it by hand | Medium |

## 6. Functional Requirements

| ID | Requirement | Status |
|---|---|---|
| FR-01 | Accept a memory dump upload with streamed size/type validation | ✅ Done |
| FR-02 | Execute the configured Volatility 3 plugin set automatically | ✅ Done |
| FR-03 | Parse heterogeneous plugin output into structured records | ✅ Done |
| FR-04 | Normalize records into the unified evidence schema | ✅ Done |
| FR-05 | Persist evidence durably with full plugin provenance | ✅ Done |
| FR-06 | Index evidence for semantic retrieval | ✅ Done |
| FR-07 | Classify and correlate related evidence across plugins | ✅ Done |
| FR-08 | Answer natural-language questions using only retrieved evidence | 🔶 In Progress |
| FR-09 | Attach citations (plugin + artifact) to every AI answer | 🔶 In Progress |
| FR-10 | Return an explicit "no evidence found" response when retrieval is empty | 🔶 In Progress |
| FR-11 | Generate a PDF investigation report on request | 🔶 In Progress |
| FR-12 | Persist conversation history within an investigation session | ⬜ Not Started |
| FR-13 | Export evidence/report data as JSON in addition to PDF | ⬜ Not Started |

> Status reflects a direct audit of the codebase, not the original plan. See `04_Development_Status_and_Roadmap.md` for the reasoning behind each status.

## 7. Non-Functional Requirements

| Requirement | Definition of Done |
|---|---|
| Evidence traceability | Every stored artifact retains its originating plugin and dump |
| No fabrication | The LLM is constitutionally restricted to retrieved evidence; unsupported claims are refused, not softened |
| Modularity | A new Volatility plugin can be onboarded without touching unrelated modules |
| Local-first operation | The full pipeline — forensic execution and inference — runs with no external network dependency |
| Predictable failure | A single failing plugin or a low-confidence retrieval degrades gracefully rather than crashing the investigation |
| Maintainable codebase | Each pipeline stage (parse, normalize, retrieve, prompt, generate) is independently testable |

## 8. Out of Scope for the Current Phase

These are legitimate future directions, not gaps in the current build:

- Disk or mobile forensics
- Live acquisition from a running system
- Multi-user accounts, authentication, or role-based access
- Distributed / multi-node processing
- SIEM or SOAR integration

## 9. Constraints

- Single-machine, local deployment — no distributed infrastructure
- Upload capped at 64 GB per dump, enforced during the streamed upload itself
- Each Volatility plugin subprocess is bounded by a 30-minute timeout
- LLM context window is bounded (currently 8K tokens), which limits how much evidence a single answer can draw on directly
- No production-scale timing benchmark exists yet — performance targets below are design goals, not measured results

## 10. Acceptance Criteria

The current phase is complete when a single real memory dump can be carried through the entire pipeline without manual intervention: uploaded, analyzed by the full plugin set, normalized into evidence, queried successfully through the chat interface with correct citations, and exported as a report. This has not yet been demonstrated end-to-end on a real dump — it is the single acceptance gate the rest of this specification exists to support.

## 11. Success Metrics

| Metric | Target |
|---|---|
| Plugin coverage | 100% of configured plugins attempt execution; partial failure does not block the run |
| Parsing accuracy | > 95% of plugin rows successfully normalized |
| Answer grounding | 100% of AI answers either cite evidence or state none was found |
| Response latency (excluding analysis) | < 5 seconds — design target, unverified |
