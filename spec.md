# Spec — SOC Triage Agent

## Problem
Junior SOC analysts waste time on noisy, unsorted alerts. They need a fast first pass: severity, short rationale, and a draft analyst note they can edit.

## Users
- **Primary:** Student / junior analyst building SOC skills (demo + practice)
- **Secondary:** Hiring managers reviewing a portfolio repo

## Goals
1. Ingest a batch of structured alerts (JSON)
2. Score each alert (severity + confidence)
3. Produce a draft analyst note with cited evidence fields
4. Expose results via CLI (MVP) and a thin API (follow-on)
5. Measure triage quality on a labeled sample set

## Non‑goals (MVP)
- Live SIEM / EDR connectors
- Ticket system write-back (ServiceNow, Jira)
- Real-time streaming pipeline
- Full case management UI
- Automated containment actions

## Success metrics
| Metric | Target (MVP) |
|--------|----------------|
| Labeled sample set size | ≥ 50 alerts across ≥ 5 categories |
| Severity agreement vs labels | ≥ 70% exact match on held-out set |
| Time to triage 20 alerts (CLI) | < 30 seconds wall clock (rules path) |
| Demo path | One command runs end-to-end on fixtures |
| Test coverage of scoring rules | All severity rules have unit tests |

T9 measures that held-out row on `fixtures/heldout/` (30 alerts, labeled before scoring). Exact-match accuracy is 24/30 (80%). Within-one-level accuracy is 27/30 (90%). Together with 20 tuning labels, the labeled sample is 50 alerts. The tuning-set score is 20/20 on the alerts the rules were written against.

## Functional requirements
1. **Alert schema** — id, timestamp, source, category, raw fields, optional IOCs
2. **Rules engine** — deterministic severity scoring from category + field heuristics
3. **Optional LLM assist** — `soc-triage run --llm-notes` may rewrite the draft note through an OpenAI-compatible chat endpoint. Off by default (`SOC_TRIAGE_LLM_PROVIDER=none`). The local API uses the same gate: a request `llm_notes=true` flag or `soc-triage serve --llm-notes`, both default off. Severity, confidence, needs_review, and reasons stay with the rules. Missing config, timeout, error, or invalid text falls back to the template note.
4. **Output** — JSON + human-readable summary per alert
5. **Eval harness** — compare predicted severity to labels; print confusion summary
6. **Safety banner** — every run states synthetic/demo mode
7. **Local API** — optional extra. `GET /health`, `POST /triage` (one alert), `POST /triage/batch` (at most 500), `GET /fixtures/demo`, OpenAPI at `/docs`. Same rules and note fallback as the CLI. Loopback by default. No authentication.

## User stories
- As an analyst, I can point the CLI at a fixture file and get a ranked triage list.
- As a reviewer, I can open `spec.md` / `plan.md` and understand architecture in under 5 minutes.
- As a hiring manager, I can clone, run fixtures, and see tests pass without API keys (rules-only path).

## Resolved in plan
- LLM provider: rules-only offline path by default. Optional OpenAI-compatible notes (T7), including xAI Grok, OpenAI, and a local Ollama `/v1` server. No LLM SDK in the base install.
- Categories seeded: brute force, phishing URL, malware hash, lateral movement, policy noise
