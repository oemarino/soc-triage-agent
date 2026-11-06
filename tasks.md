# Tasks — SOC Triage Agent

Ordered work items. Check boxes as PRs merge. One task ≈ one PR.

## P0 — MVP (resume-ready CLI)

- [x] **T1 — Project skeleton**  
  Create Python package layout, `pyproject.toml`, README stub, `.env.example`, `.gitignore`, mirror safety rules for Cursor.  
  **Done when:** `pytest` runs (empty/pass), package imports, README explains how to run later.

- [x] **T2 — Alert schema + fixtures**  
  Pydantic `Alert` model; ≥20 synthetic alerts across ≥5 categories; `fixtures/labels.json` for a subset.  
  **Done when:** fixtures validate against model; loader tested.

- [x] **T3 — Rules engine**  
  Deterministic severity + confidence + `reasons[]`; allowlist downgrades; unit tests per rule family.  
  **Done when:** known fixture alerts map to expected severities in tests.

- [x] **T4 — CLI triage command**  
  `soc-triage run fixtures/alerts` → ranked JSON + markdown summary; synthetic-mode banner.  
  **Done when:** one command demos end-to-end without API keys.

- [x] **T5 — Eval harness**  
  Compare predictions to labels; print accuracy + confusion-style summary.  
  **Done when:** `soc-triage eval` reports metrics on labeled set; documented in README.

- [x] **T6 — README + architecture**  
  Architecture diagram (mermaid or ascii), limitations, resume-safe project blurb, demo GIF/script.  
  **Done when:** cold clone instructions work for a stranger.

## P1 — Enrichment

- [x] **T7 — Optional LLM draft notes**  
  Interface + OpenAI-compatible client; gated by env; falls back to template notes.  
  **Done when:** with key, notes enrich; without key, rules path unchanged.

- [ ] **T8 — FastAPI read API**  
  `POST /triage` accepts alert batch, returns results; OpenAPI.  
  **Done when:** curl example in README; tests for happy path.

## P2 — Polish

- [x] **T9 — More fixtures + held-out eval**  
  30 synthetic alerts in `fixtures/heldout/`, labeled from the severity definitions before scoring, plus five more labels on the existing tuning set (50 labeled alerts in total). `soc-triage eval --alerts fixtures/heldout/alerts --labels fixtures/heldout/labels.json` reports exact-match accuracy, within-one-level accuracy, and a confusion matrix.  
  **Done when:** the held-out file is committed before the eval run; README reports the tuning score and the held-out score with an error analysis; `rules.py` is unchanged.
- [ ] **T10 — Minimal UI** (optional)  
  Streamlit or simple Next page over the API — only after P0 solid.

## Definition of done (project)
All P0 tasks complete, tests green, limitations documented, constitution still accurate.
