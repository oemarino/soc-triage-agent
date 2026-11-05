# SOC Triage Agent

Portfolio project for a cybersecurity student: a first-pass assistant that ranks **synthetic** SOC alerts and drafts analyst notes a person can edit.

This is a learning and demo repo. It is not a SIEM, and it does not connect to a live security stack.

**Status:** T1 project skeleton is in place. Scoring, fixtures, the CLI demo, and eval land in T2–T6 (`tasks.md`). The `run` and `eval` commands currently print a synthetic-mode banner and point at those tasks.

## What the MVP will do

| Step | Behavior |
|------|----------|
| Ingest | Read a batch of structured JSON alerts from `fixtures/alerts/` |
| Score | Assign severity and confidence with deterministic rules, plus reasons a reviewer can check |
| Note | Draft a short analyst note that cites alert fields |
| Demo | `soc-triage run` on fixtures, no API key |
| Eval | Compare predicted severity to `fixtures/labels.json` |

A human still makes the final call. The tool will not close, block, or notify anyone.

## Five-phase docs (Cox-style)

Work follows a five-phase spec workflow. The phase docs at the repo root are the source of truth; code stays inside the current task.

| Phase | File | Role |
|-------|------|------|
| 1. Constitution | `constitution.md` | Non-negotiables: synthetic data, no offensive tooling, human review, secrets out of git |
| 2. Spec | `spec.md` | Users, goals, non-goals, success metrics |
| 3. Plan | `plan.md` | Stack, architecture, severity model, repo layout |
| 4. Tasks | `tasks.md` | Ordered work. One task at a time |
| 5. Implement | `src/soc_triage/` | Code for the open task only |

Cursor reads the same safety rules from `.cursor/rules/soc-triage.mdc`.

## Safety

- Synthetic and demo data only. No real customer, employer, or classmate PII.
- Detection and triage only. No exploit code, payloads, or attack tooling.
- Rules decide severity. An optional LLM (later, T7) may help draft notes and is off unless you set a key.
- Missing or low-confidence input fails closed to `needs_review` once scoring exists (T3).
- `.env` is gitignored. Copy `.env.example` if you need local variables. You do not need it for tests.

## Install and run

Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
soc-triage --help
```

`pytest` should pass on a fresh clone with no API keys. `soc-triage run` and `soc-triage eval` are stubs until T4 and T5.

## Layout

```
constitution.md  spec.md  plan.md  tasks.md
src/soc_triage/     package (models, ingest, rules, notes, report, cli, eval)
tests/              pytest
fixtures/alerts/    synthetic alert JSON (empty until T2)
fixtures/labels.json
.env.example
.cursor/rules/soc-triage.mdc
```

`fixtures/labels.json` is a placeholder:

```json
{
  "dataset": "synthetic-soc-triage",
  "description": "…",
  "labels": []
}
```

T2 replaces `labels` with entries for a subset of fixture alerts. Each value is a severity: `critical`, `high`, `medium`, `low`, or `info`.

## Limitations

- T1 only. There is no alert schema, rule engine, ranked report, or eval metric yet.
- No live SIEM, EDR, or ticket write-back (out of scope for the MVP).
- No automated containment.
- Not for production security operations. Resume language should match the code, not a production SOC platform.
- Sample data, once added, is synthetic. Do not drop real alerts into `fixtures/`.

## Next step

**T2 — Alert schema + fixtures.** Add the Pydantic `Alert` model, at least 20 synthetic alerts across at least 5 categories, and labels for a subset. Done when fixtures validate and the loader is tested.

Confirm this skeleton first:

```bash
pip install -e ".[dev]" && pytest && soc-triage --help
```
