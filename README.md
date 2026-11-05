# SOC Triage Agent

Portfolio project for a cybersecurity student: a first-pass assistant that ranks **synthetic** SOC alerts and drafts analyst notes a person can edit.

This is a learning and demo repo. It is not a SIEM, and it does not connect to a live security stack.

**Status:** T2 alert schema and synthetic fixtures are in place. Rules, the CLI demo, and eval are still T3–T5 (`tasks.md`). `soc-triage run` and `soc-triage eval` print a synthetic-mode banner and exit.

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

## Fixtures

`fixtures/alerts/` holds 25 hand-authored alerts, five in each seed category: `brute_force`, `phishing_url`, `malware_hash`, `lateral_movement`, and `policy_noise`. Addresses are RFC 5737 documentation IPs. Names use RFC 2606 `example` domains. Hashes are repeated-nibble placeholders, not malware samples.

`fixtures/labels.json` is ground truth for 15 of those alerts, so a later eval can score severity. It is a subset, not a full answer key.

```bash
python -c "from soc_triage.ingest import default_alerts_dir, load_alerts; print(len(load_alerts(default_alerts_dir())))"
```

## Layout

```
constitution.md  spec.md  plan.md  tasks.md
src/soc_triage/     package (models, ingest, rules, notes, report, cli, eval)
tests/              pytest
fixtures/alerts/    25 synthetic alerts in five category files
fixtures/labels.json  severity labels for 15 of those alerts
.env.example
.cursor/rules/soc-triage.mdc
```

Label entries look like this:

```json
{"id": "SYN-BF-001", "severity": "critical"}
```

Severity values are `critical`, `high`, `medium`, `low`, and `info`.

## Limitations

- Schema and synthetic fixtures only. There is no rule engine, ranked report, or eval metric yet.
- No live SIEM, EDR, or ticket write-back (out of scope for the MVP).
- No automated containment.
- Not for production security operations. Resume language should match the code, not a production SOC platform.
- Sample data is synthetic. Do not drop real alerts into `fixtures/`.

## Next step

**T3 — Rules engine.** Deterministic severity, confidence, and `reasons[]`, including allowlist downgrades. Done when known fixture alerts map to expected severities in unit tests.

```bash
pytest
```
