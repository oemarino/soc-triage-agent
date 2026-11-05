# SOC Triage Agent

Portfolio project for a cybersecurity student: a first-pass assistant that ranks **synthetic** SOC alerts and drafts analyst notes a person can edit.

This is a learning and demo repo. It is not a SIEM, and it does not connect to a live security stack.

**Status:** T3 rules score every fixture alert. The CLI demo and eval command are still T4 and T5 (`tasks.md`). `soc-triage run` and `soc-triage eval` print a synthetic-mode banner and exit.

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

`fixtures/labels.json` is ground truth for 15 of those alerts, so a later eval can score severity. It is a subset, not a full answer key. The rules engine matches those 15 labels. There are no intentional mismatches.

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

## Rules

`score_alert` in `src/soc_triage/rules.py` is deterministic and does not use an API key. It starts from a category baseline, then applies IOC reputation, count thresholds, an incomplete-context cap (`low` plus `needs_review`), and an allowlist downgrade to `info`.

```bash
python -c "from soc_triage.ingest import default_alerts_dir, load_alerts; from soc_triage.rules import score_alert; alert = load_alerts(default_alerts_dir())[0]; result = score_alert(alert); print(alert.id, result.severity.value, result.confidence)"
```

## Limitations

- Rules score severity, confidence, and reasons. The CLI does not rank a directory yet, and there is no eval report yet.
- No live SIEM, EDR, or ticket write-back (out of scope for the MVP).
- No automated containment. A human makes the final call.
- Not for production security operations. Resume language should match the code, not a production SOC platform.
- Sample data is synthetic. Do not drop real alerts into `fixtures/`.

## Next step

**T4 — CLI triage command.** `soc-triage run fixtures/alerts` should print a synthetic-mode banner plus a ranked JSON and markdown summary, with no API key.

```bash
pytest
```
