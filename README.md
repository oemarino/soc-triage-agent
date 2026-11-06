# SOC Triage Agent

Portfolio project for a cybersecurity student: a first-pass assistant that ranks **synthetic** SOC alerts and drafts analyst notes a person can edit.

This is a learning and demo repo. It is not a SIEM, and it does not connect to a live security stack.

**Status:** T5 `soc-triage eval` scores the 15 labeled fixtures and prints accuracy plus a confusion matrix. README architecture polish is still T6 (`tasks.md`).

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

`pytest`, `soc-triage run`, and `soc-triage eval` should work on a fresh clone with no API keys.

## Demo

```bash
soc-triage run fixtures/alerts
soc-triage run fixtures/alerts --json triage.json
soc-triage run fixtures/alerts/brute_force.json --format json
soc-triage eval
soc-triage eval --alerts fixtures/alerts --labels fixtures/labels.json --json eval.json
```

`run` accepts a directory or one JSON file. It prints the synthetic-mode banner, then a markdown table ranked by severity and confidence. `--format json` prints the same ranking as JSON on stdout (the banner goes to stderr so the stream stays valid JSON). `--json PATH` always writes the full ranked results, including reasons and draft notes.

The start of a real `soc-triage run fixtures/alerts` looks like this:

```text
Synthetic/demo mode. This tool recommends severity and drafts notes; a human makes the final call. No auto-close, auto-block, or external notify.

# Triage summary (25 alerts)

4 critical · 4 high · 5 medium · 5 low · 7 info

Ranked by severity, then confidence. Recommendations only; a human makes the final call.

| Rank | Id | Category | Severity | Confidence | Needs review | Top reasons |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | SYN-BF-001 | brute_force | critical | 0.90 | no | raw_fields.failure_count=86 · raw_fields.success_after_failures=true after 86 failures |
| 2 | SYN-LM-001 | lateral_movement | critical | 0.90 | no | spread=14; raw_fields.dest_host_count=14, raw_fields.admin_share_conn... · iocs ipv4 203.0.113.50 reputation=malicious |
| 3 | SYN-MH-001 | malware_hash | critical | 0.90 | no | sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa... · iocs sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa... |
| 4 | SYN-PH-001 | phishing_url | critical | 0.90 | no | raw_fields.url=https://sso.login.example/reset · raw_fields.clicked=true and IOC reputation=malicious |
```

Draft notes follow the table. Each note cites rule reasons and alert fields. Severity still comes only from the rules.

## Fixtures

`fixtures/alerts/` holds 25 hand-authored alerts, five in each seed category: `brute_force`, `phishing_url`, `malware_hash`, `lateral_movement`, and `policy_noise`. Addresses are RFC 5737 documentation IPs. Names use RFC 2606 `example` domains. Hashes are repeated-nibble placeholders, not malware samples.

`fixtures/labels.json` is ground truth for 15 of those alerts. `soc-triage eval` scores that subset. The other 10 alerts are unlabeled and are left out of the accuracy denominator. The rules were written against this same labeled set, so a perfect score here is not evidence of real-world performance.

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

## Eval

`soc-triage eval` scores the labeled alerts with the rules engine and compares them to `fixtures/labels.json`. This is the real output on the bundled set:

```text
Synthetic/demo mode. This tool recommends severity and drafts notes; a human makes the final call. No auto-close, auto-block, or external notify.

# Eval summary

Labeled alerts: 15 of 25 loaded. Unlabeled alerts are excluded.
Exact-match accuracy: 15/15 (100%).

The labeled set is small and synthetic. The rules were tuned on these same alerts, so this score is not a measure of real-world accuracy. A held-out split is future work (T9).

## Per severity

Counts use only labeled alerts. Precision and recall are n/a when the denominator is 0.

| Severity | Labeled | Predicted | TP | Precision | Recall |
| --- | --- | --- | --- | --- | --- |
| critical | 4 | 4 | 4 | 1.00 | 1.00 |
| high | 3 | 3 | 3 | 1.00 | 1.00 |
| medium | 3 | 3 | 3 | 1.00 | 1.00 |
| low | 2 | 2 | 2 | 1.00 | 1.00 |
| info | 3 | 3 | 3 | 1.00 | 1.00 |

## Confusion matrix

Rows are labeled severity. Columns are predicted severity.

| Labeled \ Predicted | critical | high | medium | low | info |
| --- | --- | --- | --- | --- | --- |
| critical | 4 | 0 | 0 | 0 | 0 |
| high | 0 | 3 | 0 | 0 | 0 |
| medium | 0 | 0 | 3 | 0 | 0 |
| low | 0 | 0 | 0 | 2 | 0 |
| info | 0 | 0 | 0 | 0 | 3 |

## Mismatches

No mismatches.
```

## Limitations

- Exact-match accuracy on these 15 labels is 100% because the rules were tuned on that same synthetic set. It is not a measure of real-world detection performance. A held-out split belongs in T9, which grows the labeled set.
- Notes are templates. There is no language-model call.
- No live SIEM, EDR, or ticket write-back (out of scope for the MVP).
- No automated containment. A human makes the final call.
- Not for production security operations. Resume language should match the code, not a production SOC platform.
- Sample data is synthetic. Do not drop real alerts into `fixtures/`.

## Next step

**T6 — README + architecture.** Add an architecture diagram, a resume-safe project blurb, and a demo a stranger can follow from a cold clone.

```bash
pytest
soc-triage eval
```
