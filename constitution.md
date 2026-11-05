# Constitution — SOC Triage Agent

## Purpose
Build a portfolio SOC triage assistant that helps a junior analyst prioritize alerts and draft first-pass notes. This project exists for learning, demos, and resume evidence — not for production security operations.

## Non‑negotiables
1. **Synthetic data only.** Use fixture alerts and public/open sample datasets. Never ingest real customer, employer, or classmate PII.
2. **No offensive tooling.** Do not include exploit code, payload generation, credential theft, or attack rehearsal. Detection and triage only.
3. **Human in the loop.** The agent recommends severity and drafts notes; a human makes the final call. Never auto-close, auto-block, or auto-notify external parties.
4. **Explainability over magic.** Every triage decision must cite alert fields and rule/model reasons a reviewer can check.
5. **Safe defaults.** Fail closed on missing data: if confidence is low, mark `needs_review` instead of guessing critical.
6. **Secrets stay out of git.** API keys and `.env` never commit. Provide `.env.example` only.
7. **Reproducible demos.** A new clone + documented steps must reproduce the demo without private infrastructure.
8. **Honest claims.** README and resume bullets must match what the code actually does (no “production SIEM” language).

## Quality bar
- Typed inputs/outputs for alert schema and triage results
- Unit tests for scoring rules and parsers
- At least one labeled evaluation set with reported metrics
- Clear README: architecture, how to run, limitations

## Voice & docs
- Docs are concise and actionable
- Prefer tables for severity matrix and task lists
- Keep phase docs (`constitution`, `spec`, `plan`, `tasks`) current as the project evolves
