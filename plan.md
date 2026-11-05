# Plan — SOC Triage Agent

## Stack
| Layer | Choice | Why |
|-------|--------|-----|
| Language | Python 3.11+ | Fast to ship, strong SOC tooling ecosystem |
| Packaging | `uv` or `pip` + `pyproject.toml` | Simple, modern |
| CLI | Typer or Click | Clean demo UX |
| API (phase 2) | FastAPI | Typed, easy OpenAPI |
| Storage (MVP) | Filesystem JSON fixtures | No infra tax |
| Rules | Pure Python modules | Deterministic, testable |
| LLM (optional) | OpenAI-compatible API behind an interface | Swap/local later |
| Tests | pytest | Standard |
| CI | GitHub Actions / Origin checks | Lint + pytest on PR |

## Architecture (MVP)
```
fixtures/alerts/*.json
        │
        ▼
   ingest.parse ──► Alert model (pydantic)
        │
        ▼
   triage.rules ──► Severity + confidence + reasons[]
        │
        ├─(optional)► triage.llm_notes ──► draft note
        │
        ▼
   report.render ──► ranked JSON + markdown summary
        │
        ▼
   eval.compare ──► metrics vs labels
```

## Severity model (v1)
| Level | Meaning |
|-------|---------|
| critical | Likely active compromise / high-impact IOC |
| high | Strong malicious signal, needs prompt review |
| medium | Suspicious; investigate in queue |
| low | Weak signal / incomplete context |
| info | Noise / policy / expected admin activity |

Rules combine: category baseline + IOC presence + burst/count heuristics + allowlist hits (downgrade).

## Repo layout
```
constitution.md
spec.md
plan.md
tasks.md
README.md
.pyproject.toml / requirements
src/soc_triage/
  __init__.py
  models.py
  ingest.py
  rules.py
  notes.py
  report.py
  cli.py
  eval.py
tests/
fixtures/alerts/
fixtures/labels.json
.env.example
.cursor/rules/ (or AGENTS.md) — mirror constitution safety
```

## Cursor workflow
1. Keep phase docs as source of truth
2. Implement **one** `tasks.md` item per PR
3. Cloud agent prompt = task id + acceptance criteria + link to plan section
4. Rules-only path must always work without secrets
5. LLM path gated by env var; skipped in CI if no key

## Risks & mitigations
| Risk | Mitigation |
|------|------------|
| Toy data looks fake | Mix categories; document dataset provenance |
| LLM hallucinations in notes | Notes cite rule reasons + alert fields; severity from rules |
| Scope creep to “full SIEM” | Non-goals list; UI last |
| Resume overclaim | README limitations section required |

## Phased delivery
- **P0:** schema, fixtures, rules, CLI, tests, eval
- **P1:** optional LLM notes, FastAPI read endpoint
- **P2:** tiny dashboard, more datasets, better metrics
