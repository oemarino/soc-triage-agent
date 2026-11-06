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
fixtures/alerts/*.json          POST /triage JSON body
        │                              │
        ▼                              ▼
   ingest.parse ──► Alert model (pydantic) ◄── FastAPI
        │
        ▼
   triage.rules ──► Severity + confidence + reasons[]
        │
        ├─(optional)► triage.llm_notes ──► draft note
        │
        ▼
   report.render ──► ranked JSON + markdown summary
        │                 │
        ▼                 ▼
   soc-triage run    soc-triage serve
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
  llm.py
  report.py
  cli.py
  api.py
  eval.py
tests/
fixtures/alerts/
fixtures/labels.json          tuning labels
fixtures/heldout/alerts/      alerts the rules were not tuned on
fixtures/heldout/labels.json
.env.example
.cursor/rules/ (or AGENTS.md) — mirror constitution safety
```

## Cursor workflow
1. Keep phase docs as source of truth
2. Implement **one** `tasks.md` item per PR
3. Cloud agent prompt = task id + acceptance criteria + link to plan section
4. Rules-only path must always work without secrets
5. LLM path requires an explicit opt-in (`soc-triage run --llm-notes`, `llm_notes=true`, or `soc-triage serve --llm-notes`) and `SOC_TRIAGE_LLM_PROVIDER=openai_compatible`. CI and the default demo omit the flag, so they make no network call.

## Risks & mitigations
| Risk | Mitigation |
|------|------------|
| Toy data looks fake | Mix categories; document dataset provenance |
| LLM hallucinations in notes | Notes cite rule reasons + alert fields; severity from rules |
| Scope creep to “full SIEM” | Non-goals list; UI last |
| Resume overclaim | README limitations section required |

## Optional LLM notes (T7)
`soc-triage run --llm-notes` rewrites note text when the provider is `openai_compatible` and the base URL and model are set. The default provider is `none`. The client posts to `{base_url}/chat/completions` with the standard library (xAI Grok at `https://api.x.ai/v1`, OpenAI, or Ollama at `http://localhost:11434/v1` with no key). Severity, confidence, `needs_review`, and reasons always come from `rules.score_alert`. The model sees delimited alert fields and rule reasons and is told not to invent facts. The timeout default is 8 seconds. Missing config, transport errors, and empty or oversized text fall back to `notes.draft_note`. JSON records `note_source` as `rules` or `llm`. Markdown marks model notes `AI-drafted, analyst review required.` Eval does not call the model.

## Local API (T8)
`soc-triage serve` imports FastAPI only when the `api` extra is installed (`pip install -e ".[api]"`). The base install and the CLI do not require it. The default bind is `127.0.0.1:8000`. `POST /triage` takes one `Alert`. `POST /triage/batch` takes a JSON list of at most 500. Both call `report.build_report`, so the score and the note match `soc-triage run`. `GET /fixtures/demo` triages `fixtures/alerts`. `GET /health` and `/docs` are local convenience. Request bodies are capped at 1 MiB. Invalid input is HTTP 422 with no stack trace. There is no authentication and no CORS wildcard. LLM notes stay off unless the request sets `llm_notes=true` or the process was started with `--llm-notes`. The fallback is the same template note as T7. The service is a local demo and needs authentication before any network exposure.

## Phased delivery
- **P0:** schema, fixtures, rules, CLI, tests, eval
- **P1:** optional LLM notes (T7), FastAPI read API (T8)
- **P2:** held-out set and within-one accuracy (T9), then a tiny dashboard
