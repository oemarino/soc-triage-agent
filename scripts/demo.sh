#!/usr/bin/env bash
# End-to-end demo for the synthetic SOC triage CLI.
# Install first: python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v soc-triage >/dev/null 2>&1; then
  echo "soc-triage is not on PATH. Create a venv, install with pip install -e \".[dev]\", and activate it." >&2
  exit 1
fi

echo "== soc-triage run fixtures/alerts =="
soc-triage run fixtures/alerts
echo
echo "== soc-triage eval =="
soc-triage eval
echo
echo "== soc-triage eval fixtures/heldout =="
soc-triage eval --alerts fixtures/heldout/alerts --labels fixtures/heldout/labels.json
