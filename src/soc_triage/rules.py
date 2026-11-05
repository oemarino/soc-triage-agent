"""Deterministic severity scoring.

TODO(T3): category baseline, IOC presence, burst/count heuristics, and
allowlist downgrades. Return severity, confidence, and reasons[] that cite
alert fields. If confidence is low, mark needs_review instead of guessing
critical. Rules are the only source of severity.
"""

TODO = "T3"
