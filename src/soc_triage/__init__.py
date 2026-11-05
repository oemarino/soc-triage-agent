"""SOC triage assistant for synthetic alerts.

Portfolio and practice tool. Not a production SIEM.
Severity comes from deterministic rules; a human makes the final call.
See constitution.md.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("soc-triage")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
