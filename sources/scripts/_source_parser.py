"""
_source_parser.py — shared parsing primitives for the manual seed/extended
source files used by both build_metadata.py and validate_manual_sources.py.

Each file in sources/manual/ uses a small text grammar:
  - blank lines and comment lines (`#`) are ignored
  - lines matching `# === Section Name ===` open a named section
  - everything else is a domain, attributed to the current section

This module exposes the single source of truth for the regex shapes
and the line iterator. Higher-level callers can layer their own
collection or validation logic on top via iter_source_entries().

Pure functions (no I/O beyond reading the path passed in); safe to
import anywhere.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Tuple

# ---------------------------------------------------------------------------
# Regex shared by every consumer.
# ---------------------------------------------------------------------------
HEADER_RE = re.compile(r"^#\s*=+\s*(.*?)\s*=+\s*$")

# RFC 1123 strict domain pattern. Both build_metadata and
# validate_manual_sources used to ship private copies; consolidating
# eliminated a drift bug where build_metadata used a looser
# `[A-Za-z0-9.-]+` regex that accepted strings the validator later flagged.
#
# Per-label rules (RFC 1123 §2.1):
#   - length 1..63
#   - must start AND end with [a-z0-9]
#   - hyphens permitted only in the interior
#
# Original pattern enforced these for non-final labels but used the looser
# class `[a-z0-9-]{2,63}` for the TLD, which silently accepted `foo.-bar`,
# `foo.bar-`, `foo.-baz-`. The TLD is now constrained to the same shape
# as other labels, with a minimum length of 2 characters (single-letter
# TLDs don't exist in the IANA root zone).
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
)

UNSECTIONED = "Unsectioned"


def iter_source_entries(
    path: Path,
) -> Iterator[Tuple[str, str]]:
    """Yield ``(section, raw_domain)`` pairs for every non-comment, non-blank
    line in `path`. The caller decides what to do with each pair:

      - build_metadata.py keeps only entries that pass DOMAIN_RE and tags
        them with section-based ecosystem metadata.
      - validate_manual_sources.py keeps every entry (including invalid
        ones) so it can report duplicates and invalid format counts.

    Yielded ``raw_domain`` is already lowercased and trailing-dot-stripped
    but is NOT validated — the caller must apply DOMAIN_RE if it wants
    only RFC-conformant entries.

    Section name is the most-recent `# === Section Name ===` header,
    or "Unsectioned" before any header is seen.

    Silently returns nothing if `path` does not exist. Callers that need
    to distinguish "missing file" from "empty file" must check existence
    themselves.
    """
    if not path.exists():
        return

    section = UNSECTIONED
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = HEADER_RE.match(line)
            if m:
                section = m.group(1).strip()
            continue
        yield section, line.lower().rstrip(".")
