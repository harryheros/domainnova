#!/usr/bin/env python3
"""
test_version_consistency.py — pin the DomainNova version single-source.

Three things historically drifted:
  - constants.__version__  (now the source of truth)
  - README.md version badge (now the latest-release badge, which cannot drift)
  - workflow / log banner strings (no such literals at the moment, but if
    any are added in future, they must read from constants.__version__).

The README badge follows the latest GitHub release, so it no longer needs
a hand edit; the test keeps a hand-written badge from coming back.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sources" / "scripts"))

import constants  # noqa: E402


class TestVersionConsistency(unittest.TestCase):
    def test_constants_has_version(self):
        self.assertTrue(
            hasattr(constants, "__version__"),
            "constants.py must expose __version__",
        )
        self.assertRegex(
            constants.__version__,
            r"^\d+\.\d+\.\d+$",
            f"__version__ must be SemVer (got {constants.__version__!r})",
        )

    def test_readme_badge_cannot_go_stale(self):
        # The badge shows the latest GitHub release, so it never needs a
        # hand edit; a hand-written `version-vX.Y.Z` badge used to drift.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("img.shields.io/github/v/release/harryheros/domainnova", readme)
        self.assertNotIn("img.shields.io/badge/version-", readme)

if __name__ == "__main__":
    unittest.main(verbosity=2)
