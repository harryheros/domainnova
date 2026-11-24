#!/usr/bin/env python3
"""
test_version_consistency.py — pin the DomainNova version single-source.

Three things historically drifted:
  - constants.__version__  (now the source of truth)
  - README.md shields badge `version-vX.Y.Z-blue`
  - workflow / log banner strings (no such literals at the moment, but if
    any are added in future, they must read from constants.__version__).

This test catches README badge drift at CI time, so the static badge never
lags behind the released code.
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

    def test_readme_badge_matches_version(self):
        # Static badge, updated with each release (a badge that made
        # shields.io query GitHub showed as a broken image).
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            f"img.shields.io/badge/version-v{constants.__version__}-blue", readme
        )
        self.assertNotIn("img.shields.io/github/", readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
