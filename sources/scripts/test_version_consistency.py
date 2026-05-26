#!/usr/bin/env python3
"""
test_version_consistency.py — pin the DomainNova version single-source.

Three things historically drifted:
  - constants.__version__  (now the source of truth)
  - README.md shields badge `version-vX.Y-blue`
  - workflow / log banner strings (no such literals at the moment, but if
    any are added in future, they must read from constants.__version__).

This test catches the README divergence at CI time so the badge is never
stale relative to the released code.
"""
from __future__ import annotations

import re
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
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        m = re.search(r"version-v(\d+\.\d+)(?:\.\d+)?-blue", readme)
        self.assertIsNotNone(m, "README must contain a version badge")
        badge = m.group(1)
        # README badge typically shows major.minor only; verify the prefix.
        actual_prefix = ".".join(constants.__version__.split(".")[:2])
        self.assertEqual(
            badge,
            actual_prefix,
            f"README badge {badge!r} disagrees with "
            f"constants.__version__ {constants.__version__!r}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
