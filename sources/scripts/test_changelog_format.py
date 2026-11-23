"""
test_changelog_format.py — CHANGELOG.md has one dated entry per release,
newest first: `## X.Y.Z (YYYY-MM-DD)`, closed by one `## Before 3.1.0`
section for the untagged versions.
"""

import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import constants

HEADING = re.compile(r"^## (\d+)\.(\d+)\.(\d+) \(\d{4}-\d{2}-\d{2}\)$")


def headings():
    text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.startswith("## ")]


class TestChangelogFormat(unittest.TestCase):
    def test_every_release_has_a_dated_entry(self):
        hs = headings()
        self.assertEqual(hs[-1], "## Before 3.1.0")
        bad = [h for h in hs[:-1] if not HEADING.match(h)]
        self.assertEqual(bad, [])

    def test_newest_first_from_310_to_current(self):
        versions = [tuple(int(x) for x in HEADING.match(h).groups())
                    for h in headings()[:-1]]
        self.assertEqual(versions, sorted(versions, reverse=True))
        self.assertEqual(versions[-1], (3, 1, 0))
        self.assertIn((3, 2, 0), versions)
        self.assertIn((3, 3, 0), versions)
        current = tuple(int(x) for x in constants.__version__.split("."))
        self.assertEqual(versions[0], current)

    def test_no_dead_data_tag_link(self):
        text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertNotIn("/domainnova/data-2026-11-23/", text)


if __name__ == "__main__":
    unittest.main()
