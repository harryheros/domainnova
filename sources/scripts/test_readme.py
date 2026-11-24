"""README checks: header, badges, links and the toolkit line.

The README is the project's front page, so its links must work and its
version badge must never go stale (it follows the latest GitHub release).
"""

from __future__ import annotations

import re
import unicodedata
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = "domainnova"
NAME = "DomainNova"
COMMERCIAL = True  # sold under a commercial license through novaod
EXTRA_DOCS = ["docs/how-it-works.md"]  # other Markdown files whose links are checked
TOOLKIT_LINE = (
    "Part of the [Nova infrastructure toolkit](https://github.com/harryheros)."
)


def slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").replace("*", "").lower()
    text = "".join(ch for ch in text if ch.isalnum() or ch in " -_")
    return text.replace(" ", "-")


def anchors(text: str) -> set[str]:
    out, in_code = set(), False
    for line in text.splitlines():
        if line.startswith("```"):
            in_code = not in_code
        elif not in_code and re.match(r"^#{1,6} ", line):
            out.add(slug(line.lstrip("#").strip()))
    return out


def links(text: str) -> list[str]:
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    return re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(
        r'<img [^>]*src="([^"]+)"', text
    )


class TestReadme(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_header_is_left_aligned(self):
        # Title, a one-line blockquote, then badges: aligned left, as the
        # owner prefers (a centered header was tried and dropped).
        self.assertTrue(self.text.startswith("# " + NAME + "\n\n> "))
        self.assertNotIn("<div", self.text)

    def test_table_cells_are_short(self):
        # Tables only for short, grid-like data; a long cell leaves wide
        # blank areas in the other columns, so longer text goes in lists.
        in_code = False
        for line in self.text.splitlines():
            if line.startswith("```"):
                in_code = not in_code
            if in_code or not line.startswith("|") or re.match(r"^\|[-|: ]+\|$", line):
                continue
            for cell in line.strip("|").split(" | "):
                visible = (
                    re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", cell)
                    .replace("`", "")
                    .replace("*", "")
                )
                with self.subTest(cell=cell):
                    self.assertLessEqual(len(visible.strip()), 40)

    def test_version_badge_follows_the_latest_release(self):
        self.assertIn(f"img.shields.io/github/v/release/harryheros/{REPO}", self.text)
        self.assertNotIn("img.shields.io/badge/version-", self.text)

    def test_ends_with_the_toolkit_line(self):
        self.assertEqual(self.text.rstrip().splitlines()[-1], TOOLKIT_LINE)

    def test_licensing_link(self):
        if COMMERCIAL:
            self.assertIn("https://novaod.com/licensing", self.text)
        else:
            self.assertNotIn("novaod", self.text)

    def test_no_emoji_in_headings(self):
        for doc in ["README.md", *EXTRA_DOCS]:
            for line in (ROOT / doc).read_text(encoding="utf-8").splitlines():
                if line.startswith("#"):
                    with self.subTest(doc=doc, heading=line):
                        self.assertFalse(
                            any(unicodedata.category(c) == "So" for c in line)
                        )

    def test_links_resolve(self):
        for doc in ["README.md", *EXTRA_DOCS]:
            path = ROOT / doc
            text = path.read_text(encoding="utf-8")
            for target in links(text):
                if re.match(r"^[a-z]+:", target):
                    continue
                file_part, _, frag = target.partition("#")
                dest = (path.parent / file_part).resolve() if file_part else path
                with self.subTest(doc=doc, link=target):
                    self.assertTrue(dest.exists(), f"{target} does not exist")
                    if frag and dest.suffix == ".md":
                        self.assertIn(frag, anchors(dest.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
