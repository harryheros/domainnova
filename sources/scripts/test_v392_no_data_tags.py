"""
test_v392_no_data_tags.py — v3.9.2: data versions are pinned by commit.

3.9.0 tagged every build that changed the data `data-YYYY-MM-DD`. A commit
of the weekly update pins the lists just as well, and a tag per build
crowded the repository's tags, so the tags are gone: no workflow step makes
them, the script is removed, and the README and the quality page explain how
to pin a version by commit.
"""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import build_quality_report

WORKFLOW = REPO / ".github" / "workflows" / "update.yml"
README = REPO / "README.md"


class TestNoDataTags(unittest.TestCase):
    def test_workflow_makes_no_data_tag(self):
        wf = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("data_tag.py", wf)
        self.assertNotIn("Tag data version", wf)

    def test_tag_script_is_gone(self):
        self.assertFalse((HERE / "data_tag.py").exists())

    def test_readme_pins_by_commit(self):
        readme = README.read_text(encoding="utf-8")
        self.assertNotIn("data-YYYY-MM-DD", readme)
        self.assertNotIn("/domainnova/data-", readme)
        self.assertIn("https://raw.githubusercontent.com/harryheros/domainnova/<commit>/dist/domains_cn.txt", readme)

    def test_quality_page_does_not_mention_tags(self):
        src = Path(build_quality_report.__file__).read_text(encoding="utf-8")
        self.assertNotIn("data-YYYY-MM-DD", src)


if __name__ == "__main__":
    unittest.main()
