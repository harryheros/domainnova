"""
v3.9.0: every published data build gets a fixed name.

data_tag.py tags the pushed commit data-YYYY-MM-DD (a second build the
same day: .2, .3 …), never moves a tag, and records the published counts
in the tag message. Tested against a local bare repository standing in
for GitHub.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import constants  # noqa: E402
import data_tag  # noqa: E402

REPO = HERE.parents[1]
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
}


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


class TagName(unittest.TestCase):
    def test_first_build_of_the_day(self):
        self.assertEqual(data_tag.tag_name("2026-11-23", set()), "data-2026-11-23")

    def test_later_builds_get_a_suffix(self):
        have = {"data-2026-11-23", "data-2026-11-23.2"}
        self.assertEqual(data_tag.tag_name("2026-11-23", have), "data-2026-11-23.3")

    def test_other_days_do_not_matter(self):
        self.assertEqual(data_tag.tag_name("2026-11-24", {"data-2026-11-23"}),
                         "data-2026-11-24")

    def test_message_has_counts_build_time_and_version(self):
        stats = json.loads((REPO / "data" / "stats.json").read_text(encoding="utf-8"))
        msg = data_tag.tag_message("data-2026-11-23", stats)
        self.assertIn(f"Published: {stats['dist_domains']:,} domains", msg)
        self.assertIn(f"CN {stats['buckets']['cn']['included']:,}", msg)
        self.assertIn(f"Built: {stats['generated_at']}", msg)
        self.assertIn(f"Code: v{constants.__version__}", msg)

    def test_message_without_stats(self):
        self.assertIn("Code: v", data_tag.tag_message("data-2026-11-23", {}))


class TagAndPush(unittest.TestCase):
    def setUp(self):
        self._env = patch.dict(os.environ, GIT_ENV)
        self._env.start()
        self.tmp = Path(tempfile.mkdtemp())
        self.origin = self.tmp / "origin.git"
        self.work = self.tmp / "work"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True)
        subprocess.run(["git", "clone", "-q", str(self.origin), str(self.work)],
                       check=True, capture_output=True)
        self.commit("v1")
        stats = self.tmp / "stats.json"
        stats.write_text(json.dumps({"dist_domains": 10, "buckets": {"cn": {"included": 7}},
                                     "generated_at": "2026-11-23T02:40:00Z"}))
        self._stats = patch.object(data_tag, "STATS", stats)
        self._stats.start()

    def tearDown(self):
        self._stats.stop()
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def commit(self, text):
        (self.work / "f.txt").write_text(text)
        git("add", "f.txt", cwd=self.work)
        git("commit", "-qm", text, cwd=self.work)
        git("push", "-q", "origin", "HEAD:main", cwd=self.work)

    def tag(self, **kw):
        return data_tag.run(cwd=self.work, day="2026-11-23", **kw)

    def origin_tag_commit(self, name):
        return git("rev-parse", f"{name}^{{commit}}", cwd=self.origin)

    def test_tags_head_and_pushes_an_annotated_tag(self):
        name = self.tag()
        self.assertEqual(name, "data-2026-11-23")
        self.assertEqual(self.origin_tag_commit(name), git("rev-parse", "HEAD", cwd=self.work))
        self.assertEqual(git("cat-file", "-t", name, cwd=self.origin), "tag")
        body = git("cat-file", "-p", name, cwd=self.origin)
        self.assertIn("Published: 10 domains (CN 7)", body)

    def test_second_build_same_day_does_not_move_the_first_tag(self):
        first_commit = git("rev-parse", "HEAD", cwd=self.work)
        self.tag()
        self.commit("v2")
        self.assertEqual(self.tag(), "data-2026-11-23.2")
        self.assertEqual(self.origin_tag_commit("data-2026-11-23"), first_commit)
        self.assertEqual(self.origin_tag_commit("data-2026-11-23.2"),
                         git("rev-parse", "HEAD", cwd=self.work))

    def test_tag_made_elsewhere_is_seen_on_the_remote(self):
        # A fresh CI checkout has no tags locally; names come from the remote.
        other = self.tmp / "other"
        subprocess.run(["git", "clone", "-q", str(self.origin), str(other)],
                       check=True, capture_output=True)
        data_tag.run(cwd=other, day="2026-11-23")
        self.commit("v2")
        self.assertEqual(self.tag(), "data-2026-11-23.2")

    def test_rerun_on_a_tagged_head_does_nothing(self):
        self.tag()
        self.assertEqual(self.tag(), "data-2026-11-23")
        out = git("ls-remote", "--tags", "--refs", str(self.origin), cwd=self.work)
        self.assertEqual(len(out.splitlines()), 1)

    def test_dry_run_pushes_nothing(self):
        self.assertEqual(self.tag(dry_run=True), "data-2026-11-23")
        self.assertEqual(git("ls-remote", "--tags", str(self.origin), cwd=self.work), "")

    def test_name_taken_during_the_push_moves_to_the_next(self):
        # The remote listing misses a tag pushed a moment later.
        real = data_tag.remote_tags
        calls = []

        def stale(remote, cwd):
            calls.append(1)
            return set() if len(calls) == 1 else real(remote, cwd)

        other = self.tmp / "other"
        subprocess.run(["git", "clone", "-q", str(self.origin), str(other)],
                       check=True, capture_output=True)
        data_tag.run(cwd=other, day="2026-11-23")
        self.commit("v2")
        with patch.object(data_tag, "remote_tags", stale):
            self.assertEqual(self.tag(), "data-2026-11-23.2")
        self.assertEqual(git("tag", "--list", "data-*", cwd=self.work).split(),
                         ["data-2026-11-23.2"])


class Workflow(unittest.TestCase):
    def test_workflow_tags_only_after_a_pushed_data_commit(self):
        wf = (REPO / ".github" / "workflows" / "update.yml").read_text(encoding="utf-8")
        self.assertIn("python sources/scripts/data_tag.py", wf)
        step = wf.split("name: Tag data version", 1)[1].split("- name:", 1)[0]
        self.assertIn("steps.commit.outputs.pushed == 'true'", step)
        self.assertIn('echo "pushed=true" >> "$GITHUB_OUTPUT"', wf)

    def test_readme_explains_pinning(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        self.assertIn("/domainnova/data-", readme)


if __name__ == "__main__":
    unittest.main()
