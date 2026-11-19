"""v3.8.0: backfill_provenance.py rebuilds the origin of every extended.txt
domain from git history, so the registry is reproducible."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _provenance as prov  # noqa: E402
import backfill_provenance as bf  # noqa: E402

ENV = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1",
           GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")


class Backfill(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.manual = self.root / "sources" / "manual"
        self.manual.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")

    def git(self, *args, date=None):
        env = dict(ENV)
        if date:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"{date}T12:00:00+00:00"
        subprocess.run(["git", *args], cwd=self.root, env=env, check=True, capture_output=True)

    def commit(self, date, discovery=None, extended=None):
        if discovery is not None:
            (self.manual / "discovery.txt").write_text(discovery, encoding="utf-8")
        if extended is not None:
            (self.manual / "extended.txt").write_text(extended, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", date, date=date)

    def test_history(self):
        head = "# DomainNova - Extended Domains\n"
        self.commit("2026-03-27", extended=head + "imported.cn\n")
        self.commit("2026-04-11", discovery="# --- upstream:felixonmars-accelerated 2026-04-11 ---\nfromlist.cn\n")
        self.commit("2026-04-20", discovery="# --- ct-logs:%.cn 2026-04-20 ---\nfromct.cn\n",
                    extended=head + "imported.cn\nfromlist.cn\n")
        self.commit("2026-05-02", extended=head + "imported.cn\nfromlist.cn\nfromct.cn\nbyhand.cn\n")
        got = bf.reconstruct(self.root)
        self.assertEqual(got["imported.cn"][:2], ("manual", "first extended.txt, curated by hand"))
        self.assertEqual(got["imported.cn"][2], "2026-03-27")
        self.assertEqual(got["fromlist.cn"], ("dnsmasq-china-list", "accelerated-domains", "2026-04-11"))
        self.assertEqual(got["fromct.cn"], ("ct-logs", "%.cn", "2026-04-20"))
        self.assertEqual(got["byhand.cn"], ("manual", "added by hand", "2026-05-02"))

        self.assertEqual(bf.main(["--repo", str(self.root)]), 0)
        self.assertEqual(prov.load(self.root)["fromct.cn"][0], "ct-logs")
        # running it again changes nothing; existing rows are never overwritten
        prov.record(self.root, [])
        before = prov.path(self.root).read_bytes()
        bf.main(["--repo", str(self.root)])
        self.assertEqual(prov.path(self.root).read_bytes(), before)

    def test_shallow_clone_refused(self):
        self.commit("2026-03-27", extended="# x\nimported.cn\n")
        clone = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, clone)
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{self.root}", str(clone / "r")],
                       env=ENV, check=True, capture_output=True)
        self.assertNotEqual(bf.main(["--repo", str(clone / "r")]), 0)


if __name__ == "__main__":
    unittest.main()
