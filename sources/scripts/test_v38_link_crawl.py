"""Tests for agent_link_crawl.py (offline: pages and robots.txt are served by a fake session)."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "discovery_agents"))

import agent_link_crawl as lc  # noqa: E402
import _provenance  # noqa: E402

PAGES = {
    "https://seed-one.cn/": """<html><a href="https://news.newsite.com.cn/a">x</a>
        <a href='//cdn.other.cn/x.js'>y</a> <img src="http://img.third.com.hk/p.png">
        <a href="/local">local</a> <a href="https://known.cn/">k</a>
        <a href="https://sub.known.cn/">covered</a> <a href="https://www.google.com/">g</a>
        <a href="https://10.0.0.1/">ip</a> <a href="mailto:a@b.cn">m</a>
        <a href="https://bad--lookalike.cn/">lookalike</a>
        <script src="https://www.googletagmanager.com/gtm.js"></script>
        <a href="https://www.linkedin.com/company/x">in</a>
        <script src="//cdn.jsdelivr.net/npm/x.js"></script></html>""",
    "https://seed-two.hk/": '<a href="https://newsite.com.cn/">dup</a><a href="https://another.com.hk/">n</a>',
    "https://blocked.cn/": '<a href="https://never.cn/">should not be read</a>',
}
ROBOTS = {
    "https://blocked.cn/robots.txt": "User-agent: *\nDisallow: /\n",
}


class FakeResponse:
    def __init__(self, url, status, text="", ctype="text/html; charset=utf-8"):
        self.url, self.status_code, self._text = url, status, text
        self.headers = {"Content-Type": ctype}
        self.encoding = "utf-8"
        self.text = text

    def iter_content(self, chunk_size=65536):
        data = self._text.encode("utf-8")
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]

    def close(self):
        pass


class FakeSession:
    def __init__(self):
        self.requested = []
        self.headers = {}

    def get(self, url, timeout=None, stream=False, allow_redirects=True):
        self.requested.append(url)
        if url.endswith("/robots.txt"):
            if url in ROBOTS:
                return FakeResponse(url, 200, ROBOTS[url], "text/plain")
            return FakeResponse(url, 404)
        if url in PAGES:
            return FakeResponse(url, 200, PAGES[url])
        return FakeResponse(url, 404)


class Helpers(unittest.TestCase):
    def test_registrable(self):
        r = lc.registrable
        self.assertEqual(r("news.sina.com.cn"), "sina.com.cn")
        self.assertEqual(r("www.beijing.gov.cn"), "beijing.gov.cn")
        self.assertEqual(r("a.b.example.cn"), "example.cn")
        self.assertEqual(r("shop.example.co.jp"), "example.co.jp")
        self.assertEqual(r("x.bj.cn"), "x.bj.cn")
        self.assertEqual(r("img.third.com.hk"), "third.com.hk")
        self.assertEqual(r("example.com"), "example.com")
        self.assertIsNone(r("com.cn"))
        self.assertIsNone(r("localhost"))

    def test_hosts_in(self):
        hosts = lc.hosts_in(PAGES["https://seed-one.cn/"])
        self.assertIn("news.newsite.com.cn", hosts)
        self.assertIn("cdn.other.cn", hosts)
        self.assertIn("img.third.com.hk", hosts)
        self.assertNotIn("local", " ".join(hosts))

    def test_pages_rotate_through_every_domain(self):
        domains = [f"d{i}.cn" for i in range(10)]
        seen = set()
        for week in range(4):
            seen |= set(lc.pick_pages(domains, 3, week))
        self.assertEqual(len(lc.pick_pages(domains, 3, 0)), 3)
        self.assertEqual(seen, set(domains))  # four weeks of 3 cover all 10


class Run(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        manual = self.root / "sources" / "manual"
        manual.mkdir(parents=True)
        (manual / "seed_cn.txt").write_text("# seeds\nseed-one.cn\nblocked.cn\nknown.cn\n", encoding="utf-8")
        (manual / "seed_hk.txt").write_text("# seeds\nseed-two.hk\n", encoding="utf-8")
        (manual / "extended.txt").write_text("# extended\n", encoding="utf-8")
        (manual / "discovery.txt").write_text("# DomainNova - Discovery Layer\n", encoding="utf-8")

    def run_agent(self, **kw):
        session = FakeSession()
        with patch.object(lc, "make_session", return_value=session), patch("builtins.print"):
            added = lc.run(self.root, pages=10, week=0, **kw)
        return added, session

    def test_candidates_with_referrer(self):
        added, session = self.run_agent()
        disc = _provenance.discovery_sections(self.root / "sources" / "manual" / "discovery.txt")
        self.assertEqual(disc["newsite.com.cn"][:2], ("link-crawl", "seed-one.cn"))
        self.assertEqual(disc["other.cn"][:2], ("link-crawl", "seed-one.cn"))
        self.assertEqual(disc["third.com.hk"][:2], ("link-crawl", "seed-one.cn"))
        self.assertEqual(disc["another.com.hk"][:2], ("link-crawl", "seed-two.hk"))
        for gone in ("known.cn", "google.com", "bad--lookalike.cn", "never.cn",
                     "googletagmanager.com", "linkedin.com", "jsdelivr.net"):
            self.assertNotIn(gone, disc)
        self.assertEqual(added, 4)
        # robots.txt was honoured: the blocked page was never fetched
        self.assertIn("https://blocked.cn/robots.txt", session.requested)
        self.assertNotIn("https://blocked.cn/", session.requested)
        self.assertNotIn("http://blocked.cn/", session.requested)

    def test_budget_and_capacity(self):
        added, _ = self.run_agent(max_new=2)
        self.assertEqual(added, 2)
        with patch.object(lc, "DISCOVERY_MAX", 0):
            added, session = self.run_agent()
        self.assertEqual((added, session.requested), (0, []))

    def test_all_sites_reads_every_known_site(self):
        manual = self.root / "sources" / "manual"
        many = [f"site{i:02d}.cn" for i in range(30)]
        (manual / "extended.txt").write_text("# extended\n" + "\n".join(many) + "\n", encoding="utf-8")
        session = FakeSession()
        with patch.object(lc, "make_session", return_value=session), patch("builtins.print"):
            lc.run(self.root, pages=3, week=0, all_sites=True)
        read = {u.split("/")[2] for u in session.requested if not u.endswith("robots.txt")}
        self.assertTrue(set(many) <= read)
        # the weekly slice reads only `pages` sites
        session = FakeSession()
        with patch.object(lc, "make_session", return_value=session), patch("builtins.print"):
            lc.run(self.root, pages=3, week=0)
        read = {u.split("/")[2] for u in session.requested if not u.endswith("robots.txt")}
        self.assertLessEqual(len(read), 3)

    def test_main_all_flag(self):
        with patch.object(lc, "run") as run:
            lc.main(["--all"])
        self.assertEqual(run.call_args.kwargs, {"max_new": lc.ALL_MAX_NEW, "all_sites": True})
        with patch.object(lc, "run") as run:
            lc.main([])
        self.assertEqual(run.call_args.kwargs, {})

    def test_workflow_full_crawl_input(self):
        wf = (Path(__file__).resolve().parents[2] / ".github" / "workflows" / "update.yml").read_text()
        self.assertIn("full_crawl:", wf)
        self.assertIn("github.event.inputs.full_crawl == 'yes'", wf)
        self.assertIn("agent_link_crawl.py --all", wf)
        # the input reaches the shell through env, never interpolated into it
        self.assertNotIn("${{ github.event.inputs.full_crawl }}\n          then", wf)
        self.assertIn('if [ "$FULL_CRAWL" = "yes" ]', wf)

    def test_a_connection_dropped_mid_page_does_not_stop_the_run(self):
        # v3.8.0 full crawl: one site's chunked body broke off mid-read
        # (urllib3 ProtocolError surfaced by iter_content) and the uncaught
        # exception ended the whole run with nothing written.
        import requests

        class Broken(FakeResponse):
            def iter_content(self, chunk_size=65536):
                yield b"<a href='https://partial.cn/'>"
                raise requests.exceptions.ChunkedEncodingError("Connection broken")

        class BadEncoding(FakeResponse):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                self.encoding = "x-no-such-codec"

        class Session(FakeSession):
            def get(self, url, **kw):
                if url == "https://seed-one.cn/":
                    self.requested.append(url)
                    return Broken(url, 200, "")
                if url == "https://seed-two.hk/":
                    self.requested.append(url)
                    return BadEncoding(url, 200, PAGES.get(url, "<a href='https://enc.hk/'>"))
                if url == "https://known.cn/robots.txt":
                    raise requests.exceptions.ConnectionError("reset")
                return super().get(url, **kw)

        session = Session()
        with patch.object(lc, "make_session", return_value=session), patch("builtins.print"):
            lc.run(self.root, pages=10, week=0)
        # every site was still visited, and the run finished
        self.assertIn("https://seed-two.hk/", session.requested)
        self.assertIn("https://known.cn/", session.requested)

    def test_crawl_site_never_raises(self):
        class Exploding(FakeSession):
            def get(self, url, **kw):
                raise RuntimeError("anything at all")
        self.assertEqual(lc.crawl_site(Exploding(), "x.cn"), [])

    def test_regional_tlds_first(self):
        ordered = lc.prioritise(["a.com", "b.cn", "c.net", "d.com.hk", "e.jp"])
        self.assertEqual(ordered[:3], ["b.cn", "d.com.hk", "e.jp"])


class RealHTTP(unittest.TestCase):
    """crawl_site() with a real requests session against a local http-only server."""

    def serve(self, robots):
        import http.server
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/robots.txt" and robots is not None:
                    body, ctype = robots.encode(), "text/plain"
                elif self.path == "/":
                    body, ctype = b'<a href="https://linked.example.cn/">x</a>', "text/html; charset=utf-8"
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f"127.0.0.1:{srv.server_port}"

    def test_reads_page_over_http(self):
        site = self.serve(robots=None)
        self.assertEqual(lc.crawl_site(lc.make_session(total_retries=0), site), ["linked.example.cn"])

    def test_http_only_robots_disallow_is_honoured(self):
        site = self.serve(robots="User-agent: *\nDisallow: /\n")
        self.assertEqual(lc.crawl_site(lc.make_session(total_retries=0), site), [])


if __name__ == "__main__":
    unittest.main()
