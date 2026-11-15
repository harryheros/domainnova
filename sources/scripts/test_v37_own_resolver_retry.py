"""
v3.7.1: our own resolver is asked a second time only when the first try
failed (no HTTP answer, SERVFAIL, REFUSED…), not when it answered that the
name has no address (NXDOMAIN, or NOERROR with no A record). Before, every
name without an address cost two lookups at our resolver, and with the
www. fallback up to four, before the public resolvers were even asked.
"""
import importlib
import os
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_domains  # noqa: E402

OWN = "https://dns.example/ecs-x"


class FakeResponse:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content


def wire_answer(bd, name, rcode, ips=()):
    """A DNS response to bd's own query for name, with rcode and A records."""
    q = bytearray(bd._encode_dns_wire_query(name))
    qdend = 12
    while q[qdend] != 0:
        qdend += q[qdend] + 1
    qdend += 5  # root label, QTYPE, QCLASS
    resp = bytearray(q[:qdend])
    resp[2:4] = struct.pack(">H", 0x8180 | rcode)
    resp[6:8] = struct.pack(">H", len(ips))
    resp[8:12] = b"\x00\x00\x00\x00"
    for ip in ips:
        resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes(int(x) for x in ip.split("."))
    return bytes(resp)


class FakeSession:
    """Answers our resolver with the scripted responses, in order."""

    def __init__(self, bd, script):
        self.bd, self.script, self.calls = bd, list(script), []

    def post(self, url, data=None, timeout=None, headers=None):
        self.calls.append(url)
        kind = self.script.pop(0)
        if kind == "down":
            raise build_domains.requests.ConnectionError("down")
        if kind == "http500":
            return FakeResponse(500)
        rcode, ips = kind
        return FakeResponse(200, wire_answer(self.bd, "example.cn", rcode, ips))


class OwnResolverRetry(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"DOMAINNOVA_DOH_URL": OWN, "DOMAINNOVA_PUBLIC_DOH": "off"})
        self.env.start()
        self.bd = importlib.reload(build_domains)
        self.sleep = patch.object(self.bd.time, "sleep")
        self.sleep.start()

    def tearDown(self):
        self.sleep.stop()
        self.env.stop()
        importlib.reload(build_domains)

    def asked(self, script):
        s = FakeSession(self.bd, script)
        ips = self.bd._resolve_name("example.cn", s)
        return ips, len(s.calls)

    def test_answer_used_at_once(self):
        self.assertEqual(self.asked([(0, ["1.0.1.1"])]), (["1.0.1.1"], 1))

    def test_nxdomain_asked_once(self):
        self.assertEqual(self.asked([(3, [])]), ([], 1))

    def test_no_address_asked_once(self):
        self.assertEqual(self.asked([(0, [])]), ([], 1))

    def test_servfail_asked_again(self):
        self.assertEqual(self.asked([(2, []), (0, ["1.0.1.1"])]), (["1.0.1.1"], 2))

    def test_refused_asked_again(self):
        self.assertEqual(self.asked([(5, []), (0, ["1.0.1.1"])]), (["1.0.1.1"], 2))

    def test_transport_failure_asked_again(self):
        self.assertEqual(self.asked(["down", (0, ["1.0.1.1"])]), (["1.0.1.1"], 2))
        self.assertEqual(self.asked(["http500", (3, [])]), ([], 2))

    def test_public_resolvers_still_asked_after_nxdomain_when_on(self):
        with patch.dict(os.environ, {"DOMAINNOVA_PUBLIC_DOH": "on"}):
            bd = importlib.reload(build_domains)
        with patch.object(bd.time, "sleep"), \
             patch.object(bd, "_do_resolve", return_value=["1.0.1.1"]) as public:
            s = FakeSession(bd, [(3, [])])
            self.assertEqual(bd._resolve_name("example.cn", s), ["1.0.1.1"])
        self.assertEqual(len(s.calls), 1)
        public.assert_called()


if __name__ == "__main__":
    unittest.main()
