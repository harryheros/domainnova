#!/usr/bin/env python3
"""
Unit tests for compare_resolvers.py and the own-resolver settings
(DOMAINNOVA_DOH_URL, DOMAINNOVA_PUBLIC_DOH). No network calls.
"""
from __future__ import annotations

import importlib
import ipaddress
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_domains  # noqa: E402
import compare_resolvers as cr  # noqa: E402

LOOKUP = build_domains.build_region_lookup({
    "CN": [ipaddress.ip_network("1.0.1.0/24")],
    "HK": [ipaddress.ip_network("1.0.2.0/24")],
    "JP": [ipaddress.ip_network("1.0.3.0/24")],
})


def fixed(answers):
    """A resolver answering from a dict: name -> IPs (None: failure)."""
    def resolve(name, subnet):
        return answers.get(name, [])
    return resolve


class RegionOf(unittest.TestCase):
    def test_share(self):
        self.assertEqual(cr.region_of(["1.0.1.1", "1.0.1.2", "1.0.2.1"], LOOKUP), "CN")  # 2/3
        self.assertEqual(cr.region_of(["1.0.1.1", "1.0.2.1"], LOOKUP), "")  # half each
        self.assertEqual(cr.region_of(["9.9.9.9"], LOOKUP), "")
        self.assertEqual(cr.region_of([], LOOKUP), "")

    def test_subnet_is_stable(self):
        self.assertEqual(cr.subnet_for("example.cn"), cr.subnet_for("example.cn"))
        self.assertIn(cr.subnet_for("example.cn"), build_domains.ECS_SUBNETS)


class CompareOne(unittest.TestCase):
    def test_outcomes(self):
        own = fixed({"a.cn": ["1.0.1.1"], "b.cn": ["1.0.2.1"], "c.cn": [], "d.cn": None, "www.e.cn": ["1.0.3.1"]})
        goo = fixed({"a.cn": ["1.0.1.9"], "b.cn": ["1.0.1.9"], "c.cn": ["1.0.1.9"], "d.cn": ["1.0.1.9"], "www.e.cn": ["1.0.3.9"]})
        got = {d: cr.compare_one(d, "CN", own, goo, LOOKUP)["outcome"] for d in ("a.cn", "b.cn", "c.cn", "d.cn", "e.cn")}
        self.assertEqual(got, {"a.cn": "agree", "b.cn": "differ", "c.cn": "own_no_answer", "d.cn": "own_failed", "e.cn": "agree"})
        r = cr.compare_one("e.cn", "JP", own, goo, LOOKUP)
        self.assertEqual((r["own"]["name"], r["own"]["region"]), ("www.e.cn", "JP"))

    def test_summary(self):
        rows = [{"listed": "CN", "outcome": o} for o in ("agree", "agree", "agree", "differ", "own_failed")]
        s = cr.summarise(rows)
        self.assertEqual(s["agreement"], 0.75)  # failures are not counted against it
        self.assertEqual(s["by_listed_region"]["CN"]["agree"], 3)


class OwnResolverSettings(unittest.TestCase):
    def reload(self, env):
        with patch.dict(os.environ, env, clear=False):
            return importlib.reload(build_domains)

    def tearDown(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DOMAINNOVA_DOH_URL", None)
            os.environ.pop("DOMAINNOVA_PUBLIC_DOH", None)
            importlib.reload(build_domains)

    def test_default_is_public_resolvers_only(self):
        os.environ.pop("DOMAINNOVA_DOH_URL", None)
        os.environ.pop("DOMAINNOVA_PUBLIC_DOH", None)
        bd = importlib.reload(build_domains)
        self.assertEqual(bd.DOH_RESCUE, "")
        self.assertTrue(bd.PUBLIC_DOH)
        self.assertNotIn("", bd.DOH_UPSTREAMS)
        # no tier 0 is asked: straight to the public resolvers
        with patch.object(bd, "_resolve_via_json") as j, patch.object(bd, "_resolve_via_wire") as w:
            self.assertEqual(bd._resolve_rescue("example.cn", None), [])
            j.assert_not_called()
            w.assert_not_called()

    def test_own_resolver_first_public_off(self):
        bd = self.reload({"DOMAINNOVA_DOH_URL": "https://dns.example/ecs-x", "DOMAINNOVA_PUBLIC_DOH": "off"})
        self.assertEqual(bd.DOH_RESCUE, "https://dns.example/ecs-x")
        self.assertEqual(bd._rescue_mode, "wire")
        self.assertFalse(bd.PUBLIC_DOH)
        asked = []
        with patch.object(bd, "_resolve_rescue", return_value=[]), \
             patch.object(bd, "_do_resolve", side_effect=lambda d, u, s: asked.append(u) or ["1.0.1.1"]):
            self.assertEqual(bd._resolve_name("example.cn", None), [])
        self.assertEqual(asked, [], "public resolvers asked with DOMAINNOVA_PUBLIC_DOH=off")

    def test_own_resolver_asked_twice(self):
        bd = self.reload({"DOMAINNOVA_DOH_URL": "https://dns.example/ecs-x", "DOMAINNOVA_PUBLIC_DOH": "off"})
        answers = [[], ["1.0.1.1"]]
        with patch.object(bd, "_resolve_rescue", side_effect=lambda d, s: answers.pop(0)):
            self.assertEqual(bd._resolve_name("example.cn", None), ["1.0.1.1"])
        # without our own resolver configured, tier 0 is asked once (and has nothing)
        bd = self.reload({"DOMAINNOVA_DOH_URL": "", "DOMAINNOVA_PUBLIC_DOH": "off"})
        calls = []
        with patch.object(bd, "_resolve_rescue", side_effect=lambda d, s: calls.append(d) or []):
            bd._resolve_name("example.cn", None)
        self.assertEqual(len(calls), 1)

    def test_public_fallback_when_on(self):
        bd = self.reload({"DOMAINNOVA_DOH_URL": "https://dns.example/ecs-x", "DOMAINNOVA_PUBLIC_DOH": ""})
        with patch.object(bd, "_resolve_rescue", return_value=[]), \
             patch.object(bd, "_do_resolve", return_value=["1.0.1.1"]):
            self.assertEqual(bd._resolve_name("example.cn", None), ["1.0.1.1"])


class AgentWire(unittest.TestCase):
    def test_query_and_answer(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "discovery_agents"))
        import agent_ip_neighbor as agent
        q = agent._wire_query("www.example.cn", "219.141.140.0/24")
        self.assertIn(b"\x00\x08\x00\x07\x00\x01\x18\x00\xdb\x8d\x8c", q)  # ECS: IPv4 /24 219.141.140
        self.assertIn(b"\x03www\x07example\x02cn\x00", q)
        # a response: the question, then two A records (one through a pointer)
        resp = bytearray(q[:12])
        resp[2:4] = b"\x81\x80"
        resp[6:8] = b"\x00\x02"
        resp[10:12] = b"\x00\x00"
        resp += b"\x03www\x07example\x02cn\x00\x00\x01\x00\x01"
        resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([1, 0, 1, 1])
        resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([1, 0, 1, 2])
        self.assertEqual(agent._answer_ipv4(bytes(resp)), ["1.0.1.1", "1.0.1.2"])
        resp[3] = 0x83  # NXDOMAIN
        self.assertEqual(agent._answer_ipv4(bytes(resp)), [])


if __name__ == "__main__":
    unittest.main()
