#!/usr/bin/env python3
"""
test_schema_version.py — lock-down tests for _parse_schema_version().

Regression guard for a string-comparison bug discovered during code review:
the previous implementation compared IPNova's data.json schema_version field
as a string (`schema < "3.2"`), which would incorrectly treat "3.10" as
older than "3.2" because '1' < '2' in ASCII order. As IPNova approaches
schema 3.10 / 4.x, this would silently disable the CIDR→ASN map and
fall back to the static heuristic table.

These tests pin the new tuple-of-int comparison.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_domains as bd  # noqa: E402


class TestParseSchemaVersion(unittest.TestCase):
    def test_simple_two_part(self):
        self.assertEqual(bd._parse_schema_version("3.2"), (3, 2))

    def test_three_part(self):
        self.assertEqual(bd._parse_schema_version("3.2.1"), (3, 2, 1))

    def test_double_digit_minor_orders_correctly(self):
        # The original bug: "3.10" < "3.2" as strings.
        self.assertGreater(
            bd._parse_schema_version("3.10"),
            bd._parse_schema_version("3.2"),
        )
        self.assertGreater(
            bd._parse_schema_version("3.10"),
            bd._parse_schema_version("3.9"),
        )

    def test_major_version_jump(self):
        self.assertGreater(
            bd._parse_schema_version("4.0"),
            bd._parse_schema_version("3.99"),
        )

    def test_empty_string_is_zero(self):
        self.assertEqual(bd._parse_schema_version(""), (0,))

    def test_non_numeric_component_treated_as_zero(self):
        # "3.x" should not raise; an unknown component becomes 0.
        self.assertEqual(bd._parse_schema_version("3.x"), (3, 0))

    def test_min_schema_gate(self):
        MIN = (3, 2)
        self.assertFalse(bd._parse_schema_version("3.1") >= MIN)
        self.assertTrue(bd._parse_schema_version("3.2") >= MIN)
        self.assertTrue(bd._parse_schema_version("3.10") >= MIN)
        self.assertTrue(bd._parse_schema_version("4.0") >= MIN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
