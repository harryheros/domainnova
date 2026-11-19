"""
_psl.py - the Public Suffix List (https://publicsuffix.org/).

A public suffix is a name under which anyone can register: `com`, `com.cn`,
`com.my`, and, in the list's private section, names that a company hands
out to its users (`sakura.ne.jp`, `myshopify.com`, `github.io`). The
registrable name of a host is its public suffix plus one label.

Implements the list's algorithm (https://github.com/publicsuffix/list/wiki/Format):
the longest matching rule wins, `*.x` matches any one label under x, an
exception `!y.x` wins over everything and makes x the suffix, and a name
that matches no rule has its last label as suffix. Rules in Unicode are
also matched in their ASCII (xn--) form, which is the form in the data.

Reads sources/third_party/public_suffix_list.dat (MPL-2.0) once. Pure stdlib.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Tuple

LIST_PATH = Path(__file__).resolve().parents[1] / "third_party" / "public_suffix_list.dat"

ICANN, PRIVATE = "icann", "private"


def _ascii(name: str) -> Optional[str]:
    try:
        return ".".join(
            lab if lab.isascii() else "xn--" + lab.encode("punycode").decode("ascii")
            for lab in name.split("."))
    except UnicodeError:
        return None


@lru_cache(maxsize=None)
def _load(path: Path = LIST_PATH) -> Tuple[Dict[str, str], Dict[str, str], FrozenSet[str]]:
    """-> (rules, wildcards, exceptions). rules and wildcards map a name
    (for a wildcard, the name under the `*`) to its section."""
    rules: Dict[str, str] = {}
    wildcards: Dict[str, str] = {}
    exceptions = set()
    section = ICANN
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("// ===BEGIN PRIVATE DOMAINS"):
            section = PRIVATE
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        for form in {rule, _ascii(rule)} - {None}:
            if form.startswith("!"):
                exceptions.add(form[1:])
            elif form.startswith("*."):
                wildcards[form[2:]] = section
            else:
                rules[form] = section
    if len(rules) < 1000:
        raise RuntimeError(f"{path} does not look like the Public Suffix List")
    return rules, wildcards, frozenset(exceptions)


def _labels(host: str) -> list:
    return host.strip().lower().rstrip(".").split(".")


def _suffix(labels: list, private: bool) -> Tuple[int, str]:
    """-> (number of labels in the public suffix, section of the rule)."""
    rules, wildcards, exceptions = _load()
    n = len(labels)
    for i in range(n):  # an exception wins over every other rule
        if ".".join(labels[i:]) in exceptions:
            parent = ".".join(labels[i + 1:])
            return n - i - 1, rules.get(parent, wildcards.get(parent, ICANN))
    best, section = 1, ICANN  # the implicit "*" rule
    for i in range(n):
        name = ".".join(labels[i:])
        size = n - i
        for table, extra in ((rules, 0), (wildcards, 1)):
            sec = table.get(name)
            if sec is None or (sec == PRIVATE and not private):
                continue
            if extra and i == 0:
                continue  # "*.x" needs a label under x
            if size + extra > best:
                best, section = size + extra, sec
    return best, section


def public_suffix(host: str, private: bool = True) -> str:
    """news.sina.com.cn -> com.cn; x.sakura.ne.jp -> sakura.ne.jp
    (ne.jp with private=False)."""
    labels = _labels(host)
    size, _ = _suffix(labels, private)
    return ".".join(labels[-size:])


def is_public_suffix(name: str, private: bool = True) -> bool:
    labels = _labels(name)
    return _suffix(labels, private)[0] >= len(labels)


def registrable(host: str, private: bool = True) -> Optional[str]:
    """news.sina.com.cn -> sina.com.cn; None for a public suffix itself."""
    labels = _labels(host)
    if not all(labels):
        return None
    size, _ = _suffix(labels, private)
    if size >= len(labels):
        return None
    return ".".join(labels[-size - 1:])


def private_suffix(host: str) -> Optional[str]:
    """The private-section suffix `host` is or is under, else None."""
    labels = _labels(host)
    size, section = _suffix(labels, True)
    return ".".join(labels[-size:]) if section == PRIVATE else None


def rule_counts() -> Tuple[int, int]:
    """(ICANN rules, private rules), counting each rule's forms."""
    rules, wildcards, exceptions = _load()
    secs = list(rules.values()) + list(wildcards.values())
    return secs.count(ICANN), secs.count(PRIVATE)
