"""
_local_view.py — the regional view, on trial (v3.9; nothing is published from it).

The build asks where a domain is hosted as a client in China would (the
client subnet of a Chinese carrier). For the other regions that view is
often wrong: a Hong Kong site with geographic DNS may send Chinese users
to a mainland CDN and its own users to its servers in Hong Kong. Of every
20 HK, MO, SG and TW seeds checked, only 1 or 2 resolve in their own region
this way; the rest are placed only because they are curated.

The regional view asks again with a client subnet inside the region: a
block of the region's main consumer ISP (CONSUMER_BLOCKS), whose users the
region's geographic DNS and CDNs certainly place there. Asked that way, though, a global service also answers from its node in the
region, so a domain found "local" this way must pass every guard below
before it counts, and for now nothing counts: each build only records what
the view would add and what the guards stopped (`data/stats.json` →
`local_view`, and `data/QUALITY.md`), so the guards can be judged on real
answers before the view is allowed to change a list.

Who is asked: domains with a regional hint, region R —
  - seeds of R (calibration: they are in R, so the view should find them),
  - non-seed domains under R's ccTLD that the build does not place in R,
  - control names of global services (they must never pass).

Verdicts, in order (the first that applies):
  cn-view-elsewhere  the build already places it in another region
  unresolved         no answer for R's subnet
  not-local          under 60% of the addresses are in R's IPNova ranges
  foreign-edge       counting only addresses outside the networks where the
                     control names land in R, under 60% are in R
  cdn                the addresses belong to a known global CDN
  follows-asker      a client elsewhere gets an answer elsewhere too: asked
                     from a probe region Q, the answer is in Q — a service
                     with a node near every client, not hosting in R
  local              passed (for a domain the build already places in R,
                     this confirms it)

A domain is added to `would_add` only after being `local` in two different
ISO weeks with no other verdict in between. For seeds the report also says
why the others were not found (`seed_verdicts`, with a few `seed_examples`).
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Callable, Dict, Iterable, List, Optional, Tuple

REGIONS = ("HK", "MO", "TW", "JP", "KR", "SG")   # CN keeps the build's own view
CCTLD_REGION = {r.lower(): r for r in REGIONS}
PROBE_REGION = {"HK": "SG", "MO": "SG", "TW": "SG", "JP": "SG", "KR": "SG", "SG": "HK"}
# Each region is asked from a block of its main consumer ISP. A region's
# largest IPNova range, used before v3.9.1 and still the fallback when IPNova
# no longer has the block in the region, can belong to a cloud or transit
# operator whose addresses are used worldwide: SG's was a cloud provider's
# 43.0.0.0/9 and HK's a transit operator's 63.216.0.0/13, so geographic DNS
# answered as for a client elsewhere (2 of 73 SG seeds found in SG).
CONSUMER_BLOCKS = {
    "HK": "113.252.0.0/14",   # HKT (Netvigator)
    "MO": "60.246.0.0/16",    # CTM
    "TW": "1.160.0.0/12",     # Chunghwa Telecom (HiNet)
    "JP": "126.0.0.0/8",      # SoftBank
    "KR": "121.128.0.0/10",   # KT
    "SG": "116.14.0.0/15",    # Singtel (SingNet)
}
THRESHOLD = 0.60
REQUIRED_WEEKS = 2
MAX_CHECKS = 3000

# Global services, asked from every region: the /24s where they answer
# inside a region are not regional hosting (foreign edges), and they are
# also checked as candidates, without that guard, to see that the others
# still stop them. First-party edges and global CDNs' customers both.
CONTROLS = (
    "www.google.com", "www.gstatic.com", "fonts.googleapis.com", "www.youtube.com",
    "www.googletagmanager.com", "www.facebook.com", "x.com", "www.linkedin.com",
    "www.apple.com", "www.microsoft.com", "www.amazon.com", "www.netflix.com",
    "www.reddit.com", "www.nytimes.com", "www.bbc.com", "www.booking.com",
    "www.spotify.com", "www.wikipedia.org", "www.cloudflare.com",
)

Resolve = Callable[[str, str], List[str]]          # (name, subnet) -> IPv4 addresses
Bucket = Callable[[str], str]                       # ip -> region or ""
Provider = Callable[[List[str]], Tuple[str, int]]   # ips -> (provider, cdn_masked)


def region_subnets(region_cidrs: Dict[str, List[ipaddress.IPv4Network]]) -> Dict[str, str]:
    """One client subnet per region, the same between builds: the first /24
    of its consumer ISP's block (CONSUMER_BLOCKS) while IPNova has that /24
    in the region; otherwise the first /24 of its largest IPNova range
    (lowest address on a tie)."""
    out = {}
    for r in REGIONS:
        nets = [n for n in region_cidrs.get(r) or [] if n.version == 4]
        if not nets:
            continue
        own = next(ipaddress.ip_network(CONSUMER_BLOCKS[r]).subnets(new_prefix=24))
        if any(own.subnet_of(n) for n in nets):
            out[r] = str(own)
            continue
        big = min(nets, key=lambda n: (n.prefixlen, int(n.network_address)))
        sub = next(big.subnets(new_prefix=24)) if big.prefixlen <= 24 else big.supernet(new_prefix=24)
        out[r] = str(sub)
    return out


def subnet_kind(region: str, subnet: str) -> str:
    """"consumer ISP" when the subnet is in the region's consumer block."""
    block = CONSUMER_BLOCKS.get(region)
    if block and ipaddress.ip_network(subnet).subnet_of(ipaddress.ip_network(block)):
        return "consumer ISP"
    return "largest range"


def _slash24(ip: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(f"{ipaddress.IPv4Address(ip)}/24", strict=False))
    except ValueError:
        return None


def _ipv4(ips: Iterable[str]) -> List[str]:
    return [ip for ip in ips if _slash24(ip)]


def share_in(ips: List[str], region: str, bucket: Bucket, skip: frozenset = frozenset()) -> float:
    v4 = _ipv4(ips)
    if not v4:
        return 0.0
    return sum(1 for ip in v4 if _slash24(ip) not in skip and bucket(ip) == region) / len(v4)


def hint_region(domain: str, source: str) -> str:
    """R for a seed of R or a name under R's ccTLD; "" otherwise."""
    if source.startswith("seed_") and source[5:].upper() in REGIONS:
        return source[5:].upper()
    return CCTLD_REGION.get(domain.rsplit(".", 1)[-1], "")


def foreign_edges(subnets: Dict[str, str], resolve: Resolve, bucket: Bucket) -> Dict[str, frozenset]:
    """Per region, the /24s inside it where CONTROLS answer its clients."""
    out = {}
    for r, sub in subnets.items():
        nets = set()
        for name in CONTROLS:
            for ip in _ipv4(resolve(name, sub)):
                if bucket(ip) == r:
                    nets.add(_slash24(ip))
        out[r] = frozenset(nets)
    return out


def classify(domain: str, region: str, cn_bucket: str, cn_score: int, subnets: Dict[str, str],
             edges: Dict[str, frozenset], resolve: Resolve, bucket: Bucket, provider: Provider,
             use_edges: bool = True) -> str:
    if cn_bucket and cn_bucket != region and cn_score >= 60:
        return "cn-view-elsewhere"
    ips = _ipv4(resolve(domain, subnets[region]))
    if not ips:
        return "unresolved"
    if share_in(ips, region, bucket) < THRESHOLD:
        return "not-local"
    if use_edges and share_in(ips, region, bucket, edges.get(region, frozenset())) < THRESHOLD:
        return "foreign-edge"
    if provider(ips)[1]:
        return "cdn"
    probe = PROBE_REGION[region]
    if probe in subnets:
        elsewhere = _ipv4(resolve(domain, subnets[probe]))
        if elsewhere and share_in(elsewhere, probe, bucket) >= THRESHOLD:
            return "follows-asker"
    return "local"


def update_state(state: dict, results: Dict[Tuple[str, str], str], week: str) -> dict:
    """{domain: {"region": R, "weeks": [...]}}: a week is added on `local`;
    any other verdict, or a different region, starts the domain over."""
    new = {}
    for (domain, region), verdict in results.items():
        if verdict != "local":
            continue
        prev = state.get(domain) or {}
        weeks = list(prev.get("weeks", [])) if prev.get("region") == region else []
        if week not in weeks:
            weeks.append(week)
        new[domain] = {"region": region, "weeks": weeks[-4:]}
    return new


def run(rows, subnets: Dict[str, str], resolve: Resolve, bucket: Bucket, provider: Provider,
        state: dict, week: str, map_fn: Callable = map) -> Tuple[dict, dict]:
    """Classify every hinted row and the controls; (report, new state).
    `rows` are DomainRecords after the build's own placement; untouched."""
    report: dict = {"mode": "shadow", "subnets": dict(subnets),
                    "subnet_kind": {r: subnet_kind(r, s) for r, s in subnets.items()}}
    if not subnets:
        report["skipped"] = "no regional ranges"
        return report, state
    edges = foreign_edges(subnets, resolve, bucket)
    report["foreign_networks"] = {r: len(edges.get(r, ())) for r in subnets}

    jobs = []
    for row in rows:
        r = hint_region(row.domain, row.source)
        if not r or r not in subnets:
            continue
        seed = row.source.startswith("seed_")
        if not seed and row.bucket == r and row.score >= 60:
            continue  # already placed in R by the build
        jobs.append((row.domain, r, row.bucket, row.score, seed))
    jobs = jobs[:MAX_CHECKS]

    def one(job):
        d, r, b, sc, _seed = job
        try:
            return classify(d, r, b, sc, subnets, edges, resolve, bucket, provider)
        except Exception:
            return "unresolved"

    verdicts = list(map_fn(one, jobs))
    results = {(j[0], j[1]): v for j, v in zip(jobs, verdicts, strict=True)}

    seeds: Dict[str, Dict[str, int]] = {}
    why: Dict[str, Counter] = {}                     # seeds not found: verdicts
    examples: Dict[str, Dict[str, List[str]]] = {}   # ... and a few of them
    others: Counter = Counter()
    for (d, r, _b, _sc, seed), v in zip(jobs, verdicts, strict=True):
        if seed:
            s = seeds.setdefault(r, {"checked": 0, "local": 0})
            s["checked"] += 1
            s["local"] += v == "local"
            if v != "local":
                why.setdefault(r, Counter())[v] += 1
                ex = examples.setdefault(r, {}).setdefault(v, [])
                if len(ex) < 5:
                    ex.append(d)
        else:
            others[v] += 1
    report["checked"] = len(jobs)
    report["seeds"] = {r: seeds[r] for r in REGIONS if r in seeds}
    report["seed_verdicts"] = {r: dict(why[r].most_common()) for r in REGIONS if r in why}
    report["seed_examples"] = {r: examples[r] for r in REGIONS if r in examples}
    report["verdicts"] = dict(others.most_common())

    passed = []
    controls = 0
    for name in CONTROLS:
        for r in subnets:
            controls += 1
            if classify(name, r, "", 0, subnets, edges, resolve, bucket, provider, use_edges=False) == "local":
                passed.append(f"{name}@{r}")
    report["controls"] = {"checked": controls, "passed": len(passed), "passed_names": passed}

    seed_names = {j[0] for j in jobs if j[4]}  # calibration only, never "added"
    new_state = update_state(state, {k: v for k, v in results.items()
                                     if k[0] not in seed_names}, week)
    would, pending = {}, Counter()
    for d, e in sorted(new_state.items()):
        if len(e["weeks"]) >= REQUIRED_WEEKS:
            would.setdefault(e["region"], []).append(d)
        else:
            pending[e["region"]] += 1
    report["would_add"] = {r: would[r] for r in REGIONS if r in would}
    report["pending"] = {r: pending[r] for r in REGIONS if pending[r]}
    report["required_weeks"] = REQUIRED_WEEKS
    return report, new_state
