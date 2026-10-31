"""
BGP IP Pool — weighted random IP generation from live BGP routing tables.
Sources: BGPView (api.bgpview.io) with RIPE NCC fallback (stat.ripe.net).
Cache:   bgp_cache.json (24 h TTL).
Liveness: TCP probe on common web ports before handing IPs to the scanner.
rDNS:    PTR-record neighbour expansion — non-generic hostnames boost the /24.
"""

import ipaddress
import json
import os
import random
import socket
import threading
from datetime import datetime, timedelta

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_CACHE_FILE  = "bgp_cache.json"
_BLOCKS_FILE = "scanned_blocks.json"
_HTTP_TIMEOUT = 15

# Default hosting/cloud ASNs — typical targets for .env exposure
DEFAULT_ASNS = {
    "Amazon AWS":    [16509, 14618],
    "DigitalOcean":  [14061],
    "Linode/Akamai": [63949],
    "OVH":           [16276],
    "Hetzner":       [24940],
    "Vultr":         [20473],
    "Contabo":       [51167],
    "LeaseWeb":      [60781],
}

_GENERIC_PTR_HINTS = (
    "static", "dynamic", "pool", "dhcp", "ptr", "rev",
    "reverse", "dsl", "cable", "broad", "cust", "client",
    "user", "ip-", "host-",
)


# ── Internal helpers ─────────────────────────────────────────────────────────

def _ip_to_slash24(ip: str) -> str:
    p = ip.split(".")
    return f"{p[0]}.{p[1]}.{p[2]}.0/24"


def _is_generic_ptr(name: str) -> bool:
    nl = name.lower()
    return any(h in nl for h in _GENERIC_PTR_HINTS)


def _check_liveness_parallel(ip: str, ports: tuple, timeout: float) -> int | None:
    """
    Probe all ports simultaneously. Returns the first port that opens,
    or None if all time out. Much faster than sequential probing —
    worst case is 1× timeout instead of len(ports)× timeout.
    """
    found_port: list = [None]
    found_ev   = threading.Event()

    def _try(port):
        if found_ev.is_set():
            return
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                if not found_ev.is_set():
                    found_port[0] = port
                    found_ev.set()
        except Exception:
            pass

    threads = [threading.Thread(target=_try, args=(p,), daemon=True) for p in ports]
    for t in threads:
        t.start()
    found_ev.wait(timeout=timeout + 0.3)   # wait for first success (or all timeout)
    return found_port[0]


# ── BGP prefix cache ─────────────────────────────────────────────────────────

def _load_cache(max_age_h: int = 24) -> dict | None:
    if not os.path.exists(_CACHE_FILE):
        return None
    try:
        with open(_CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if datetime.now() - datetime.fromisoformat(data["fetched_at"]) > timedelta(hours=max_age_h):
            return None
        return data["prefixes"]
    except Exception:
        return None


def _save_cache(prefixes: dict):
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": datetime.now().isoformat(), "prefixes": prefixes}, f)
    except Exception:
        pass


# ── BGP data fetching ────────────────────────────────────────────────────────

def _fetch_bgpview(asn: int, session: requests.Session) -> list[str]:
    try:
        r = session.get(f"https://api.bgpview.io/asn/{asn}/prefixes",
                        timeout=_HTTP_TIMEOUT, verify=False)
        return [p["prefix"]
                for p in r.json().get("data", {}).get("ipv4_prefixes", [])]
    except Exception:
        return []


def _fetch_ripe(asn: int, session: requests.Session) -> list[str]:
    try:
        r = session.get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",
            timeout=_HTTP_TIMEOUT, verify=False,
        )
        return [p["prefix"] for p in r.json().get("data", {}).get("prefixes", [])]
    except Exception:
        return []


def fetch_all_bgp_prefixes(
    asns: dict | None = None,
    proxy: str | None = None,
    log_cb=None,
    max_age_h: int = 24,
) -> dict:
    """
    Return {provider_name: [cidr, ...]} for every configured ASN.
    Cache is reused for max_age_h hours; stale cache triggers a fresh fetch.
    Falls back from BGPView → RIPE NCC automatically.
    """
    def _log(m):
        if log_cb:
            log_cb(m)

    cached = _load_cache(max_age_h)
    if cached:
        _log("[BGP] Using cached prefix data (< 24 h old)")
        return cached

    target_asns = asns or DEFAULT_ASNS
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    result: dict[str, list[str]] = {}
    for name, asn_list in target_asns.items():
        prefixes: list[str] = []
        for asn in asn_list:
            _log(f"[BGP] Fetching AS{asn} ({name}) via BGPView…")
            p = _fetch_bgpview(asn, session)
            if not p:
                _log(f"[BGP] BGPView empty — RIPE fallback for AS{asn}")
                p = _fetch_ripe(asn, session)
            prefixes.extend(p)
            _log(f"[BGP] AS{asn}: {len(p)} prefixes")
        result[name] = list(set(prefixes))

    _save_cache(result)
    total = sum(len(v) for v in result.values())
    _log(f"[BGP] Fetch complete — {total} unique prefixes across {len(result)} providers")
    return result


# ── SmartIPGenerator ─────────────────────────────────────────────────────────

class SmartIPGenerator:
    """
    Weighted-random IP generator over BGP CIDR ranges.
    Larger CIDRs get proportionally more weight.
    Hotspot scoring dynamically re-weights /24s that return findings.
    """

    def __init__(self):
        self._lock    = threading.RLock()
        self._cidrs:   list[tuple] = []   # (start_int, end_int, size, cidr_str)
        self._weights: list[int]   = []   # cumulative weight array
        self._total   = 0
        self._scores: dict[str, dict] = {}
        self._scanned_blocks: set[str] = set()
        self.loaded = False
        self._load_scanned_blocks()

    # ── persistence ──────────────────────────────────────────────────────────

    def _load_scanned_blocks(self):
        if os.path.exists(_BLOCKS_FILE):
            try:
                with open(_BLOCKS_FILE, encoding="utf-8") as f:
                    self._scanned_blocks = set(json.load(f))
            except Exception:
                pass

    def save_scanned_blocks(self):
        try:
            with open(_BLOCKS_FILE, "w", encoding="utf-8") as f:
                json.dump(list(self._scanned_blocks), f)
        except Exception:
            pass

    # ── loading ───────────────────────────────────────────────────────────────

    def load_from_prefixes(self, prefixes: dict, log_cb=None):
        """Parse {provider: [cidr,...]} into the weighted CIDR table."""
        cidrs: list[tuple] = []
        for prefix_list in prefixes.values():
            for cidr in prefix_list:
                try:
                    net = ipaddress.IPv4Network(cidr, strict=False)
                    if net.prefixlen < 8 or net.prefixlen > 28:
                        continue
                    start = int(net.network_address)
                    end   = int(net.broadcast_address)
                    cidrs.append((start, end, end - start + 1, str(net)))
                except Exception:
                    continue

        with self._lock:
            self._cidrs   = cidrs
            self._weights = []
            total = 0
            for _, _, size, _ in cidrs:
                total += size
                self._weights.append(total)
            self._total = total
            self.loaded = True

        if log_cb:
            log_cb(f"[BGP] Generator ready — {len(cidrs)} CIDRs, {self._total:,} IPs")

    def seed_cidrs(self, cidr_list: list[str]):
        """Append extra CIDRs (e.g. from manual user input)."""
        with self._lock:
            for cidr in cidr_list:
                try:
                    net   = ipaddress.IPv4Network(cidr, strict=False)
                    start = int(net.network_address)
                    end   = int(net.broadcast_address)
                    size  = end - start + 1
                    self._cidrs.append((start, end, size, str(net)))
                    self._total += size
                    self._weights.append(self._total)
                except Exception:
                    continue

    # ── scoring / hotspot ────────────────────────────────────────────────────

    def record_hit(self, ip: str):
        block = _ip_to_slash24(ip)
        with self._lock:
            s = self._scores.setdefault(block, {"hits": 0, "scanned": 0})
            s["hits"] += 1
            s["last_hit"] = datetime.now().isoformat()

    def record_scan(self, ip: str):
        block = _ip_to_slash24(ip)
        with self._lock:
            self._scores.setdefault(block, {"hits": 0, "scanned": 0})["scanned"] += 1

    def add_hotspot(self, ip: str):
        """Re-insert the /24 around a finding with boosted probability."""
        try:
            net   = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            start = int(net.network_address)
            end   = int(net.broadcast_address)
            with self._lock:
                # Append the /24 block three extra times (4× total weight boost).
                # _total must equal the actual sum of all block sizes so that
                # bisect_right in get_next() never goes out of bounds.
                for _ in range(3):
                    self._cidrs.append((start, end, 256, str(net)))
                    self._total += 256
                    self._weights.append(self._total)
        except Exception:
            pass

    def get_top_ranges(self, n: int = 10) -> list[tuple]:
        with self._lock:
            scored = [(k, v["hits"]) for k, v in self._scores.items()]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:n]

    # ── generation ───────────────────────────────────────────────────────────

    def get_next(self) -> str | None:
        with self._lock:
            if not self._cidrs or self._total == 0:
                return None
            r = random.randint(0, self._total - 1)
            lo, hi = 0, len(self._weights) - 1
            while lo < hi:
                mid = (lo + hi) // 2
                if self._weights[mid] <= r:
                    lo = mid + 1
                else:
                    hi = mid
            start, end, _, _ = self._cidrs[lo]
            return str(ipaddress.IPv4Address(random.randint(start, end)))


# ── Liveness probing ─────────────────────────────────────────────────────────

def check_liveness(
    ip: str,
    ports: tuple = (80, 443, 8080, 8443),
    timeout: float = 3.0,
) -> bool:
    """Return True if any port responds (parallel probe)."""
    return _check_liveness_parallel(ip, ports, timeout) is not None


# ── rDNS neighbour expansion ─────────────────────────────────────────────────

def reverse_neighbor_check(ip: str, generator: SmartIPGenerator):
    """
    PTR-record lookup: non-generic hostname → real server → boost the /24.
    Generic reverse DNS entries (pool-*, static-*, cable-*, etc.) are ignored.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if not _is_generic_ptr(hostname):
            generator.add_hotspot(ip)
    except Exception:
        pass


# ── Pool builder ─────────────────────────────────────────────────────────────

def generate_live_ips(
    generator: SmartIPGenerator,
    target_count: int,
    liveness_timeout: float = 3.0,
    liveness_ports: tuple = (80, 443, 8080, 8443),
    stop_evt=None,
    log_cb=None,
    workers: int = 120,
    on_found_cb=None,
) -> list[str]:
    """
    Parallel liveness prober — runs `workers` concurrent IP probes.
    Each probe checks all ports simultaneously so worst-case per dead IP
    is 1× timeout (not 4×). Results stream to log_cb in real time.
    on_found_cb(url) fires immediately when each live IP is discovered,
    enabling probe+scan pipelines without waiting for the full pool.
    """
    from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

    def _log(m):
        if log_cb:
            log_cb(m)

    live:    list[str] = []
    probed = [0]
    lock   = threading.Lock()

    def probe_ip(ip: str):
        port = _check_liveness_parallel(ip, liveness_ports, liveness_timeout)
        with lock:
            probed[0] += 1
        return ip, port

    _log(f"[BGP] Starting parallel probe  ({workers} concurrent workers, {liveness_timeout}s timeout)")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending: dict = {}

        # Pre-fill the pool
        for _ in range(min(workers, target_count * 10)):
            ip = generator.get_next()
            if ip is None:
                break
            pending[pool.submit(probe_ip, ip)] = ip

        while pending and len(live) < target_count:
            if stop_evt and stop_evt.is_set():
                break

            done_futs, _ = wait(list(pending), timeout=1.0,
                                return_when=FIRST_COMPLETED)

            for fut in done_futs:
                del pending[fut]
                ip, port = fut.result()

                if port:
                    scheme = "https" if port in (443, 8443) else "http"
                    suffix = "" if port in (80, 443) else f":{port}"
                    url    = f"{scheme}://{ip}{suffix}"
                    with lock:
                        live.append(url)
                        n = len(live)
                    _log(f"[BGP] {probed[0]:>5,} probed  ·  {n}/{target_count} live  ·  ✓ {url}")
                    generator.record_hit(ip)
                    reverse_neighbor_check(ip, generator)
                    if on_found_cb:
                        on_found_cb(url)   # fire immediately — starts scan without waiting for full pool
                else:
                    # Log dead IPs every 10 to show progress without flooding
                    if probed[0] % 10 == 0:
                        _log(f"[BGP] {probed[0]:>5,} probed  ·  {len(live)}/{target_count} live  ·  still searching…")
                    generator.record_scan(ip)

                # Replenish the pool
                if len(live) < target_count and not (stop_evt and stop_evt.is_set()):
                    nxt = generator.get_next()
                    if nxt:
                        pending[pool.submit(probe_ip, nxt)] = nxt

    _log(f"[BGP] Complete — {len(live)} live IPs found from {probed[0]:,} probed")
    generator.save_scanned_blocks()
    return live
