"""
SB Scanner — OSINT target discovery via Shodan and FOFA APIs.
Supports multiple queries (one per line), fully paginated with no result cap.
"""

import base64
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 22

# ── Shodan ────────────────────────────────────────────────────────────────────

SHODAN_SEARCH = "https://api.shodan.io/shodan/host/search"
SHODAN_COUNT  = "https://api.shodan.io/shodan/host/count"

SHODAN_PRESETS = {
    # ── CMS ──────────────────────────────────────────────────────────────────
    "Laravel":          "http.component:laravel",
    "WordPress":        "http.component:wordpress",
    "Joomla":           "http.component:joomla",
    "Drupal":           "http.component:drupal",
    "Magento":          "http.component:magento",
    # ── PHP / Server tech ─────────────────────────────────────────────────────
    "PHP/5":            '"X-Powered-By: PHP/5"',
    "PHP/7":            '"X-Powered-By: PHP/7"',
    "PHP/8":            '"X-Powered-By: PHP/8"',
    # ── Admin / Hosting panels ────────────────────────────────────────────────
    "phpMyAdmin":       'http.title:"phpMyAdmin"',
    "Adminer":          'http.title:"Adminer"',
    "cPanel":           'http.title:"cPanel"',
    "WHM":              'http.title:"WebHost Manager"',
    "Plesk":            'http.title:"Plesk"',
    "Webmin":           'http.title:"Webmin"',
    "pgAdmin":          'http.title:"pgAdmin"',
    "Mongo Express":    'http.title:"Mongo Express"',
    "Redis Commander":  'http.title:"Redis Commander"',
    # ── DevOps / CI / Monitoring ──────────────────────────────────────────────
    "Jenkins":          'http.title:"Jenkins"',
    "Grafana":          'http.title:"Grafana"',
    "Jupyter":          'http.title:"Jupyter"',
    "Kibana":           'http.title:"Kibana"',
    "Portainer":        'http.title:"Portainer"',
    "Tomcat":           'http.headers.server:"Apache Tomcat"',
    "Spring Boot":      'http.component:spring-boot',
    "GitLab":           'http.component:gitlab',
    "Prometheus":       'http.title:"Prometheus Time Series"',
    "Traefik":          'http.title:"Traefik"',
    "ArgoCD":           'http.title:"Argo CD"',
    "RabbitMQ Mgmt":    'http.title:"RabbitMQ Management"',
    "Kubernetes Dash":  'http.title:"Kubernetes Dashboard"',
    "HashiVault":       'http.html:"hashicorp" http.title:"Vault"',
    "MinIO":            'http.title:"MinIO Browser"',
    "Swagger UI":       'http.title:"Swagger UI"',
    "Docker API":       'port:2375 product:"Docker"',
    # ── Exposed credentials in page body ─────────────────────────────────────
    ".env Leak":        'http.html:"APP_KEY" "DB_PASSWORD"',
    "AWS Keys":         'http.html:"AWS_ACCESS_KEY_ID"',
    "Stripe Leak":      'http.html:"STRIPE_SECRET"',
    "Twilio Leak":      'http.html:"TWILIO_ACCOUNT_SID"',
    "SendGrid":         'http.html:"SENDGRID_API_KEY"',
    "Shopify Key":      'http.html:"SHOPIFY_API_KEY"',
    "Binance Key":      'http.html:"BINANCE_API_KEY"',
    "Coinbase Key":     'http.html:"COINBASE_API_KEY"',
    "MongoDB Conn":     'http.html:"mongodb+srv://"',
    "Firebase":         'http.html:"FIREBASE_API_KEY" "FIREBASE_AUTH_DOMAIN"',
    "SSH Key":          'http.html:"BEGIN RSA PRIVATE KEY"',
    "WP-Config Bak":    'http.html:"DB_PASSWORD" http.html:"DB_NAME" http.html:"define("',
    "OpenAI Key":       'http.html:"OPENAI_API_KEY"',
    "Anthropic Key":    'http.html:"ANTHROPIC_API_KEY"',
    "Supabase Key":     'http.html:"SUPABASE_ANON_KEY"',
    "HuggingFace Key":  'http.html:"HUGGINGFACE_API_KEY"',
    "Slack Webhook":    'http.html:"hooks.slack.com/services"',
    "Discord Webhook":  'http.html:"discord.com/api/webhooks"',
    # ── Known vulnerable paths ────────────────────────────────────────────────
    "Exposed Git":      'http.html:"[core]" http.title:"Index of"',
    "phpUnit RCE":      'http.html:"eval-stdin.php"',
}


def _sh_parse_target(m: dict) -> str | None:
    """
    Extract one URL from a single Shodan match.
    Prefers hostname over raw IP to avoid scanning the same server twice
    when both appear in the result set.
    """
    port   = m.get('port', 80)
    ssl    = bool(m.get('ssl'))
    scheme = 'https' if (ssl or port in (443, 8443)) else 'http'
    std    = port in (80, 443)

    hostnames = m.get('hostnames') or []
    if hostnames:
        hn = hostnames[0]
        return f"{scheme}://{hn}" if std else f"{scheme}://{hn}:{port}"

    ip = m.get('ip_str', '')
    if ip:
        return f"{scheme}://{ip}" if std else f"{scheme}://{ip}:{port}"
    return None


def shodan_search(api_key: str, queries: list[str],
                  stop_evt=None, pause_evt=None,
                  log_cb=None, yield_cb=None) -> tuple[list[str], str | None]:
    """
    Run each query against Shodan in sequence, paginate all pages, merge results.
    No result cap — returns everything the API gives back.
    yield_cb(url): optional callback fired immediately for each new unique URL discovered.
    Returns (unique_url_list, error_or_None).
    """
    def log(m): log_cb and log_cb(m)

    all_targets: dict[str, bool] = {}
    queries = [q.strip() for q in queries if q.strip() and not q.strip().startswith('#')]

    if not queries:
        return [], "No queries provided"

    for qi, query in enumerate(queries, 1):
        if stop_evt and stop_evt.is_set():
            log(f"[!] Fetch stopped — {len(all_targets)} targets collected")
            break

        log(f"[*] Shodan [{qi}/{len(queries)}]: {query}")

        # ── get total count ────────────────────────────────────────────────
        try:
            r = requests.get(SHODAN_COUNT, timeout=_TIMEOUT,
                             params={'key': api_key, 'query': query})
            if r.status_code == 401:
                return list(all_targets), "Shodan: Invalid API key"
            if r.status_code == 400:
                log(f"[!] Shodan: bad query — {r.json().get('error', 'check syntax')}")
                continue
            if r.status_code != 200:
                log(f"[!] Shodan: HTTP {r.status_code} on count")
                continue
            total = r.json().get('total', 0)
            log(f"[*] Shodan: {total:,} total results")
            if total == 0:
                continue
        except requests.exceptions.ConnectionError:
            return list(all_targets), "Shodan: No internet connection"
        except Exception as e:
            log(f"[!] Shodan count error: {e}")
            continue

        # ── paginate all pages ─────────────────────────────────────────────
        page = 1
        while True:
            if stop_evt and stop_evt.is_set():
                log(f"[!] Fetch stopped — {len(all_targets)} targets collected")
                break
            if pause_evt:
                pause_evt.wait()   # blocks here while paused
            if stop_evt and stop_evt.is_set():
                break
            try:
                r = requests.get(SHODAN_SEARCH, timeout=_TIMEOUT, params={
                    'key': api_key, 'query': query,
                    'page': page, 'minify': 'true',
                })
                if r.status_code == 401:
                    return list(all_targets), "Shodan: Invalid API key"
                if r.status_code == 402:
                    # Free API accounts cannot page beyond page 1
                    log(f"[!] Shodan: paid plan required for page {page}+ — got {len(all_targets)} so far")
                    break
                if r.status_code != 200:
                    log(f"[!] Shodan: HTTP {r.status_code} on page {page}")
                    break

                matches = r.json().get('matches', [])
                if not matches:
                    break

                before = len(all_targets)
                for m in matches:
                    url = _sh_parse_target(m)
                    if url and url not in all_targets:
                        all_targets[url] = True
                        if yield_cb:
                            try:
                                yield_cb(url)
                            except Exception:
                                pass

                new = len(all_targets) - before
                log(f"[*] Shodan: query {qi} page {page} — "
                    f"{len(matches)} hits, {new} new  (total unique: {len(all_targets)})")

                if len(matches) < 100:
                    break          # last page
                page += 1

            except requests.exceptions.ConnectionError:
                log("[!] Shodan: connection lost")
                break
            except Exception as e:
                log(f"[!] Shodan page {page} error: {e}")
                break

    result = list(all_targets)
    log(f"[+] Shodan: {len(result)} unique targets from {len(queries)} quer{'y' if len(queries)==1 else 'ies'}")
    return result, None


# ── FOFA ──────────────────────────────────────────────────────────────────────

FOFA_SEARCH = "https://fofa.info/api/v1/search/all"

FOFA_PRESETS = {
    # ── CMS ──────────────────────────────────────────────────────────────────
    "Laravel":          'app="Laravel"',
    "WordPress":        'app="WordPress"',
    "Joomla":           'app="Joomla"',
    "Drupal":           'app="Drupal"',
    "Magento":          'app="Magento"',
    # ── PHP / Server tech ─────────────────────────────────────────────────────
    "PHP/5":            'header="X-Powered-By: PHP/5"',
    "PHP/7":            'header="X-Powered-By: PHP/7"',
    "PHP/8":            'header="X-Powered-By: PHP/8"',
    # ── Admin / Hosting panels ────────────────────────────────────────────────
    "phpMyAdmin":       'app="phpMyAdmin"',
    "Adminer":          'app="Adminer"',
    "cPanel":           'title="cPanel"',
    "WHM":              'title="WebHost Manager"',
    "Plesk":            'app="Plesk"',
    "Webmin":           'app="Webmin"',
    "pgAdmin":          'title="pgAdmin"',
    "Mongo Express":    'title="Mongo Express"',
    "Redis Commander":  'title="Redis Commander"',
    # ── DevOps / CI / Monitoring ──────────────────────────────────────────────
    "Jenkins":          'app="Jenkins"',
    "Grafana":          'app="Grafana"',
    "Jupyter":          'title="JupyterLab" || title="Jupyter Notebook"',
    "Kibana":           'app="Kibana"',
    "Portainer":        'app="Portainer"',
    "Tomcat":           'app="Apache-Tomcat"',
    "Spring Boot":      'app="Spring-Boot"',
    "GitLab":           'app="GitLab"',
    "Prometheus":       'title="Prometheus Time Series"',
    "Traefik":          'app="Traefik"',
    "ArgoCD":           'title="Argo CD"',
    "RabbitMQ":         'app="RabbitMQ"',
    "Kubernetes Dash":  'title="Kubernetes Dashboard"',
    "HashiVault":       'title="Vault" && body="hashicorp"',
    "MinIO":            'app="MinIO"',
    "Swagger UI":       'title="Swagger UI"',
    "Docker API":       'port=2375 && banner="docker"',
    # ── Exposed credentials in body ───────────────────────────────────────────
    ".env Leak":        'body="APP_ENV" && body="APP_KEY"',
    "AWS Keys":         'body="AWS_ACCESS_KEY_ID"',
    "Stripe Leak":      'body="STRIPE_SECRET"',
    "Twilio Leak":      'body="TWILIO_ACCOUNT_SID"',
    "SendGrid":         'body="SENDGRID_API_KEY"',
    "Shopify Key":      'body="SHOPIFY_API_KEY"',
    "Binance Key":      'body="BINANCE_API_KEY"',
    "Coinbase Key":     'body="COINBASE_API_KEY"',
    "MongoDB Conn":     'body="mongodb+srv://"',
    "Firebase":         'body="FIREBASE_API_KEY" && body="FIREBASE_AUTH_DOMAIN"',
    "SSH Key":          'body="BEGIN RSA PRIVATE KEY"',
    "WP-Config Bak":    'body="DB_PASSWORD" && body="DB_NAME" && body="define("',
    "OpenAI Key":       'body="OPENAI_API_KEY"',
    "Anthropic Key":    'body="ANTHROPIC_API_KEY"',
    "Supabase Key":     'body="SUPABASE_ANON_KEY"',
    "HuggingFace Key":  'body="HUGGINGFACE_API_KEY"',
    "Slack Webhook":    'body="hooks.slack.com/services"',
    "Discord Webhook":  'body="discord.com/api/webhooks"',
    # ── Known vulnerable paths ────────────────────────────────────────────────
    "Open .git":        'body="[core]" && title="Index of"',
    "phpUnit RCE":      'body="eval-stdin.php"',
}


def _fo_parse_row(row) -> str | None:
    """Extract URL from a single FOFA result row."""
    try:
        host, ip, port, proto = row[0], row[1], str(row[2]), row[3]
        scheme = proto if proto in ('http', 'https') else 'http'
        if host:
            return (host if host.startswith(('http://', 'https://'))
                    else f"{scheme}://{host}").rstrip('/')
        if ip:
            return (f"{scheme}://{ip}" if port in ('80', '443')
                    else f"{scheme}://{ip}:{port}")
    except (IndexError, TypeError):
        pass
    return None


def fofa_search(email: str, api_key: str, queries: list[str],
                stop_evt=None, pause_evt=None,
                log_cb=None, yield_cb=None) -> tuple[list[str], str | None]:
    """
    Run each query against FOFA in sequence, paginate all pages, merge results.
    No result cap — uses size=10000 per page and continues until exhausted.
    yield_cb(url): optional callback fired immediately for each new unique URL discovered.
    Returns (unique_url_list, error_or_None).
    """
    def log(m): log_cb and log_cb(m)

    all_targets: dict[str, bool] = {}
    queries = [q.strip() for q in queries if q.strip() and not q.strip().startswith('#')]

    if not queries:
        return [], "No queries provided"

    PER_PAGE = 10_000   # max FOFA allows per request (paid); free accounts cap at 100

    for qi, query in enumerate(queries, 1):
        if stop_evt and stop_evt.is_set():
            log(f"[!] Fetch stopped — {len(all_targets)} targets collected")
            break

        log(f"[*] FOFA [{qi}/{len(queries)}]: {query}")
        q_b64 = base64.b64encode(query.encode()).decode()
        page  = 1

        while True:
            if stop_evt and stop_evt.is_set():
                log(f"[!] Fetch stopped — {len(all_targets)} targets collected")
                break
            if pause_evt:
                pause_evt.wait()   # blocks here while paused
            if stop_evt and stop_evt.is_set():
                break
            try:
                r = requests.get(FOFA_SEARCH, timeout=_TIMEOUT, params={
                    'email':   email,
                    'key':     api_key,
                    'qbase64': q_b64,
                    'fields':  'host,ip,port,protocol',
                    'size':    PER_PAGE,
                    'page':    page,
                    'full':    'true',
                })

                if r.status_code == 401:
                    return list(all_targets), "FOFA: Invalid credentials"
                if r.status_code != 200:
                    log(f"[!] FOFA: HTTP {r.status_code} on page {page}")
                    break

                data = r.json()
                if data.get('error'):
                    log(f"[!] FOFA: {data.get('errmsg', 'API error')}")
                    break

                total   = data.get('size', 0)
                results = data.get('results', [])

                if page == 1:
                    log(f"[*] FOFA: {total:,} total results")

                if not results:
                    break

                before = len(all_targets)
                for row in results:
                    url = _fo_parse_row(row)
                    if url and url not in all_targets:
                        all_targets[url] = True
                        if yield_cb:
                            try:
                                yield_cb(url)
                            except Exception:
                                pass

                new = len(all_targets) - before
                log(f"[*] FOFA: query {qi} page {page} — "
                    f"{len(results)} hits, {new} new  (total unique: {len(all_targets)})")

                # Stop when last page reached
                if len(results) < PER_PAGE:
                    break
                # Stop if we've collected everything FOFA reported
                if len(all_targets) >= total and total > 0:
                    break

                page += 1

            except requests.exceptions.ConnectionError:
                log("[!] FOFA: connection lost")
                break
            except Exception as e:
                log(f"[!] FOFA page {page} error: {e}")
                break

    result = list(all_targets)
    log(f"[+] FOFA: {len(result)} unique targets from {len(queries)} quer{'y' if len(queries)==1 else 'ies'}")
    return result, None


# ── BGP /24 neighbourhood expansion ──────────────────────────────────────────
# After FOFA/Shodan returns results, optionally expand the pool by probing
# random neighbours within the same /24 blocks.  If one host in a datacenter
# rack exposes credentials, siblings are strong candidates too.

import ipaddress as _ipv4mod
import random    as _rnd
import socket    as _sock
import threading as _threading
from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _as_completed

# Expanded port set: adds 3000/5000/8000/8888 (Node, Flask, dev servers)
_BGP_PORTS = (80, 443, 8080, 8443, 3000, 5000, 8000, 8888)


def _tg_port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with _sock.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def bgp_expand_targets(
    base_urls:        list[str],
    extra_per_block:  int   = 15,
    liveness_timeout: float = 2.0,
    max_workers:      int   = 60,
    stop_evt=None,
    log_cb=None,
) -> list[str]:
    """
    For every IP discovered by FOFA/Shodan, probe extra_per_block additional
    hosts in the same /24 block. Returns original list + live neighbours.

    v2 improvements vs v1:
    - All blocks probed in parallel (ThreadPoolExecutor, max_workers=60)
    - 8 web ports per IP (added 3000/5000/8000/8888)
    - Biased candidate ordering: low octets (1-30) first — servers cluster there
    - Round-robin interleaving so all blocks get early probe slots
    - Tighter default timeout (2s vs 3s) — dead hosts respond faster than live ones
    """
    def _log(m):
        if log_cb:
            log_cb(m)

    def _extract_ip(url: str) -> str | None:
        host = url.split("//", 1)[-1].split("/")[0].split(":")[0]
        try:
            _ipv4mod.IPv4Address(host)
            return host
        except Exception:
            return None

    def _probe(ip: str) -> bool:
        for port in _BGP_PORTS:
            if _tg_port_open(ip, port, liveness_timeout):
                return True
        return False

    known: set[str] = set(base_urls)

    # Collect unique /24 prefixes
    blocks: dict[str, set[str]] = {}
    for url in base_urls:
        ip = _extract_ip(url)
        if not ip:
            continue
        parts = ip.split(".")
        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
        blocks.setdefault(prefix, set()).add(ip)

    if not blocks:
        return list(base_urls)

    _log(f"[BGP-Expand] {len(blocks)} unique /24 blocks — "
         f"targeting {extra_per_block} live hosts/block  "
         f"({max_workers} workers, ports {'/'.join(str(p) for p in _BGP_PORTS)})")

    # Per-block hit tracking (thread-safe)
    block_hits: dict[str, int] = {p: 0 for p in blocks}
    hits_lock = _threading.Lock()

    # Build candidate lists per block with biased ordering:
    #   1. Low octets 2-30   (servers in DC racks tend to cluster here)
    #   2. High octets 240-254  (secondary servers, edge nodes)
    #   3. Random middle fill to reach extra_per_block × 6 total
    per_block_candidates: dict[str, list[str]] = {}
    for prefix, seen_ips in blocks.items():
        seen_last = {int(ip.split(".")[-1]) for ip in seen_ips}
        used: set[str] = set(seen_ips)
        cands: list[str] = []

        low = [i for i in range(2, 31) if i not in seen_last]
        _rnd.shuffle(low)
        for last in low:
            ip = f"{prefix}.{last}"
            if ip not in used:
                cands.append(ip)
                used.add(ip)

        high = [i for i in range(240, 255) if i not in seen_last]
        _rnd.shuffle(high)
        for last in high:
            ip = f"{prefix}.{last}"
            if ip not in used:
                cands.append(ip)
                used.add(ip)

        budget = extra_per_block * 6
        mid_pool = list(range(31, 240))
        _rnd.shuffle(mid_pool)
        for last in mid_pool:
            if len(cands) >= budget:
                break
            ip = f"{prefix}.{last}"
            if ip not in used:
                cands.append(ip)
                used.add(ip)

        per_block_candidates[prefix] = cands

    # Round-robin interleave: block A's #1 cand, block B's #1 cand, ...
    # This ensures all blocks get early worker slots, not just the first few.
    from itertools import zip_longest as _zl
    lists = list(per_block_candidates.values())
    prefixes = list(per_block_candidates.keys())
    # Map ip → prefix for result attribution
    ip_to_prefix: dict[str, str] = {}
    for pref, cands in per_block_candidates.items():
        for ip in cands:
            ip_to_prefix[ip] = pref

    interleaved: list[str] = []
    for row in _zl(*lists):
        for ip in row:
            if ip is not None:
                interleaved.append(ip)

    _log(f"[BGP-Expand] {len(interleaved)} candidates queued across all blocks")

    expanded: list[str] = []
    expanded_set: set[str] = set(known)

    with _TPE(max_workers=max_workers) as pool:
        futures = {}
        for ip in interleaved:
            if stop_evt and stop_evt.is_set():
                break
            prefix = ip_to_prefix[ip]
            with hits_lock:
                # Skip submission if block already saturated
                if block_hits[prefix] >= extra_per_block:
                    continue
            futures[pool.submit(_probe, ip)] = ip

        for fut in _as_completed(futures):
            if stop_evt and stop_evt.is_set():
                break
            ip = futures[fut]
            prefix = ip_to_prefix[ip]
            try:
                live = fut.result()
            except Exception:
                continue
            if not live:
                continue
            with hits_lock:
                if block_hits[prefix] >= extra_per_block:
                    continue
                block_hits[prefix] += 1

            scheme = "https" if _tg_port_open(ip, 443, liveness_timeout) else "http"
            url = f"{scheme}://{ip}"
            if url not in expanded_set:
                expanded.append(url)
                expanded_set.add(url)

    _log(f"[BGP-Expand] Added {len(expanded)} live neighbours to pool")
    return list(base_urls) + expanded


# ── Censys v2 ─────────────────────────────────────────────────────────────────

CENSYS_SEARCH = "https://search.censys.io/api/v2/hosts/search"

CENSYS_PRESETS = {
    # ── Credential leaks ─────────────────────────────────────────────────────
    "Laravel .env":     'services.http.response.body:"APP_KEY" and services.http.response.body:"DB_PASSWORD"',
    "AWS Keys":         'services.http.response.body:"AWS_ACCESS_KEY_ID"',
    "Stripe Leak":      'services.http.response.body:"STRIPE_SECRET"',
    "Shopify Key":      'services.http.response.body:"SHOPIFY_API_KEY"',
    "Binance Key":      'services.http.response.body:"BINANCE_API_KEY"',
    "Firebase":         'services.http.response.body:"FIREBASE_API_KEY"',
    "SSH Key":          'services.http.response.body:"BEGIN RSA PRIVATE KEY"',
    "MongoDB URI":      'services.http.response.body:"mongodb+srv://"',
    "OpenAI Key":       'services.http.response.body:"OPENAI_API_KEY"',
    "Anthropic Key":    'services.http.response.body:"ANTHROPIC_API_KEY"',
    "Supabase Key":     'services.http.response.body:"SUPABASE_ANON_KEY"',
    "HuggingFace Key":  'services.http.response.body:"HUGGINGFACE_API_KEY"',
    "Slack Webhook":    'services.http.response.body:"hooks.slack.com/services"',
    "Twilio Leak":      'services.http.response.body:"TWILIO_ACCOUNT_SID"',
    "Sendgrid Key":     'services.http.response.body:"SENDGRID_API_KEY"',
    # ── Admin panels ─────────────────────────────────────────────────────────
    "phpMyAdmin":       'services.http.response.html_title:"phpMyAdmin"',
    "cPanel":           'services.http.response.html_title:"cPanel"',
    "pgAdmin":          'services.http.response.html_title:"pgAdmin"',
    "Mongo Express":    'services.http.response.html_title:"Mongo Express"',
    # ── DevOps / Infra ────────────────────────────────────────────────────────
    "WordPress":        'services.http.response.html_title:"WordPress"',
    "Jenkins":          'services.http.response.html_title:"Jenkins"',
    "Grafana":          'services.http.response.html_title:"Grafana"',
    "Kubernetes Dash":  'services.http.response.html_title:"Kubernetes Dashboard"',
    "Traefik":          'services.http.response.html_title:"Traefik"',
    "MinIO":            'services.http.response.html_title:"MinIO Browser"',
    "Swagger UI":       'services.http.response.html_title:"Swagger UI"',
    "HashiVault":       'services.http.response.html_title:"Vault"',
    "ArgoCD":           'services.http.response.html_title:"Argo CD"',
    "Portainer":        'services.http.response.html_title:"Portainer"',
    # ── Exposed surfaces ─────────────────────────────────────────────────────
    "Spring Actuator":  'services.http.response.body:"/actuator/env"',
    "Open Git":         'services.http.response.body:"[core]"',
}


def censys_search(api_id: str, api_secret: str, queries: list[str],
                  stop_evt=None, log_cb=None, yield_cb=None) -> tuple[list[str], str | None]:
    """Search Censys v2 Hosts API. No result cap — paginates until exhausted.
    yield_cb(url): optional callback fired immediately for each new unique URL discovered.
    Returns (unique_url_list, error_or_None)."""
    def log(m): log_cb and log_cb(m)

    import base64 as _b64
    all_targets: dict[str, bool] = {}
    queries = [q.strip() for q in queries if q.strip() and not q.strip().startswith('#')]
    if not queries:
        return [], "No queries provided"

    creds = _b64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    headers = {'Authorization': f'Basic {creds}', 'Content-Type': 'application/json'}

    for qi, query in enumerate(queries, 1):
        if stop_evt and stop_evt.is_set():
            break
        log(f"[*] Censys [{qi}/{len(queries)}]: {query[:60]}")
        cursor = None
        page = 0
        collected = 0
        while True:
            if stop_evt and stop_evt.is_set():
                break
            try:
                body = {'q': query, 'per_page': 100}
                if cursor:
                    body['cursor'] = cursor
                r = requests.post(CENSYS_SEARCH, json=body, headers=headers, timeout=_TIMEOUT)
                if r.status_code == 401:
                    return list(all_targets), "Censys: Invalid API credentials"
                if r.status_code == 429:
                    log("[!] Censys: rate limited — pausing 10s")
                    import time; time.sleep(10)
                    continue
                if r.status_code != 200:
                    log(f"[!] Censys: HTTP {r.status_code}")
                    break
                data = r.json()
                result = data.get('result', {})
                hits = result.get('hits', [])
                if page == 0:
                    log(f"[*] Censys: {result.get('total', '?')} total results")
                if not hits:
                    break
                before = len(all_targets)
                for hit in hits:
                    ip = hit.get('ip', '')
                    if not ip:
                        continue
                    services = hit.get('services', [])
                    # Prefer HTTPS, fall back to HTTP, pick highest port if non-standard
                    https_ports = [s.get('port') for s in services
                                   if s.get('transport_protocol') == 'TCP'
                                   and s.get('port') in (443, 8443)]
                    http_ports  = [s.get('port') for s in services
                                   if s.get('transport_protocol') == 'TCP'
                                   and s.get('port') in (80, 8080)]
                    if https_ports:
                        p = https_ports[0]
                        url = f"https://{ip}" if p == 443 else f"https://{ip}:{p}"
                    elif http_ports:
                        p = http_ports[0]
                        url = f"http://{ip}" if p == 80 else f"http://{ip}:{p}"
                    else:
                        url = f"http://{ip}"
                    if url not in all_targets:
                        all_targets[url] = True
                        if yield_cb:
                            try:
                                yield_cb(url)
                            except Exception:
                                pass
                collected += len(hits)
                new = len(all_targets) - before
                log(f"[*] Censys: page {page+1} — {len(hits)} hits, {new} new  (total: {len(all_targets)})")
                cursor = result.get('links', {}).get('next')
                if not cursor or len(hits) < 100:
                    break
                page += 1
            except requests.exceptions.ConnectionError:
                return list(all_targets), "Censys: No internet connection"
            except Exception as e:
                log(f"[!] Censys error: {e}")
                break

    result_list = list(all_targets)
    log(f"[+] Censys: {len(result_list)} unique targets")
    return result_list, None


# ── LeakIX ────────────────────────────────────────────────────────────────────

LEAKIX_SEARCH = "https://leakix.net/search"

LEAKIX_PRESETS = {
    # ── .env credential leaks — DotEnvConfigPlugin guarantees a real .env ──────
    # Base: filter by exposed .env, then add secret name(s) at the back to target
    ".env → AWS":           '+plugin:"DotEnvConfigPlugin" ("AWS_ACCESS_KEY_ID" OR "AWS_SECRET_ACCESS_KEY")',
    ".env → DB creds":      '+plugin:"DotEnvConfigPlugin" ("DB_PASSWORD" OR "DATABASE_URL" OR "DB_PASS")',
    ".env → Stripe":        '+plugin:"DotEnvConfigPlugin" ("STRIPE_SECRET" OR "STRIPE_KEY")',
    ".env → Twilio":        '+plugin:"DotEnvConfigPlugin" ("TWILIO_ACCOUNT_SID" OR "TWILIO_AUTH_TOKEN")',
    ".env → Mail creds":    '+plugin:"DotEnvConfigPlugin" ("MAILGUN_SECRET" OR "SENDGRID_API_KEY" OR "MAIL_PASSWORD") "MAIL_"',
    ".env → AI keys":       '+plugin:"DotEnvConfigPlugin" ("OPENAI_API_KEY" OR "ANTHROPIC_API_KEY" OR "HUGGINGFACE_API_KEY")',
    ".env → Firebase":      '+plugin:"DotEnvConfigPlugin" ("FIREBASE_API_KEY" OR "FIREBASE_AUTH_DOMAIN")',
    ".env → Payment":       '+plugin:"DotEnvConfigPlugin" ("PAYPAL_SECRET" OR "RAZORPAY_KEY" OR "COINBASE_API_KEY" OR "BINANCE_API_KEY")',
    ".env → Shopify":       '+plugin:"DotEnvConfigPlugin" ("SHOPIFY_API_KEY" OR "SHOPIFY_API_SECRET")',
    ".env → Slack/Discord": '+plugin:"DotEnvConfigPlugin" ("hooks.slack.com" OR "discord.com/api/webhooks")',
    ".env → SSH keys":      '+plugin:"DotEnvConfigPlugin" "BEGIN RSA PRIVATE KEY"',
    ".env Fresh <7d":       '+plugin:"DotEnvConfigPlugin" +age:<7',
    ".env Fresh <24d":      '+plugin:"DotEnvConfigPlugin" +age:<24',
    # ── Git exposure ──────────────────────────────────────────────────────────
    "Git + GitHub Token":   '+plugin:"GitConfigHttpPlugin" +"github.com"',
    "Git Config":           '+plugin:"GitConfigHttpPlugin"',
    # ── Open databases (verified plugin names from /api/plugins) ─────────────
    "MongoDB Open":         '+plugin:"MongoOpenPlugin"',
    "Elasticsearch Open":   '+plugin:"ElasticSearchOpenPlugin"',
    "Redis Open":           '+protocol:redis',
    "CouchDB Open":         '+plugin:"CouchDbOpenPlugin"',
    "ClickHouse Open":      '+plugin:"ClickHousePlugin"',
    "Cassandra Open":       '+plugin:"CassandraOpenPlugin"',
    "Etcd Open":            '+plugin:"EtcdOpenPlugin"',
    "Neo4j Open":           '+plugin:"Neo4jOpenPlugin"',
    "HDFS Open":            '+plugin:"HdfsOpenPlugin"',
    "Kafka Open":           '+plugin:"KafkaOpenPlugin"',
    "Memcached Open":       '+plugin:"MemcachedOpenPlugin"',
    "MySQL Open":           '+plugin:"MysqlOpenPlugin"',
    "ArangoDB Open":        '+plugin:"ArangoDBOpenPlugin"',
    "Mongo Express":        '+plugin:"MongoExpressPlugin"',
    # ── DevOps / infra panels ─────────────────────────────────────────────────
    "Grafana Open":         '+plugin:"GrafanaOpenPlugin"',
    "Jenkins Open":         '+plugin:"JenkinsOpenPlugin"',
    "Jupyter Open":         '+plugin:"JupyterPlugin"',
    "Docker API Open":      '+plugin:"DockerAPIPlugin"',
    "Docker Registry":      '+plugin:"DockerRegistryHttpPlugin"',
    "MinIO Open":           '+plugin:"MinioPlugin"',
    "Airflow Open":         '+plugin:"AirflowPlugin"',
    "N8n Open":             '+plugin:"N8nPlugin"',
    "GitLab":               '+plugin:"GitlabPlugin"',
    # ── AI / ML exposed tools (2024/2025 attack surface) ─────────────────────
    "ChromaDB Open":        '+plugin:"ChromaPlugin"',
    "Milvus Open":          '+plugin:"MilvusPlugin"',
    "MLflow Open":          '+plugin:"MLflowPlugin"',
    "Flowise Open":         '+plugin:"FlowiseVersionPlugin"',
    "Langflow Open":        '+plugin:"LangflowPlugin"',
    "LiteLLM Open":         '+plugin:"LiteLLMPlugin"',
    "ComfyUI Open":         '+plugin:"ComfyUIPlugin"',
    # ── App debug / API exposure ──────────────────────────────────────────────
    "GraphQL Introspect":   '+plugin:"GraphQLIntrospectionPlugin"',
    "Laravel Telescope":    '+plugin:"LaravelTelescopeHttpPlugin"',
    "Django Debug":         '+plugin:"DjangoPlugin"',
    "Metabase Open":        '+plugin:"MetabaseHttpPlugin"',
    "H2 Console":           '+plugin:"H2ConsolePlugin"',
    # ── Severity-based catch-all ──────────────────────────────────────────────
    "Critical Leaks":       '+leak.severity:"critical"',
    "High Fresh <24d":      '+leak.severity:"high" +age:<24',
}


# Ports treated as HTTP-scannable — kept in the URL as-is.
# Anything outside this set is stripped: the IP enters the pool as http://host
# and the InternetDB pre-filter decides whether it has a live web surface.
_LEAKIX_WEB_PORTS = frozenset({
    80, 443,
    8080, 8443, 8000, 8001, 8008, 8081, 8088, 8888,
    3000, 3001, 5000, 5001,
    9000, 9001, 9090, 9443,
})


def leakix_search(api_key: str, queries: list[str],
                  stop_evt=None, log_cb=None, yield_cb=None) -> tuple[list[str], str | None]:
    """Search LeakIX API. api_key is optional (empty string = anonymous).
    No result cap — paginates until exhausted.
    yield_cb(url): optional callback fired immediately for each new unique URL discovered.
    Returns (unique_url_list, error_or_None).
    """
    def log(m): log_cb and log_cb(m)

    all_targets: dict[str, bool] = {}
    queries = [q.strip() for q in queries if q.strip() and not q.strip().startswith('#')]
    if not queries:
        return [], "No queries provided"

    headers = {'Accept': 'application/json'}
    if api_key:
        headers['api-key'] = api_key

    for qi, query in enumerate(queries, 1):
        if stop_evt and stop_evt.is_set():
            break
        log(f"[*] LeakIX [{qi}/{len(queries)}]: {query}")
        page = 0
        while True:
            if stop_evt and stop_evt.is_set():
                break
            try:
                r = requests.get(LEAKIX_SEARCH, headers=headers, timeout=_TIMEOUT,
                                 params={'q': query, 'scope': 'service', 'page': page})
                if r.status_code == 401:
                    return list(all_targets), "LeakIX: Invalid API key"
                if r.status_code == 429:
                    log("[!] LeakIX: rate limited — pausing 15s")
                    import time; time.sleep(15)
                    continue
                if r.status_code == 404 or r.status_code == 204:
                    break
                if r.status_code != 200:
                    log(f"[!] LeakIX: HTTP {r.status_code}")
                    break
                hits = r.json()
                if not hits:
                    break
                before = len(all_targets)
                for hit in hits:
                    ip   = hit.get('ip', '')
                    # Cast to int — LeakIX returns port as int but some responses
                    # come back as string, breaking `port in (443, 8443)` checks
                    try:
                        port = int(hit.get('port', 80))
                    except (TypeError, ValueError):
                        port = 80
                    transport = hit.get('transport', [])
                    tls = 'tls' in transport or port in (443, 8443)
                    # Prefer hostname from SSL CN over raw IP
                    cn = ''
                    try:
                        cn = hit.get('ssl', {}).get('certificate', {}).get('cn', '')
                    except Exception:
                        pass
                    host = cn if cn and '.' in cn else ip
                    if not host:
                        continue
                    # Normalise to a scannable HTTP URL:
                    #   - standard ports (80/443) → strip port
                    #   - known web ports (8080, 8443, etc.) → keep port
                    #   - non-web protocol ports (Redis 6379, MongoDB 27017, …) → strip
                    #     port and fall back to http://host so the IP still enters the
                    #     scanner pool and InternetDB pre-filter decides fate
                    if port == 80:
                        url = f"http://{host}"
                    elif port == 443 or (tls and port not in _LEAKIX_WEB_PORTS):
                        url = f"https://{host}"
                    elif port in _LEAKIX_WEB_PORTS:
                        scheme = 'https' if tls else 'http'
                        url = f"{scheme}://{host}:{port}"
                    else:
                        # Non-web port — keep the IP but scan on standard HTTP
                        url = f"http://{host}"
                    if url not in all_targets:
                        all_targets[url] = True
                        if yield_cb:
                            try:
                                yield_cb(url)
                            except Exception:
                                pass
                new = len(all_targets) - before
                log(f"[*] LeakIX: query {qi} page {page} — {len(hits)} hits, {new} new  (total: {len(all_targets)})")
                if len(hits) == 0:
                    break
                page += 1
            except requests.exceptions.ConnectionError:
                return list(all_targets), "LeakIX: No internet connection"
            except Exception as e:
                log(f"[!] LeakIX error: {e}")
                break

    result_list = list(all_targets)
    log(f"[+] LeakIX: {len(result_list)} unique targets")
    return result_list, None


# ── crt.sh Certificate Transparency ──────────────────────────────────────────

CRTSH_API = "https://crt.sh/"


def crtsh_search(domains: list[str], log_cb=None) -> tuple[list[str], str | None]:
    """
    Find subdomains via certificate transparency logs (crt.sh).
    domains: list of apex domains e.g. ['example.com']
    Returns (unique_url_list, error_or_None).
    No API key required.
    """
    def log(m): log_cb and log_cb(m)

    all_targets: dict[str, bool] = {}
    domains = [d.strip().lstrip('*.').lower() for d in domains
               if d.strip() and not d.strip().startswith('#')]
    if not domains:
        return [], "No domains provided"

    for di, domain in enumerate(domains, 1):
        log(f"[*] crt.sh [{di}/{len(domains)}]: *.{domain}")
        try:
            r = requests.get(CRTSH_API, timeout=30,
                             params={'q': f'%.{domain}', 'output': 'json'},
                             headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code != 200:
                log(f"[!] crt.sh: HTTP {r.status_code} for {domain}")
                continue
            entries = r.json()
            log(f"[*] crt.sh: {len(entries)} certificate entries for {domain}")
            seen: set[str] = set()
            for entry in entries:
                # name_value may contain newline-separated SANs
                names = set()
                for field in ('common_name', 'name_value'):
                    val = entry.get(field, '')
                    for n in val.split('\n'):
                        n = n.strip().lstrip('*.')
                        if n and '.' in n and not n.startswith('@'):
                            names.add(n.lower())
                for name in names:
                    if name in seen:
                        continue
                    seen.add(name)
                    # Use https by default; scanner will try http on SSL errors
                    url = f"https://{name}"
                    all_targets[url] = True
            log(f"[+] crt.sh: {len(seen)} unique subdomains for {domain}")
        except requests.exceptions.ConnectionError:
            return list(all_targets), "crt.sh: No internet connection"
        except Exception as e:
            log(f"[!] crt.sh error for {domain}: {e}")
            continue

    result_list = list(all_targets)
    log(f"[+] crt.sh total: {len(result_list)} unique targets")
    return result_list, None


# ── Shodan InternetDB pre-filter (free, no key required) ─────────────────────

INTERNETDB_API = "https://internetdb.shodan.io/"
_WEB_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000, 5000})


def internetdb_prefilter(targets: list[str], log_cb=None) -> list[str]:
    """
    Pre-filter IP-based targets through Shodan's free InternetDB API.
    Keeps IPs that have confirmed web ports; passes through hostname-based targets.
    Reduces wasted scan time by ~40-60% on raw IP pools.
    """
    import re
    def log(m): log_cb and log_cb(m)

    _ip_re = re.compile(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    filtered: list[str] = []
    ip_targets  = [t for t in targets if _ip_re.match(t)]
    host_targets = [t for t in targets if not _ip_re.match(t)]

    log(f"[InternetDB] Pre-filtering {len(ip_targets)} IP targets ({len(host_targets)} hostnames pass-through)…")

    kept = 0
    for t in ip_targets:
        ip = _ip_re.match(t).group(1)
        try:
            r = requests.get(f"{INTERNETDB_API}{ip}", timeout=5)
            if r.status_code == 200:
                ports = set(r.json().get('ports', []))
                if ports & _WEB_PORTS:
                    filtered.append(t)
                    kept += 1
            elif r.status_code == 404:
                pass   # IP unknown to Shodan — skip
            else:
                filtered.append(t)  # keep on unexpected status
        except Exception:
            filtered.append(t)      # keep on timeout/error

    log(f"[InternetDB] Kept {kept}/{len(ip_targets)} IPs with open web ports")
    return host_targets + filtered
