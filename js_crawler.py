"""
SB - Professional Security Scanner
Deep JS crawler — extracts all script bundles from a target page and
scans each for exposed API keys.  Validates OpenAI / GitHub /
HuggingFace / Stripe keys immediately when found.
Authorized use only.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_MAX_JS_FILES  = 50          # hard cap per target
_MAX_TOTAL_MB  = 5           # total bytes cap per target
_MAX_FILE_SIZE = 500_000     # bytes per individual JS file

_SCRIPT_SRC = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE
)

# Extra patterns specific to compiled JS (supplement scan_for_api_creds)
_JS_EXTRA_PATTERNS = {
    'OpenAI_Key':        r'sk-(?:proj-[A-Za-z0-9\-_]{50,}|[A-Za-z0-9]{48})',
    'Anthropic_Key':     r'sk-ant-(?:api\d{2}-)?[A-Za-z0-9\-_]{80,}',
    'HuggingFace_Token': r'hf_[A-Za-z0-9]{30,}',
    'GitHub_PAT':        r'github_pat_[A-Za-z0-9_]{80,}',
    'GitHub_Token':      r'gh[os]_[A-Za-z0-9]{36,}',
    'Gemini_Key':        r'AIza[0-9A-Za-z\-_]{35}',
    # Removed: Mapbox_Token (public browser key, not a secret),
    #          Azure_Subscription (plain UUID — matches every JS UUID constant)
}

# Key types we can validate with a single API call
_VALIDATABLE = {'OpenAI_Key', 'GitHub_PAT', 'GitHub_Token', 'HuggingFace_Token', 'Stripe_SK'}

# Skip third-party analytics / ad scripts — never contain app keys
_SKIP_HOSTS = frozenset({
    'google-analytics.com', 'googletagmanager.com', 'googleadservices.com',
    'facebook.com', 'fbcdn.net', 'twitter.com', 'hotjar.com',
    'intercom.io', 'crisp.chat', 'segment.com', 'mixpanel.com',
    'amplitude.com', 'fullstory.com', 'sentry.io', 'datadog.com',
})


def _extract_js_urls(base_url: str, html: str) -> list[str]:
    """Return same-origin absolute JS URLs from HTML."""
    base_parsed = urlparse(base_url)
    base_host   = base_parsed.netloc
    seen = set()
    urls = []
    for src in _SCRIPT_SRC.findall(html):
        src = src.strip()
        if not src or src.startswith('data:'):
            continue
        abs_url = urljoin(base_url, src)
        parsed  = urlparse(abs_url)
        # Skip known third-party analytics hosts
        if any(skip in (parsed.netloc or '') for skip in _SKIP_HOSTS):
            continue
        # Only same-origin bundles
        if parsed.netloc and parsed.netloc != base_host:
            continue
        path = parsed.path
        if not (path.endswith('.js') or '.js' in path.split('/')[-1]):
            continue
        if abs_url not in seen:
            seen.add(abs_url)
            urls.append(abs_url)
    return urls


def _scan_text(content: str) -> dict:
    """Run all key patterns against JS content. Returns {label: matched_value}."""
    from extractor import scan_for_api_creds
    found = scan_for_api_creds(content) or {}
    for name, pat in _JS_EXTRA_PATTERNS.items():
        if name in found:
            continue
        m = re.search(pat, content)
        if m:
            val = m.group(0)
            if len(val) >= 10:
                found[name] = val[:160]
    return found


def _validate_found(key_type: str, value: str, timeout: int) -> dict:
    """
    Live-validate a regex-matched key where possible.
    Returns a result dict to merge into finding data.
    Empty dict = no validator available for this type.
    """
    try:
        if key_type == 'OpenAI_Key':
            from validator import validate_openai
            return validate_openai(value, timeout) or {}
        if key_type in ('GitHub_PAT', 'GitHub_Token'):
            from validator import validate_github_token
            return validate_github_token(value, timeout) or {}
        if key_type == 'HuggingFace_Token':
            from validator import validate_huggingface
            return validate_huggingface(value, timeout) or {}
        if key_type == 'Stripe_SK':
            from validator import validate_stripe
            return validate_stripe(value, timeout) or {}
    except Exception:
        pass
    return {}


def crawl_js(base_url: str, session, timeout: int, log_cb=None) -> list[dict]:
    """
    1. Fetch the root page and extract <script src="..."> URLs.
    2. Download up to _MAX_JS_FILES same-origin JS bundles (5MB cap total).
    3. Scan each with scan_for_api_creds + _JS_EXTRA_PATTERNS.
    4. Validate OpenAI / GitHub / HuggingFace / Stripe keys immediately.
    Returns a list of finding dicts compatible with Scanner._handle().
    """
    findings = []
    try:
        r = session.get(base_url, timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code not in (200, 206):
            return []

        js_urls = _extract_js_urls(base_url, r.text)
        if not js_urls:
            return []

        cap = min(len(js_urls), _MAX_JS_FILES)
        if log_cb:
            log_cb(f"  [JS] {base_url} — {cap}/{len(js_urls)} JS bundle(s) to crawl")

        total_bytes = 0
        scanned     = 0
        lock        = __import__('threading').Lock()

        def _process(js_url: str):
            nonlocal total_bytes, scanned
            with lock:
                if total_bytes >= _MAX_TOTAL_MB * 1_000_000:
                    return None
            try:
                jr = session.get(js_url, timeout=timeout, verify=False)
                if jr.status_code != 200:
                    return None
                raw = jr.text[:_MAX_FILE_SIZE]
                with lock:
                    total_bytes += len(raw.encode('utf-8', errors='replace'))
                    scanned     += 1
                creds = _scan_text(raw)
                if not creds:
                    return None
                # Validate what we can; mark the rest as accessible
                validated_any = False
                extra = {}
                for ktype, kval in creds.items():
                    if ktype in _VALIDATABLE:
                        result = _validate_found(ktype, kval, timeout)
                        if result:
                            extra.update(result)
                            if result.get('validated') is True or 'LIVE' in result.get('validation', ''):
                                validated_any = True
                suffix = '/' + js_url.replace(base_url.rstrip('/'), '').lstrip('/')
                return {
                    'type': 'api_keys',
                    'url':  base_url,
                    'path': suffix[:200],
                    'data': {
                        'note':      'API key(s) found in JS bundle',
                        'js_url':    js_url,
                        'validated': True if validated_any else None,
                        **creds,
                        **extra,
                    },
                }
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(_process, url): url for url in js_urls[:cap]}
            for fut in as_completed(futs):
                result = fut.result()
                if result:
                    findings.append(result)

        if log_cb:
            log_cb(f"  [JS] {base_url} — {scanned} file(s) scanned  "
                   f"{total_bytes // 1024}KB read  {len(findings)} hit(s)")

    except Exception:
        pass

    return findings
