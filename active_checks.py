"""
SB - Professional Security Scanner
Active misconfiguration probes — CORS reflection, Host header injection,
open redirect, HTTP verb tampering, X-Forwarded-For bypass.

Each probe sends one crafted request and inspects the response.
Nothing executes on the target. Nothing writes. Passive-read only.
"""

_REDIRECT_PARAMS = [
    'next', 'url', 'redirect', 'redirect_uri', 'redirect_url',
    'return', 'return_to', 'returnUrl', 'returnTo', 'continue',
    'destination', 'goto', 'target', 'redir', 'location',
    'forward', 'callback', 'successUrl', 'back', 'ref', 'referer',
]

_EVIL_ORIGIN   = 'https://evil-cors-probe.example.com'
_EVIL_HOST     = 'evil-host-inject.example.com'
_EVIL_REDIRECT = 'https://evil-redir-probe.example.com'

_ADMIN_PATHS   = [
    '/admin', '/admin/', '/internal', '/internal/',
    '/api/internal', '/management', '/management/',
    '/actuator', '/actuator/env',
]


def _req(session, url, timeout, **kwargs):
    return session.get(url, timeout=timeout, verify=False, **kwargs)


def check_cors(base_url, session, timeout, log_cb=None) -> list:
    """CORS misconfiguration — arbitrary Origin reflection or null origin acceptance."""
    findings = []
    target = base_url.rstrip('/') + '/'

    for origin in (_EVIL_ORIGIN, 'null'):
        try:
            r = _req(session, target, timeout,
                     headers={'Origin': origin}, allow_redirects=True)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '').lower()
            if acao not in ('', '*', 'null') and acao == origin:
                # Reflected specific origin — worst case
                sev = 'CRITICAL' if acac == 'true' else 'HIGH'
                findings.append({
                    'type': 'misconfig', 'url': base_url, 'path': '/',
                    'data': {
                        'note':      (f'CORS misconfiguration [{sev}] — '
                                      f'ACAO: {acao} | ACAC: {acac or "not set"}. '
                                      f'Cross-origin reads{"+ credentialed requests" if acac == "true" else ""} possible.'),
                        'cors_origin':      acao,
                        'cors_credentials': acac,
                        'validated':        True,
                    },
                })
                break
            elif acao == '*' and acac == 'true':
                # Spec violation but some servers do this
                findings.append({
                    'type': 'misconfig', 'url': base_url, 'path': '/',
                    'data': {
                        'note':      'CORS misconfiguration [HIGH] — wildcard ACAO with credentials flag.',
                        'cors_origin': '*',
                        'cors_credentials': acac,
                        'validated': True,
                    },
                })
                break
            elif origin == 'null' and acao == 'null':
                findings.append({
                    'type': 'misconfig', 'url': base_url, 'path': '/',
                    'data': {
                        'note':      'CORS misconfiguration [MEDIUM] — null origin accepted. '
                                     'Sandbox iframe bypass possible.',
                        'cors_origin': 'null',
                        'validated': True,
                    },
                })
        except Exception:
            continue
    return findings


def check_host_header(base_url, session, timeout, log_cb=None) -> list:
    """Host header injection — does the server reflect an injected Host value?"""
    findings = []
    try:
        r = _req(session, base_url.rstrip('/') + '/',
                 timeout=timeout,
                 headers={'Host': _EVIL_HOST, 'X-Forwarded-Host': _EVIL_HOST},
                 allow_redirects=False)
        location = r.headers.get('Location', '')
        body     = r.text[:4000]
        reflected_in = None
        if _EVIL_HOST in location:
            reflected_in = f'Location: {location[:200]}'
        elif _EVIL_HOST in body:
            reflected_in = 'response body'
        if reflected_in:
            findings.append({
                'type': 'misconfig', 'url': base_url, 'path': '/',
                'data': {
                    'note':         ('Host header injection — server reflects injected Host value. '
                                     'Password-reset poisoning / web-cache poisoning surface.'),
                    'reflected_in': reflected_in,
                    'injected_host': _EVIL_HOST,
                    'validated':    True,
                },
            })
    except Exception:
        pass
    return findings


def check_open_redirect(base_url, session, timeout, log_cb=None) -> list:
    """Open redirect — test common redirect params for external URL reflection."""
    findings = []
    for param in _REDIRECT_PARAMS:
        try:
            r = _req(session, f'{base_url.rstrip("/")}/?{param}={_EVIL_REDIRECT}',
                     timeout=timeout, allow_redirects=False)
            location = r.headers.get('Location', '')
            if _EVIL_REDIRECT in location and r.status_code in (301, 302, 303, 307, 308):
                findings.append({
                    'type': 'misconfig', 'url': base_url, 'path': '/',
                    'data': {
                        'note':      f'Open redirect via ?{param}= — arbitrary external redirect confirmed.',
                        'param':     param,
                        'location':  location[:300],
                        'validated': True,
                    },
                })
                break
        except Exception:
            continue
    return findings


def check_http_methods(base_url, session, timeout, live_paths=None, log_cb=None) -> list:
    """HTTP verb tampering — flag if PUT / DELETE / TRACE are advertised via OPTIONS."""
    findings = []
    dangerous = {'PUT', 'DELETE', 'TRACE', 'CONNECT'}
    targets   = [base_url.rstrip('/') + '/']
    if live_paths:
        for p in list(live_paths)[:6]:
            targets.append(base_url.rstrip('/') + p)

    for url in targets:
        try:
            r = session.options(url, timeout=timeout, verify=False)
            allow = (r.headers.get('Allow', '') + ' '
                     + r.headers.get('Public', '') + ' '
                     + r.headers.get('Access-Control-Allow-Methods', ''))
            found = {m for m in dangerous if m in allow.upper()}
            if found:
                path = url.replace(base_url.rstrip('/'), '') or '/'
                findings.append({
                    'type': 'misconfig', 'url': base_url, 'path': path,
                    'data': {
                        'note':      f'Dangerous HTTP methods allowed: {", ".join(sorted(found))}',
                        'methods':   sorted(found),
                        'allow_hdr': allow.strip()[:200],
                        'validated': True,
                    },
                })
        except Exception:
            continue
    return findings


def check_xff_bypass(base_url, session, timeout, log_cb=None) -> list:
    """X-Forwarded-For bypass — does spoofing loopback IP unlock restricted paths?"""
    findings = []
    bypass_headers = {
        'X-Forwarded-For':   '127.0.0.1',
        'X-Real-IP':         '127.0.0.1',
        'X-Original-IP':     '127.0.0.1',
        'X-Remote-IP':       '127.0.0.1',
        'CF-Connecting-IP':  '127.0.0.1',
        'True-Client-IP':    '127.0.0.1',
        'X-Client-IP':       '127.0.0.1',
    }
    for apath in _ADMIN_PATHS:
        url = base_url.rstrip('/') + apath
        try:
            r_base = _req(session, url, timeout, allow_redirects=False)
            if r_base.status_code not in (401, 403):
                continue
            r_bypass = _req(session, url, timeout,
                            headers=bypass_headers, allow_redirects=False)
            if r_bypass.status_code not in (401, 403):
                findings.append({
                    'type': 'misconfig', 'url': base_url, 'path': apath,
                    'data': {
                        'note':            (f'IP whitelist bypass via X-Forwarded-For: 127.0.0.1 — '
                                            f'{r_base.status_code} → {r_bypass.status_code} on {apath}'),
                        'baseline_status': r_base.status_code,
                        'bypass_status':   r_bypass.status_code,
                        'path':            apath,
                        'validated':       True,
                    },
                })
                break
        except Exception:
            continue
    return findings


def run_active_checks(base_url, session, timeout, live_paths=None, log_cb=None) -> list:
    """Run all active misconfiguration probes. Called once per target."""
    if log_cb:
        log_cb(f'  [>] {base_url} — active checks: CORS, Host-inject, redirect, verb, XFF')
    findings = []
    for fn in (check_cors, check_host_header, check_open_redirect, check_xff_bypass):
        try:
            findings.extend(fn(base_url, session, timeout, log_cb))
        except Exception:
            pass
    try:
        findings.extend(check_http_methods(base_url, session, timeout, live_paths, log_cb))
    except Exception:
        pass
    return findings
