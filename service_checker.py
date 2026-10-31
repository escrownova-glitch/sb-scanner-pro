"""
SB - Professional Security Scanner
Service detection: FTP / SSH / cPanel / WHM / Webmail.
Authorized use only.
"""

import ftplib
import re
import socket

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CPANEL_CHECKS = [
    (2082, 'http',  'cPanel',   ['cpanel', 'webhost']),
    (2083, 'https', 'cPanel',   ['cpanel', 'webhost']),
    (2086, 'http',  'WHM',      ['whm', 'webhost manager', 'webhost']),
    (2087, 'https', 'WHM',      ['whm', 'webhost manager', 'webhost']),
    (2095, 'http',  'Webmail',  ['webmail', 'roundcube', 'horde', 'squirrelmail']),
    (2096, 'https', 'Webmail',  ['webmail', 'roundcube', 'horde', 'squirrelmail']),
]

PLESK_CHECKS = [
    (8443, 'https', 'Plesk', ['plesk', 'parallels', 'webadmin']),
    (8880, 'http',  'Plesk', ['plesk', 'parallels']),
]

FTP_PORTS = (21, 2121)
SSH_PORTS = (22, 2222)


def _extract_host(url: str) -> str:
    m = re.match(r'https?://([^/:]+)', url.strip())
    return m.group(1) if m else url.strip()


def _banner(host: str, port: int, timeout: int) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(2048)
            return data.decode('utf-8', errors='ignore').strip()
    except Exception:
        return None


def _check_ftp(host: str, timeout: int) -> dict | None:
    """
    Detect FTP precisely: banner must start with 220 (FTP welcome code,
    also used by SMTP) AND either identify itself as FTP in the banner
    OR pass a protocol-level handshake via ftplib.
    """
    for port in FTP_PORTS:
        b = _banner(host, port, timeout)
        if not b or not b.startswith('220'):
            continue

        bu = b.upper()
        is_ftp_banner = any(k in bu for k in
                            ('FTP', 'FILEZILLA', 'PROFTPD', 'VSFTPD', 'PURE-FTPD'))

        confirmed_ftp = False
        anon_ok       = False
        files         = None
        ftp           = ftplib.FTP()
        try:
            ftp.connect(host, port, timeout=timeout)
            try:
                ftp.login('anonymous', 'probe@scan.local')
                confirmed_ftp = True
                anon_ok       = True
                try:
                    files = str(ftp.nlst()[:10])
                except Exception:
                    pass
            except ftplib.error_perm:
                # Server spoke FTP and rejected anon — confirmed FTP
                confirmed_ftp = True
        except (ftplib.error_proto, ftplib.error_reply, ftplib.error_temp):
            # 220 banner but not FTP protocol — likely SMTP / other
            continue
        except Exception:
            pass
        finally:
            try:
                ftp.quit()
            except Exception:
                pass

        if not (confirmed_ftp or is_ftp_banner):
            continue

        result = {
            'port':      port,
            'banner':    b[:200],
            'url':       f"ftp://{host}:{port}/",
            'note':      (f"FTP ANONYMOUS LOGIN on port {port}" if anon_ok
                          else f"FTP service on port {port}"),
            'validated': True if anon_ok else None,
        }
        if anon_ok:
            result['username'] = 'anonymous'
            result['password'] = 'anonymous'
        if files:
            result['files'] = files
        return result
    return None


def _check_ssh(host: str, timeout: int) -> dict | None:
    for port in SSH_PORTS:
        b = _banner(host, port, timeout)
        if b and 'SSH' in b:
            return {'port': port, 'banner': b[:200],
                    'url': f"ssh://{host}:{port}",
                    'note': f"SSH service on port {port}"}
    return None


def _check_panels(host: str, session, timeout: int) -> list[dict]:
    results = []
    for port, scheme, label, keywords in CPANEL_CHECKS:
        url = f"{scheme}://{host}:{port}/"
        try:
            r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            if r.status_code not in (200, 301, 302, 401, 403):
                continue
            cl = r.text.lower()
            if any(k in cl for k in keywords):
                results.append({
                    'note':   f"{label} panel detected on port {port}",
                    'url':    url,
                    'status': r.status_code,
                    'label':  label,
                    'port':   port,
                })
        except Exception:
            continue
    return results


def _check_plesk(host: str, session, timeout: int) -> list[dict]:
    results = []
    for port, scheme, label, keywords in PLESK_CHECKS:
        url = f"{scheme}://{host}:{port}/"
        try:
            r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            if r.status_code not in (200, 301, 302, 401, 403):
                continue
            cl = r.text.lower()
            if any(k in cl for k in keywords):
                results.append({
                    'note':   f"{label} panel on port {port}",
                    'url':    url,
                    'status': r.status_code,
                    'label':  label,
                    'port':   port,
                    'scheme': scheme,
                })
        except Exception:
            continue
    return results


def scan_services(base_url: str, session, timeout: int) -> list[dict]:
    """
    Detect FTP, SSH, cPanel, WHM, Webmail, and Plesk on a given target.

    Policy: report what is present and save the finding — do NOT attempt
    wordlist credential brute-forcing.  Only anonymous FTP login is tried
    because that requires no guessing (the server either allows it or not).
    If credentials are later extracted from a vuln path (.env, config leak),
    _probe_db_creds_on_services() will test those *known* credentials against
    SSH/cPanel separately — that is targeted credential reuse, not guessing.
    """
    host     = _extract_host(base_url)
    svc_to   = min(timeout, 2)   # port probes: 2s is enough; closed ports timeout fast
    findings = []

    # ── FTP — only report when anonymous login succeeds (real access) ────────
    ftp = _check_ftp(host, svc_to)
    if ftp and ftp.get('validated') is True:
        findings.append({
            'type': 'ftp',
            'url':  base_url,
            'path': f":{ftp['port']}/",
            'data': {'host': host, **ftp},
        })

    # SSH banner-only detection dropped — no credentials, not actionable.
    # Credential reuse against SSH is handled separately by _probe_db_creds_on_services().

    # cPanel / WHM / Webmail / Plesk panel detection dropped — login pages
    # with no credentials. Credential reuse against cPanel port 2083 is handled
    # separately by _probe_db_creds_on_services().

    return findings
