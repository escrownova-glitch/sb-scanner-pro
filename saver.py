"""
SB - Professional Security Scanner
Result saving — routes each finding to its dedicated results file.
"""

import os
import sys
import threading
from datetime import datetime

_write_lock    = threading.Lock()
_ip_file_lock  = threading.Lock()
_ip_log_files: dict = {}   # source_key → filepath (for streaming auto-save)
_dir_init_lock = threading.Lock()
_dir_initialized = False   # ensure_results_dir runs its 60-file setup only once


def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


_SESSION_STAMP = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
RESULTS_DIR    = os.path.join(get_base_dir(), "results", _SESSION_STAMP)

RESULT_FILES = {
    # ── Infrastructure ──────────────────────────────────────────────────────
    'db':             'db.txt',
    'aws':            'aws.txt',
    'stripe':         'stripe.txt',
    'shopify':        'shopify.txt',
    'binance':        'binance.txt',
    'coinbase':       'coinbase.txt',
    'paxful':         'paxful.txt',
    'api_keys':       'api-keys.txt',
    # ── SMTP / Email providers ───────────────────────────────────────────────
    'mail':           'mail-smtp.txt',
    'mail_gmail':     'smtp-gmail.txt',
    'mail_office365': 'smtp-office365.txt',
    'mail_amazon':    'smtp-amazon-ses.txt',
    'mail_sendgrid':  'smtp-sendgrid.txt',
    'mail_mailgun':   'smtp-mailgun.txt',
    'mail_brevo':     'smtp-brevo.txt',
    'mail_zoho':      'smtp-zoho.txt',
    'mail_mandrill':  'smtp-mandrill.txt',
    'mail_ionos':     'smtp-ionos.txt',
    'mail_rackspace': 'smtp-rackspace.txt',
    'mail_other':     'smtp-other.txt',
    'mailgun':        'mailgun.txt',
    'sendgrid':       'sendgrid.txt',
    'postmark':       'postmark.txt',
    'brevo':          'brevo.txt',
    'sparkpost':      'sparkpost.txt',
    'mandrill':       'mandrill.txt',
    'mailjet':        'mailjet.txt',
    'elasticemail':   'elasticemail.txt',
    # ── SMS / Voice providers ────────────────────────────────────────────────
    'twilio':         'twilio-api.txt',
    'plivo':          'plivo.txt',
    'nexmo':          'nexmo.txt',
    'messagebird':    'messagebird.txt',
    'sinch':          'sinch.txt',
    'telnyx':         'telnyx.txt',
    'bandwidth':      'bandwidth.txt',
    'africas_talking':'africas-talking.txt',
    'bulksms':        'bulksms.txt',
    'clicksend':      'clicksend.txt',
    'telesign':       'telesign.txt',
    'clickatell':     'clickatell.txt',
    'sms_api':        'sms-api.txt',
    # ── Combo / access logs (compact one-liner format) ────────────────────────
    'db_combo':       'db-combos.txt',
    'ssh_access':     'ssh-access.txt',
    'cpanel_access':  'cpanel-access.txt',
    'phpmyadmin':     'phpmyadmin-access.txt',
    # ── Vulnerable path index ─────────────────────────────────────────────────
    'vuln_paths':     'vuln-paths.txt',
    # ── CMS ─────────────────────────────────────────────────────────────────
    'wordpress':      'wordpress.txt',
    'wp_exploits':    'wp-exploits.txt',
    'joomla':         'joomla.txt',
    'laravel':        'laravel.txt',
    'magento':        'magento.txt',
    # ── Services / Access ────────────────────────────────────────────────────
    'shell':          'shells.txt',
    'cpanel':         'cpanel.txt',
    'whm':            'whm.txt',
    'plesk':          'plesk.txt',
    'ftp':            'ftp.txt',
    'ssh':            'ssh.txt',
    'exposure':       'exposure.txt',
    'general':        'general.txt',
}


def ensure_results_dir():
    global _dir_initialized
    # Fast path — after first call this is a single bool check with no I/O.
    if _dir_initialized:
        return
    with _dir_init_lock:
        if _dir_initialized:
            return
        os.makedirs(RESULTS_DIR, exist_ok=True)
        for label, fname in RESULT_FILES.items():
            fpath = os.path.join(RESULTS_DIR, fname)
            if not os.path.exists(fpath):
                with open(fpath, 'w', encoding='utf-8') as f:
                    f.write(f"# SB - Professional Security Scanner\n")
                    f.write(f"# Category: {label.upper()}\n")
                    f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d')}\n")
                    f.write("=" * 70 + "\n\n")
        master = os.path.join(RESULTS_DIR, 'all_findings.txt')
        if not os.path.exists(master):
            with open(master, 'w', encoding='utf-8') as f:
                f.write("# SB - Professional Security Scanner — All Findings\n")
                f.write("=" * 70 + "\n\n")
        _dir_initialized = True


def save_extracted_ip(source: str, url: str) -> None:
    """
    Append one URL to the session's auto-save log for a given OSINT source.
    Each source gets its own timestamped file under results/{session}/extracted_ips/.
    Called immediately as each IP is discovered during streaming fetch.
    """
    ensure_results_dir()
    key = source.lower().replace(' ', '_')
    with _ip_file_lock:
        if key not in _ip_log_files:
            ips_dir = os.path.join(RESULTS_DIR, 'extracted_ips')
            os.makedirs(ips_dir, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            fpath = os.path.join(ips_dir, f'{key}_{ts}.txt')
            _ip_log_files[key] = fpath
            with open(fpath, 'w', encoding='utf-8') as f:
                f.write(f"# {source.upper()} Extracted IPs\n")
                f.write(f"# Session: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        log_path = _ip_log_files[key]
    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(url + '\n')
    except Exception:
        pass


def save_finding(finding_type, url, path, data):
    ensure_results_dir()
    filename  = RESULT_FILES.get(finding_type, 'general.txt')
    filepath  = os.path.join(RESULTS_DIR, filename)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target    = f"{url}{path}"

    block_lines = [
        f"\n{'=' * 70}",
        f"[{timestamp}]  [{finding_type.upper()}]  {target}",
        f"{'=' * 70}",
        f"  {'URL':<35} {target}",
    ]
    if isinstance(data, dict):
        # Write credentials/keys first, then metadata, then status last
        META_KEYS = {'note', 'url', 'source_url', 'validated', 'validation',
                     'preview', 'size_bytes', 'indicators', 'label', 'status',
                     'host', 'port', 'banner', 'files', 'exec_confirmed'}
        cred_lines = []
        meta_lines = []
        for k, v in data.items():
            if k == 'url':       # already printed as URL header
                continue
            if k in META_KEYS:
                meta_lines.append(f"  {k:<35} {v}")
            else:
                cred_lines.append(f"  {k:<35} {v}")
        block_lines.extend(cred_lines)
        block_lines.extend(meta_lines)
    else:
        block_lines.append(f"  {data}")
    block_lines.append("")
    block = "\n".join(block_lines) + "\n"

    # Category-specific SMTP routing: write a quick combo line to the provider file
    _SMTP_CAT_KEY = {
        'gmail':      'mail_gmail',
        'office365':  'mail_office365',
        'amazon_ses': 'mail_amazon',
        'sendgrid':   'mail_sendgrid',
        'mailgun':    'mail_mailgun',
        'brevo':      'mail_brevo',
        'zoho':       'mail_zoho',
        'mandrill':   'mail_mandrill',
        'ionos':      'mail_ionos',
        'rackspace':  'mail_rackspace',
        'other':      'mail_other',
    }
    cat_block = None
    if (finding_type == 'mail' and isinstance(data, dict)
            and data.get('validated') is True
            and data.get('smtp_combo')):
        cat_key  = _SMTP_CAT_KEY.get(data.get('smtp_category', 'other'), 'mail_other')
        cat_file = RESULT_FILES.get(cat_key)
        if cat_file:
            source   = data.get('source_url', target)
            cat_line = f"{source} | {data['smtp_combo']}\n"
            cat_block = (os.path.join(RESULTS_DIR, cat_file), cat_line)

    # ── Compact combo lines for quick-use files ───────────────────────────────
    combo_blocks = []   # list of (filepath, line)
    if isinstance(data, dict):
        # DB combo: source_url | db_host | db_user | db_pass | db_name
        if finding_type == 'db':
            db_h = data.get('DB_HOST', '')
            db_u = data.get('DB_USERNAME', '')
            db_p = data.get('DB_PASSWORD', '')
            db_n = data.get('DB_DATABASE', '')
            if db_u and db_p:
                combo_line = f"{target} | {db_h} | {db_u} | {db_p} | {db_n}\n"
                combo_blocks.append((os.path.join(RESULTS_DIR, RESULT_FILES['db_combo']),
                                     combo_line))
        # SSH access: source_url | user@host:22
        if data.get('ssh_login'):
            ssh_line = f"{target} | {data['ssh_login']}\n"
            combo_blocks.append((os.path.join(RESULTS_DIR, RESULT_FILES['ssh_access']),
                                 ssh_line))
        # cPanel access: source_url | user@host:2083
        if data.get('cpanel_login'):
            cp_line = f"{target} | {data['cpanel_login']}\n"
            combo_blocks.append((os.path.join(RESULTS_DIR, RESULT_FILES['cpanel_access']),
                                 cp_line))
        # phpMyAdmin access
        if data.get('phpmyadmin_login'):
            pma_line = f"{target} | {data['phpmyadmin_login']}\n"
            combo_blocks.append((os.path.join(RESULTS_DIR, RESULT_FILES['phpmyadmin']),
                                 pma_line))

    with _write_lock:
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(block)
        if cat_block:
            with open(cat_block[0], 'a', encoding='utf-8') as f:
                f.write(cat_block[1])
        for cb_path, cb_line in combo_blocks:
            with open(cb_path, 'a', encoding='utf-8') as f:
                f.write(cb_line)

        # Append every confirmed finding's URL to the vuln-paths index
        vuln_paths_file = os.path.join(RESULTS_DIR, RESULT_FILES['vuln_paths'])
        with open(vuln_paths_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{finding_type.upper():<14}] {target}\n")

        master = os.path.join(RESULTS_DIR, 'all_findings.txt')
        with open(master, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{finding_type.upper():<12}] {target}\n")
            if isinstance(data, dict):
                for k, v in data.items():
                    f.write(f"    {k}: {v}\n")
            f.write("\n")
