"""
SB - Professional Security Scanner
Credential and data extraction from HTTP responses.
"""

import re
import json


_ENV_SKIP = frozenset({
    'null', 'false', 'true', '', 'your-key-here', 'secret', 'password',
    'example', 'changeme', 'your-application-key', 'xxxxxxxxxxxxxxxxxxxxxxxx',
})


def extract_env_var(content, key):
    # ── Plain text format: KEY=value ─────────────────────────────────────────
    pattern = rf'^{re.escape(key)}[ \t]*=[ \t]*(.+?)[ \t]*$'
    match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
    if match:
        val = match.group(1).strip().strip('"\'').strip()
        if val and val.lower() not in _ENV_SKIP and not val.startswith('**'):
            return val

    # ── Laravel debug HTML table format: <td>KEY</td><td><pre…>value</span> ─
    # APP_DEBUG=true exposes all env vars in an HTML table on exception pages.
    html_pat = (rf'<td[^>]*>\s*{re.escape(key)}\s*</td>'
                rf'\s*<td[^>]*>\s*(?:<pre[^>]*>)?(.*?)(?:</span>|</pre>|</td>)')
    m = re.search(html_pat, content, re.IGNORECASE | re.DOTALL)
    if m:
        val = re.sub(r'<[^>]+>', '', m.group(1)).strip().strip('"\'').strip()
        if val and val.lower() not in _ENV_SKIP and not val.startswith('**'):
            return val

    return None


def _pick(content, keys):
    return {k: v for k in keys if (v := extract_env_var(content, k))}


# ── .env credential extractors ───────────────────────────────────────────────

def extract_db(content):
    keys = ['DB_CONNECTION', 'DB_HOST', 'DB_PORT', 'DB_DATABASE', 'DB_USERNAME', 'DB_PASSWORD']
    creds = _pick(content, keys)
    return creds if (creds.get('DB_PASSWORD') or creds.get('DB_DATABASE')) else None


def extract_aws(content):
    keys = [
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION',
        'AWS_BUCKET', 'AWS_URL', 'AWS_ENDPOINT', 'AWS_USE_PATH_STYLE_ENDPOINT',
        # Alternate key names found in many Laravel apps
        'AWS_KEY', 'AWS_SECRET', 'AWS_REGION',
        # AWS SES-specific variants
        'SES_KEY', 'SES_SECRET', 'SES_REGION',
        # S3 / S3-compatible storage (Flysystem, Laravel filesystem driver)
        'S3_KEY', 'S3_SECRET', 'S3_BUCKET', 'S3_REGION', 'S3_URL', 'S3_ENDPOINT',
        'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY',
        'FILESYSTEM_ACCESS_KEY_ID', 'FILESYSTEM_SECRET_ACCESS_KEY',
        # DigitalOcean Spaces
        'DO_SPACES_KEY', 'DO_SPACES_SECRET', 'DO_SPACES_BUCKET',
        'DO_SPACES_REGION', 'DO_SPACES_ENDPOINT',
        'SPACES_KEY', 'SPACES_SECRET',
        # Cloudflare R2
        'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_BUCKET', 'R2_ENDPOINT',
        'CLOUDFLARE_R2_ACCESS_KEY_ID', 'CLOUDFLARE_R2_SECRET_ACCESS_KEY',
        # Wasabi
        'WASABI_ACCESS_KEY_ID', 'WASABI_SECRET_ACCESS_KEY', 'WASABI_BUCKET', 'WASABI_REGION',
        # Backblaze B2
        'B2_KEY_ID', 'B2_APP_KEY', 'B2_BUCKET', 'B2_REGION',
        'BACKBLAZE_KEY_ID', 'BACKBLAZE_APPLICATION_KEY',
        # MinIO
        'MINIO_ACCESS_KEY', 'MINIO_SECRET_KEY', 'MINIO_BUCKET', 'MINIO_ENDPOINT',
        'MINIO_ROOT_USER', 'MINIO_ROOT_PASSWORD',
        # Generic object storage catch-all
        'OBJECT_STORAGE_KEY', 'OBJECT_STORAGE_SECRET', 'OBJECT_STORAGE_BUCKET',
        'STORAGE_ACCESS_KEY', 'STORAGE_SECRET_KEY',
    ]
    creds = _pick(content, keys)

    # Regex scan for raw AKIA* access keys regardless of variable name
    m_akia = re.search(r'(?:^|[\s=\'"])(\bAKIA[0-9A-Z]{16}\b)', content, re.MULTILINE)
    if m_akia and not creds.get('AWS_ACCESS_KEY_ID'):
        creds['AWS_ACCESS_KEY_ID'] = m_akia.group(1)

    # Normalize alternate / provider-specific names → standard AWS keys
    # so the validator (which expects AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) fires
    _access_alts = (
        'AWS_KEY', 'SES_KEY',
        'S3_KEY', 'S3_ACCESS_KEY_ID', 'FILESYSTEM_ACCESS_KEY_ID',
        'DO_SPACES_KEY', 'SPACES_KEY', 'R2_ACCESS_KEY_ID', 'CLOUDFLARE_R2_ACCESS_KEY_ID',
        'WASABI_ACCESS_KEY_ID', 'B2_KEY_ID', 'BACKBLAZE_KEY_ID', 'MINIO_ACCESS_KEY',
        'MINIO_ROOT_USER', 'OBJECT_STORAGE_KEY', 'STORAGE_ACCESS_KEY',
    )
    _secret_alts = (
        'AWS_SECRET', 'SES_SECRET',
        'S3_SECRET', 'S3_SECRET_ACCESS_KEY', 'FILESYSTEM_SECRET_ACCESS_KEY',
        'DO_SPACES_SECRET', 'SPACES_SECRET', 'R2_SECRET_ACCESS_KEY', 'CLOUDFLARE_R2_SECRET_ACCESS_KEY',
        'WASABI_SECRET_ACCESS_KEY', 'B2_APP_KEY', 'BACKBLAZE_APPLICATION_KEY', 'MINIO_SECRET_KEY',
        'MINIO_ROOT_PASSWORD', 'OBJECT_STORAGE_SECRET', 'STORAGE_SECRET_KEY',
    )
    _region_alts = ('AWS_REGION', 'SES_REGION', 'S3_REGION', 'DO_SPACES_REGION',
                    'WASABI_REGION', 'B2_REGION')

    if not creds.get('AWS_ACCESS_KEY_ID'):
        for alt in _access_alts:
            if creds.get(alt):
                creds['AWS_ACCESS_KEY_ID'] = creds.pop(alt)
                break
    if not creds.get('AWS_SECRET_ACCESS_KEY'):
        for alt in _secret_alts:
            if creds.get(alt):
                creds['AWS_SECRET_ACCESS_KEY'] = creds.pop(alt)
                break
    if not creds.get('AWS_DEFAULT_REGION'):
        for alt in _region_alts:
            if creds.get(alt):
                creds['AWS_DEFAULT_REGION'] = creds.pop(alt)
                break

    # Tag which provider the key came from so results are readable
    endpoint = (creds.get('S3_ENDPOINT') or creds.get('MINIO_ENDPOINT')
                or creds.get('DO_SPACES_ENDPOINT') or creds.get('R2_ENDPOINT', ''))
    for src_key, label in [
        ('DO_SPACES_BUCKET', 'DigitalOcean Spaces'), ('R2_BUCKET', 'Cloudflare R2'),
        ('WASABI_BUCKET', 'Wasabi'), ('B2_BUCKET', 'Backblaze B2'),
        ('MINIO_BUCKET', 'MinIO'),
    ]:
        if creds.get(src_key):
            creds.setdefault('storage_provider', label)
            break

    return creds if (creds.get('AWS_ACCESS_KEY_ID') or creds.get('AWS_SECRET_ACCESS_KEY')) else None


def extract_aws_credentials_file(content: str) -> dict | None:
    """
    Parse the ~/.aws/credentials INI format:
        [default]
        aws_access_key_id     = AKIA...
        aws_secret_access_key = ...
    Returns keys in uppercase to match what validate_aws expects.
    Returns None if no real AWS key material is present.
    """
    result = {}
    m = re.search(r'aws_access_key_id\s*[=:]\s*([A-Z0-9]{16,20})', content, re.IGNORECASE)
    if m:
        result['AWS_ACCESS_KEY_ID'] = m.group(1)
    m = re.search(r'aws_secret_access_key\s*[=:]\s*([A-Za-z0-9/+=]{40})', content, re.IGNORECASE)
    if m:
        result['AWS_SECRET_ACCESS_KEY'] = m.group(1)
    m = re.search(r'aws_session_token\s*[=:]\s*([A-Za-z0-9/+=]{50,})', content, re.IGNORECASE)
    if m:
        result['AWS_SESSION_TOKEN'] = m.group(1)
    m = re.search(r'region\s*[=:]\s*([a-z][a-z0-9-]{3,19})', content, re.IGNORECASE)
    if m:
        result['AWS_DEFAULT_REGION'] = m.group(1)
    profiles = re.findall(r'^\[([^\]]+)\]', content, re.MULTILINE)
    if profiles:
        result['profiles'] = ', '.join(profiles)
    return result if (result.get('AWS_ACCESS_KEY_ID') or result.get('AWS_SECRET_ACCESS_KEY')) else None


def extract_twilio(content):
    keys = ['TWILIO_SID', 'TWILIO_TOKEN', 'TWILIO_AUTH_TOKEN', 'TWILIO_ACCOUNT_SID',
            'TWILIO_API_KEY', 'TWILIO_API_SECRET', 'TWILIO_FROM', 'TWILIO_PHONE_NUMBER',
            'TWILIO_NUMBER', 'TWILIO_WHATSAPP_FROM']
    creds = _pick(content, keys)
    return creds if creds else None


def extract_stripe(content):
    keys = ['STRIPE_KEY', 'STRIPE_SECRET', 'STRIPE_PUBLISHABLE_KEY', 'STRIPE_WEBHOOK_SECRET',
            'STRIPE_PUBLIC_KEY', 'STRIPE_PRIVATE_KEY', 'STRIPE_WEBHOOK_KEY', 'STRIPE_PRICE_ID']
    creds = _pick(content, keys)
    return creds if (creds.get('STRIPE_SECRET') or creds.get('STRIPE_KEY') or creds.get('STRIPE_PRIVATE_KEY')) else None


def extract_mail(content):
    keys = [
        # Laravel / generic .env
        'MAIL_MAILER', 'MAIL_HOST', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD',
        'MAIL_ENCRYPTION', 'MAIL_FROM_ADDRESS', 'MAIL_FROM_NAME',
        'MAIL_PASS', 'MAIL_USER', 'MAIL_DRIVER',
        # Raw SMTP keys
        'SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD', 'SMTP_ENCRYPTION',
        'SMTP_USER', 'SMTP_PASS', 'SMTP_AUTH', 'SMTP_FROM',
        # Django (EMAIL_*)
        'EMAIL_HOST', 'EMAIL_PORT', 'EMAIL_HOST_USER', 'EMAIL_HOST_PASSWORD',
        'EMAIL_USE_TLS', 'EMAIL_USE_SSL', 'EMAIL_BACKEND',
        'DEFAULT_FROM_EMAIL', 'SERVER_EMAIL',
        # Symfony 5+ DSN format
        'MAILER_DSN', 'MAILER_URL',
        # Less-common but real key names seen in the wild
        'EMAIL_PASSWORD', 'EMAIL_USERNAME', 'EMAIL_USER', 'EMAIL_PASS',
        'MAIL_SECRET', 'SMTP_SECRET', 'SMTP_API_KEY',
        'POSTFIX_PASSWORD', 'SENDMAIL_HOST',
        'OUTGOING_MAIL_HOST', 'OUTGOING_MAIL_PASSWORD', 'OUTGOING_MAIL_USERNAME',
        'NOTIFICATION_EMAIL_HOST', 'NOTIFICATION_EMAIL_PASSWORD',
    ]
    creds = _pick(content, keys)

    # Symfony MAILER_DSN encodes creds in URL form — parse them robustly.
    dsn = creds.get('MAILER_DSN') or creds.get('MAILER_URL', '')
    if dsn:
        m = re.match(r'smtps?://(.*)', dsn)
        if m:
            rest = m.group(1)
            if '@' in rest:
                userinfo, hostpart = rest.rsplit('@', 1)
                host = hostpart.split(':')[0]
                port = hostpart.split(':')[1] if ':' in hostpart else None
                if ':' in userinfo:
                    uname, passwd = userinfo.rsplit(':', 1)
                    import urllib.parse as _up
                    creds.setdefault('SMTP_USERNAME', _up.unquote(uname))
                    creds.setdefault('SMTP_PASSWORD', _up.unquote(passwd))
                creds.setdefault('SMTP_HOST', host)
                if port:
                    creds.setdefault('SMTP_PORT', port)

    # Normalise aliases so the validator always finds standard keys
    if not creds.get('MAIL_PASSWORD'):
        for alt in ('MAIL_PASS', 'SMTP_PASS', 'SMTP_SECRET', 'EMAIL_PASSWORD',
                    'EMAIL_PASS', 'MAIL_SECRET', 'OUTGOING_MAIL_PASSWORD',
                    'NOTIFICATION_EMAIL_PASSWORD'):
            if creds.get(alt):
                creds['MAIL_PASSWORD'] = creds.pop(alt)
                break
    if not creds.get('MAIL_USERNAME'):
        for alt in ('MAIL_USER', 'SMTP_USER', 'EMAIL_USERNAME', 'EMAIL_USER',
                    'OUTGOING_MAIL_USERNAME', 'NOTIFICATION_EMAIL_HOST'):
            if creds.get(alt):
                creds['MAIL_USERNAME'] = creds.pop(alt)
                break

    host = (creds.get('MAIL_HOST') or creds.get('SMTP_HOST')
            or creds.get('EMAIL_HOST', ''))

    # Skip known test/placeholder hosts
    _SKIP_HOSTS = ('mailtrap.io', 'mailhog', 'localhost', '127.0.0.1', '0.0.0.0')
    if not host or any(s in host for s in _SKIP_HOSTS) or host.startswith('**'):
        return None

    has_pwd = (
        creds.get('MAIL_PASSWORD')
        or creds.get('SMTP_PASSWORD')
        or creds.get('EMAIL_HOST_PASSWORD')
    )
    if not has_pwd:
        # No password extracted — but if this is a recognisable real SMTP host,
        # save it anyway so it shows up as accessible (manual review).
        _REAL_PROVIDERS = ('gmail.com', 'googlemail.com', 'office365.com', 'outlook.com',
                           'sendgrid.net', 'mailgun.org', 'amazonaws.com', 'awsapps.com',
                           'zoho.com', 'mandrillapp.com', 'mailjet.com', 'brevo.com',
                           'sendinblue.com', 'postmarkapp.com', 'smtp2go.com', 'ionos.com')
        if not any(p in host for p in _REAL_PROVIDERS):
            return None
        creds['note'] = 'SMTP host found — no password in .env (may use API mailer or env injection)'

    return creds


def extract_mailgun(content):
    keys = ['MAILGUN_API_KEY', 'MAILGUN_SECRET', 'MAILGUN_DOMAIN',
            'MAILGUN_ENDPOINT', 'MAILGUN_FROM', 'MAILGUN_WEBHOOK_SECRET']
    creds = _pick(content, keys)
    return creds if (creds.get('MAILGUN_API_KEY') or creds.get('MAILGUN_SECRET')) else None


def extract_plivo(content):
    keys = ['PLIVO_AUTH_ID', 'PLIVO_AUTH_TOKEN', 'PLIVO_NUMBER', 'PLIVO_FROM', 'PLIVO_APP_ID']
    creds = _pick(content, keys)
    return creds if (creds.get('PLIVO_AUTH_ID') or creds.get('PLIVO_AUTH_TOKEN')) else None


def extract_brevo(content):
    keys = ['BREVO_API_KEY', 'SENDINBLUE_API_KEY', 'BREVO_SMTP_KEY',
            'BREVO_API_V3_KEY', 'SENDINBLUE_SMTP_KEY', 'BREVO_LIST_ID']
    creds = _pick(content, keys)
    return creds if (creds.get('BREVO_API_KEY') or creds.get('SENDINBLUE_API_KEY') or
                     creds.get('BREVO_SMTP_KEY') or creds.get('BREVO_API_V3_KEY')) else None


def extract_nexmo(content):
    keys = ['NEXMO_KEY', 'NEXMO_SECRET', 'NEXMO_API_KEY', 'NEXMO_API_SECRET',
            'VONAGE_API_KEY', 'VONAGE_API_SECRET', 'VONAGE_APPLICATION_ID', 'VONAGE_FROM_NUMBER']
    creds = _pick(content, keys)
    return creds if (creds.get('NEXMO_KEY') or creds.get('NEXMO_API_KEY') or
                     creds.get('VONAGE_API_KEY')) else None


def extract_messagebird(content):
    keys = ['MESSAGEBIRD_ACCESS_KEY', 'MESSAGEBIRD_API_KEY', 'MESSAGEBIRD_ORIGINATOR']
    creds = _pick(content, keys)
    return creds if (creds.get('MESSAGEBIRD_ACCESS_KEY') or creds.get('MESSAGEBIRD_API_KEY')) else None


def extract_sinch(content):
    keys = ['SINCH_APP_KEY', 'SINCH_APP_SECRET', 'SINCH_SERVICE_PLAN_ID', 'SINCH_API_TOKEN',
            'SINCH_FROM_NUMBER', 'SINCH_ACCESS_KEY_ID', 'SINCH_KEY_SECRET']
    creds = _pick(content, keys)
    return creds if (creds.get('SINCH_APP_KEY') or creds.get('SINCH_API_TOKEN') or
                     creds.get('SINCH_SERVICE_PLAN_ID')) else None


def extract_telnyx(content):
    keys = ['TELNYX_API_KEY', 'TELNYX_PUBLIC_KEY', 'TELNYX_FROM_NUMBER']
    creds = _pick(content, keys)
    return creds if creds.get('TELNYX_API_KEY') else None


def extract_bandwidth(content):
    keys = ['BANDWIDTH_API_TOKEN', 'BANDWIDTH_API_SECRET', 'BANDWIDTH_ACCOUNT_ID',
            'BANDWIDTH_USERNAME', 'BANDWIDTH_PASSWORD']
    creds = _pick(content, keys)
    return creds if (creds.get('BANDWIDTH_API_TOKEN') or creds.get('BANDWIDTH_USERNAME')) else None


def extract_africas_talking(content):
    keys = ['AFRICASTALKING_API_KEY', 'AFRICASTALKING_USERNAME', 'AT_API_KEY', 'AT_USERNAME']
    creds = _pick(content, keys)
    return creds if (creds.get('AFRICASTALKING_API_KEY') or creds.get('AT_API_KEY')) else None


def extract_bulksms(content):
    keys = ['BULKSMS_TOKEN', 'BULKSMS_USERNAME', 'BULKSMS_PASSWORD']
    creds = _pick(content, keys)
    return creds if (creds.get('BULKSMS_TOKEN') or creds.get('BULKSMS_USERNAME')) else None


def extract_clicksend(content):
    keys = ['CLICKSEND_API_KEY', 'CLICKSEND_USERNAME', 'CLICKSEND_PASSWORD']
    creds = _pick(content, keys)
    return creds if (creds.get('CLICKSEND_API_KEY') or creds.get('CLICKSEND_USERNAME')) else None


def extract_telesign(content):
    keys = ['TELESIGN_CUSTOMER_ID', 'TELESIGN_API_KEY']
    creds = _pick(content, keys)
    return creds if (creds.get('TELESIGN_CUSTOMER_ID') or creds.get('TELESIGN_API_KEY')) else None


def extract_sendgrid(content):
    keys = ['SENDGRID_API_KEY', 'SENDGRID_KEY', 'SENDGRID_FROM', 'SENDGRID_FROM_EMAIL']
    creds = _pick(content, keys)
    return creds if (creds.get('SENDGRID_API_KEY') or creds.get('SENDGRID_KEY')) else None


def extract_postmark(content):
    keys = ['POSTMARK_TOKEN', 'POSTMARK_API_TOKEN', 'POSTMARK_SERVER_TOKEN', 'POSTMARK_FROM_EMAIL']
    creds = _pick(content, keys)
    return creds if (creds.get('POSTMARK_TOKEN') or creds.get('POSTMARK_API_TOKEN') or
                     creds.get('POSTMARK_SERVER_TOKEN')) else None


def extract_sparkpost(content):
    keys = ['SPARKPOST_API_KEY', 'SPARKPOST_KEY', 'SPARKPOST_SENDING_DOMAIN']
    creds = _pick(content, keys)
    return creds if (creds.get('SPARKPOST_API_KEY') or creds.get('SPARKPOST_KEY')) else None


def extract_mandrill(content):
    keys = ['MANDRILL_API_KEY', 'MANDRILL_KEY', 'MAILCHIMP_TRANSACTIONAL_KEY']
    creds = _pick(content, keys)
    return creds if (creds.get('MANDRILL_API_KEY') or creds.get('MANDRILL_KEY') or
                     creds.get('MAILCHIMP_TRANSACTIONAL_KEY')) else None


def extract_mailjet(content):
    keys = ['MAILJET_API_KEY', 'MJ_APIKEY_PUBLIC', 'MJ_APIKEY_PRIVATE',
            'MAILJET_API_SECRET', 'MAILJET_FROM_EMAIL']
    creds = _pick(content, keys)
    return creds if (creds.get('MAILJET_API_KEY') or creds.get('MJ_APIKEY_PUBLIC')) else None


def extract_elasticemail(content):
    keys = ['ELASTICEMAIL_API_KEY', 'ELASTIC_EMAIL_API_KEY', 'ELASTICEMAIL_FROM']
    creds = _pick(content, keys)
    return creds if (creds.get('ELASTICEMAIL_API_KEY') or
                     creds.get('ELASTIC_EMAIL_API_KEY')) else None


def extract_shopify(content):
    keys = [
        'SHOPIFY_API_KEY', 'SHOPIFY_API_SECRET', 'SHOPIFY_ACCESS_TOKEN',
        'SHOPIFY_ADMIN_API_ACCESS_TOKEN', 'SHOPIFY_STOREFRONT_ACCESS_TOKEN',
        'SHOPIFY_WEBHOOK_SECRET', 'SHOPIFY_APP_KEY', 'SHOPIFY_APP_SECRET',
        'SHOPIFY_SHOP', 'SHOPIFY_DOMAIN',
    ]
    creds = _pick(content, keys)
    return creds if (
        creds.get('SHOPIFY_API_KEY') or creds.get('SHOPIFY_ACCESS_TOKEN') or
        creds.get('SHOPIFY_ADMIN_API_ACCESS_TOKEN') or creds.get('SHOPIFY_APP_KEY')
    ) else None


def extract_binance(content):
    keys = [
        'BINANCE_API_KEY', 'BINANCE_API_SECRET', 'BINANCE_SECRET_KEY',
        'BINANCE_KEY', 'BINANCE_SECRET', 'BINANCE_TESTNET_API_KEY',
        'BINANCE_TESTNET_SECRET', 'BINANCE_BASE_URL',
    ]
    creds = _pick(content, keys)
    return creds if (creds.get('BINANCE_API_KEY') or creds.get('BINANCE_KEY')) else None


def extract_coinbase(content):
    keys = [
        'COINBASE_API_KEY', 'COINBASE_API_SECRET', 'COINBASE_WEBHOOK_SECRET',
        'COINBASE_COMMERCE_API_KEY', 'COINBASE_CLIENT_ID', 'COINBASE_CLIENT_SECRET',
        'COINBASE_ACCESS_TOKEN', 'COINBASE_REFRESH_TOKEN',
        'CB_API_KEY', 'CB_API_SECRET', 'CB_COMMERCE_KEY',
    ]
    creds = _pick(content, keys)
    return creds if (
        creds.get('COINBASE_API_KEY') or creds.get('COINBASE_COMMERCE_API_KEY') or
        creds.get('CB_API_KEY') or creds.get('CB_COMMERCE_KEY')
    ) else None


def extract_paxful(content):
    keys = ['PAXFUL_API_KEY', 'PAXFUL_API_SECRET', 'PAXFUL_KEY', 'PAXFUL_SECRET']
    creds = _pick(content, keys)
    return creds if (creds.get('PAXFUL_API_KEY') or creds.get('PAXFUL_KEY')) else None


def extract_clickatell(content):
    keys = ['CLICKATELL_USER', 'CLICKATELL_PASS', 'CLICKATELL_API_ID',
            'CLICKATELL_API_KEY', 'CLICKATELL_HTTP_API_ID']
    creds = _pick(content, keys)
    return creds if (creds.get('CLICKATELL_USER') or creds.get('CLICKATELL_API_KEY')
                     or creds.get('CLICKATELL_API_ID')) else None


def extract_sms_api(content):
    """Catch-all SMS API extractor — providers not covered by dedicated extractors."""
    keys = [
        # Kaleyra
        'KALEYRA_API_KEY', 'KALEYRA_SID',
        # D7 Networks
        'D7_API_TOKEN', 'D7NETWORKS_API_TOKEN',
        # TextMagic
        'TEXTMAGIC_API_KEY', 'TEXTMAGIC_USERNAME',
        # Termii
        'TERMII_API_KEY',
        # CM.com
        'CM_API_KEY', 'CM_PRODUCT_TOKEN',
        # SMSGlobal
        'SMSGLOBAL_API_KEY', 'SMSGLOBAL_SECRET',
        # MailerSend (SMS)
        'MAILERSEND_API_TOKEN',
        # AWS SNS
        'SNS_ACCESS_KEY', 'SNS_SECRET_KEY', 'SNS_REGION',
    ]
    found = _pick(content, keys)
    return found if found else None


def extract_api_keys(content):
    keys = [
        'MAILCHIMP_API_KEY', 'MAILCHIMP_LIST_ID',
        'PUSHER_APP_ID', 'PUSHER_APP_KEY', 'PUSHER_APP_SECRET', 'PUSHER_APP_CLUSTER',
        'ABLY_KEY',
        'PAYPAL_CLIENT_ID', 'PAYPAL_SECRET', 'PAYPAL_MODE',
        'PAYSTACK_PUBLIC_KEY', 'PAYSTACK_SECRET_KEY',
        'FLUTTERWAVE_PUBLIC_KEY', 'FLUTTERWAVE_SECRET_KEY', 'FLUTTERWAVE_SECRET_HASH',
        'RAZORPAY_KEY', 'RAZORPAY_SECRET',
        'SQUARE_ACCESS_TOKEN',
        'BRAINTREE_MERCHANT_ID', 'BRAINTREE_PUBLIC_KEY', 'BRAINTREE_PRIVATE_KEY',
        'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_MAPS_API_KEY', 'GOOGLE_API_KEY',
        'FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET',
        'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
        'TWITTER_CONSUMER_KEY', 'TWITTER_CONSUMER_SECRET',
        'LINKEDIN_CLIENT_ID', 'LINKEDIN_CLIENT_SECRET',
        'SLACK_WEBHOOK_URL', 'SLACK_BOT_TOKEN',
        'CLOUDINARY_URL', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET',
        'FIREBASE_API_KEY', 'FIREBASE_AUTH_DOMAIN', 'FIREBASE_PROJECT_ID',
        'ALGOLIA_APP_ID', 'ALGOLIA_SECRET',
        'DO_SPACES_KEY', 'DO_SPACES_SECRET',
        'REDIS_PASSWORD',
        'RECAPTCHA_SECRET_KEY', 'RECAPTCHA_SITE_KEY',
        'SENTRY_DSN',
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
        'TELEGRAM_BOT_TOKEN',
    ]
    found = _pick(content, keys)
    return found if found else None


def extract_from_env(url, path, content):
    """Parse .env and extract all credential categories."""
    findings = []

    for fn, ftype in [
        (extract_db,              'db'),
        (extract_aws,             'aws'),
        (extract_stripe,          'stripe'),
        (extract_mail,            'mail'),
        (extract_mailgun,         'mailgun'),
        (extract_sendgrid,        'sendgrid'),
        (extract_postmark,        'postmark'),
        (extract_brevo,           'brevo'),
        (extract_sparkpost,       'sparkpost'),
        (extract_mandrill,        'mandrill'),
        (extract_mailjet,         'mailjet'),
        (extract_elasticemail,    'elasticemail'),
        (extract_twilio,          'twilio'),
        (extract_plivo,           'plivo'),
        (extract_nexmo,           'nexmo'),
        (extract_messagebird,     'messagebird'),
        (extract_sinch,           'sinch'),
        (extract_telnyx,          'telnyx'),
        (extract_bandwidth,       'bandwidth'),
        (extract_africas_talking, 'africas_talking'),
        (extract_bulksms,         'bulksms'),
        (extract_clicksend,       'clicksend'),
        (extract_telesign,        'telesign'),
        (extract_shopify,         'shopify'),
        (extract_binance,         'binance'),
        (extract_coinbase,        'coinbase'),
        (extract_paxful,          'paxful'),
        (extract_clickatell,      'clickatell'),
        (extract_sms_api,         'sms_api'),
        (extract_api_keys,        'api_keys'),
    ]:
        creds = fn(content)
        if creds:
            creds['source_url'] = url + path   # exact .env file URL in the data body
            findings.append({'type': ftype, 'url': url, 'path': path, 'data': creds})

    # Last-pass: regex scan for raw credential tokens that structured extractors
    # can miss (non-standard variable names, inline secrets, etc.)
    # Only run if a typed cred finding wasn't already produced — avoids duplicates.
    already_typed = {f['type'] for f in findings if f['type'] not in ('laravel', 'api_keys')}
    regex_creds = scan_for_api_creds(content)
    if regex_creds:
        # Strip AWS key if already captured by extract_aws so we don't double-report
        if 'aws' in already_typed:
            regex_creds.pop('AWS_Access_Key', None)
            regex_creds.pop('AWS_Session_Token', None)
        if regex_creds:
            findings.append({
                'type': 'api_keys', 'url': url, 'path': path,
                'data': {'note': 'Raw credential tokens found in .env file',
                         'source_url': url + path, **regex_creds},
            })

    if not findings:
        preview = content[:500].replace('\r', '')
        findings.append({
            'type': 'laravel', 'url': url, 'path': path,
            'data': {'note': '.env file exposed (no high-value secrets detected)', 'preview': preview}
        })
    return findings


# ── CMS config extractors ─────────────────────────────────────────────────────

def extract_wp_config(content):
    """Extract DB credentials from exposed wp-config.php backup variants."""
    info = {}
    patterns = {
        'DB_NAME':         r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
        'DB_USER':         r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
        'DB_PASSWORD':     r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
        'DB_HOST':         r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
        'AUTH_KEY':        r"define\s*\(\s*['\"]AUTH_KEY['\"]\s*,\s*['\"]([^'\"]{10,})['\"]",
        'SECURE_AUTH_KEY': r"define\s*\(\s*['\"]SECURE_AUTH_KEY['\"]\s*,\s*['\"]([^'\"]{10,})['\"]",
    }
    skip = ('', 'database_name_here', 'username_here', 'password_here',
            'put your unique phrase here')
    for key, pattern in patterns.items():
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if val.lower() not in skip:
                info[key] = val
    tp = re.search(r'\$table_prefix\s*=\s*[\'"]([^\'"]+)[\'"]', content)
    if tp:
        info['table_prefix'] = tp.group(1)
    return info if (info.get('DB_PASSWORD') or info.get('DB_USER')) else None


def extract_joomla_config(content):
    """Extract credentials from Joomla configuration.php."""
    info = {}
    fields = {
        'db':       r'public\s+\$db\s*=\s*[\'"]([^\'"]+)[\'"]',
        'dbtype':   r'public\s+\$dbtype\s*=\s*[\'"]([^\'"]+)[\'"]',
        'host':     r'public\s+\$host\s*=\s*[\'"]([^\'"]+)[\'"]',
        'user':     r'public\s+\$user\s*=\s*[\'"]([^\'"]+)[\'"]',
        'password': r'public\s+\$password\s*=\s*[\'"]([^\'"]*)[\'"]',
        'dbprefix': r'public\s+\$dbprefix\s*=\s*[\'"]([^\'"]+)[\'"]',
        'secret':   r'public\s+\$secret\s*=\s*[\'"]([^\'"]{8,})[\'"]',
        'sitename': r'public\s+\$sitename\s*=\s*[\'"]([^\'"]+)[\'"]',
    }
    for key, pattern in fields.items():
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if val:
                info[key] = val
    return info if (info.get('user') or info.get('db')) else None


def extract_magento_config(content):
    """Extract credentials from Magento app/etc/local.xml or env.php."""
    info = {}
    xml_fields = {
        'host':     r'<host><!\[CDATA\[([^\]]+)\]\]></host>',
        'username': r'<username><!\[CDATA\[([^\]]+)\]\]></username>',
        'password': r'<password><!\[CDATA\[([^\]]+)\]\]></password>',
        'dbname':   r'<dbname><!\[CDATA\[([^\]]+)\]\]></dbname>',
    }
    for key, pattern in xml_fields.items():
        m = re.search(pattern, content, re.IGNORECASE)
        if m and m.group(1).strip():
            info[key] = m.group(1).strip()
    if not info:
        for key, pattern in {
            'host':     r'[\'"]host[\'"]\s*=>\s*[\'"]([^\'"]+)[\'"]',
            'username': r'[\'"]username[\'"]\s*=>\s*[\'"]([^\'"]+)[\'"]',
            'password': r'[\'"]password[\'"]\s*=>\s*[\'"]([^\'"]+)[\'"]',
            'dbname':   r'[\'"]dbname[\'"]\s*=>\s*[\'"]([^\'"]+)[\'"]',
        }.items():
            m = re.search(pattern, content, re.IGNORECASE)
            if m and m.group(1).strip():
                info[key] = m.group(1).strip()
    return info if (info.get('password') or info.get('username')) else None


# ── Detection helpers ─────────────────────────────────────────────────────────

def detect_php_version(content):
    m = re.search(r'PHP Version\s*</td>\s*<td[^>]*>([\d.]+)', content, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'PHP\s+([\d]+\.[\d]+\.[\d]+)', content)
    return m.group(1) if m else 'Unknown'


def detect_joomla_version(content):
    m = re.search(r'"version"\s*:\s*"([\d.]+)"', content)
    if m:
        return m.group(1)
    m = re.search(r'<version>([\d.]+)</version>', content, re.IGNORECASE)
    return m.group(1) if m else 'Unknown'


def detect_webshell(content):
    """Return list of matched webshell indicator strings."""
    indicators = [
        'FilesMan', 'c99shell', 'r57shell', 'b374k', 'WSO Shell',
        'IndoXploit', 'ghost shell', 'vodka shell', 'alfa shell',
        'WSOsetcookie', 'auth_pass', 'login_pass',
        'eval(gzinflate', 'eval(base64_decode', 'eval(gzuncompress',
        "POST['cmd']", "GET['cmd']", "REQUEST['cmd']",
        'passthru($_', 'system($_', 'shell_exec($_',
        'Backdoor Shell', 'Execute command', 'Server IP :', 'uname -a',
    ]
    cl = content.lower()
    return [ind for ind in indicators if ind.lower() in cl]


# Compiled once at import — re.compile() is cheap but calling it on every
# response body adds up fast under high concurrency.
_CRED_PATTERNS = {
    # Cloud / infra
    'AWS_Access_Key':       r'AKIA[0-9A-Z]{16}',
    'AWS_Session_Token':    r'"SessionToken"\s*:\s*"(IQoJ|AQOD|//oEA|//g[A-Z])[A-Za-z0-9_/+=]{100,}"',
    'GCP_Private_Key_ID':   r'"private_key_id"\s*:\s*"[a-f0-9]{40}"',
    'GCP_Service_Account':  r'"type"\s*:\s*"service_account"',
    # Payment — sk_live is unambiguous; pk_live is public-facing so skip
    'Stripe_SK':            r'sk_live_[0-9a-zA-Z]{24,}',
    # Comms / email — SendGrid format is highly specific
    'SendGrid':             r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    # Slack — xox prefix is unique to Slack tokens
    'Slack_Token':          r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,}',
    # Source control — all have unambiguous vendor-specific prefixes
    'GitHub_Token':         r'ghp_[A-Za-z0-9]{36}',
    'GitHub_PAT':           r'github_pat_[A-Za-z0-9_]{80,}',
    'GitHub_App_Token':     r'gh[os]_[A-Za-z0-9]{36,}',
    'GitLab_PAT':           r'glpat-[A-Za-z0-9_-]{20}',
    'GitLab_CI_Token':      r'GR1348941[A-Za-z0-9_-]{20}',
    # Maps / analytics
    'Google_API':           r'AIza[0-9A-Za-z\-_]{35}',
    # Private key material — extremely specific header
    'Private_Key':          r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    # E-commerce
    'Shopify_Token':        r'shp(?:at|ss|ca|pa)_[A-Fa-f0-9]{32}',
    # AI platform keys — all have unambiguous vendor prefixes
    'OpenAI_Key':           r'sk-(?:proj-[A-Za-z0-9\-_]{50,}|[A-Za-z0-9]{48})',
    'Anthropic_Key':        r'sk-ant-(?:api\d{2}-)?[A-Za-z0-9\-_]{80,}',
    'HuggingFace_Token':    r'hf_[A-Za-z0-9]{30,}',
    # Package registries
    'NPM_Token':            r'npm_[A-Za-z0-9]{20,}',
    'PyPI_Token':           r'pypi-[A-Za-z0-9_-]{28,}',
    # Infrastructure / secrets management
    'Databricks_Token':     r'dapi[a-f0-9]{20,}',
    'Pulumi_Token':         r'pul-[a-f0-9]{32,}',
    'New_Relic_Key':        r'NRAK-[A-Z0-9]{20,}',
    # Okta — require key-name context to avoid matching session IDs / MD5 hashes
    'Okta_Token':           r'(?:okta[_\-.]?(?:api[_\-.]?)?token|OKTA_TOKEN|ssws)\s*[=:"\s]+\s*["\']?(00[A-Za-z0-9]{40})["\']?',
    # Kubernetes service-account JWT — the alg header is k8s-specific
    'K8s_SA_Token':         r'eyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9_-]{10,}',
    # Removed — too broad, match common web content (not credentials):
    #   JWT            eyJ... matches any JWT on any page
    #   Bearer_Token   matches authorization headers in captured traffic
    #   Mapbox_Token   public-facing key, designed to be in browser code
    #   Twilio_SID     AC+32hex matches too many strings; useless without auth token
    #   Mailgun_Key    hex pattern too broad
    #   Terraform_Cloud / HashiCorp_Vault — kept as internal-only, removed for now
}
_COMPILED_CRED_PATTERNS = {name: re.compile(pat) for name, pat in _CRED_PATTERNS.items()}


def scan_for_api_creds(content):
    """Generic regex scan of any response for exposed credentials."""
    found = {}
    for name, rx in _COMPILED_CRED_PATTERNS.items():
        m = rx.search(content)
        if m:
            # Prefer the last capture group (the actual secret) over the full match,
            # which matters for context-anchored patterns like Okta_Token that wrap
            # the token value in a keyword-context prefix.
            val = m.group(m.lastindex) if m.lastindex else m.group(0)
            found[name] = val[:120]
    return found if found else None


def extract_wp_users(content):
    """Parse WordPress /wp-json/wp/v2/users response."""
    try:
        users = json.loads(content)
        if isinstance(users, list):
            return [{'id': u.get('id'), 'name': u.get('name'), 'slug': u.get('slug')}
                    for u in users[:10]]
    except Exception:
        pass
    return []


def extract_git_config(content):
    info = {}
    for field, pattern in [('remote_url', r'url\s*=\s*(.+)'),
                            ('email', r'email\s*=\s*(.+)'),
                            ('name', r'name\s*=\s*(.+)')]:
        m = re.search(pattern, content)
        if m:
            info[field] = m.group(1).strip()
    return info if info else {'raw_preview': content[:300]}
