"""
Telegram alert integration for RedScan Pro.
Sends HTML-formatted finding alerts to a configured bot chat.
Mirrors the category/icon logic from DeadScan v2.0.
"""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TIMEOUT = 10

_ICON_MAP = {
    "aws":          "☁️",
    "azure":        "☁️",
    "stripe":       "💳",
    "paypal":       "💰",
    "coinbase":     "🪙",
    "mail":         "📧",
    "smtp":         "📧",
    "sendgrid":     "📨",
    "mailgun":      "📨",
    "db":           "🗄️",
    "database":     "🗄️",
    "mysql":        "🗄️",
    "postgres":     "🗄️",
    "mongo":        "🗄️",
    "twilio":       "📱",
    "plivo":        "📱",
    "nexmo":        "📱",
    "sinch":        "📱",
    "telnyx":       "📱",
    "messagebird":  "📱",
    "slack":        "💬",
    "discord":      "💬",
    "firebase":     "🔥",
    "github":       "🐙",
    "shell":        "💀",
    "wp_exploit":   "🔴",
    "wordpress":    "🔵",
    "laravel":      "🟡",
    "joomla":       "🟠",
    "ssh":          "🔐",
    "ftp":          "📁",
    "cpanel":       "🖥️",
    "whm":          "🖥️",
    "plesk":        "🖥️",
    "exposure":     "🕵️",
    "api_keys":     "🔑",
    "google":       "🔍",
}

# Finding types that must never be sent to Telegram (saved to results only)
_BLOCKED_TYPES = frozenset({'exposure'})

_SKIP_KEYS = frozenset({
    "validated", "note", "preview", "indicators", "size_bytes",
    "account_id", "account_name", "account_status", "account_type",
    "date_created", "http_status", "server_name",
    "url", "source_url",   # already shown as the header URL line
    "exposed_creds",       # supplemental scan noise — too many false positives for Telegram
})


def _icon(category: str) -> str:
    cat = category.lower()
    for k, v in _ICON_MAP.items():
        if k in cat:
            return v
    return "🔑"


class TelegramNotifier:
    """
    Sends scan findings to a Telegram bot chat.
    filter_cats: comma-separated category names, or "ALL" to receive everything.
    """

    def __init__(
        self,
        token: str,
        chat_id: str,
        filter_cats: str = "ALL",
        enabled: bool = True,
    ):
        self.token    = (token    or "").strip()
        self.chat_id  = (chat_id  or "").strip()
        self.enabled  = enabled and bool(self.token) and bool(self.chat_id)
        self._base    = f"https://api.telegram.org/bot{self.token}"
        raw = (filter_cats or "ALL").upper().strip()
        # Pre-parse once so send_finding never rebuilds the set on every call.
        self._filter_all  = (raw == "ALL")
        self._filter_cats = {c.strip().lower() for c in raw.split(",") if c.strip()} if raw != "ALL" else set()

    # ── Low-level send ────────────────────────────────────────────────────────

    def send_message(self, text: str):
        if not self.enabled:
            return
        # Telegram hard limit is 4096 chars per message.
        _SUFFIX = "\n…[truncated]"
        _LIMIT  = 4096
        if len(text) > _LIMIT:
            text = text[:_LIMIT - len(_SUFFIX)] + _SUFFIX
        try:
            r = requests.post(
                f"{self._base}/sendMessage",
                json={
                    "chat_id":    self.chat_id,
                    "text":       text,
                    "parse_mode": "HTML",
                },
                timeout=_TIMEOUT,
                verify=False,
            )
            # HTTP 200 with ok=false means a Telegram API error (e.g. 429 rate limit).
            if r.status_code == 200:
                body = r.json()
                if not body.get("ok"):
                    # Silently ignore — caller does not need to retry logic here
                    pass
        except Exception:
            pass

    # ── Structured finding alert ──────────────────────────────────────────────

    def send_finding(self, finding_type: str, url: str, data: dict):
        """
        Send a finding alert ONLY if:
          1. validated == True  (credential confirmed live by validator)
          2. finding_type is in the allowed category list (or filter is ALL)
        """
        if not self.enabled:
            return

        # Hard gate — only send confirmed-valid credentials
        if data.get("validated") is not True:
            return

        # Blocked types — exposure findings stay in results folder only
        if finding_type.lower() in _BLOCKED_TYPES:
            return

        # Category filter — use pre-parsed set from __init__, not rebuilt per call.
        if not self._filter_all:
            if finding_type.lower() not in self._filter_cats:
                return

        lines = [
            f"{_icon(finding_type)} <b>[{finding_type.upper()}]</b>  ✓ VALID",
            f"<code>{url}</code>",
        ]
        for k, v in data.items():
            if k in _SKIP_KEYS or not v or not isinstance(v, str):
                continue
            lines.append(f"  <b>{k}:</b> <code>{str(v)[:80]}</code>")

        self.send_message("\n".join(lines))

    # ── Session-level messages ────────────────────────────────────────────────

    def send_startup(self, details: str = ""):
        msg = "🚀 <b>RedScan Pro started</b>"
        if details:
            msg += f"\n{details}"
        self.send_message(msg)

    def send_summary(self, total_found: int, total_targets: int):
        self.send_message(
            f"✅ <b>Scan complete</b>\n"
            f"Targets scanned: <b>{total_targets:,}</b>\n"
            f"Findings: <b>{total_found}</b>"
        )

    # ── Connectivity test ─────────────────────────────────────────────────────

    def test_connection(self) -> tuple[bool, str]:
        """Return (ok, message) — call from UI to verify token + chat_id."""
        if not self.token or not self.chat_id:
            return False, "Missing token or chat ID"
        try:
            r    = requests.get(f"{self._base}/getMe", timeout=_TIMEOUT, verify=False)
            data = r.json()
            if data.get("ok"):
                uname = data.get("result", {}).get("username", "unknown")
                return True, f"@{uname}"
            return False, data.get("description", "API error")
        except Exception as e:
            return False, str(e)
