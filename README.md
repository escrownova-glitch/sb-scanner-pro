# SB Scanner Pro

**Advanced Authorized Security Scanner**

Professional-grade red team reconnaissance and credential discovery tool with live validation capabilities. Built for authorized penetration testing engagements.

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![PyQt5](https://img.shields.io/badge/GUI-PyQt5-green.svg)
![License](https://img.shields.io/badge/License-Private-red.svg)

---

## Overview

SB Scanner Pro is a comprehensive security assessment tool that combines:
- **OSINT-based target discovery** via Shodan, FOFA, Censys, LeakIX, and CRT.sh
- **Credential extraction** from exposed configuration files (.env, wp-config, etc.)
- **Live validation** of discovered API keys and credentials
- **WordPress exploit framework** with 44+ CVE payloads
- **Service enumeration** (SSH, FTP, cPanel, WHM, Plesk, phpMyAdmin)

---

## Features

### Target Discovery (OSINT)
| Source | Capabilities |
|--------|-------------|
| **Shodan** | Search by component, exposed credentials, vulnerable services |
| **FOFA** | Chinese search engine with extensive web fingerprinting |
| **Censys** | Certificate and service discovery |
| **LeakIX** | Pre-indexed data leaks and exposures |
| **CRT.sh** | Certificate Transparency subdomain enumeration |

### Credential Extraction
Extracts credentials from:
- **Laravel** `.env` files (APP_KEY, DB_*, MAIL_*, AWS_*, etc.)
- **WordPress** `wp-config.php` backups
- **Joomla** `configuration.php` 
- **Magento** `env.php` / `local.xml`
- **Django** settings leaks
- **Git** exposed `.git/config` with credentials
- **AWS** `~/.aws/credentials` files

### Live Validation
Real-time API validation for discovered credentials:

| Category | Services |
|----------|----------|
| **Cloud** | AWS (STS, SES, S3), DigitalOcean Spaces, Cloudflare R2, MinIO |
| **Email/SMS** | Twilio, SendGrid, Mailgun, Brevo, Postmark, Mandrill, Sparkpost, Plivo, Nexmo, MessageBird, Sinch, Telnyx, Bandwidth, Africa's Talking, BulkSMS, ClickSend, Telesign, Clickatell |
| **Payment** | Stripe (balance check, test charges) |
| **E-commerce** | Shopify Admin API |
| **Crypto** | Binance, Coinbase, Paxful |
| **AI** | OpenAI, Anthropic, HuggingFace |
| **Dev Tools** | GitHub tokens, Slack webhooks |

### WordPress Exploits
44+ CVE payloads including:
- PHPUnit RCE (CVE-2017-9841)
- Plugin file upload vulnerabilities
- User enumeration (REST API + author archive)
- Credential bruteforce
- Shell upload and verification

### Service Scanning
- **SSH** login testing with extracted DB credentials
- **cPanel/WHM** credential reuse detection
- **phpMyAdmin** discovery and login
- **FTP** credential testing
- **Database** TCP reachability probes

### Additional Modules
- **LFI Probing** — Local File Inclusion detection
- **JS Crawling** — JavaScript file analysis for hardcoded secrets
- **Webshell Detection** — Known shell signature scanning
- **BGP Proxy Pool** — Rotating proxies via BGP.tools integration

---

## Requirements

### System
- Python 3.12+
- Windows 10/11 (primary), Linux/macOS (untested)

### Dependencies
```
customtkinter>=5.2.2
requests>=2.32.0
urllib3>=2.0.0
Pillow>=10.0.0
paramiko>=3.4.0
cryptography>=42.0.0
PyQt5>=5.15.10,<6
```

Install with:
```bash
pip install -r requirements.txt
```

### Optional API Keys
For OSINT target discovery:
- Shodan API key
- FOFA email + API key
- Censys API ID + Secret
- LeakIX API key (optional, works without)

---

## Usage

### GUI Mode (Recommended)
```bash
python sb_scanner_qt.py
```

### CLI Mode
```bash
python sb_scanner.py --targets targets.txt --threads 20 --timeout 8
```

### Pre-built Executable
```bash
# Build with PyInstaller
pyinstaller sb_scanner.spec

# Or use existing build
./dist/sb_scanner.exe
```

---

## Architecture

```
sb_scanner_qt.py      # PyQt5 GUI application
scanner_core.py       # Core scanning engine (session-pooled, threaded)
extractor.py          # Credential extraction patterns
validator.py          # Live API validation
wp_exploits.py        # WordPress CVE framework
bruter.py             # Bruteforce capabilities
osint.py              # OSINT API integrations
paths_config.py       # Scan path definitions
saver.py              # Results file management
telegram_notifier.py  # Real-time Telegram alerts
bgp_pool.py           # BGP proxy rotation
js_crawler.py         # JavaScript secret extraction
lfi_probe.py          # LFI vulnerability detection
active_checks.py      # Service enumeration
service_checker.py    # Port/service scanning
target_utils.py       # Target normalization
```

---

## Output

Results are saved to `./results/<timestamp>/` with categorized findings:

```
results/
└── 2026-07-14_16-30-00/
    ├── all_findings.txt      # Combined output
    ├── db.txt                # Database credentials
    ├── aws.txt               # AWS keys
    ├── stripe.txt            # Payment credentials
    ├── smtp-*.txt            # Email provider credentials
    ├── twilio-api.txt        # SMS/Voice APIs
    ├── wordpress.txt         # WP installations
    ├── wp-exploits.txt       # Successful exploits
    ├── shells.txt            # Discovered webshells
    ├── ssh-access.txt        # SSH credentials
    ├── cpanel-access.txt     # cPanel logins
    └── ...
```

---

## Configuration

### config.json
Persistent settings stored in project root:
```json
{
  "shodan_key": "your-api-key",
  "shodan_queries": "http.html:\"DB_PASSWORD\"\nhttp.html:\"AWS_ACCESS_KEY_ID\"",
  "fofa_email": "user@example.com",
  "fofa_key": "your-fofa-key",
  "tg_token": "your-bot-token",
  "tg_chat": "your-chat-id",
  "tg_enabled": true,
  "redteam_email": "findings@yourteam.com"
}
```

### Telegram Alerts
Real-time notifications for high-value findings:
1. Create bot via [@BotFather](https://t.me/BotFather)
2. Get chat ID from [@userinfobot](https://t.me/userinfobot)
3. Enable in GUI or config.json

---

## Potential Upgrades

### High Priority
- [ ] **Async I/O** — Migrate from ThreadPoolExecutor to `asyncio` + `aiohttp` for 5-10x throughput
- [ ] **Database Backend** — SQLite/PostgreSQL for findings (enables deduplication, search, export)
- [ ] **API Mode** — REST API for headless operation and integration with other tools
- [ ] **Docker Support** — Containerized deployment with volume mounts for results

### Medium Priority
- [ ] **Nuclei Integration** — Run Nuclei templates against discovered targets
- [ ] **Cloud Provider Enumeration** — S3 bucket enumeration, Azure blob discovery
- [ ] **Subdomain Takeover** — Check for dangling DNS records
- [ ] **WAF Fingerprinting** — Detect and log WAF vendor (Cloudflare, Akamai, etc.)
- [ ] **Rate Limiting** — Per-domain rate limits to avoid blocks
- [ ] **Proxy Chains** — SOCKS5/HTTP proxy support beyond BGP pool

### Low Priority
- [ ] **Machine Learning** — Train classifier for false positive reduction
- [ ] **Report Generation** — PDF/HTML reports with executive summary
- [ ] **Plugin System** — Loadable Python modules for custom checks
- [ ] **Web Dashboard** — Flask/FastAPI dashboard for team collaboration
- [ ] **CI/CD Integration** — GitHub Actions workflow for scheduled scans

### Security Hardening
- [ ] **Credential Encryption** — Encrypt stored API keys at rest
- [ ] **Audit Logging** — Full audit trail of scan activities
- [ ] **Scope Enforcement** — Whitelist/blacklist domains and IPs
- [ ] **Certificate Pinning** — Pin API endpoint certificates

---

## Legal Disclaimer

**This tool is intended for authorized security testing only.**

Usage of SB Scanner Pro for attacking targets without prior mutual consent is illegal. The developer assumes no liability for misuse or damage caused by this program.

Always obtain written authorization before conducting security assessments.

---

## Author

**spammerbrain101**

---

## Changelog

### v1.0.0 (2026-07-14)
- Initial release
- PyQt5 GUI with dark theme
- OSINT integration (Shodan, FOFA, Censys, LeakIX, CRT.sh)
- 30+ credential validators
- WordPress exploit framework (44 CVEs)
- Telegram real-time alerts
- BGP proxy pool rotation
