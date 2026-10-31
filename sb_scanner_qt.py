#!/usr/bin/env python3
"""SB Scanner Pro — PyQt5 GUI"""

import sys, os, json, subprocess, threading
from pathlib import Path
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QScrollArea, QTabWidget, QLabel, QPushButton,
    QLineEdit, QTextEdit, QCheckBox, QSpinBox, QProgressBar,
    QListWidget, QFileDialog, QFrame, QGroupBox, QSizePolicy,
    QGridLayout, QListWidgetItem,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QColor, QTextCursor, QIcon

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

try:
    from scanner_core import Scanner
    from osint import (shodan_search, fofa_search, censys_search,
                       leakix_search, crtsh_search)
    from paths_config import PATH_MODULES
    from target_utils import parse_targets
    MODULES_OK = True
except ImportError as e:
    MODULES_OK = False
    IMPORT_ERR = str(e)

CONFIG_FILE = BASE_DIR / 'config.json'

# ── finding meta ──────────────────────────────────────────────────────────────
FINDING_META = {
    'db':             ('DB Creds',        '#22c55e'),
    'aws':            ('AWS Keys',        '#f59e0b'),
    'stripe':         ('Stripe',          '#8b5cf6'),
    'shopify':        ('Shopify',         '#06b6d4'),
    'binance':        ('Binance',         '#f59e0b'),
    'coinbase':       ('Coinbase',        '#3b82f6'),
    'api_keys':       ('API Keys',        '#84cc16'),
    'mail':           ('SMTP',            '#38bdf8'),
    'sendgrid':       ('SendGrid',        '#38bdf8'),
    'mailgun':        ('Mailgun',         '#38bdf8'),
    'brevo':          ('Brevo',           '#38bdf8'),
    'postmark':       ('Postmark',        '#38bdf8'),
    'mandrill':       ('Mandrill',        '#38bdf8'),
    'mailjet':        ('Mailjet',         '#38bdf8'),
    'sparkpost':      ('SparkPost',       '#38bdf8'),
    'elasticemail':   ('ElasticEmail',    '#38bdf8'),
    'twilio':         ('Twilio',          '#ef4444'),
    'plivo':          ('Plivo',           '#ef4444'),
    'nexmo':          ('Nexmo',           '#ef4444'),
    'messagebird':    ('MessageBird',     '#ef4444'),
    'sinch':          ('Sinch',           '#ef4444'),
    'telnyx':         ('Telnyx',          '#ef4444'),
    'bandwidth':      ('Bandwidth',       '#ef4444'),
    'africas_talking':("Africa's Talk",  '#ef4444'),
    'bulksms':        ('BulkSMS',         '#ef4444'),
    'clicksend':      ('ClickSend',       '#ef4444'),
    'clickatell':     ('Clickatell',      '#ef4444'),
    'telesign':       ('Telesign',        '#ef4444'),
    'sms_api':        ('SMS API',         '#ef4444'),
    'paxful':         ('Paxful',          '#f59e0b'),
    'wordpress':      ('WordPress',       '#3b82f6'),
    'wp_exploits':    ('WP Exploits',     '#ef4444'),
    'joomla':         ('Joomla',          '#f97316'),
    'laravel':        ('Laravel',         '#ef4444'),
    'magento':        ('Magento',         '#f97316'),
    'shell':          ('Webshells',       '#ef4444'),
    'cpanel':         ('cPanel',          '#8b5cf6'),
    'whm':            ('WHM',             '#8b5cf6'),
    'plesk':          ('Plesk',           '#8b5cf6'),
    'ftp':            ('FTP',             '#f97316'),
    'ssh':            ('SSH',             '#f97316'),
    'lfi':            ('LFI',             '#ef4444'),
    'misconfig':      ('Misconfig',       '#f59e0b'),
    'exposure':       ('Exposure',        '#6b7280'),
    'general':        ('General',         '#9ca3af'),
}

LOG_COLORS = {
    '[+]': '#22c55e',
    '[!]': '#ef4444',
    '[*]': '#38bdf8',
    '[-]': '#f97316',
    '[~]': '#a78bfa',
}

# ── stylesheet ────────────────────────────────────────────────────────────────
QSS = """
* { box-sizing: border-box; }
QMainWindow, QWidget { background:#1a1a2e; color:#e2e2e2; font-family:'Segoe UI',Arial,sans-serif; font-size:13px; }
QScrollArea { border:none; background:transparent; }
QScrollBar:vertical { background:#16213e; width:7px; border-radius:3px; }
QScrollBar::handle:vertical { background:#e94560; border-radius:3px; min-height:20px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QScrollBar:horizontal { background:#16213e; height:7px; border-radius:3px; }
QScrollBar::handle:horizontal { background:#e94560; border-radius:3px; min-width:20px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }
QGroupBox { border:1px solid #2d2d4f; border-radius:6px; margin-top:10px; padding-top:10px; color:#808099; font-size:11px; font-weight:bold; letter-spacing:1px; }
QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; }
QLineEdit, QSpinBox { background:#0f0f1e; border:1px solid #2d2d4f; border-radius:4px; color:#e2e2e2; padding:4px 8px; }
QLineEdit:focus, QSpinBox:focus { border-color:#e94560; }
QTextEdit { background:#0a0a1a; border:1px solid #2d2d4f; border-radius:4px; color:#e2e2e2; padding:4px; }
QTextEdit:focus { border-color:#e94560; }
QSpinBox::up-button, QSpinBox::down-button { background:#2d2d4f; border:none; width:18px; }
QSpinBox::up-arrow { border-left:4px solid transparent; border-right:4px solid transparent; border-bottom:5px solid #e2e2e2; width:0; height:0; }
QSpinBox::down-arrow { border-left:4px solid transparent; border-right:4px solid transparent; border-top:5px solid #e2e2e2; width:0; height:0; }
QPushButton { background:#2d2d4f; border:1px solid #3d3d6f; border-radius:5px; color:#e2e2e2; padding:6px 14px; font-weight:500; }
QPushButton:hover { background:#3d3d6f; border-color:#e94560; }
QPushButton:pressed { background:#e94560; }
QPushButton:disabled { color:#444466; border-color:#222240; background:#1e1e38; }
QPushButton#btn_start { background:#166534; border-color:#22c55e; color:#fff; font-weight:bold; font-size:14px; padding:10px; }
QPushButton#btn_start:hover { background:#15803d; }
QPushButton#btn_start:pressed { background:#22c55e; }
QPushButton#btn_stop { background:#7f1d1d; border-color:#ef4444; color:#fff; font-weight:bold; }
QPushButton#btn_stop:hover { background:#991b1b; }
QPushButton#btn_pause { background:#78350f; border-color:#f59e0b; color:#fff; font-weight:bold; }
QPushButton#btn_pause:hover { background:#92400e; }
QCheckBox { spacing:6px; color:#c0c0d8; }
QCheckBox::indicator { width:16px; height:16px; background:#0f0f1e; border:1px solid #3d3d6f; border-radius:3px; }
QCheckBox::indicator:checked { background:#e94560; border-color:#e94560; }
QTabWidget::pane { border:1px solid #2d2d4f; border-radius:4px; background:#16213e; top:-1px; }
QTabBar::tab { background:#0f0f1e; color:#666688; padding:6px 12px; border:1px solid #2d2d4f; border-bottom:none; border-top-left-radius:4px; border-top-right-radius:4px; margin-right:2px; font-size:12px; }
QTabBar::tab:selected { background:#16213e; color:#e94560; border-color:#e94560; }
QTabBar::tab:hover { color:#e2e2e2; }
QProgressBar { background:#0f0f1e; border:1px solid #2d2d4f; border-radius:4px; text-align:center; color:#e2e2e2; font-size:11px; max-height:16px; }
QProgressBar::chunk { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #e94560,stop:1 #f97316); border-radius:3px; }
QListWidget { background:#0a0a1a; border:1px solid #2d2d4f; border-radius:4px; color:#e2e2e2; }
QListWidget::item { padding:3px 6px; }
QListWidget::item:hover { background:#1e1e3e; }
QListWidget::item:selected { background:#e94560; color:#fff; }
QSplitter::handle { background:#2d2d4f; width:2px; height:2px; }
"""

# ── worker threads ─────────────────────────────────────────────────────────────
class ScanWorker(QThread):
    log_sig      = pyqtSignal(str)
    finding_sig  = pyqtSignal(dict)
    progress_sig = pyqtSignal(int, int)
    stats_sig    = pyqtSignal(int, int)
    done_sig     = pyqtSignal(str)

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self._scanner = None
        self._stop_requested = False

    def run(self):
        status = 'completed'
        try:
            cfg = self.cfg
            tg = None
            if cfg.get('tg_enabled') and cfg.get('tg_token') and cfg.get('tg_chat'):
                try:
                    from telegram_notifier import TelegramNotifier
                    tg = TelegramNotifier(cfg['tg_token'], cfg['tg_chat'])
                except Exception as exc:
                    self.log_sig.emit(f'[!] Telegram disabled: {exc}')

            self._scanner = Scanner(
                log_cb=self.log_sig.emit,
                finding_cb=self.finding_sig.emit,
                progress_cb=self.progress_sig.emit,
                stats_cb=self.stats_sig.emit,
                check_services=cfg.get('services', False),
                skip_waf=cfg.get('skip_waf', False),
                lfi_probe=cfg.get('lfi', False),
                active_checks=cfg.get('active', False),
                js_crawl=cfg.get('js', False),
                redteam_email=cfg.get('redteam_email', ''),
                telegram=tg,
            )
            if self._stop_requested:
                self._scanner.stop()
            self._scanner.scan_all(cfg['targets'], cfg['paths'],
                                   cfg['threads'], cfg['timeout'])
        except Exception as e:
            self.log_sig.emit(f'[!] Scan error: {e}')
            status = 'failed'
        finally:
            if self._stop_requested:
                status = 'stopped'
            self.done_sig.emit(status)

    def pause(self):
        if self._scanner: self._scanner.pause()

    def resume(self):
        if self._scanner: self._scanner.resume()

    def stop(self):
        self._stop_requested = True
        if self._scanner: self._scanner.stop()


class FetchWorker(QThread):
    log_sig    = pyqtSignal(str)
    result_sig = pyqtSignal(list)
    done_sig   = pyqtSignal()

    def __init__(self, fn, *args, stop_evt=None, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.stop_evt = stop_evt

    def run(self):
        try:
            kwargs = dict(self.kwargs)
            if self.stop_evt is not None:
                kwargs['stop_evt'] = self.stop_evt
            result, err = self.fn(*self.args, log_cb=self.log_sig.emit, **kwargs)
            if err:
                self.log_sig.emit(f'[!] Fetch error: {err}')
            self.result_sig.emit(result or [])
        except Exception as e:
            self.log_sig.emit(f'[!] Fetch exception: {e}')
            self.result_sig.emit([])
        finally:
            self.done_sig.emit()

    def stop(self):
        if self.stop_evt is not None:
            self.stop_evt.set()


# ── counter card ──────────────────────────────────────────────────────────────
class CounterCard(QFrame):
    def __init__(self, label, color, parent=None):
        super().__init__(parent)
        self.color = color
        self.setFixedSize(110, 56)
        self.setStyleSheet(f"""
            QFrame {{
                background: #0f0f1e;
                border: 1px solid #2d2d4f;
                border-radius: 6px;
            }}
            QFrame:hover {{ border-color: {color}; }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 4, 6, 4)
        lay.setSpacing(2)

        self._count = QLabel('0')
        self._count.setAlignment(Qt.AlignCenter)
        self._count.setStyleSheet(f'color:{color}; font-size:20px; font-weight:bold; border:none;')
        lay.addWidget(self._count)

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet('color:#666688; font-size:10px; border:none;')
        lbl.setWordWrap(True)
        lay.addWidget(lbl)

    def set_count(self, n):
        self._count.setText(str(n))
        if n > 0:
            self.setStyleSheet(f"""
                QFrame {{
                    background: #0f0f1e;
                    border: 1px solid {self.color};
                    border-radius: 6px;
                }}
            """)


# ── main window ───────────────────────────────────────────────────────────────
class SBScannerQT(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SB Scanner Pro')
        self.setMinimumSize(1200, 750)
        self.resize(1400, 860)

        icon_path = BASE_DIR / 'sb.ico'
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self._worker = None
        self._fetch_workers = set()
        self._paused = False
        self._findings_count = {k: 0 for k in FINDING_META}
        self._counter_cards = {}
        self._results_dir = None
        self._fetched_targets = []

        self._cfg = self._load_config()
        self._build_ui()
        self.setStyleSheet(QSS)
        self.show()

        if not MODULES_OK:
            self._log(f'[!] Import error: {IMPORT_ERR}')

    # ── config ────────────────────────────────────────────────────────────────
    def _load_config(self):
        try:
            if CONFIG_FILE.exists():
                return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
        return {}

    def _save_config(self):
        cfg = {
            'shodan_key':     self._inp_shodan_key.text().strip(),
            'shodan_queries': self._txt_shodan_q.toPlainText().strip(),
            'fofa_email':     self._inp_fofa_email.text().strip(),
            'fofa_key':       self._inp_fofa_key.text().strip(),
            'fofa_queries':   self._txt_fofa_q.toPlainText().strip(),
            'censys_id':      self._inp_censys_id.text().strip(),
            'censys_secret':  self._inp_censys_sec.text().strip(),
            'censys_queries': self._txt_censys_q.toPlainText().strip(),
            'leakix_key':     self._inp_leakix_key.text().strip(),
            'leakix_queries': self._txt_leakix_q.toPlainText().strip(),
            'crt_domains':    self._inp_crt.text().strip(),
            'redteam_email':  self._inp_rt_email.text().strip(),
            'tg_token':       self._inp_tg_token.text().strip(),
            'tg_chat':        self._inp_tg_chat.text().strip(),
            'tg_enabled':     self._chk_tg.isChecked(),
        }
        try:
            CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
        except Exception:
            pass

    # ── UI build ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vlay = QVBoxLayout(root)
        vlay.setContentsMargins(0, 0, 0, 0)
        vlay.setSpacing(0)

        vlay.addWidget(self._build_header())

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([360, 1040])
        splitter.setHandleWidth(3)
        vlay.addWidget(splitter, 1)

        vlay.addWidget(self._build_status_bar())

    def _build_header(self):
        hdr = QFrame()
        hdr.setFixedHeight(60)
        hdr.setStyleSheet('background:#0f0f1e; border-bottom:2px solid #e94560;')
        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(16, 0, 16, 0)

        logo = QLabel('SB')
        logo.setStyleSheet('color:#e94560; font-size:28px; font-weight:900; letter-spacing:3px;')
        lay.addWidget(logo)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet('color:#2d2d4f;')
        lay.addWidget(sep)

        title_col = QVBoxLayout()
        title_col.setSpacing(0)
        t1 = QLabel('SCANNER PRO')
        t1.setStyleSheet('color:#e2e2e2; font-size:16px; font-weight:bold; letter-spacing:2px;')
        t2 = QLabel('Advanced Authorized Security Scanner  ·  Go Edition')
        t2.setStyleSheet('color:#555577; font-size:11px;')
        title_col.addWidget(t1)
        title_col.addWidget(t2)
        lay.addLayout(title_col)
        lay.addStretch()

        self._lbl_status_dot = QLabel('●')
        self._lbl_status_dot.setStyleSheet('color:#333355; font-size:18px;')
        self._lbl_status_text = QLabel('Ready')
        self._lbl_status_text.setStyleSheet('color:#555577; font-size:12px;')
        lay.addWidget(self._lbl_status_dot)
        lay.addWidget(self._lbl_status_text)

        return hdr

    # ── LEFT PANEL ────────────────────────────────────────────────────────────
    def _build_left_panel(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedWidth(365)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        container = QWidget()
        lay = QVBoxLayout(container)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)

        lay.addWidget(self._build_target_tabs())
        lay.addWidget(self._build_modules_group())
        lay.addWidget(self._build_perf_group())
        lay.addWidget(self._build_options_group())
        lay.addWidget(self._build_telegram_group())
        lay.addWidget(self._build_rt_email_group())
        lay.addWidget(self._build_control_buttons())
        lay.addStretch()

        scroll.setWidget(container)
        return scroll

    def _build_target_tabs(self):
        grp = QGroupBox('TARGET SOURCE')
        lay = QVBoxLayout(grp)
        lay.setContentsMargins(8, 14, 8, 8)
        lay.setSpacing(6)

        tabs = QTabWidget()
        tabs.setTabPosition(QTabWidget.North)

        # Manual
        manual_w = QWidget()
        m_lay = QVBoxLayout(manual_w)
        m_lay.setContentsMargins(6, 6, 6, 6)
        m_lay.setSpacing(4)
        self._txt_targets = QTextEdit()
        self._txt_targets.setPlaceholderText('https://target.com\n192.168.1.1\n...')
        self._txt_targets.setMinimumHeight(100)
        m_lay.addWidget(self._txt_targets)
        btn_browse = QPushButton('Browse File')
        btn_browse.clicked.connect(self._browse_file)
        m_lay.addWidget(btn_browse)
        tabs.addTab(manual_w, 'Manual')

        # Shodan
        shodan_w = QWidget()
        s_lay = QVBoxLayout(shodan_w)
        s_lay.setContentsMargins(6, 6, 6, 6)
        s_lay.setSpacing(4)
        self._inp_shodan_key = QLineEdit(self._cfg.get('shodan_key', ''))
        self._inp_shodan_key.setPlaceholderText('Shodan API Key')
        self._inp_shodan_key.setEchoMode(QLineEdit.Password)
        s_lay.addWidget(self._inp_shodan_key)
        self._txt_shodan_q = QTextEdit(self._cfg.get('shodan_queries', 'http.html:"DB_PASSWORD"\nhttp.html:"AWS_ACCESS_KEY_ID"\nhttp.html:".env" "APP_KEY"'))
        self._txt_shodan_q.setMinimumHeight(70)
        s_lay.addWidget(QLabel('Queries (one per line):'))
        s_lay.addWidget(self._txt_shodan_q)
        btn_sh = QPushButton('Fetch Targets')
        btn_sh.clicked.connect(lambda: self._fetch_osint('shodan'))
        s_lay.addWidget(btn_sh)
        tabs.addTab(shodan_w, 'Shodan')

        # FOFA
        fofa_w = QWidget()
        f_lay = QVBoxLayout(fofa_w)
        f_lay.setContentsMargins(6, 6, 6, 6)
        f_lay.setSpacing(4)
        self._inp_fofa_email = QLineEdit(self._cfg.get('fofa_email', ''))
        self._inp_fofa_email.setPlaceholderText('FOFA Email')
        f_lay.addWidget(self._inp_fofa_email)
        self._inp_fofa_key = QLineEdit(self._cfg.get('fofa_key', ''))
        self._inp_fofa_key.setPlaceholderText('FOFA API Key')
        self._inp_fofa_key.setEchoMode(QLineEdit.Password)
        f_lay.addWidget(self._inp_fofa_key)
        self._txt_fofa_q = QTextEdit(self._cfg.get('fofa_queries', 'body="DB_PASSWORD"\nbody="AWS_ACCESS_KEY_ID"'))
        self._txt_fofa_q.setMinimumHeight(60)
        f_lay.addWidget(QLabel('Queries:'))
        f_lay.addWidget(self._txt_fofa_q)
        btn_fo = QPushButton('Fetch Targets')
        btn_fo.clicked.connect(lambda: self._fetch_osint('fofa'))
        f_lay.addWidget(btn_fo)
        tabs.addTab(fofa_w, 'FOFA')

        # Censys
        censys_w = QWidget()
        c_lay = QVBoxLayout(censys_w)
        c_lay.setContentsMargins(6, 6, 6, 6)
        c_lay.setSpacing(4)
        self._inp_censys_id = QLineEdit(self._cfg.get('censys_id', ''))
        self._inp_censys_id.setPlaceholderText('Censys API ID')
        c_lay.addWidget(self._inp_censys_id)
        self._inp_censys_sec = QLineEdit(self._cfg.get('censys_secret', ''))
        self._inp_censys_sec.setPlaceholderText('Censys API Secret')
        self._inp_censys_sec.setEchoMode(QLineEdit.Password)
        c_lay.addWidget(self._inp_censys_sec)
        self._txt_censys_q = QTextEdit(self._cfg.get('censys_queries', 'services.http.response.body:"DB_PASSWORD"'))
        self._txt_censys_q.setMinimumHeight(60)
        c_lay.addWidget(QLabel('Queries:'))
        c_lay.addWidget(self._txt_censys_q)
        btn_ce = QPushButton('Fetch Targets')
        btn_ce.clicked.connect(lambda: self._fetch_osint('censys'))
        c_lay.addWidget(btn_ce)
        tabs.addTab(censys_w, 'Censys')

        # LeakIX
        leakix_w = QWidget()
        l_lay = QVBoxLayout(leakix_w)
        l_lay.setContentsMargins(6, 6, 6, 6)
        l_lay.setSpacing(4)
        self._inp_leakix_key = QLineEdit(self._cfg.get('leakix_key', ''))
        self._inp_leakix_key.setPlaceholderText('LeakIX API Key (optional)')
        self._inp_leakix_key.setEchoMode(QLineEdit.Password)
        l_lay.addWidget(self._inp_leakix_key)
        self._txt_leakix_q = QTextEdit(self._cfg.get('leakix_queries', '+service:"HTTP" +leak.severity:"critical"'))
        self._txt_leakix_q.setMinimumHeight(60)
        l_lay.addWidget(QLabel('Queries:'))
        l_lay.addWidget(self._txt_leakix_q)
        btn_lx = QPushButton('Fetch Targets')
        btn_lx.clicked.connect(lambda: self._fetch_osint('leakix'))
        l_lay.addWidget(btn_lx)
        tabs.addTab(leakix_w, 'LeakIX')

        # CRT.sh
        crt_w = QWidget()
        cr_lay = QVBoxLayout(crt_w)
        cr_lay.setContentsMargins(6, 6, 6, 6)
        cr_lay.setSpacing(4)
        cr_lay.addWidget(QLabel('Domains (comma or newline):'))
        self._inp_crt = QLineEdit(self._cfg.get('crt_domains', ''))
        self._inp_crt.setPlaceholderText('example.com, target.org')
        cr_lay.addWidget(self._inp_crt)
        btn_crt = QPushButton('Enumerate Subdomains')
        btn_crt.clicked.connect(lambda: self._fetch_osint('crt'))
        cr_lay.addWidget(btn_crt)
        cr_lay.addStretch()
        tabs.addTab(crt_w, 'CRT.sh')

        lay.addWidget(tabs)

        self._lbl_fetched = QLabel('Fetched: 0 targets')
        self._lbl_fetched.setStyleSheet('color:#555577; font-size:11px;')
        lay.addWidget(self._lbl_fetched)

        return grp

    def _build_modules_group(self):
        grp = QGroupBox('SCAN MODULES')
        grid = QGridLayout(grp)
        grid.setContentsMargins(8, 14, 8, 8)
        grid.setSpacing(4)

        modules = [
            ('Laravel',   'laravel',   True),
            ('WordPress', 'wordpress', True),
            ('Joomla',    'joomla',    True),
            ('Magento',   'magento',   True),
            ('Shells',    'shell',     True),
            ('Exposure',  'exposure',  True),
        ]
        self._module_chks = {}
        for i, (label, key, default) in enumerate(modules):
            chk = QCheckBox(label)
            chk.setChecked(default)
            self._module_chks[key] = chk
            grid.addWidget(chk, i // 2, i % 2)

        return grp

    def _build_perf_group(self):
        grp = QGroupBox('PERFORMANCE')
        lay = QGridLayout(grp)
        lay.setContentsMargins(8, 14, 8, 8)
        lay.setSpacing(6)

        lay.addWidget(QLabel('Threads:'), 0, 0)
        self._spin_threads = QSpinBox()
        self._spin_threads.setRange(1, 100)
        self._spin_threads.setValue(20)
        lay.addWidget(self._spin_threads, 0, 1)

        lay.addWidget(QLabel('Timeout (s):'), 1, 0)
        self._spin_timeout = QSpinBox()
        self._spin_timeout.setRange(3, 60)
        self._spin_timeout.setValue(8)
        lay.addWidget(self._spin_timeout, 1, 1)

        return grp

    def _build_options_group(self):
        grp = QGroupBox('OPTIONS')
        grid = QGridLayout(grp)
        grid.setContentsMargins(8, 14, 8, 8)
        grid.setSpacing(4)

        opts = [
            ('LFI Probe',      '_chk_lfi',      False),
            ('Active Checks',  '_chk_active',   True),
            ('JS Crawl',       '_chk_js',       False),
            ('Service Scan',   '_chk_services', True),
            ('Brute Force',    '_chk_brute',    False),
            ('Skip WAF',       '_chk_skip_waf', False),
        ]
        for i, (label, attr, default) in enumerate(opts):
            chk = QCheckBox(label)
            chk.setChecked(default)
            setattr(self, attr, chk)
            grid.addWidget(chk, i // 2, i % 2)

        return grp

    def _build_telegram_group(self):
        grp = QGroupBox('TELEGRAM ALERTS')
        lay = QVBoxLayout(grp)
        lay.setContentsMargins(8, 14, 8, 8)
        lay.setSpacing(4)

        self._chk_tg = QCheckBox('Enable Telegram notifications')
        self._chk_tg.setChecked(self._cfg.get('tg_enabled', False))
        lay.addWidget(self._chk_tg)

        self._inp_tg_token = QLineEdit(self._cfg.get('tg_token', ''))
        self._inp_tg_token.setPlaceholderText('Bot Token')
        self._inp_tg_token.setEchoMode(QLineEdit.Password)
        lay.addWidget(self._inp_tg_token)

        self._inp_tg_chat = QLineEdit(self._cfg.get('tg_chat', ''))
        self._inp_tg_chat.setPlaceholderText('Chat ID')
        lay.addWidget(self._inp_tg_chat)

        return grp

    def _build_rt_email_group(self):
        grp = QGroupBox('RED TEAM EMAIL')
        lay = QVBoxLayout(grp)
        lay.setContentsMargins(8, 14, 8, 8)
        self._inp_rt_email = QLineEdit(self._cfg.get('redteam_email', ''))
        self._inp_rt_email.setPlaceholderText('Receive SMTP findings at...')
        lay.addWidget(self._inp_rt_email)
        return grp

    def _build_control_buttons(self):
        frame = QFrame()
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        self._btn_start = QPushButton('▶  START SCAN')
        self._btn_start.setObjectName('btn_start')
        self._btn_start.clicked.connect(self._start)
        lay.addWidget(self._btn_start)

        row = QHBoxLayout()
        self._btn_pause = QPushButton('⏸  Pause')
        self._btn_pause.setObjectName('btn_pause')
        self._btn_pause.setEnabled(False)
        self._btn_pause.clicked.connect(self._toggle_pause)
        row.addWidget(self._btn_pause)

        self._btn_stop = QPushButton('⏹  Stop')
        self._btn_stop.setObjectName('btn_stop')
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._stop)
        row.addWidget(self._btn_stop)
        lay.addLayout(row)

        btn_results = QPushButton('📁  Open Results Folder')
        btn_results.clicked.connect(self._open_results)
        lay.addWidget(btn_results)

        return frame

    # ── RIGHT PANEL ───────────────────────────────────────────────────────────
    def _build_right_panel(self):
        splitter = QSplitter(Qt.Vertical)

        # Log area
        log_frame = QFrame()
        log_lay = QVBoxLayout(log_frame)
        log_lay.setContentsMargins(6, 6, 6, 0)
        log_lay.setSpacing(4)

        log_header = QHBoxLayout()
        log_lbl = QLabel('LIVE LOG')
        log_lbl.setStyleSheet('color:#e94560; font-weight:bold; font-size:12px; letter-spacing:1px;')
        log_header.addWidget(log_lbl)
        log_header.addStretch()
        btn_clear = QPushButton('Clear')
        btn_clear.setFixedSize(55, 24)
        btn_clear.clicked.connect(self._clear_log)
        log_header.addWidget(btn_clear)
        log_lay.addLayout(log_header)

        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setFont(QFont('Consolas', 11))
        self._log_view.document().setMaximumBlockCount(5000)
        log_lay.addWidget(self._log_view)
        splitter.addWidget(log_frame)

        # Bottom tabs: counters + vuln targets
        bottom = QTabWidget()

        # Counter grid
        counter_w = QWidget()
        counter_scroll = QScrollArea()
        counter_scroll.setWidgetResizable(True)
        counter_inner = QWidget()
        grid = QGridLayout(counter_inner)
        grid.setContentsMargins(8, 8, 8, 8)
        grid.setSpacing(6)
        cols = 8
        for i, (key, (label, color)) in enumerate(FINDING_META.items()):
            card = CounterCard(label, color)
            self._counter_cards[key] = card
            grid.addWidget(card, i // cols, i % cols)
        counter_scroll.setWidget(counter_inner)
        c_lay = QVBoxLayout(counter_w)
        c_lay.setContentsMargins(0, 0, 0, 0)
        c_lay.addWidget(counter_scroll)
        bottom.addTab(counter_w, 'Finding Counters')

        # Vuln targets
        vuln_w = QWidget()
        v_lay = QVBoxLayout(vuln_w)
        v_lay.setContentsMargins(6, 6, 6, 6)
        v_lay.setSpacing(4)
        hdr = QHBoxLayout()
        hdr.addWidget(QLabel('Vulnerable URLs'))
        hdr.addStretch()
        btn_copy = QPushButton('Copy All')
        btn_copy.setFixedSize(70, 24)
        btn_copy.clicked.connect(self._copy_vuln_list)
        hdr.addWidget(btn_copy)
        v_lay.addLayout(hdr)
        self._vuln_list = QListWidget()
        v_lay.addWidget(self._vuln_list)
        bottom.addTab(vuln_w, 'Vuln Targets')

        splitter.addWidget(bottom)
        splitter.setSizes([520, 220])
        return splitter

    def _build_status_bar(self):
        bar = QFrame()
        bar.setFixedHeight(38)
        bar.setStyleSheet('background:#0f0f1e; border-top:1px solid #2d2d4f;')
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 12, 0)
        lay.setSpacing(16)

        self._prog_bar = QProgressBar()
        self._prog_bar.setRange(0, 100)
        self._prog_bar.setValue(0)
        self._prog_bar.setFixedWidth(200)
        lay.addWidget(self._prog_bar)

        self._lbl_checked = QLabel('Checked: 0')
        self._lbl_checked.setStyleSheet('color:#555577; font-size:12px;')
        lay.addWidget(self._lbl_checked)

        self._lbl_found = QLabel('Found: 0')
        self._lbl_found.setStyleSheet('color:#22c55e; font-size:12px; font-weight:bold;')
        lay.addWidget(self._lbl_found)

        lay.addStretch()

        self._lbl_session = QLabel('')
        self._lbl_session.setStyleSheet('color:#444466; font-size:11px;')
        lay.addWidget(self._lbl_session)

        return bar

    # ── actions ───────────────────────────────────────────────────────────────
    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Select Targets File', '', 'Text Files (*.txt);;All Files (*)')
        if path:
            try:
                lines = Path(path).read_text(errors='ignore').splitlines()
                targets = [l.strip() for l in lines if l.strip() and not l.startswith('#')]
                self._txt_targets.setPlainText('\n'.join(targets))
                self._log(f'[*] Loaded {len(targets)} targets from {path}')
            except Exception as e:
                self._log(f'[!] File error: {e}')

    def _fetch_osint(self, source):
        if not MODULES_OK:
            self._log('[!] Scanner modules not available'); return

        stop_evt = threading.Event()

        if source == 'shodan':
            key = self._inp_shodan_key.text().strip()
            queries = [q.strip() for q in self._txt_shodan_q.toPlainText().splitlines() if q.strip()]
            if not key or not queries:
                self._log('[!] Shodan: key and queries required'); return
            worker = FetchWorker(shodan_search, key, queries, stop_evt=stop_evt)

        elif source == 'fofa':
            email = self._inp_fofa_email.text().strip()
            key   = self._inp_fofa_key.text().strip()
            queries = [q.strip() for q in self._txt_fofa_q.toPlainText().splitlines() if q.strip()]
            if not email or not key:
                self._log('[!] FOFA: email and key required'); return
            worker = FetchWorker(fofa_search, email, key, queries, stop_evt=stop_evt)

        elif source == 'censys':
            api_id  = self._inp_censys_id.text().strip()
            api_sec = self._inp_censys_sec.text().strip()
            queries = [q.strip() for q in self._txt_censys_q.toPlainText().splitlines() if q.strip()]
            if not api_id or not api_sec:
                self._log('[!] Censys: API ID and secret required'); return
            worker = FetchWorker(censys_search, api_id, api_sec, queries, stop_evt=stop_evt)

        elif source == 'leakix':
            key     = self._inp_leakix_key.text().strip()
            queries = [q.strip() for q in self._txt_leakix_q.toPlainText().splitlines() if q.strip()]
            worker = FetchWorker(leakix_search, key, queries, stop_evt=stop_evt)

        elif source == 'crt':
            raw = self._inp_crt.text().strip()
            domains = [d.strip() for d in raw.replace(',', '\n').splitlines() if d.strip()]
            if not domains:
                self._log('[!] CRT.sh: enter at least one domain'); return
            worker = FetchWorker(crtsh_search, domains)

        else:
            return

        def on_result(targets):
            fetched, invalid = parse_targets(targets)
            current_targets, _ = parse_targets(self._txt_targets.toPlainText().splitlines())
            current_set = set(current_targets)
            self._fetched_targets = list(dict.fromkeys(self._fetched_targets + fetched))
            new_lines = [t for t in fetched if t not in current_set]
            if new_lines:
                self._txt_targets.setPlainText('\n'.join(current_targets + new_lines))
            self._lbl_fetched.setText(f'Fetched: {len(self._fetched_targets)} targets')
            self._log(f'[+] {source.upper()} fetched {len(fetched)} valid targets')
            if invalid:
                self._log(f'[!] Ignored {len(invalid)} malformed fetched targets')

        worker.log_sig.connect(self._log)
        worker.result_sig.connect(on_result)
        self._fetch_workers.add(worker)
        worker.finished.connect(lambda w=worker: self._release_fetch_worker(w))
        worker.start()
        self._log(f'[*] {source.upper()} fetch started...')

    def _get_targets(self):
        targets, invalid = parse_targets(self._txt_targets.toPlainText().splitlines())
        for raw, reason in invalid[:10]:
            self._log(f'[!] Ignoring target {raw!r}: {reason}')
        if len(invalid) > 10:
            self._log(f'[!] Ignoring {len(invalid) - 10} additional malformed targets')
        return targets

    def _release_fetch_worker(self, worker):
        self._fetch_workers.discard(worker)
        worker.deleteLater()

    def _get_paths(self):
        paths = []
        seen = set()
        for key, chk in self._module_chks.items():
            if chk.isChecked() and key in PATH_MODULES:
                for p in PATH_MODULES[key]:
                    if p not in seen:
                        seen.add(p)
                        paths.append(p)
        return paths

    def _start(self):
        if not MODULES_OK:
            self._log(f'[!] Cannot scan — import error: {IMPORT_ERR}'); return

        targets = self._get_targets()
        if not targets:
            self._log('[!] No targets. Add URLs to the Manual tab or fetch from OSINT.'); return

        paths = self._get_paths()
        if not paths:
            self._log('[!] No modules selected — check at least one module.'); return

        self._save_config()
        self._reset_counters()
        self._vuln_list.clear()

        cfg = {
            'targets':      targets,
            'paths':        paths,
            'threads':      self._spin_threads.value(),
            'timeout':      self._spin_timeout.value(),
            'lfi':          self._chk_lfi.isChecked(),
            'active':       self._chk_active.isChecked(),
            'js':           self._chk_js.isChecked(),
            'services':     self._chk_services.isChecked(),
            'skip_waf':     self._chk_skip_waf.isChecked(),
            'redteam_email': self._inp_rt_email.text().strip(),
            'tg_enabled':   self._chk_tg.isChecked(),
            'tg_token':     self._inp_tg_token.text().strip(),
            'tg_chat':      self._inp_tg_chat.text().strip(),
        }

        self._log(f'[*] Starting scan — {len(targets)} targets · {len(paths)} paths · {cfg["threads"]} threads')

        self._worker = ScanWorker(cfg)
        self._worker.log_sig.connect(self._log)
        self._worker.finding_sig.connect(self._on_finding)
        self._worker.progress_sig.connect(self._on_progress)
        self._worker.stats_sig.connect(self._on_stats)
        self._worker.done_sig.connect(self._on_scan_done)
        self._worker.start()

        self._btn_start.setEnabled(False)
        self._btn_pause.setEnabled(True)
        self._btn_stop.setEnabled(True)
        self._paused = False
        self._set_status('Scanning…', '#e94560')
        self._prog_bar.setRange(0, 0)  # indeterminate

    def _toggle_pause(self):
        if not self._worker: return
        if self._paused:
            self._worker.resume()
            self._btn_pause.setText('⏸  Pause')
            self._set_status('Scanning…', '#e94560')
            self._paused = False
            self._log('[*] Resumed')
        else:
            self._worker.pause()
            self._btn_pause.setText('▶  Resume')
            self._set_status('Paused', '#f59e0b')
            self._paused = True
            self._log('[~] Paused')

    def _stop(self):
        if self._worker:
            self._worker.stop()
            self._log('[!] Stop signal sent…')
            self._set_status('Stopping…', '#f97316')

    def _on_scan_done(self, status):
        self._btn_start.setEnabled(True)
        self._btn_pause.setEnabled(False)
        self._btn_stop.setEnabled(False)
        self._prog_bar.setRange(0, 100)
        total = sum(self._findings_count.values())
        if status == 'completed':
            self._prog_bar.setValue(100)
            self._log(f'[+] Scan complete — {total} findings')
            self._set_status(f'Done · {total} findings', '#22c55e')
        elif status == 'stopped':
            self._log(f'[!] Scan stopped — {total} findings retained')
            self._set_status(f'Stopped · {total} findings', '#f97316')
        else:
            self._log(f'[!] Scan failed — {total} findings retained')
            self._set_status('Failed', '#ef4444')
        self._worker = None

    def _on_finding(self, f):
        ftype = f.get('type', 'general')
        if ftype in self._findings_count:
            self._findings_count[ftype] += 1
            self._counter_cards[ftype].set_count(self._findings_count[ftype])

        url  = f.get('url', '')
        path = f.get('path', '')
        entry = f'{url.rstrip("/")}/{path.lstrip("/")}'.rstrip('/')
        item = QListWidgetItem(entry)
        color = FINDING_META.get(ftype, ('', '#e2e2e2'))[1]
        item.setForeground(QColor(color))
        self._vuln_list.addItem(item)
        self._vuln_list.scrollToBottom()

        data = f.get('data', {})
        validated = data.get('validated') or data.get('validation')
        tag = ' ✓ VALIDATED' if validated else ''
        self._log(f'[+] {ftype.upper():<14} {entry}{tag}')

    def _on_progress(self, cur, tot):
        if tot > 0:
            self._prog_bar.setRange(0, tot)
            self._prog_bar.setValue(cur)

    def _on_stats(self, checked, found):
        self._lbl_checked.setText(f'Checked: {checked:,}')
        self._lbl_found.setText(f'Found: {found:,}')

    def _log(self, msg):
        color = '#e2e2e2'
        for prefix, c in LOG_COLORS.items():
            if msg.startswith(prefix):
                color = c
                break
        # bold for validated findings
        bold = 'VALIDATED' in msg or 'LIVE' in msg or 'CONFIRMED' in msg
        tag = 'b' if bold else 'span'
        safe = (msg.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))
        ts = datetime.now().strftime('%H:%M:%S')
        html = (f'<span style="color:#333355;">[{ts}]</span> '
                f'<{tag} style="color:{color};">{safe}</{tag}><br>')
        self._log_view.moveCursor(QTextCursor.End)
        self._log_view.insertHtml(html)
        self._log_view.moveCursor(QTextCursor.End)

    def _clear_log(self):
        self._log_view.clear()

    def _reset_counters(self):
        self._findings_count = {k: 0 for k in FINDING_META}
        for card in self._counter_cards.values():
            card.set_count(0)
        self._prog_bar.setRange(0, 100)
        self._prog_bar.setValue(0)
        self._lbl_checked.setText('Checked: 0')
        self._lbl_found.setText('Found: 0')

    def _copy_vuln_list(self):
        lines = [self._vuln_list.item(i).text() for i in range(self._vuln_list.count())]
        QApplication.clipboard().setText('\n'.join(lines))
        self._log(f'[*] Copied {len(lines)} URLs to clipboard')

    def _open_results(self):
        results_dir = BASE_DIR / 'results'
        if results_dir.exists():
            os.startfile(str(results_dir))
        else:
            self._log('[!] No results folder yet — run a scan first')

    def _set_status(self, text, color):
        self._lbl_status_dot.setStyleSheet(f'color:{color}; font-size:18px;')
        self._lbl_status_text.setStyleSheet(f'color:{color}; font-size:12px;')
        self._lbl_status_text.setText(text)

    def closeEvent(self, event):
        self._save_config()
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(3000)
        for worker in list(self._fetch_workers):
            worker.stop()
            worker.wait(3000)
        event.accept()


# ── entry point ───────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName('SB Scanner Pro')
    app.setStyle('Fusion')
    window = SBScannerQT()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
