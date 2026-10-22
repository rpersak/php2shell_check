#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_check.py - all-in-one LOCAL checker for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619).

Read-only: it never changes files, never sends traffic, never exploits anything.
Python 3.6+, standard library only. Linux. Run as root for full visibility:

    sudo python3 php2shell_check.py
    sudo python3 php2shell_check.py --since 2026-10-17 --json report.json
    sudo python3 php2shell_check.py --webroot /srv/app --access-log '/data/logs/*.log*'

What it checks
  1. PHP versions (CLI/FPM/CGI binaries, mod_php modules) against the fixed
     releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, including distro backports
     (package changelog mentions the CVE ids).
  2. Configuration relevant to the PHP advisory mitigations
     (session.upload_progress.enabled, memory_limit, post_max_size,
     fatal_error_backtraces, pm.max_requests, per-pool overrides).
  3. Running processes: workers still running a replaced (deleted) binary after
     an update, shells / recon tools spawned by web or PHP processes,
     outbound connections from web processes.
  4. Files: recently changed code in web roots, webshell patterns, PHP inside
     upload/cache dirs, PHP hidden in images, auto_prepend_file tricks,
     suspicious files in /tmp, /var/tmp, /dev/shm.
  5. Persistence: cron of web users, ld.so.preload, extra UID 0 accounts,
     recently modified system files, authorized_keys of web users.
  6. Logs: access logs (nginx/Apache, also .gz) and error/syslog files from
     --since onward.

IMPORTANT LIMITS
  * There are no official IOCs. Log and file heuristics come from public
    community write-ups and may produce false positives or miss real attacks.
  * Access logs do not contain request bodies, so "no hits" does NOT prove
    the server was not attacked. Memory disclosure and file reads leave no
    files on disk. If a host was exposed, rotate secrets PHP could read.
  * A log hit is an attempt, not a compromise. Host evidence (process, file,
    connection) is what indicates compromise.

Exit code: 2 = at least one HIGH finding, 1 = at least one MEDIUM, 0 = else.
"""

import argparse
import datetime as dt
import functools
import glob
import gzip
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------
FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
CVE_RE = re.compile(r"CVE-2026-10961[89]")
DEFAULT_SINCE = "2026-10-17"  # earliest publicly reported exploitation attempt

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
COLORS = {"INFO": "\033[36m", "LOW": "\033[32m", "MEDIUM": "\033[33m", "HIGH": "\033[1;31m"}
RESET = "\033[0m"

WEB_PREFIXES = ("php-fpm", "php-cgi", "php-fcgi", "lsphp", "apache2", "httpd", "nginx",
                "caddy", "frankenphp", "lighttpd", "litespeed", "lshttpd")
PHP_PROC_PREFIXES = ("php-fpm", "php-cgi", "php-fcgi", "lsphp", "frankenphp")
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "mksh", "ash"}
RECON = {"whoami", "id", "hostname", "uname", "nc", "ncat", "netcat", "socat", "nmap",
         "wget", "curl", "xxd", "base64", "openssl", "python", "python3", "perl", "ruby", "busybox"}
RECON_IN_CMD = re.compile(r"(^|[\s;|&/])(whoami|id|hostname|uname|nc|ncat|netcat|socat|xxd|base64|"
                          r"openssl|curl|wget|/dev/tcp|chmod \+x)(\s|;|$)")

PHPEXT = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".pht", ".phar", ".phps"}
IMGEXT = {".jpg", ".jpeg", ".png", ".gif", ".ico", ".webp", ".bmp"}
UPLOAD_RE = re.compile(r"(^|/)(uploads?|files|cache|tmp|temp|media|images|img)(/|$)", re.I)
SKIP_DIRS = {".git", "node_modules", ".svn"}

WEBSHELL_PATTERNS = [
    ("HIGH", "eval of decoded payload",
     re.compile(rb"eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|stripslashes)\s*\(", re.I)),
    ("HIGH", "command execution of request input",
     re.compile(rb"(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", re.I)),
    ("HIGH", "assert() of request input",
     re.compile(rb"assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", re.I)),
    ("HIGH", "preg_replace /e modifier",
     re.compile(rb"preg_replace\s*\(\s*['\"]/[^'\"]*/[a-z]*e[a-z]*['\"]", re.I)),
    ("HIGH", "known webshell family string",
     re.compile(rb"FilesMan|c99shell|r57shell|b374k|WSO\s*[0-9.]+|JACKALPOC|php2shell", re.I)),
    ("MEDIUM", "variable function call on request input",
     re.compile(rb"\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(")),
    ("MEDIUM", "base64_decode of request input",
     re.compile(rb"base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", re.I)),
]
HTACCESS_PATTERNS = [
    ("HIGH", "auto_prepend/append_file", re.compile(rb"auto_(prepend|append)_file", re.I)),
    ("MEDIUM", "AddType/AddHandler php", re.compile(rb"Add(Type|Handler)\s+\S*php", re.I)),
    ("MEDIUM", "php_value/php_flag override",
     re.compile(rb"php_(admin_)?(value|flag)\s+(memory_limit|session\.upload_progress)", re.I)),
    ("MEDIUM", "user.ini override",
     re.compile(rb"^\s*(memory_limit|session\.upload_progress\.\w+)\s*=", re.I | re.M)),
]

ACC_BODY = (r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>(?:[^"\\]|\\.)*)" '
            r'(?P<status>\d{3}) (?P<size>\S+)'
            r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')
ACC_RE = re.compile(r"^" + ACC_BODY)
ACC_RE_VHOST = re.compile(r"^\S+ " + ACC_BODY)
POC_RE = re.compile(r"php2shell|jackalpoc", re.I)
UP_RE = re.compile(r"PHP_SESSION_UPLOAD_PROGRESS|upload_progress", re.I)
WEBSHELL_URL_RE = re.compile(r"(?i)/(uploads?|files|cache|tmp|temp|media|images|img)/[^?\s]*\.(php\d?|phtml|phar|pht)(\?|$)")

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


class Report(object):
    def __init__(self, color):
        self.items = []
        self.color = color
        self.sections = []

    def add(self, sev, section, title, details=None):
        if section not in self.sections:
            self.sections.append(section)
        self.items.append({"severity": sev, "section": section, "title": title,
                           "details": list(details or [])})

    def worst(self):
        return max([SEV_RANK[i["severity"]] for i in self.items] or [0])

    def counts(self):
        c = Counter(i["severity"] for i in self.items)
        return {k: c.get(k, 0) for k in SEV_RANK}

    def print(self, sample):
        for sec in self.sections:
            print("\n== %s ==" % sec)
            for it in [i for i in self.items if i["section"] == sec]:
                tag = "[%s]" % it["severity"]
                if self.color:
                    tag = COLORS[it["severity"]] + tag + RESET
                print("%s %s" % (tag, it["title"]))
                d = it["details"]
                for line in d[:sample]:
                    print("      " + line)
                if len(d) > sample:
                    print("      ... (+%d more, see --json)" % (len(d) - sample))


def run(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, universal_newlines=True)
        return p.returncode, p.stdout
    except Exception as e:  # noqa
        return 127, str(e)


def read_text(path, limit=None):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rt", errors="replace") as f:
                return f.read(limit) if limit else f.read()
        with open(path, "r", errors="replace") as f:
            return f.read(limit) if limit else f.read()
    except Exception:
        return ""


def read_bytes(path, limit):
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except Exception:
        return b""


def fmt(v):
    return ".".join(str(x) for x in v)


def trunc(s, n=220):
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[:n] + "..."


def uniq_real(paths):
    seen, out = set(), []
    for p in paths:
        try:
            r = os.path.realpath(p)
        except Exception:
            continue
        if r not in seen and os.path.isfile(r):
            seen.add(r)
            out.append(r)
    return out


def safe(rep, name, fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:  # noqa
        rep.add("LOW", name, "Check crashed and was skipped: %s: %s" % (type(e).__name__, e))
        return None


def is_web(comm):
    return any(comm.startswith(p) for p in WEB_PREFIXES)


# --------------------------------------------------------------------------
# 1. PHP versions
# --------------------------------------------------------------------------
def find_php_binaries():
    cands = []
    for name in ("php", "php-cgi", "php-fpm", "lsphp"):
        p = shutil.which(name)
        if p:
            cands.append(p)
    patterns = ["/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/local/bin/php*", "/usr/local/sbin/php-fpm*",
                "/opt/remi/php*/root/usr/bin/php*", "/opt/remi/php*/root/usr/sbin/php-fpm*",
                "/opt/plesk/php/*/bin/php*", "/opt/plesk/php/*/sbin/php-fpm*",
                "/usr/local/php*/bin/php*", "/usr/local/lsws/lsphp*/bin/lsphp"]
    for pat in patterns:
        cands.extend(glob.glob(pat))
    ok = re.compile(r"^(lsphp|php(-cgi|-fpm)?)[0-9.]*$")
    out = []
    for p in uniq_real(cands):
        if ok.match(os.path.basename(p)) and os.access(p, os.X_OK):
            out.append(p)
    # keep also the names that users call (symlink names) for kind detection
    return out


def php_version(binary):
    rc, out = run([binary, "-v"])
    m = re.search(r"PHP (\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(x) for x in m.groups()) if m else None


def pkg_owner(path):
    real = os.path.realpath(path)
    if shutil.which("dpkg"):
        rc, out = run(["dpkg", "-S", real])
        if rc == 0 and out.strip():
            first = out.splitlines()[0]
            pkg = first.split(":")[0].split(",")[0].strip()
            if pkg:
                return pkg, "dpkg"
    if shutil.which("rpm"):
        rc, out = run(["rpm", "-qf", real, "--qf", "%{NAME}\n"])
        if rc == 0 and out.strip() and "not owned" not in out:
            return out.splitlines()[0].strip(), "rpm"
    return None, None


def pkg_version(pkg, mgr):
    if mgr == "dpkg":
        rc, out = run(["dpkg-query", "-W", "-f", "${Version}", pkg])
    else:
        rc, out = run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg])
    return out.strip() if rc == 0 else ""


def changelog_cves(pkg, mgr):
    found = set()
    if mgr == "dpkg":
        for c in glob.glob("/usr/share/doc/%s/changelog*" % pkg.split(":")[0]):
            found.update(CVE_RE.findall(read_text(c)))
    elif mgr == "rpm":
        rc, out = run(["rpm", "-q", "--changelog", pkg], timeout=60)
        if rc == 0:
            found.update(CVE_RE.findall(out))
    return found


def assess(v, fixes):
    key = v[:2]
    if key in FIXED:
        if v >= FIXED[key]:
            return "INFO", "version %s is at or above the fixed release %s" % (fmt(v), fmt(FIXED[key]))
        base = "version %s is below the fixed release %s" % (fmt(v), fmt(FIXED[key]))
    elif key > (8, 5):
        return "INFO", "version %s is newer than the known branches; verify it contains the fix" % fmt(v)
    else:
        base = "version %s is on branch %d.%d which has no upstream fix (EOL)" % (fmt(v), key[0], key[1])
    if all(c in fixes for c in CVE_IDS):
        return "INFO", "%s, but the package changelog lists both CVEs (distro backport): looks patched" % base
    if fixes:
        return "MEDIUM", "%s; changelog mentions only %s" % (base, ", ".join(sorted(fixes)))
    return "HIGH", "VULNERABLE: %s and no distro backport found" % base


def check_php(rep):
    sec = "1. PHP versions"
    state = {"vulnerable": False, "found": False, "fpm_bins": []}
    bins = find_php_binaries()
    for b in bins:
        v = php_version(b)
        if not v:
            continue
        state["found"] = True
        pkg, mgr = pkg_owner(b)
        fixes = changelog_cves(pkg, mgr) if pkg else set()
        sev, text = assess(v, fixes)
        if SEV_RANK[sev] >= SEV_RANK["MEDIUM"]:
            state["vulnerable"] = True
        base = os.path.basename(b)
        if base.startswith(("php-fpm", "php-cgi", "lsphp")):
            state["fpm_bins"].append(b)
        src = "package %s %s" % (pkg, pkg_version(pkg, mgr)) if pkg else "not from a distro package"
        rep.add(sev, sec, "%s: %s" % (b, text), ["source: " + src])

    mods = []
    for pat in ("/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
                "/usr/lib/httpd/modules/libphp*.so", "/opt/remi/php*/root/usr/lib64/httpd/modules/libphp*.so"):
        mods.extend(glob.glob(pat))
    for m in uniq_real(mods):
        state["found"] = True
        pkg, mgr = pkg_owner(m)
        fixes = changelog_cves(pkg, mgr) if pkg else set()
        pv = pkg_version(pkg, mgr) if pkg else ""
        mm = re.match(r"^(?:\d+:)?(\d+)\.(\d+)\.(\d+)", pv)
        if mm:
            sev, text = assess(tuple(int(x) for x in mm.groups()), fixes)
        elif all(c in fixes for c in CVE_IDS):
            sev, text = "INFO", "package changelog lists both CVEs: looks patched"
        else:
            sev, text = "MEDIUM", "cannot determine the upstream version; verify the package is patched"
        if SEV_RANK[sev] >= SEV_RANK["MEDIUM"]:
            state["vulnerable"] = True
        rep.add(sev, sec, "mod_php %s: %s" % (m, text),
                ["source: package %s %s" % (pkg, pv)] if pkg else [])

    if not state["found"]:
        rep.add("INFO", sec, "No PHP binaries or mod_php modules found on this host")
    rep.add("INFO", sec, "Containers and other hosts are NOT inspected here. Run the check inside each "
            "container image or check the image tag (fixed: %s)." % " / ".join(fmt(x) for x in FIXED.values()))
    return state


# --------------------------------------------------------------------------
# 2. configuration
# --------------------------------------------------------------------------
INI_KEYS = ("session.upload_progress.enabled", "memory_limit", "post_max_size", "upload_max_filesize",
            "fatal_error_backtraces", "max_input_nesting_level")
INI_RE = re.compile(r"^\s*(%s)\s*=\s*\"?([^\";\s]+)\"?" % "|".join(re.escape(k) for k in INI_KEYS))
POOL_DIRECTIVE_RE = re.compile(r"^\s*(php_admin_value|php_value|php_admin_flag|php_flag)\[([^\]]+)\]\s*=\s*(\S+)")
POOL_HDR_RE = re.compile(r"^\s*\[([^\]]+)\]")
FALSE_VALUES = {"0", "off", "false", "no", "none", ""}


def ini_families():
    fams = []
    for d in sorted(glob.glob("/etc/php/[0-9]*")):
        for sapi in ("fpm", "apache2", "cgi", "litespeed"):
            base = os.path.join(d, sapi)
            if os.path.isdir(base):
                files = [os.path.join(base, "php.ini")] + sorted(glob.glob(os.path.join(base, "conf.d", "*.ini")))
                pools = []
                if sapi == "fpm":
                    pools = sorted(glob.glob(os.path.join(base, "pool.d", "*.conf"))) + \
                        [os.path.join(base, "php-fpm.conf")]
                fams.append(("%s %s (Debian-style)" % (os.path.basename(d), sapi), files, pools))
    if os.path.exists("/etc/php.ini"):
        fams.append(("system php (RHEL-style)", ["/etc/php.ini"] + sorted(glob.glob("/etc/php.d/*.ini")),
                     sorted(glob.glob("/etc/php-fpm.d/*.conf")) + ["/etc/php-fpm.conf"]))
    for d in sorted(glob.glob("/etc/opt/remi/php*")):
        fams.append(("remi " + os.path.basename(d),
                     [os.path.join(d, "php.ini")] + sorted(glob.glob(os.path.join(d, "php.d", "*.ini"))),
                     sorted(glob.glob(os.path.join(d, "php-fpm.d", "*.conf"))) + [os.path.join(d, "php-fpm.conf")]))
    if os.path.isdir("/usr/local/etc/php"):
        fams.append(("docker-style /usr/local/etc/php",
                     ["/usr/local/etc/php/php.ini"] + sorted(glob.glob("/usr/local/etc/php/conf.d/*.ini")),
                     sorted(glob.glob("/usr/local/etc/php-fpm.d/*.conf")) + ["/usr/local/etc/php-fpm.conf"]))
    return fams


def parse_ini(files):
    eff = {}
    for f in files:
        if not os.path.isfile(f):
            continue
        for line in read_text(f).splitlines():
            if line.lstrip().startswith((";", "#")):
                continue
            m = INI_RE.match(line)
            if m:
                eff[m.group(1)] = (m.group(2), f)
    return eff


def parse_pools(files):
    pools = {}
    users = set()
    for f in files:
        if not os.path.isfile(f):
            continue
        cur = None
        for line in read_text(f).splitlines():
            if line.lstrip().startswith(";"):
                continue
            h = POOL_HDR_RE.match(line)
            if h:
                cur = (h.group(1), f)
                if h.group(1) != "global":
                    pools.setdefault(cur, {"overrides": [], "max_requests": None, "user": None})
                continue
            if cur is None or cur[0] == "global":
                continue
            d = POOL_DIRECTIVE_RE.match(line)
            if d:
                pools[cur]["overrides"].append((d.group(1), d.group(2), d.group(3)))
            m = re.match(r"^\s*pm\.max_requests\s*=\s*(\d+)", line)
            if m:
                pools[cur]["max_requests"] = int(m.group(1))
            u = re.match(r"^\s*user\s*=\s*(\S+)", line)
            if u:
                pools[cur]["user"] = u.group(1)
                users.add(u.group(1))
    return pools, users


def check_config(rep, vulnerable, state):
    sec = "2. PHP configuration"
    pool_users = set()
    fams = ini_families()
    if not fams:
        rep.add("INFO", sec, "No php.ini / pool configuration found in the usual locations")
    hint = "MEDIUM" if vulnerable else "LOW"
    for label, files, pool_files in fams:
        eff = parse_ini(files)
        pools, users = parse_pools(pool_files)
        pool_users |= users
        up_val = eff.get("session.upload_progress.enabled", ("1 (PHP default)", None))[0]
        summary = ["%s=%s" % (k, eff[k][0]) for k in INI_KEYS if k in eff]
        det = ["config files: " + ", ".join(sorted({v[1] for v in eff.values()})[:4]) if eff else
               "no explicit settings of the tracked keys found (PHP defaults apply)"]
        if summary:
            det.append("effective ini: " + ", ".join(summary))
        up_on = str(up_val).split()[0].lower() not in FALSE_VALUES

        # per-pool upload_progress / memory_limit
        on_pools, mem_not_admin, php_value_mem, no_maxreq = [], [], [], []
        for (pname, pfile), info in pools.items():
            pool_up = None
            mem_admin = False
            for kind, key, val in info["overrides"]:
                if key == "session.upload_progress.enabled":
                    pool_up = (kind, val)
                if key == "memory_limit":
                    if kind.startswith("php_admin") and val == "-1":
                        mem_admin = True
                    elif kind.startswith("php_value"):
                        php_value_mem.append(pname)
            eff_up = up_on
            if pool_up:
                eff_up = pool_up[1].lower() not in FALSE_VALUES
                if not pool_up[0].startswith("php_admin"):
                    det.append("pool [%s] sets upload_progress via %s (overridable by the app, "
                               "prefer php_admin_value)" % (pname, pool_up[0]))
            if eff_up:
                on_pools.append(pname)
            if not mem_admin:
                mem_not_admin.append(pname)
            if not info["max_requests"] or info["max_requests"] > 1:
                no_maxreq.append(pname)
        if pools:
            det.append("FPM pools: %d (%s)" % (len(pools), ", ".join(sorted({p[0] for p in pools})[:8])))
        if label.endswith("apache2 (Debian-style)") or "apache2" in label:
            det.append("mod_php: set values in php.ini or Apache config with php_admin_value, then restart Apache")

        sev = hint if (up_on and not pools) or on_pools else "INFO"
        title = "%s: session.upload_progress.enabled is %s" % (label, "ON" if (up_on or on_pools) else "off")
        if up_on or on_pools:
            title += " (advisory mitigation: set it to 0 in php.ini/pool; advice is to keep it off even after patching)"
        if on_pools and pools:
            det.append("pools with upload_progress still on: " + ", ".join(on_pools[:10]))
        rep.add(sev, sec, title, det)
        if vulnerable:
            extra = []
            if pools and mem_not_admin:
                extra.append("memory_limit=-1 via php_admin_value NOT set in pools: " + ", ".join(mem_not_admin[:10]))
            if php_value_mem:
                extra.append("memory_limit set with overridable php_value in pools: " + ", ".join(php_value_mem[:10]))
            if no_maxreq:
                extra.append("pm.max_requests is not 1 in pools: " + ", ".join(no_maxreq[:10]))
            pm = eff.get("post_max_size")
            if pm:
                extra.append("post_max_size=%s (PHP suggests 8M, or 32M if uploads are needed)" % pm[0])
            if state.get("found"):
                extra.append("PHP 8.5 only: also fatal_error_backtraces=0 (found: %s)" %
                             eff.get("fatal_error_backtraces", ("not set",))[0])
            if extra:
                rep.add("MEDIUM", sec, "%s: interim mitigations from the PHP advisory not (fully) applied; "
                        "these only reduce exposure, updating is the only complete fix" % label, extra)

    # Apache config overrides
    hits = []
    for pat in ("/etc/apache2/**/*.conf", "/etc/httpd/**/*.conf"):
        for f in glob.glob(pat, recursive=True):
            for ln, line in enumerate(read_text(f).splitlines(), 1):
                if re.search(r"^\s*php_(admin_)?(value|flag)\s+(memory_limit|session\.upload_progress)", line):
                    hits.append("%s:%d: %s" % (f, ln, trunc(line.strip())))
    if hits:
        rep.add("INFO", sec, "Apache config sets mitigation-related PHP values", hits)
    return pool_users


# --------------------------------------------------------------------------
# 3. processes and connections
# --------------------------------------------------------------------------
def proc_table():
    t = {}
    for e in os.listdir("/proc"):
        if not e.isdigit():
            continue
        pid = int(e)
        try:
            with open("/proc/%d/stat" % pid) as f:
                data = f.read()
            l, r = data.find("("), data.rfind(")")
            comm = data[l + 1:r]
            rest = data[r + 2:].split()
            ppid = int(rest[1])
            uid = os.stat("/proc/%d" % pid).st_uid
        except Exception:
            continue
        t[pid] = {"pid": pid, "ppid": ppid, "comm": comm, "uid": uid}
    return t


def cmdline(pid):
    return read_bytes("/proc/%d/cmdline" % pid, 4096).replace(b"\0", b" ").decode("utf-8", "replace").strip()


def uname(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def check_processes(rep):
    sec = "3. Processes and connections"
    if not os.path.isdir("/proc"):
        rep.add("LOW", sec, "/proc not available; process checks skipped")
        return set()
    t = proc_table()
    web = {pid for pid, p in t.items() if is_web(p["comm"])}
    web_users = {uname(t[p]["uid"]) for p in web if t[p]["uid"] != 0}

    # replaced binaries still running
    stale = defaultdict(list)
    for pid in web:
        comm = t[pid]["comm"]
        try:
            exe = os.readlink("/proc/%d/exe" % pid)
        except Exception:
            exe = ""
        if comm.startswith(PHP_PROC_PREFIXES) and exe.endswith("(deleted)"):
            stale[comm].append(pid)
        elif comm.startswith(("apache2", "httpd")):
            maps = read_text("/proc/%d/maps" % pid)
            if any("libphp" in ln and "(deleted)" in ln for ln in maps.splitlines()):
                stale[comm].append(pid)
    for comm, pids in stale.items():
        rep.add("HIGH", sec, "%s: %d process(es) still run a replaced PHP binary/module (updated on disk but not "
                "restarted, so STILL VULNERABLE in memory). Restart the service." % (comm, len(pids)),
                ["pids: " + ", ".join(str(p) for p in sorted(pids)[:15])])

    # suspicious children of web processes
    susp = defaultdict(list)
    for pid, p in t.items():
        name = p["comm"]
        if name not in SHELLS and name not in RECON:
            continue
        cur, depth, parent_web = p["ppid"], 0, None
        while cur in t and depth < 8:
            if is_web(t[cur]["comm"]):
                parent_web = t[cur]
                break
            cur = t[cur]["ppid"]
            depth += 1
        if not parent_web:
            continue
        cmd = cmdline(pid)
        if name in SHELLS:
            if re.search(r"sendmail|msmtp|ssmtp|postdrop", cmd):
                sev = "LOW"
            elif RECON_IN_CMD.search(cmd):
                sev = "HIGH"
            else:
                sev = "MEDIUM"
        else:
            sev = "HIGH"
        susp[sev].append("pid %d (parent chain via %s[%d]) user=%s: %s" %
                         (pid, parent_web["comm"], parent_web["pid"], uname(p["uid"]), trunc(cmd)))
    for sev, lines in susp.items():
        titles = {"HIGH": "Shell/recon tool spawned by a web or PHP process (typical post-exploitation)",
                  "MEDIUM": "Shell spawned by a web or PHP process (can be legitimate exec()/system())",
                  "LOW": "Shell spawned by a web process for mail delivery (usually legitimate)"}
        rep.add(sev, sec, titles[sev], lines)
    if not susp:
        rep.add("INFO", sec, "No shell or recon tool currently running below a web/PHP process "
                "(only a snapshot of right now)")

    # outbound connections from web processes
    if shutil.which("ss"):
        rc, lis = run(["ss", "-H", "-tln"])
        listen_ports = set()
        for ln in lis.splitlines():
            parts = ln.split()
            if len(parts) >= 4:
                listen_ports.add(parts[3].rsplit(":", 1)[-1])
        rc, out = run(["ss", "-H", "-tnp"])
        conns = []
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) < 6 or parts[0] != "ESTAB":
                continue
            local, peer, proc = parts[3], parts[4], " ".join(parts[5:])
            if not re.search(r'"(php|apache2|httpd|nginx|lsphp|frankenphp|caddy)', proc):
                continue
            lport = local.rsplit(":", 1)[-1]
            if lport in listen_ports:
                continue
            ip = peer.rsplit(":", 1)[0].strip("[]")
            if re.match(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80|fd|169\.254\.)", ip):
                continue
            conns.append("%s -> %s %s" % (local, peer, trunc(proc, 90)))
        if conns:
            rep.add("LOW", sec, "Outbound connections from web/PHP processes to public IPs "
                    "(often legitimate API calls; review unknown peers)", conns)
    return web_users


# --------------------------------------------------------------------------
# 4. files
# --------------------------------------------------------------------------
def discover_webroots(extra):
    roots = list(extra)
    for pat in ("/var/www", "/var/www/*", "/srv/www", "/srv/http", "/srv/*/public", "/usr/share/nginx/html",
                "/usr/local/apache2/htdocs", "/home/*/public_html", "/home/*/www", "/home/*/htdocs",
                "/opt/bitnami/*/htdocs", "/usr/local/lsws/*/html", "/var/www/vhosts/*/httpdocs"):
        roots.extend(glob.glob(pat))
    for pat in ("/etc/nginx/**/*", "/etc/apache2/**/*", "/etc/httpd/**/*"):
        for f in glob.glob(pat, recursive=True):
            if not os.path.isfile(f) or os.path.getsize(f) > 1000000:
                continue
            for line in read_text(f).splitlines():
                m = re.match(r"^\s*root\s+([^;\s]+)\s*;", line) or \
                    re.match(r'^\s*DocumentRoot\s+"?([^"\s]+)"?', line)
                if m and m.group(1).startswith("/"):
                    roots.append(m.group(1))
    good = []
    for r in roots:
        r = os.path.realpath(r)
        if os.path.isdir(r) and r not in ("/", "/var", "/etc", "/usr", "/home", "/srv", "/opt", "/tmp"):
            good.append(r)
    good = sorted(set(good))
    final = []
    for r in good:
        if not any(r != o and r.startswith(o.rstrip("/") + "/") for o in good):
            final.append(r)
    return final


def scan_content(data, patterns):
    hits = []
    for sev, label, rx in patterns:
        if rx.search(data):
            hits.append((sev, label))
    return hits


def check_files(rep, args, since_ts, web_users):
    sec = "4. Files"
    roots = discover_webroots(args.webroot)
    if not roots:
        rep.add("LOW", sec, "No web roots found; pass --webroot /path to scan one")
    finds = defaultdict(list)
    scanned = 0
    recent_code = 0
    limit_hit = False
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            rel_dir = os.path.relpath(dirpath, root)
            for fn in filenames:
                if scanned >= args.max_files:
                    limit_hit = True
                    break
                scanned += 1
                path = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(path)
                except Exception:
                    continue
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                ext = os.path.splitext(fn)[1].lower()
                rel = os.path.join(rel_dir, fn)
                recent = max(st.st_mtime, st.st_ctime) >= since_ts
                in_upload = bool(UPLOAD_RE.search(rel.replace(os.sep, "/")))
                stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(max(st.st_mtime, st.st_ctime)))

                if ext in PHPEXT:
                    if recent:
                        recent_code += 1
                    if recent or in_upload:
                        data = read_bytes(path, 2000000)
                        hits = scan_content(data, WEBSHELL_PATTERNS)
                        for sev, label in hits:
                            finds[sev].append("%s [%s] %s" % (path, stamp, label))
                        if not hits and in_upload and recent:
                            finds["MEDIUM"].append("%s [%s] PHP file in upload/cache-like directory" % (path, stamp))
                        elif not hits and recent:
                            finds["LOW"].append("%s [%s] recently changed code file" % (path, stamp))
                elif fn in (".htaccess", ".user.ini"):
                    if recent:
                        data = read_bytes(path, 200000)
                        for sev, label in scan_content(data, HTACCESS_PATTERNS):
                            finds[sev].append("%s [%s] %s" % (path, stamp, label))
                elif ext in IMGEXT and recent:
                    if b"<?php" in read_bytes(path, 8192).lower():
                        finds["HIGH"].append("%s [%s] image file containing PHP code" % (path, stamp))
                elif recent and (st.st_mode & 0o111) and ext not in (".js", ".css", ".html"):
                    finds["MEDIUM"].append("%s [%s] recently changed executable file in web root" % (path, stamp))
            if limit_hit:
                break
        if limit_hit:
            break
    if limit_hit:
        rep.add("LOW", sec, "File limit reached (%d); raise --max-files for complete coverage" % args.max_files)
    titles = {"HIGH": "Webshell patterns / PHP hidden in files",
              "MEDIUM": "Suspicious files in web roots",
              "LOW": "Recently changed code files (legitimate updates and deployments are listed too)"}
    for sev in ("HIGH", "MEDIUM", "LOW"):
        if finds[sev]:
            rep.add(sev, sec, "%s: %d finding(s)" % (titles[sev], len(finds[sev])), finds[sev])
    rep.add("INFO", sec, "Scanned %d files in %d web root(s): %s; %d code files changed since the cutoff" %
            (scanned, len(roots), ", ".join(roots[:6]) + (" ..." if len(roots) > 6 else ""), recent_code))

    # temp dirs
    uids = set()
    for u in web_users:
        try:
            uids.add(pwd.getpwnam(u).pw_uid)
        except Exception:
            pass
    tmpf = []
    for base in ("/tmp", "/var/tmp", "/dev/shm", "/run/shm"):
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            depth = dirpath[len(base):].count(os.sep)
            if depth >= 3:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if not d.startswith("systemd-private")]
            for fn in filenames:
                if fn.startswith("sess_") or re.match(r"^php[A-Za-z0-9]{6}$", fn):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(path)
                except Exception:
                    continue
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                if max(st.st_mtime, st.st_ctime) < since_ts:
                    continue
                elf = read_bytes(path, 4) == b"\x7fELF"
                owned = st.st_uid in uids
                if elf and owned:
                    tmpf.append(("HIGH", "%s ELF binary owned by web user" % path))
                elif owned or (st.st_mode & 0o111) or fn.startswith("."):
                    why = "owned by web user" if owned else ("executable" if st.st_mode & 0o111 else "hidden file")
                    tmpf.append(("MEDIUM", "%s (%s)" % (path, why)))
    for sev in ("HIGH", "MEDIUM"):
        lines = [t[1] for t in tmpf if t[0] == sev]
        if lines:
            rep.add(sev, sec, "Recent suspicious files in /tmp, /var/tmp, /dev/shm: %d" % len(lines), lines)


# --------------------------------------------------------------------------
# 5. persistence
# --------------------------------------------------------------------------
def check_persistence(rep, since_ts, web_users, pool_users):
    sec = "5. Persistence and system changes"
    users = set(web_users) | set(pool_users) | {"www-data", "apache", "nginx", "wwwrun", "www", "httpd"}
    users = {u for u in users if u}
    for u in sorted(users):
        try:
            pw = pwd.getpwnam(u)
        except Exception:
            continue
        for cp in ("/var/spool/cron/crontabs/%s" % u, "/var/spool/cron/%s" % u):
            if os.path.isfile(cp) and read_text(cp).strip():
                lines = [l for l in read_text(cp).splitlines() if l.strip() and not l.startswith("#")]
                if lines:
                    rep.add("MEDIUM", sec, "Web user '%s' has a crontab (unusual unless you set it up)" % u,
                            [trunc(l) for l in lines[:8]])
        ak = os.path.join(pw.pw_dir, ".ssh", "authorized_keys")
        if os.path.isfile(ak) and os.path.getsize(ak) > 0:
            rep.add("MEDIUM", sec, "Web user '%s' has authorized_keys: %s" % (u, ak),
                    ["modified: " + time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(ak)))])
        if pw.pw_shell and not pw.pw_shell.endswith(("nologin", "false")) and u in ("www-data", "apache", "nginx", "wwwrun"):
            rep.add("LOW", sec, "Web user '%s' has a login shell (%s)" % (u, pw.pw_shell))

    pre = "/etc/ld.so.preload"
    if os.path.isfile(pre) and read_text(pre).strip():
        rep.add("HIGH", sec, "/etc/ld.so.preload is present and non-empty (classic rootkit/hook location)",
                [trunc(l) for l in read_text(pre).splitlines()[:5]])

    uid0 = []
    for line in read_text("/etc/passwd").splitlines():
        p = line.split(":")
        if len(p) > 3 and p[2] == "0" and p[0] != "root":
            uid0.append(line)
    if uid0:
        rep.add("HIGH", sec, "Additional account(s) with UID 0", uid0)

    watch = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/crontab", "/etc/rc.local",
             "/root/.ssh/authorized_keys", "/etc/ssh/sshd_config", "/etc/environment"]
    for pat in ("/etc/sudoers.d/*", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
                "/etc/cron.weekly/*", "/etc/profile.d/*", "/etc/systemd/system/*.service",
                "/etc/systemd/system/*.timer", "/etc/systemd/system/*/*.service", "/etc/init.d/*"):
        watch.extend(glob.glob(pat))
    changed = []
    for f in sorted(set(watch)):
        try:
            st = os.lstat(f)
        except Exception:
            continue
        if max(st.st_mtime, st.st_ctime) >= since_ts:
            changed.append("%s [%s]" % (f, time.strftime("%Y-%m-%d %H:%M", time.localtime(max(st.st_mtime, st.st_ctime)))))
    if changed:
        rep.add("MEDIUM", sec, "System files changed since the cutoff (package updates and your own changes "
                "appear here too; verify each)", changed)
    else:
        rep.add("INFO", sec, "No watched persistence/system files changed since the cutoff")


# --------------------------------------------------------------------------
# 6. logs
# --------------------------------------------------------------------------
@functools.lru_cache(maxsize=8192)
def parse_access_ts(s):
    try:
        return dt.datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except Exception:
        return None


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def log_files(patterns, since_ts):
    files = []
    for pat in patterns:
        files.extend(glob.glob(pat, recursive=True))
    out = []
    for f in uniq_real(files):
        try:
            if os.path.getmtime(f) >= since_ts:
                out.append(f)
        except Exception:
            pass
    return out


ACCESS_GLOBS = ["/var/log/nginx/*access*", "/var/log/nginx/*/*access*", "/var/log/apache2/*access*",
                "/var/log/httpd/*access*", "/var/log/lighttpd/access*", "/var/log/caddy/*.log*",
                "/var/log/apache2/other_vhosts_access.log*", "/var/www/vhosts/*/logs/*access*",
                "/var/log/litespeed/*access*", "/usr/local/lsws/logs/access*"]
ERROR_GLOBS = ["/var/log/php*fpm*.log*", "/var/log/php-fpm/*.log*", "/var/log/php*.log*", "/var/log/apache2/*error*",
               "/var/log/httpd/*error*", "/var/log/nginx/*error*", "/var/log/nginx/*/*error*",
               "/var/www/vhosts/*/logs/*error*", "/var/log/syslog*", "/var/log/messages*", "/var/log/kern.log*"]


def check_access_logs(rep, args, since_ts):
    sec = "6. Logs: access"
    files = log_files(ACCESS_GLOBS + args.access_log, since_ts)
    if not files:
        rep.add("LOW", sec, "No access logs found in the usual locations; pass --access-log '/path/*.log*'")
        return
    counts = Counter()
    ipc = defaultdict(Counter)
    samples = defaultdict(list)
    burst = Counter()
    first_ts = last_ts = None
    lines_total = parsed = 0

    def rec(cat, line, ip):
        counts[cat] += 1
        ipc[cat][ip] += 1
        if len(samples[cat]) < 40:
            samples[cat].append(trunc(line.strip(), 260))

    for path in files:
        try:
            fh = open_log(path)
        except Exception:
            continue
        with fh:
            try:
                for line in fh:
                    lines_total += 1
                    m = ACC_RE.match(line) or ACC_RE_VHOST.match(line)
                    if not m:
                        continue
                    ts = parse_access_ts(m.group("ts"))
                    if ts is None or ts < since_ts:
                        continue
                    parsed += 1
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)
                    ip = m.group("ip")
                    req = m.group("req")
                    status = int(m.group("status"))
                    ua = m.group("ua") or ""
                    parts = req.split(" ", 2)
                    method = parts[0] if parts else ""
                    target = parts[1] if len(parts) > 1 else ""
                    if POC_RE.search(line):
                        rec("poc", line, ip)
                    if UP_RE.search(req) or UP_RE.search(m.group("ref") or ""):
                        rec("upload_progress", line, ip)
                    if method == "POST":
                        burst[(ip, int(ts // 60))] += 1
                        if status >= 500:
                            rec("post500", line, ip)
                        if ua in ("", "-") or len(ua) < 3:
                            rec("emptyua", line, ip)
                    if "PHPSESSID" in req and method != "POST":
                        rec("phpsessid_url", line, ip)
                    if WEBSHELL_URL_RE.search(target) and 200 <= status < 400:
                        rec("php_in_uploads", line, ip)
            except Exception:
                continue

    cov = "no matching lines"
    if first_ts:
        cov = "%s .. %s" % (time.strftime("%Y-%m-%d %H:%M", time.localtime(first_ts)),
                            time.strftime("%Y-%m-%d %H:%M", time.localtime(last_ts)))
    rep.add("INFO", sec, "Read %d log files, %d lines (%d parsed in range). Coverage: %s" %
            (len(files), lines_total, parsed, cov), files[:12])

    def top_ips(cat):
        return "top IPs: " + ", ".join("%s(%d)" % kv for kv in ipc[cat].most_common(5))

    if counts["poc"]:
        rep.add("HIGH", sec, "Known PoC markers (php2shell / JACKALPOC) in requests: %d (attempts; check these hosts "
                "for follow-on activity)" % counts["poc"], [top_ips("poc")] + samples["poc"])
    if counts["upload_progress"]:
        rep.add("MEDIUM", sec, "Requests mentioning upload_progress in URL/referer: %d (attempt indicator; the "
                "exploit field normally sits in the body, which access logs do not show)" % counts["upload_progress"],
                [top_ips("upload_progress")] + samples["upload_progress"])
    if counts["php_in_uploads"]:
        rep.add("MEDIUM", sec, "Successful requests to PHP files inside upload/cache-like dirs: %d (possible "
                "webshell use)" % counts["php_in_uploads"],
                [top_ips("php_in_uploads")] + samples["php_in_uploads"])
    if counts["post500"]:
        worst = ipc["post500"].most_common(1)[0][1]
        rep.add("MEDIUM" if worst >= 10 else "LOW", sec,
                "POST requests answered with HTTP 5xx: %d (a crashing worker is a typical exploit side effect; "
                "also normal app errors)" % counts["post500"], [top_ips("post500")] + samples["post500"])
    if counts["emptyua"]:
        rep.add("LOW", sec, "POST requests with empty/very short User-Agent: %d" % counts["emptyua"],
                [top_ips("emptyua")] + samples["emptyua"])
    if counts["phpsessid_url"]:
        rep.add("LOW", sec, "GET/other requests with PHPSESSID in the URL: %d" % counts["phpsessid_url"],
                [top_ips("phpsessid_url")] + samples["phpsessid_url"])
    big = [(k, v) for k, v in burst.items() if v >= args.burst]
    if big:
        big.sort(key=lambda kv: -kv[1])
        lines = ["%s: %d POSTs in one minute (%s)" % (k[0], v, time.strftime("%Y-%m-%d %H:%M", time.localtime(k[1] * 60)))
                 for k, v in big[:15]]
        rep.add("MEDIUM", sec, "POST bursts >= %d per minute from one IP (brute-force/ASLR guessing or "
                "scanning)" % args.burst, lines)
    if not any(counts[c] for c in counts) and not big:
        rep.add("INFO", sec, "No suspicious patterns found in the parsed access-log range "
                "(does not prove the absence of attacks)")


ERR_TS = [
    (re.compile(r"^\[\w{3} (\w{3} +\d+ \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]"), "%b %d %H:%M:%S %Y", True),
    (re.compile(r"^\[(\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})"), "%d-%b-%Y %H:%M:%S", False),
    (re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"), "%Y/%m/%d %H:%M:%S", False),
    (re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S", True),
]
ERR_PATTERNS = [
    ("oom_unknown", "MEDIUM", re.compile(r"(Allowed memory size of \d+ bytes exhausted|Out of memory).*in Unknown on line 0", re.I)),
    ("fatal_unknown", "MEDIUM", re.compile(r"PHP Fatal error:.*in Unknown on line 0")),
    ("child_signal", "MEDIUM", re.compile(r"AH00052|exited on signal (4|6|7|8|11)\b|exit signal (Segmentation|Aborted|Bus)|"
                                          r"SIGSEGV|SIGABRT|segmentation fault", re.I)),
    ("segfault_sys", "MEDIUM", re.compile(r"(php-fpm|php-cgi|php\d|apache2|httpd|lsphp)\S*\[\d+\]: segfault at", re.I)),
    ("oom", "LOW", re.compile(r"Allowed memory size of \d+ bytes exhausted|Out of memory|Cannot allocate memory", re.I)),
    ("maxexec", "LOW", re.compile(r"Maximum execution time of \d+ seconds? exceeded")),
]
ERR_TITLES = {
    "oom_unknown": "Memory exhaustion reported 'in Unknown on line 0' (outside normal script execution; reported "
                   "PHP2Shell signature)",
    "fatal_unknown": "PHP fatal errors 'in Unknown on line 0' (reported PHP2Shell signature)",
    "child_signal": "Worker/child processes killed by a crash signal (Apache AH00052, FPM exited on signal)",
    "segfault_sys": "Kernel/syslog segfaults in PHP or web server processes",
    "oom": "Memory exhaustion errors (common in normal operation too)",
    "maxexec": "Maximum execution time errors (common in normal operation too)",
}


def err_ts(line):
    for rx, fmt_, join in ERR_TS:
        m = rx.match(line)
        if m:
            try:
                s = " ".join(m.groups()) if join else m.group(1)
                return time.mktime(dt.datetime.strptime(s, fmt_).timetuple())
            except Exception:
                return None
    return None


def check_error_logs(rep, args, since_ts):
    sec = "6b. Logs: error / syslog"
    files = log_files(ERROR_GLOBS + args.error_log, since_ts)
    if not files:
        rep.add("LOW", sec, "No PHP/web error logs found in the usual locations; pass --error-log '/path/*.log*'")
        return
    counts = Counter()
    samples = defaultdict(list)
    for path in files:
        try:
            fh = open_log(path)
        except Exception:
            continue
        with fh:
            try:
                for line in fh:
                    for name, sev, rx in ERR_PATTERNS:
                        if rx.search(line):
                            ts = err_ts(line)
                            if ts is not None and ts < since_ts:
                                break
                            counts[name] += 1
                            if len(samples[name]) < 25:
                                samples[name].append("%s: %s" % (os.path.basename(path), trunc(line.strip(), 240)))
                            break
            except Exception:
                continue
    rep.add("INFO", sec, "Read %d error/syslog files" % len(files), files[:12])
    shown = False
    for name, sev, _ in ERR_PATTERNS:
        if counts[name]:
            shown = True
            s = sev
            if name == "child_signal" and counts[name] < 3:
                s = "LOW"
            rep.add(s, sec, "%s: %d" % (ERR_TITLES[name], counts[name]), samples[name])
    if not shown:
        rep.add("INFO", sec, "No matching error-log patterns in range")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="Local read-only checker for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)")
    ap.add_argument("--since", default=DEFAULT_SINCE,
                    help="start date YYYY-MM-DD (local time); default %s, the earliest reported attempt" % DEFAULT_SINCE)
    ap.add_argument("--webroot", action="append", default=[], help="extra web root to scan (repeatable)")
    ap.add_argument("--access-log", action="append", default=[], help="extra access log glob (repeatable)")
    ap.add_argument("--error-log", action="append", default=[], help="extra error log glob (repeatable)")
    ap.add_argument("--skip-files", action="store_true", help="skip file/webshell scan")
    ap.add_argument("--skip-logs", action="store_true", help="skip log scan")
    ap.add_argument("--skip-procs", action="store_true", help="skip process/persistence checks")
    ap.add_argument("--max-files", type=int, default=400000, help="max files to walk in web roots")
    ap.add_argument("--burst", type=int, default=60, help="POSTs per minute per IP to flag as a burst")
    ap.add_argument("--sample", type=int, default=12, help="detail lines per finding on screen")
    ap.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    ap.add_argument("--no-color", action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
    try:
        since = dt.datetime.strptime(args.since, "%Y-%m-%d")
    except ValueError:
        print("--since must be YYYY-MM-DD", file=sys.stderr)
        return 3
    since_ts = time.mktime(since.timetuple())
    rep = Report(sys.stdout.isatty() and not args.no_color)

    print("php2shell_check - CVE-2026-109618 / CVE-2026-109619")
    print("host=%s  user=%s  time=%s  since=%s" % (socket.gethostname(), uname(os.geteuid()),
                                                  time.strftime("%Y-%m-%d %H:%M"), args.since))
    if not sys.platform.startswith("linux"):
        print("This checker supports Linux only.", file=sys.stderr)
        return 3
    if os.geteuid() != 0:
        rep.add("MEDIUM", "0. Notes", "Not running as root: logs, /proc of other users and many files will be "
                "unreadable, so results are incomplete. Re-run with sudo.")

    state = safe(rep, "1. PHP versions", check_php, rep) or {"vulnerable": False, "found": False, "fpm_bins": []}
    pool_users = safe(rep, "2. PHP configuration", check_config, rep, state["vulnerable"], state) or set()
    web_users = set()
    if not args.skip_procs:
        web_users = safe(rep, "3. Processes and connections", check_processes, rep) or set()
    if not args.skip_files:
        safe(rep, "4. Files", check_files, rep, args, since_ts, web_users | pool_users)
    if not args.skip_procs:
        safe(rep, "5. Persistence and system changes", check_persistence, rep, since_ts, web_users, pool_users)
    if not args.skip_logs:
        safe(rep, "6. Logs: access", check_access_logs, rep, args, since_ts)
        safe(rep, "6b. Logs: error / syslog", check_error_logs, rep, args, since_ts)

    rep.print(args.sample)
    c = rep.counts()
    print("\n== Summary ==")
    print("HIGH=%d  MEDIUM=%d  LOW=%d  INFO=%d" % (c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
    print("Updating PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) and restarting all workers is the only complete fix.")
    print("No findings does NOT prove the host was not attacked: access logs have no request bodies, and memory\n"
          "disclosure or file reads leave no files. If the host was exposed, rotate secrets PHP could read.")
    if args.json:
        try:
            with open(args.json, "w") as f:
                json.dump({"host": socket.gethostname(), "since": args.since, "summary": c, "items": rep.items},
                          f, indent=2)
            print("JSON report written to %s" % args.json)
        except Exception as e:  # noqa
            print("Could not write JSON: %s" % e, file=sys.stderr)
    return 2 if rep.worst() >= 3 else (1 if rep.worst() == 2 else 0)


if __name__ == "__main__":
    sys.exit(main())
