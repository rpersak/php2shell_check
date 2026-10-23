#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_check.py - all-in-one LOCAL checker for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619) and the related session upload progress
issue CVE-2026-115560 (PHP informational advisory of 2026-10-23).

Version 2.4.0 (2026-10-23)

Changelog
  2.4.0  2026-10-23  CVE-2026-115560: session.serialize_handler is read from php.ini, FPM pools, Apache,
                     .htaccess and .user.ini; every PHP file in the web roots is searched for
                     ini_set('session.serialize_handler', ...); a combined verdict (config + code + upload
                     progress) is reported in step 4; step 1 notes that no fixed release exists yet.
  2.3.1  2026-10-22  Header changelog: corrected the release date of 1.0.0.
  2.3.0  2026-10-22  Ideas from php2shell-triage.sh (Laravel/Forge) plus gaps found while comparing: framework
                     aware scan (PHP where Laravel/Symfony/Drupal/WordPress never keep PHP, any date), git
                     status against the committed code, deployment noise summarised, log paths taken from
                     nginx/Apache/php.ini/FPM configs and application logs, 'access_log off' warning, top POST
                     targets, OOM clusters escalated, SSH login summary, cron spools and all authorized_keys
                     watched, connections owned by children of web processes, secrets-rotation hint.
  2.2.0  2026-10-22  Date handling hardened: never crashes on forged/huge timestamps (fts), locale-independent
                     month parsing, ISO-8601 and JSON (Caddy/nginx) access logs, syslog lines without a year,
                     continuation lines inherit the previous timestamp, warning when a log format is not
                     recognised, --since accepts YYYY-MM-DD / DD.MM.YYYY / 'YYYY-MM-DD HH:MM' and rejects
                     ambiguous layouts, future file mtimes flagged (ctime used for the cutoff).
  2.1.0  2026-10-22  Step 5 also reads shell history files (bash/zsh) of all accounts: reverse shells,
                     download-and-run, decode-and-run, temp-dir execution, history tampering, PoC markers;
                     a history file on a web account is flagged by itself; secrets are masked on screen.
  2.0.0  2026-10-22  Live English narration of every step (plan, WHAT/WHY/FLAGGED banners, sub-action
                     echo, per-step result, checklist); --quiet; scope and environment detection
                     (OS, package manager, container, panels); Alpine (apk) and cPanel EA-PHP support;
                     --version flag; script version in output and JSON.
  1.0.0  2026-10-22  First all-in-one checker (versions, config, processes, files, persistence, logs).

Read-only: it never changes files, never sends traffic, never exploits anything.
Python 3.6+, standard library only. Linux. Run as root for full visibility:

    sudo python3 php2shell_check.py
    sudo python3 php2shell_check.py --since 2026-10-17 --json report.json
    sudo python3 php2shell_check.py --webroot /srv/app --access-log '/data/logs/*.log*'
    sudo python3 php2shell_check.py --quiet          # only the final report, no step narration

The script narrates everything it does: a plan at the start, a banner for every
step (what it does, why, what gets flagged), live "> ..." lines for every
sub-action, a result line per step, then the full findings and a checklist.

Suitable systems (the script also prints this, plus what it detected, at start)
  SUPPORTED : Linux (Debian/Ubuntu, RHEL/Alma/Rocky/CentOS/Fedora/Amazon Linux, SUSE) on bare metal,
              VM or LXC; also INSIDE a Docker/Podman container (run it in the container).
              Web stack: nginx, Apache (mod_php), LiteSpeed, Caddy, lighttpd, FrankenPHP with
              PHP-FPM / CGI / mod_php. Plesk, cPanel, Hestia, DirectAdmin: works, paths partly covered.
  LIMITED   : Alpine (apk: version check only, no changelog/backport check), Docker/K8s HOST (cannot
              see inside images: run it in each container or check image tags), non-standard log
              or webroot paths (use --webroot / --access-log / --error-log).
  NOT FOR   : Windows (IIS, XAMPP, WAMP), macOS, *BSD, shared hosting without shell access, managed
              PaaS (use the provider's advisory instead).

Steps
  1. PHP versions and patch status (fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35,
     distro backports detected through package changelogs)
  2. PHP configuration (interim mitigations from the PHP advisory)
  3. Running processes and network connections
  4. Web root files, webshells and temp directories
  5. Persistence and system changes
  6. Access logs
  7. Error logs and syslog

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
import calendar
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
import textwrap
import time
from collections import Counter, defaultdict

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------
FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
CVE_RE = re.compile(r"CVE-2026-10961[89]")
__version__ = "2.4.0"
VERSION_DATE = "2026-10-23"
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

# CVE-2026-115560 (PHP informational advisory 2026-10-23): an RCE path needs ALL of
#   1. session.serialize_handler = php_binary or php_serialize in the configuration,
#   2. application code switching it to 'php' with ini_set() before session_start(),
#   3. session.upload_progress.enabled still on.
# No fixed release exists yet; PHP will fix it in the next regular release. Fill in the fixed versions here
# (same layout as FIXED) once PHP publishes the full advisory.
FIXED_115560 = {}
RISKY_HANDLERS = ("php_binary", "php_serialize")
SH_SET_PHP_RE = re.compile(rb"ini_set\s*\(\s*['\"]session\.serialize_handler['\"]\s*,\s*['\"]php['\"]\s*\)", re.I)
SH_SET_ANY_RE = re.compile(rb"ini_set\s*\(\s*['\"]session\.serialize_handler['\"]\s*,", re.I)
SH_CFG_RE = re.compile(rb"session\.serialize_handler['\"]?\s*[=\s]\s*['\"]?(php_binary|php_serialize|php)\b", re.I)
SESSION_START_RE = re.compile(rb"\bsession_start\s*\(")
# filled by step 2, used by the combined CVE-2026-115560 verdict in step 4
SERIAL_STATE = {"config": [], "upload_on": [], "upload_off": [], "found_config": False}

APP_ROOTS = []  # filled by step 4, reused by step 7 to find application logs
STD_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636, 853, 993, 995, 1194, 3306, 5432,
             6379, 9200, 11211, 27017, 51820}

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
# narration helpers (everything the script does is echoed, unless --quiet)
# --------------------------------------------------------------------------
QUIET = False
WIDTH = 100


def say(msg, level=1):
    """Echo one sub-action line, e.g. '  > Reading /proc ...'."""
    if QUIET:
        return
    prefix = "  " * level + "> "
    print(textwrap.fill(msg, width=WIDTH, initial_indent=prefix,
                        subsequent_indent=" " * len(prefix), break_long_words=False,
                        break_on_hyphens=False))
    sys.stdout.flush()


def labelled(label, text):
    lab = "  %-14s: " % label
    return textwrap.fill(text, width=WIDTH, initial_indent=lab, subsequent_indent=" " * len(lab),
                         break_long_words=False, break_on_hyphens=False)


def banner(num, total, title, what, why, flagged):
    if QUIET:
        return
    print("\n" + "=" * 78)
    print("[STEP %d/%d] %s" % (num, total, title))
    print(labelled("WHAT IT DOES", what))
    print(labelled("WHY", why))
    print(labelled("FLAGGED WHEN", flagged))
    print("-" * 78)
    sys.stdout.flush()


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

    def tag(self, sev):
        t = "[%s]" % sev
        return COLORS[sev] + t + RESET if self.color else t

    def print(self, sample):
        for sec in self.sections:
            print("\n== %s ==" % sec)
            for it in [i for i in self.items if i["section"] == sec]:
                print("%s %s" % (self.tag(it["severity"]), it["title"]))
                d = it["details"]
                for line in d[:sample]:
                    print("      " + line)
                if len(d) > sample:
                    print("      ... (+%d more, see --json)" % (len(d) - sample))


def run(cmd, timeout=25, env=None):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, universal_newlines=True, env=env)
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


NOW = time.time()


def fts(ts):
    """Epoch seconds -> 'YYYY-MM-DD HH:MM' in host local time. Never raises: a forged or corrupt timestamp
    (huge, negative, NaN) would otherwise abort a whole step. Output is numeric ISO order, so no locale effects."""
    if ts is None or isinstance(ts, bool):
        return "n/a"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
    except (OverflowError, OSError, ValueError, TypeError):
        return "invalid time (%r)" % (ts,)


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
        say("this step hit an unexpected error and was skipped: %s: %s" % (type(e).__name__, e))
        return None


def is_web(comm):
    return any(comm.startswith(p) for p in WEB_PREFIXES)


# --------------------------------------------------------------------------
# 0. environment and scope
# --------------------------------------------------------------------------
SCOPE_TEXT = [
    ("SUPPORTED", "Linux (Debian/Ubuntu, RHEL/Alma/Rocky/CentOS/Fedora/Amazon Linux, SUSE) on bare metal, VM or "
                  "LXC, and INSIDE a Docker/Podman container (run the script in the container). Web stacks: nginx, "
                  "Apache (mod_php), LiteSpeed, Caddy, lighttpd, FrankenPHP with PHP-FPM / CGI / mod_php. "
                  "Plesk, cPanel, Hestia and DirectAdmin work; their paths are only partly covered."),
    ("LIMITED", "Alpine (version check only, no changelog/backport check); a Docker/Kubernetes HOST cannot see "
                "inside images (run the script in each container or check the image tags); non-standard "
                "web root or log paths (use --webroot / --access-log / --error-log)."),
    ("NOT FOR", "Windows (IIS, XAMPP, WAMP), macOS, *BSD, shared hosting without shell access, managed PaaS "
                "(use the provider's advisory)."),
]


def os_release():
    d = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            d[k] = v.strip().strip('"')
    return d


def check_environment(rep):
    sec = "0. Environment and scope"
    osr = os_release()
    name = osr.get("PRETTY_NAME") or osr.get("NAME") or "unknown Linux"
    mgr = [m for m in ("dpkg", "rpm", "apk") if shutil.which(m)]
    cont = ""
    try:
        cg = read_text("/proc/1/cgroup")
        if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv") or \
                re.search(r"docker|kubepods|containerd|libpod|lxc", cg):
            cont = "container (Docker/Podman/LXC/Kubernetes)"
    except Exception:
        pass
    panels = [n for n, pth in (("Plesk", "/usr/local/psa"), ("cPanel", "/usr/local/cpanel"),
                               ("DirectAdmin", "/usr/local/directadmin"), ("HestiaCP", "/usr/local/hestia"),
                               ("LiteSpeed", "/usr/local/lsws")) if os.path.isdir(pth)]
    id_all = (osr.get("ID", "") + " " + osr.get("ID_LIKE", "")).lower()
    supported = bool(re.search(r"debian|ubuntu|rhel|fedora|centos|rocky|alma|amzn|suse|sles", id_all))
    limited = "alpine" in id_all
    verdict = "SUPPORTED" if supported else ("LIMITED" if limited else "UNKNOWN")
    say("Reading /etc/os-release, checking for dpkg/rpm/apk, container markers and hosting panels ...")
    say("Operating system : %s" % name)
    say("Package manager  : %s" % (", ".join(mgr) or "none found (only version numbers can be judged)"))
    say("Running inside   : %s" % (cont or "no container detected (bare metal or VM)"))
    say("Hosting panels   : %s" % (", ".join(panels) or "none detected"))
    say("Python           : %s" % sys.version.split()[0])
    say("Suitability      : %s for this script" % verdict)
    if cont:
        say("Inside a container only THIS container is checked, not the host or other containers.")
    if verdict == "UNKNOWN":
        say("This distribution is not one the script was tested on; results may be incomplete.")
    sev = "INFO" if verdict != "UNKNOWN" else "LOW"
    rep.add(sev, sec, "Environment: %s; package manager: %s; %s; panels: %s; suitability: %s" %
            (name, ", ".join(mgr) or "none", cont or "no container", ", ".join(panels) or "none", verdict),
            ["%s: %s" % (k, v) for k, v in SCOPE_TEXT])
    if limited:
        rep.add("INFO", sec, "Alpine: PHP version is checked, but distro backports cannot be detected "
                "(no changelog check), so a patched backport may be reported as vulnerable")
    return verdict


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
                "/opt/cpanel/ea-php*/root/usr/bin/php*", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm*",
                "/opt/plesk/php/*/bin/php*", "/opt/plesk/php/*/sbin/php-fpm*",
                "/usr/local/php*/bin/php*", "/usr/local/lsws/lsphp*/bin/lsphp"]
    for pat in patterns:
        cands.extend(glob.glob(pat))
    ok = re.compile(r"^(lsphp|php(-cgi|-fpm)?)[0-9.]*$")
    out = []
    for p in uniq_real(cands):
        if ok.match(os.path.basename(p)) and os.access(p, os.X_OK):
            out.append(p)
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
    if shutil.which("apk"):
        rc, out = run(["apk", "info", "-W", real])
        m = re.search(r"owned by (\S+)", out)
        if rc == 0 and m:
            return re.sub(r"-\d.*$", "", m.group(1)), "apk"
    return None, None


def pkg_version(pkg, mgr):
    if mgr == "apk":
        return ""
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
    say("Searching standard locations for PHP executables (php, php-cgi, php-fpm, lsphp, Remi/Plesk/Docker-style paths) ...")
    bins = find_php_binaries()
    say("Found %d PHP executable(s)%s" % (len(bins), ": " + ", ".join(bins) if bins else ""))
    for b in bins:
        say("Running '%s -v' to read the exact PHP version" % b)
        v = php_version(b)
        if not v:
            say("no PHP version could be read from this file, skipping it", 2)
            continue
        say("version is %s" % fmt(v), 2)
        state["found"] = True
        say("Asking the package manager (dpkg/rpm) which package owns this file ...", 2)
        pkg, mgr = pkg_owner(b)
        if pkg:
            say("owned by package '%s' (%s)" % (pkg, mgr), 2)
            say("Searching that package's changelog for %s / %s (a distro can backport the fix without "
                "changing the version number) ..." % CVE_IDS, 2)
            fixes = changelog_cves(pkg, mgr)
            say("changelog mentions: %s" % (", ".join(sorted(fixes)) if fixes else "neither CVE"), 2)
        else:
            fixes = set()
            say("not owned by a distro package (self-compiled, Docker image or vendor build), so only the "
                "version number can be judged", 2)
        sev, text = assess(v, fixes)
        say("verdict: [%s] %s" % (sev, text), 2)
        if SEV_RANK[sev] >= SEV_RANK["MEDIUM"]:
            state["vulnerable"] = True
        base = os.path.basename(b)
        if base.startswith(("php-fpm", "php-cgi", "lsphp")):
            state["fpm_bins"].append(b)
        src = "package %s %s" % (pkg, pkg_version(pkg, mgr)) if pkg else "not from a distro package"
        rep.add(sev, sec, "%s: %s" % (b, text), ["source: " + src])

    say("Searching for Apache mod_php modules (libphp*.so) ...")
    mods = []
    for pat in ("/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
                "/usr/lib/httpd/modules/libphp*.so", "/opt/remi/php*/root/usr/lib64/httpd/modules/libphp*.so"):
        mods.extend(glob.glob(pat))
    mods = uniq_real(mods)
    say("Found %d mod_php module(s)%s" % (len(mods), ": " + ", ".join(mods) if mods else ""))
    for m in mods:
        state["found"] = True
        say("Checking owner package and changelog of %s ..." % m, 2)
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
        say("package '%s' version '%s' -> [%s] %s" % (pkg, pv, sev, text), 2)
        if SEV_RANK[sev] >= SEV_RANK["MEDIUM"]:
            state["vulnerable"] = True
        rep.add(sev, sec, "mod_php %s: %s" % (m, text),
                ["source: package %s %s" % (pkg, pv)] if pkg else [])

    if not state["found"]:
        rep.add("INFO", sec, "No PHP binaries or mod_php modules found on this host")
        say("No PHP found on this host.")
    say("Note: containers and other hosts are NOT inspected by this step (check the image tag or run the "
        "script inside the container).")
    if FIXED_115560:
        say("CVE-2026-115560: fixed releases are known (%s); compare the versions above" %
            " / ".join(fmt(x) for x in FIXED_115560.values()))
    else:
        say("CVE-2026-115560 (PHP advisory of 23 Oct 2026): no fixed PHP release exists yet, so the version alone "
            "cannot clear it. Whether the vulnerable combination exists is checked in step 2 (configuration) and "
            "step 4 (application code).")
    rep.add("INFO", sec, "CVE-2026-115560: %s. Mitigation until then: session.upload_progress.enabled=0 in php.ini "
            "or the FPM pool (not via ini_set or .user.ini)." %
            ("fixed in " + " / ".join(fmt(x) for x in FIXED_115560.values()) if FIXED_115560 else
             "no fixed PHP release yet (PHP fixes it in the next regular release); exposure depends on configuration "
             "and application code, see steps 2 and 4"))
    rep.add("INFO", sec, "Containers and other hosts are NOT inspected here. Run the check inside each "
            "container image or check the image tag (fixed: %s)." % " / ".join(fmt(x) for x in FIXED.values()))
    return state


# --------------------------------------------------------------------------
# 2. configuration
# --------------------------------------------------------------------------
INI_KEYS = ("session.upload_progress.enabled", "session.serialize_handler", "memory_limit", "post_max_size", "upload_max_filesize",
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
    say("Looking for php.ini, conf.d/*.ini and PHP-FPM pool files (Debian/Ubuntu, RHEL, Remi and Docker layouts) ...")
    fams = ini_families()
    say("Found %d configuration set(s)%s" % (len(fams), ": " + "; ".join(f[0] for f in fams) if fams else ""))
    if not fams:
        rep.add("INFO", sec, "No php.ini / pool configuration found in the usual locations")
        say("Nothing to evaluate here (PHP not installed, or config lives in a non-standard place).")
    hint = "MEDIUM" if vulnerable else "LOW"
    if vulnerable:
        say("PHP in step 1 was judged vulnerable, so missing mitigations will be reported as MEDIUM.")
    else:
        say("PHP in step 1 was not judged vulnerable, so config findings are informational/low.")
    for label, files, pool_files in fams:
        say("Reading %d ini file(s) and %d pool file(s) for '%s' ..." %
            (len([f for f in files if os.path.isfile(f)]), len([f for f in pool_files if os.path.isfile(f)]), label))
        eff = parse_ini(files)
        pools, users = parse_pools(pool_files)
        pool_users |= users
        up_val = eff.get("session.upload_progress.enabled", ("1 (PHP default)", None))[0]
        say("session.upload_progress.enabled in ini = %s  (the PHP2Shell upload path; advisory says to set 0)" % up_val, 2)
        summary = ["%s=%s" % (k, eff[k][0]) for k in INI_KEYS if k in eff]
        if summary:
            say("other tracked ini values: " + ", ".join(summary), 2)
        det = ["config files: " + ", ".join(sorted({v[1] for v in eff.values()})[:4]) if eff else
               "no explicit settings of the tracked keys found (PHP defaults apply)"]
        if summary:
            det.append("effective ini: " + ", ".join(summary))
        up_on = str(up_val).split()[0].lower() not in FALSE_VALUES

        if pools:
            say("Checking each FPM pool for overrides (php_admin_value = enforced, php_value = app can "
                "override) and pm.max_requests ...", 2)
        on_pools, mem_not_admin, php_value_mem, no_maxreq = [], [], [], []
        SERIAL_STATE["found_config"] = True
        sh_global = str(eff.get("session.serialize_handler", ("php",))[0]).lower()
        say("session.serialize_handler in ini = %s  (CVE-2026-115560 needs php_binary or php_serialize here plus "
            "a runtime switch to 'php' in the code)" % (sh_global if "session.serialize_handler" in eff
                                                        else "php (PHP default)"), 2)
        sh_risky = []
        for (pname, pfile), info in pools.items():
            pool_up = None
            pool_sh = None
            mem_admin = False
            for kind, key, val in info["overrides"]:
                if key == "session.serialize_handler":
                    pool_sh = val.strip('"').lower()
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
            where = "%s pool [%s]" % (label, pname)
            (SERIAL_STATE["upload_on"] if eff_up else SERIAL_STATE["upload_off"]).append(where)
            if (pool_sh or sh_global) in RISKY_HANDLERS:
                sh_risky.append((where, pool_sh or sh_global, eff_up))
            if not mem_admin:
                mem_not_admin.append(pname)
            if not info["max_requests"] or info["max_requests"] > 1:
                no_maxreq.append(pname)
            say("pool [%s]: upload_progress %s, memory_limit=-1 enforced: %s, pm.max_requests=%s" %
                (pname, "ON" if eff_up else "off", "yes" if mem_admin else "no", info["max_requests"]), 3)
        if not pools:
            (SERIAL_STATE["upload_on"] if up_on else SERIAL_STATE["upload_off"]).append(label)
            if sh_global in RISKY_HANDLERS:
                sh_risky.append((label, sh_global, up_on))
        for where, handler, upl in sh_risky:
            SERIAL_STATE["config"].append({"where": where, "handler": handler, "upload": upl})
            say("%s: session.serialize_handler=%s with upload_progress %s -> CVE-2026-115560 configuration "
                "precondition %s" % (where, handler, "ON" if upl else "off",
                                     "PRESENT (code is checked in step 4)" if upl else "present but mitigated"), 3)
        if sh_risky:
            on = [w for w, h, u in sh_risky if u]
            if on:
                rep.add("LOW", sec, "%s: session.serialize_handler is php_binary/php_serialize with upload progress ON "
                        "(1 of 3 CVE-2026-115560 preconditions; step 4 checks the application code for the runtime "
                        "switch)" % label, ["%s: %s" % (w, h) for w, h, u in sh_risky if u])
            else:
                rep.add("INFO", sec, "%s: session.serialize_handler is php_binary/php_serialize, but upload progress "
                        "is off, so CVE-2026-115560 is mitigated" % label, ["%s: %s" % (w, h) for w, h, u in sh_risky])
        if pools:
            det.append("FPM pools: %d (%s)" % (len(pools), ", ".join(sorted({p[0] for p in pools})[:8])))
        if "apache2" in label:
            det.append("mod_php: set values in php.ini or Apache config with php_admin_value, then restart Apache")

        sev = hint if (up_on and not pools) or on_pools else "INFO"
        title = "%s: session.upload_progress.enabled is %s" % (label, "ON" if (up_on or on_pools) else "off")
        if up_on or on_pools:
            title += " (advisory mitigation: set it to 0 in php.ini/pool; advice is to keep it off even after patching)"
        if on_pools and pools:
            det.append("pools with upload_progress still on: " + ", ".join(on_pools[:10]))
        say("verdict for '%s': [%s] upload_progress is %s" % (label, sev, "ON" if (up_on or on_pools) else "off"), 2)
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
                say("interim mitigations from the PHP advisory are not (fully) applied for '%s'" % label, 2)
                rep.add("MEDIUM", sec, "%s: interim mitigations from the PHP advisory not (fully) applied; "
                        "these only reduce exposure, updating is the only complete fix" % label, extra)

    say("Scanning Apache configs (/etc/apache2, /etc/httpd) for php_admin_value/php_value overrides of "
        "memory_limit, upload_progress or serialize_handler ...")
    hits = []
    for pat in ("/etc/apache2/**/*.conf", "/etc/httpd/**/*.conf"):
        for f in glob.glob(pat, recursive=True):
            for ln, line in enumerate(read_text(f).splitlines(), 1):
                if re.search(r"^\s*php_(admin_)?(value|flag)\s+(memory_limit|session\.upload_progress|"
                             r"session\.serialize_handler)", line):
                    hits.append("%s:%d: %s" % (f, ln, trunc(line.strip())))
                    m = SH_CFG_RE.search(line.encode("utf-8", "replace"))
                    if m and m.group(1).decode().lower() in RISKY_HANDLERS:
                        SERIAL_STATE["config"].append({"where": "%s:%d" % (f, ln), "handler": m.group(1).decode().lower(),
                                                       "upload": None})
    say("found %d matching Apache directive(s)" % len(hits), 2)
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
        say("/proc is not available, skipping.")
        return set()
    say("Reading /proc to build a table of all running processes (pid, parent, name, owner) ...")
    t = proc_table()
    web = {pid for pid, p in t.items() if is_web(p["comm"])}
    web_users = {uname(t[p]["uid"]) for p in web if t[p]["uid"] != 0}
    say("%d processes found, %d of them are web/PHP processes (php-fpm, apache2, httpd, nginx, lsphp, ...)" %
        (len(t), len(web)))
    if web:
        names = Counter(t[p]["comm"] for p in web)
        say("web/PHP processes by name: " + ", ".join("%s x%d" % kv for kv in names.most_common(8)), 2)

    say("Checking whether any PHP worker still runs a binary or module that was REPLACED on disk (updating "
        "the package without restarting leaves the old, vulnerable code in memory) ...")
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
    say("result: %s" % (", ".join("%s: %d process(es)" % (k, len(v)) for k, v in stale.items())
                        if stale else "no stale PHP workers"), 2)
    for comm, pids in stale.items():
        rep.add("HIGH", sec, "%s: %d process(es) still run a replaced PHP binary/module (updated on disk but not "
                "restarted, so STILL VULNERABLE in memory). Restart the service." % (comm, len(pids)),
                ["pids: " + ", ".join(str(p) for p in sorted(pids)[:15])])

    say("Looking for shells (sh, bash, ...) and recon tools (whoami, id, nc, curl, base64, ...) that have a "
        "web/PHP process among their ancestors - the typical footprint of a webshell or RCE ...")
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
    say("result: %s" % (", ".join("%s: %d" % (k, len(v)) for k, v in susp.items()) if susp
                        else "none right now (this is only a snapshot of this moment)"), 2)
    for sev, lines in susp.items():
        titles = {"HIGH": "Shell/recon tool spawned by a web or PHP process (typical post-exploitation)",
                  "MEDIUM": "Shell spawned by a web or PHP process (can be legitimate exec()/system())",
                  "LOW": "Shell spawned by a web process for mail delivery (usually legitimate)"}
        rep.add(sev, sec, titles[sev], lines)
    if not susp:
        rep.add("INFO", sec, "No shell or recon tool currently running below a web/PHP process "
                "(only a snapshot of right now)")

    if shutil.which("ss"):
        say("Listing established TCP connections with 'ss' and sorting outbound ones to public IPs into: owned by a "
            "CHILD of a web/PHP process (reverse shell / download), owned by the web process itself, and other "
            "processes on unusual ports (attackers use these for reverse shells, downloads and exfiltration) ...")
        rc, lis = run(["ss", "-H", "-tln"])
        listen_ports = set()
        for ln in lis.splitlines():
            parts = ln.split()
            if len(parts) >= 4:
                listen_ports.add(parts[3].rsplit(":", 1)[-1])
        rc, out = run(["ss", "-H", "-tnp"])
        conns, spawned, unusual = [], [], []
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) < 6 or parts[0] != "ESTAB":
                continue
            local, peer, proc = parts[3], parts[4], " ".join(parts[5:])
            lport = local.rsplit(":", 1)[-1]
            if lport in listen_ports:
                continue
            ip = peer.rsplit(":", 1)[0].strip("[]")
            if re.match(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80|fd|169\.254\.)", ip):
                continue
            from_web = bool(re.search(r'"(php|apache2|httpd|nginx|lsphp|frankenphp|caddy)', proc))
            child_of_web = False
            for pid in [int(x) for x in re.findall(r"pid=(\d+)", proc)]:
                if pid in t and is_web(t[pid]["comm"]):
                    from_web = True
                    continue
                cur, depth = t.get(pid, {}).get("ppid"), 0
                while cur in t and depth < 8:
                    if is_web(t[cur]["comm"]):
                        child_of_web = True
                        break
                    cur = t[cur]["ppid"]
                    depth += 1
            line = "%s -> %s %s" % (local, peer, trunc(proc, 90))
            if child_of_web:
                spawned.append(line)
            elif from_web:
                conns.append(line)
            else:
                try:
                    rport = int(peer.rsplit(":", 1)[-1])
                except ValueError:
                    rport = 0
                if rport not in STD_PORTS:
                    unusual.append(line)
        say("result: %d connection(s) owned by a child of a web/PHP process, %d outbound from web/PHP processes "
            "to public IPs, %d from other processes to public IPs on unusual ports" %
            (len(spawned), len(conns), len(unusual)), 2)
        if spawned:
            rep.add("HIGH", sec, "Network connection owned by a process STARTED BY a web/PHP process (typical "
                    "reverse shell, payload download or exfiltration)", spawned)
        if conns:
            rep.add("LOW", sec, "Outbound connections from web/PHP processes to public IPs "
                    "(often legitimate API calls; review unknown peers)", conns)
        if unusual:
            rep.add("LOW", sec, "Outbound connections from other processes to public IPs on unusual ports "
                    "(monitoring agents, VPNs and databases are common; review unknown peers)", unusual)
    else:
        say("'ss' is not installed, skipping the connection check.")
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


def find_app_root(root):
    """Walk up (max 3 levels) from a web root to the project root of a known framework.
    Returns (app_root, framework) or (None, None). Handles docroots like <app>/current/public."""
    cur = root
    for _ in range(4):
        for rel, fw in (("artisan", "laravel"), ("bin/console", "symfony"), ("core/lib/Drupal.php", "drupal"),
                        ("wp-config.php", "wordpress"), ("wp-includes/version.php", "wordpress")):
            if os.path.isfile(os.path.join(cur, rel)):
                if fw == "symfony" and not os.path.isfile(os.path.join(cur, "public", "index.php")):
                    continue
                return cur, fw
        parent = os.path.dirname(cur)
        if parent == cur or parent in ("/", "/var", "/home", "/srv", "/opt", "/usr", "/etc"):
            break
        cur = parent
    return None, None


def in_no_php_zone(fw, rel):
    """True if a PHP file at this path (relative to the project root) does not belong there for the framework."""
    r = rel.replace(os.sep, "/")
    if r.startswith("./"):
        r = r[2:]
    if fw == "laravel":
        if r.startswith("public/"):
            return r != "public/index.php"
        if r.startswith("storage/"):
            return not (r.startswith("storage/framework/views/") or r == "storage/framework/maintenance.php")
    elif fw == "symfony":
        return r.startswith("public/") and r != "public/index.php"
    elif fw == "drupal":
        return bool(re.match(r"^sites/[^/]+/files/", r)) and "/files/php/" not in r
    elif fw == "wordpress":
        return r.startswith("wp-content/uploads/")
    return False


ZONE_TEXT = {"laravel": "public/ (except index.php) and storage/ (except compiled views)",
             "symfony": "public/ (except index.php)", "drupal": "sites/*/files/ (except compiled templates)",
             "wordpress": "wp-content/uploads/"}


def git_dirty(path):
    """Read-only 'git status'. GIT_OPTIONAL_LOCKS=0 stops git from refreshing (writing) the index."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    rc, out = run(["git", "-c", "safe.directory=*", "-C", path, "status", "--porcelain",
                   "--untracked-files=normal"], timeout=45, env=env)
    if rc != 0:
        return None, out.strip().splitlines()[:1]
    keep = []
    for ln in out.splitlines():
        f = ln[3:].strip().strip('"')
        if re.search(r"(^|/)\.env($|\.)|(^|/)storage/|(^|/)bootstrap/cache/|(^|/)node_modules/", f):
            continue
        keep.append(ln.rstrip())
    return keep, []


def assess_115560(rep, sec, sh_code, sh_dir, php_files, limit_hit):
    """Combine configuration (step 2), per-directory files and code (step 4) into one CVE-2026-115560 verdict."""
    say("CVE-2026-115560 verdict: combining the configuration from step 2 with what was found in the code ...")
    cfg = [c for c in SERIAL_STATE["config"]]
    cfg += [{"where": p, "handler": h, "upload": None} for p, h in sh_dir if h in RISKY_HANDLERS]
    up_on, up_off = SERIAL_STATE["upload_on"], SERIAL_STATE["upload_off"]
    if not SERIAL_STATE["found_config"]:
        upload = "unknown (no php.ini/pool found; PHP default is ON)"
        upload_on = True
    elif up_on:
        upload = "ON in %d place(s)" % len(up_on)
        upload_on = True
    else:
        upload = "off everywhere it was checked"
        upload_on = False
    to_php, other = sh_code.get("php", []), sh_code.get("other", [])
    say("1) risky serialize_handler in configuration: %d place(s); 2) runtime switch to 'php' in code: %d file(s) "
        "(+%d other runtime changes); 3) upload progress: %s" % (len(cfg), len(to_php), len(other), upload), 2)
    detail = ["config: %s = %s" % (c["where"], c["handler"]) for c in cfg]
    detail += ["code: " + x for x in to_php] + ["code (other value): " + x for x in other]
    if up_on:
        detail.append("upload progress ON in: " + ", ".join(up_on[:8]))
    caveat = ("Mapping a config to an application is approximate: check that the flagged code runs under the "
              "flagged configuration and that ini_set() is executed before session_start().")
    if to_php and not upload_on:
        rep.add("INFO", sec, "CVE-2026-115560: code switches session.serialize_handler to 'php' at runtime, but upload "
                "progress is off - mitigated (keep it off)", detail)
    elif to_php and cfg:
        rep.add("HIGH", sec, "CVE-2026-115560: ALL three preconditions appear on this host (risky serialize_handler in "
                "config, runtime switch to 'php' in code, upload progress on). Set session.upload_progress.enabled=0 "
                "in php.ini/the FPM pool now and restart PHP. " + caveat, detail)
    elif to_php:
        rep.add("MEDIUM", sec, "CVE-2026-115560: code switches session.serialize_handler to 'php' at runtime and upload "
                "progress is on. No php_binary/php_serialize was found in the configuration that was read, but the "
                "application may set it elsewhere (vhost, pool or panel config not scanned). Safest: "
                "session.upload_progress.enabled=0", detail)
    elif other:
        rep.add("LOW", sec, "CVE-2026-115560: code changes session.serialize_handler at runtime to a non-literal or other "
                "value; review whether it can become 'php'", detail)
    elif cfg and upload_on:
        rep.add("INFO", sec, "CVE-2026-115560: risky serialize_handler in config with upload progress on, but no "
                "runtime switch to 'php' in %d PHP file(s) scanned - the code precondition is not present in the "
                "scanned code" % php_files, detail)
    else:
        rep.add("INFO", sec, "CVE-2026-115560: vulnerable combination not found (%d PHP file(s) searched%s)" %
                (php_files, "; file limit reached, coverage incomplete" if limit_hit else ""))
    say("note: code outside the web roots, generated/obfuscated code and values built at runtime cannot be seen by "
        "a text search", 2)


def check_files(rep, args, since_ts, web_users):
    sec = "4. Files"
    say("Discovering web roots: common paths (/var/www, /srv, /home/*/public_html, ...) plus 'root' and "
        "'DocumentRoot' directives in the nginx/Apache configs, plus any --webroot you passed ...")
    roots = discover_webroots(args.webroot)
    say("Found %d web root(s)%s" % (len(roots), ": " + ", ".join(roots[:8]) + (" ..." if len(roots) > 8 else "")
                                    if roots else ""))
    if not roots:
        rep.add("LOW", sec, "No web roots found; pass --webroot /path to scan one")
    say("Looking for framework project roots (Laravel artisan, Symfony bin/console, Drupal, WordPress) at or up "
        "to 3 levels above each web root, so that e.g. <app>/current/public is scanned together with storage/ ...")
    scan_roots, fw_of = [], {}
    for r in roots:
        app, fw = find_app_root(r)
        target = app if app and (r == app or r.startswith(app.rstrip("/") + "/")) else r
        if target not in scan_roots:
            scan_roots.append(target)
            fw_of[target] = fw
    scan_roots = [r for r in scan_roots if not any(r != o and r.startswith(o.rstrip("/") + "/") for o in scan_roots)]
    APP_ROOTS[:] = scan_roots
    for r in scan_roots:
        if fw_of.get(r):
            say("%s is a %s application: PHP files in %s are flagged at ANY date (the framework never keeps "
                "PHP there)" % (r, fw_of[r], ZONE_TEXT[fw_of[r]]), 2)
    say("Walking every file (symlinks are not followed, max %d files). For each file changed since the cutoff "
        "(or sitting in an upload/cache-like folder) the content is scanned for:" % args.max_files)
    say("PHP code with eval(base64_decode(..)), system($_POST[..]), assert($_GET[..]), preg_replace /e, known "
        "webshell names (FilesMan, c99, r57, b374k, WSO) and the PoC markers php2shell/JACKALPOC", 2)
    say(".htaccess / .user.ini with auto_prepend_file, AddType php, or php_value overrides", 2)
    say("images (jpg/png/gif/...) that actually contain '<?php'", 2)
    say("recently changed executable files and any PHP file inside an uploads/cache/tmp/media-like folder", 2)
    say("PHP files in framework directories that never hold PHP (checked regardless of date)", 2)
    say("EVERY PHP file (any date) is also searched for ini_set('session.serialize_handler', ...), and every "
        ".htaccess/.user.ini for session.serialize_handler - the code and per-directory preconditions of "
        "CVE-2026-115560", 2)
    finds = defaultdict(list)
    sh_code, sh_dir = defaultdict(list), []
    php_files = 0
    scanned = 0
    recent_code = 0
    limit_hit = False
    for root in scan_roots:
        fw = fw_of.get(root)
        say("Scanning %s ..." % root, 2)
        before = scanned
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
                if st.st_mtime > NOW + 86400 and len(finds["MEDIUM"]) < 500:
                    finds["MEDIUM"].append("%s modification time is in the future (%s): possible timestamp "
                                           "manipulation (the change time ctime is used for the cutoff instead)" %
                                           (path, fts(st.st_mtime)))
                in_upload = bool(UPLOAD_RE.search(rel.replace(os.sep, "/")))
                stamp = fts(max(st.st_mtime, st.st_ctime))

                if ext in PHPEXT:
                    php_files += 1
                    if recent:
                        recent_code += 1
                    zone = bool(fw) and in_no_php_zone(fw, rel)
                    data = read_bytes(path, 2000000)
                    if b"serialize_handler" in data:
                        m = SH_SET_PHP_RE.search(data) or SH_SET_ANY_RE.search(data)
                        if m:
                            ln_no = data[:m.start()].count(b"\n") + 1
                            ss = SESSION_START_RE.search(data, m.end())
                            kind = "php" if SH_SET_PHP_RE.match(data, m.start()) else "other"
                            sh_code[kind].append("%s:%d%s" % (path, ln_no, " (session_start() follows in the same file)"
                                                              if ss else ""))
                    if recent or in_upload or zone:
                        hits = scan_content(data, WEBSHELL_PATTERNS)
                        for sev, label in hits:
                            finds[sev].append("%s [%s] %s" % (path, stamp, label))
                        if not hits and zone:
                            finds["MEDIUM"].append("%s [%s] PHP file where a %s application never keeps PHP "
                                                   "(any date; verify it is intentional)" % (path, stamp, fw))
                        elif not hits and in_upload and recent:
                            finds["MEDIUM"].append("%s [%s] PHP file in upload/cache-like directory" % (path, stamp))
                        elif not hits and recent:
                            finds["LOW"].append("%s [%s] recently changed code file" % (path, stamp))
                elif fn in (".htaccess", ".user.ini"):
                    data = read_bytes(path, 200000)
                    m = SH_CFG_RE.search(data)
                    if m:
                        sh_dir.append((path, m.group(1).decode().lower()))
                    if recent:
                        for sev, label in scan_content(data, HTACCESS_PATTERNS):
                            finds[sev].append("%s [%s] %s" % (path, stamp, label))
                elif ext in IMGEXT and recent:
                    if b"<?php" in read_bytes(path, 8192).lower():
                        finds["HIGH"].append("%s [%s] image file containing PHP code" % (path, stamp))
                elif recent and (st.st_mode & 0o111) and ext not in (".js", ".css", ".html"):
                    finds["MEDIUM"].append("%s [%s] recently changed executable file in web root" % (path, stamp))
            if limit_hit:
                break
        say("%d files looked at in this root" % (scanned - before), 3)
        if limit_hit:
            break
    if limit_hit:
        say("file limit reached; raise --max-files for complete coverage")
        rep.add("LOW", sec, "File limit reached (%d); raise --max-files for complete coverage" % args.max_files)
    say("web roots done: %d files scanned, %d code files changed since the cutoff; findings HIGH=%d MEDIUM=%d "
        "LOW=%d" % (scanned, recent_code, len(finds["HIGH"]), len(finds["MEDIUM"]), len(finds["LOW"])))
    titles = {"HIGH": "Webshell patterns / PHP hidden in files",
              "MEDIUM": "Suspicious files in web roots",
              "LOW": "Recently changed code files (legitimate updates and deployments are listed too)"}
    for sev in ("HIGH", "MEDIUM", "LOW"):
        if not finds[sev]:
            continue
        if sev == "LOW" and len(finds[sev]) > 25:
            say("%d recently changed code files without any suspicious content: this looks like a deployment or "
                "update, so they are summarised instead of listed" % len(finds[sev]))
            rep.add("INFO", sec, "%d code files changed since the cutoff (looks like a deployment/update; their "
                    "content was scanned and nothing matched). First 10:" % len(finds[sev]), finds[sev][:10])
            continue
        rep.add(sev, sec, "%s: %d finding(s)" % (titles[sev], len(finds[sev])), finds[sev])
    rep.add("INFO", sec, "Scanned %d files in %d project/web root(s): %s; %d code files changed since the cutoff" %
            (scanned, len(scan_roots), ", ".join(scan_roots[:6]) + (" ..." if len(scan_roots) > 6 else ""),
             recent_code))
    assess_115560(rep, sec, sh_code, sh_dir, php_files, limit_hit)

    if shutil.which("git"):
        say("Checking git checkouts: 'git status' (read-only, no index refresh) shows tracked files modified and "
            "untracked files compared with the committed code - the cleanest proof that code was altered ...")
        for r in scan_roots:
            top = r
            for _ in range(4):
                if os.path.isdir(os.path.join(top, ".git")):
                    break
                top = os.path.dirname(top)
            else:
                continue
            if top in ("/", ""):
                continue
            dirty, err = git_dirty(top)
            if dirty is None:
                say("git status failed in %s: %s" % (top, " ".join(err) or "unknown error"), 2)
                rep.add("LOW", sec, "git status could not be run in %s: %s" % (top, " ".join(err) or "unknown error"))
                continue
            say("%s: %d difference(s) from the committed code (ignoring .env, storage, caches)" % (top, len(dirty)), 2)
            codey = [l for l in dirty if re.search(r"\.(php\d?|phtml|phar|pht)$|(^|/)public/|\.htaccess$", l, re.I)]
            other = [l for l in dirty if l not in codey]
            if codey:
                rep.add("MEDIUM", sec, "Git checkout %s: %d PHP/public file(s) modified or untracked compared with "
                        "the repository (review each; '??' = untracked, 'M' = modified)" % (top, len(codey)), codey)
            if other:
                rep.add("LOW", sec, "Git checkout %s: %d other difference(s) from the repository" % (top, len(other)),
                        other)
            if not dirty:
                rep.add("INFO", sec, "Git checkout %s: working tree identical to the repository" % top)

    say("Scanning /tmp, /var/tmp, /dev/shm (3 levels deep) for files changed since the cutoff that are owned by "
        "a web user, executable, hidden, or ELF binaries - where attackers drop tools ...")
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
    say("result: %d suspicious file(s) in temp directories" % len(tmpf), 2)
    for sev in ("HIGH", "MEDIUM"):
        lines = [t[1] for t in tmpf if t[0] == sev]
        if lines:
            rep.add(sev, sec, "Recent suspicious files in /tmp, /var/tmp, /dev/shm: %d" % len(lines), lines)


# --------------------------------------------------------------------------
# 5. persistence
# --------------------------------------------------------------------------
HIST_FILES = (".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".history")
HIST_PATTERNS = [
    ("download and run (curl/wget piped to a shell)",
     re.compile(r"\b(curl|wget|fetch)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")),
    ("reverse shell / raw socket",
     re.compile(r"/dev/(tcp|udp)/|\b(nc|ncat|netcat)\b[^|;]*\s-[a-z]*e\b|bash\s+-i\s*>&|\bsocat\b.*exec", re.I)),
    ("decode and run (base64 piped to a shell)",
     re.compile(r"base64\s+(-d|--decode)[^|;]*\|\s*(ba|z|da)?sh\b|\|\s*base64\s+(-d|--decode)\s*\|")),
    ("execution from a temp directory",
     re.compile(r"(chmod\s+(\+x|[0-7]*7[0-7]*)\s+|\./|\bsh\s+|\bbash\s+|python3?\s+|perl\s+|\bphp\s+)\S*"
                r"(/tmp/|/var/tmp/|/dev/shm/)|(^|[;&|]\s*)(/tmp/|/var/tmp/|/dev/shm/)\S+")),
    ("history tampering",
     re.compile(r"unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|history\s+-[cw]\b|ln\s+-s\w*\s+/dev/null\s+\S*history|"
                r"shred\b.*history|>\s*~?/?\S*\.\w*history", re.I)),
    ("PHP2Shell PoC marker", re.compile(r"php2shell|jackalpoc", re.I)),
    ("PHP one-liner executing code",
     re.compile(r"\bphp\s+-r\s+.*(system|exec|passthru|shell_exec|base64_decode|eval)\s*\(", re.I)),
]
HIST_TS_RE = re.compile(r"^#(\d{9,11})$")
ZSH_RE = re.compile(r"^: (\d{9,11}):\d+;(.*)$")
SECRET_RE = re.compile(r"(?i)(pass(?:word)?|pwd|token|secret|api_?key)(=|\s+)\S+")


def redact(cmd):
    cmd = SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", cmd)
    return re.sub(r"(\s-p)\S+", r"\1<redacted>", cmd)


def check_shell_history(rep, sec, web_users, since_ts):
    say("Looking at shell history files (.bash_history, .zsh_history, ...) of every account with a home directory. "
        "Commands run through a webshell or system() are NOT written to history; an entry only exists if someone "
        "had an interactive shell. Matching is pattern-only and secrets are masked on screen.")
    homes = {}
    for line in read_text("/etc/passwd").splitlines():
        p = line.split(":")
        if len(p) >= 7 and p[5] and os.path.isdir(p[5]):
            homes[p[0]] = p[5]
    if "root" not in homes and os.path.isdir("/root"):
        homes["root"] = "/root"
    web_set = set(web_users) | {"www-data", "apache", "nginx", "wwwrun", "httpd", "www"}
    found = defaultdict(list)
    files_seen = unreadable = lines_read = 0
    no_ts = False
    for user, home in sorted(homes.items()):
        isweb = user in web_set
        for hf in HIST_FILES:
            path = os.path.join(home, hf)
            if not os.path.lexists(path):
                continue
            files_seen += 1
            if os.path.islink(path) and os.path.realpath(path) == "/dev/null":
                say("%s is a link to /dev/null (history switched off)" % path, 2)
                found["MEDIUM" if isweb else "LOW"].append("%s -> /dev/null (history disabled%s)" %
                                                         (path, " for a web account" if isweb else ""))
                continue
            try:
                st = os.stat(path)
            except Exception:
                unreadable += 1
                continue
            if st.st_size == 0:
                continue
            stamp = fts(max(st.st_mtime, st.st_ctime))
            if isweb:
                say("web account '%s' HAS a history file %s (%d bytes, modified %s)" % (user, path, st.st_size, stamp), 2)
                found["MEDIUM"].append("%s: web account has a shell history file (%d bytes, modified %s). Such accounts "
                                       "normally have none; this means an interactive shell was used" %
                                       (path, st.st_size, stamp))
            if max(st.st_mtime, st.st_ctime) < since_ts:
                continue
            try:
                with open(path, "rb") as f:
                    if st.st_size > 2000000:
                        f.seek(-2000000, 2)
                    raw = f.read().decode("utf-8", "replace")
            except Exception:
                unreadable += 1
                continue
            say("scanning %s (user %s)" % (path, user), 2)
            ts = None
            stamped = False
            for line in raw.splitlines():
                lines_read += 1
                m = HIST_TS_RE.match(line)
                if m:
                    ts = int(m.group(1))
                    stamped = True
                    continue
                z = ZSH_RE.match(line)
                if z:
                    ts, line, stamped = int(z.group(1)), z.group(2), True
                if ts is not None and ts < since_ts:
                    continue
                for label, rx in HIST_PATTERNS:
                    if rx.search(line):
                        when = fts(ts) if ts else "no timestamp"
                        if not ts:
                            no_ts = True
                        sev = "HIGH" if isweb else "MEDIUM"
                        if label == "history tampering" and not isweb:
                            sev = "MEDIUM"
                        found[sev].append("%s [%s] %s: %s" % (path, when, label, trunc(redact(line.strip()), 170)))
                        break
    say("result: %d history file(s) looked at, %d line(s) read%s" %
        (files_seen, lines_read, ", %d unreadable (run as root)" % unreadable if unreadable else ""), 2)
    titles = {"HIGH": "Suspicious commands in the shell history of a WEB account",
              "MEDIUM": "Shell history findings (web account with history, tampering, or risky commands; admins "
                        "may have run some of these legitimately)",
              "LOW": "Shell history switched off via /dev/null"}
    for sev in ("HIGH", "MEDIUM", "LOW"):
        if found[sev]:
            det = list(found[sev])
            if no_ts and sev != "LOW":
                det.append("note: entries without a timestamp cannot be dated (HISTTIMEFORMAT not set); only the "
                           "file modification time was used")
            rep.add(sev, sec, "%s: %d" % (titles[sev], len(found[sev])), det)
    if not any(found.values()):
        rep.add("INFO", sec, "Shell history: %d file(s) checked, nothing suspicious. Webshell commands never "
                "appear in history, so this is weak evidence" % files_seen)


SSH_ACCEPT_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port \d+")


def check_ssh_logins(rep, sec, web_set, since_ts):
    say("Listing successful SSH logins since the cutoff (/var/log/auth.log*, /var/log/secure*, else journalctl) "
        "grouped by user, source address and method - a login you do not recognise, any login of a web account, "
        "or a root password login is a stronger sign of access than any web log ...")
    lines, src = [], ""
    files = [f for f in uniq_real(glob.glob("/var/log/auth.log*") + glob.glob("/var/log/secure*"))
             if os.path.getmtime(f) >= since_ts]
    if files:
        src = ", ".join(files[:4])
        for f in files:
            try:
                with open_log(f) as fh:
                    lines.extend(l for l in fh if "Accepted " in l)
            except Exception:
                continue
    elif shutil.which("journalctl"):
        src = "journalctl"
        rc, out = run(["journalctl", "-q", "--no-pager", "-o", "short-iso", "-t", "sshd", "-t", "sshd-session",
                       "--since", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since_ts))], timeout=90)
        if rc == 0:
            lines = [l for l in out.splitlines() if "Accepted " in l]
    if not src:
        say("no readable SSH log found (run as root, or logs are elsewhere); skipping", 2)
        rep.add("LOW", sec, "SSH login history could not be read (no auth.log/secure/journal access)")
        return
    agg = {}
    for l in lines:
        m = SSH_ACCEPT_RE.search(l)
        if not m:
            continue
        ts = err_ts(l)
        if ts is None or ts < since_ts:
            continue
        method, user, ip = m.groups()
        a = agg.setdefault((user, ip, method), [0, ts, ts])
        a[0] += 1
        a[1], a[2] = min(a[1], ts), max(a[2], ts)
    say("source: %s; %d distinct (user, source, method) combination(s) since the cutoff" % (src, len(agg)), 2)
    web = {u for u in web_set}
    rows = sorted(agg.items(), key=lambda kv: -kv[1][2])
    fmt_row = lambda kv: "%s from %s via %s: %dx, %s .. %s" % (kv[0][0], kv[0][1], kv[0][2], kv[1][0],
                                                              fts(kv[1][1]), fts(kv[1][2]))
    bad = [fmt_row(kv) for kv in rows if kv[0][0] in web]
    if bad:
        rep.add("HIGH", sec, "SSH login as a web/PHP service account (these accounts should never log in)", bad)
    rootpw = [fmt_row(kv) for kv in rows if kv[0][0] == "root" and kv[0][2] in ("password", "keyboard-interactive/pam")]
    if rootpw:
        rep.add("MEDIUM", sec, "Root logged in over SSH with a password", rootpw)
    if rows:
        rep.add("INFO", sec, "Successful SSH logins since the cutoff: %d distinct (user, source, method); check "
                "that every source address is expected" % len(rows), [fmt_row(kv) for kv in rows[:25]])
    else:
        rep.add("INFO", sec, "No successful SSH logins found in %s since the cutoff" % src)


def check_persistence(rep, since_ts, web_users, pool_users):
    sec = "5. Persistence and system changes"
    users = set(web_users) | set(pool_users) | {"www-data", "apache", "nginx", "wwwrun", "www", "httpd"}
    users = {u for u in users if u}
    say("Checking the web/PHP service accounts (%s) for crontabs, SSH authorized_keys and login shells - a "
        "web user normally has none of these ..." % ", ".join(sorted(users)))
    for u in sorted(users):
        try:
            pw = pwd.getpwnam(u)
        except Exception:
            continue
        for cp in ("/var/spool/cron/crontabs/%s" % u, "/var/spool/cron/%s" % u):
            if os.path.isfile(cp) and read_text(cp).strip():
                lines = [l for l in read_text(cp).splitlines() if l.strip() and not l.startswith("#")]
                if lines:
                    say("account '%s' HAS a crontab (%d entries)" % (u, len(lines)), 2)
                    rep.add("MEDIUM", sec, "Web user '%s' has a crontab (unusual unless you set it up)" % u,
                            [trunc(l) for l in lines[:8]])
        ak = os.path.join(pw.pw_dir, ".ssh", "authorized_keys")
        if os.path.isfile(ak) and os.path.getsize(ak) > 0:
            say("account '%s' HAS authorized_keys: %s" % (u, ak), 2)
            rep.add("MEDIUM", sec, "Web user '%s' has authorized_keys: %s" % (u, ak),
                    ["modified: " + fts(os.path.getmtime(ak))])
        if pw.pw_shell and not pw.pw_shell.endswith(("nologin", "false")) and u in ("www-data", "apache", "nginx", "wwwrun"):
            say("account '%s' has a login shell (%s)" % (u, pw.pw_shell), 2)
            rep.add("LOW", sec, "Web user '%s' has a login shell (%s)" % (u, pw.pw_shell))

    say("Checking /etc/ld.so.preload (libraries injected into every process; a classic rootkit location) ...")
    pre = "/etc/ld.so.preload"
    if os.path.isfile(pre) and read_text(pre).strip():
        say("/etc/ld.so.preload is PRESENT and not empty", 2)
        rep.add("HIGH", sec, "/etc/ld.so.preload is present and non-empty (classic rootkit/hook location)",
                [trunc(l) for l in read_text(pre).splitlines()[:5]])
    else:
        say("not present / empty - OK", 2)

    say("Checking /etc/passwd for additional accounts with UID 0 (root-equivalent backdoor accounts) ...")
    uid0 = []
    for line in read_text("/etc/passwd").splitlines():
        p = line.split(":")
        if len(p) > 3 and p[2] == "0" and p[0] != "root":
            uid0.append(line)
    say("%s" % ("FOUND: " + "; ".join(uid0) if uid0 else "only 'root' has UID 0 - OK"), 2)
    if uid0:
        rep.add("HIGH", sec, "Additional account(s) with UID 0", uid0)

    check_shell_history(rep, sec, users, since_ts)

    check_ssh_logins(rep, sec, users, since_ts)

    say("Checking whether sensitive system files changed since the cutoff (also cron spools and every user's "
        "authorized_keys; passwd, shadow, sudoers, cron, "
        "systemd units, rc.local, profile.d, init.d, sshd_config, root authorized_keys) ...")
    watch = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/crontab", "/etc/rc.local",
             "/root/.ssh/authorized_keys", "/etc/ssh/sshd_config", "/etc/environment"]
    for pat in ("/etc/sudoers.d/*", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
                "/etc/cron.weekly/*", "/etc/profile.d/*", "/etc/systemd/system/*.service",
                "/etc/systemd/system/*.timer", "/etc/systemd/system/*/*.service", "/etc/init.d/*",
                "/var/spool/cron/crontabs/*", "/var/spool/cron/*", "/home/*/.ssh/authorized_keys",
                "/home/*/.ssh/authorized_keys2", "/root/.ssh/authorized_keys2"):
        watch.extend(glob.glob(pat))
    changed = []
    for f in sorted(set(watch)):
        try:
            st = os.lstat(f)
        except Exception:
            continue
        if max(st.st_mtime, st.st_ctime) >= since_ts:
            changed.append("%s [%s]" % (f, fts(max(st.st_mtime, st.st_ctime))))
    say("%d of %d watched files changed since the cutoff (package updates and your own edits appear here too)" %
        (len(changed), len(set(watch))), 2)
    if changed:
        rep.add("MEDIUM", sec, "System files changed since the cutoff (package updates and your own changes "
                "appear here too; verify each)", changed)
    else:
        rep.add("INFO", sec, "No watched persistence/system files changed since the cutoff")


# --------------------------------------------------------------------------
# 6. logs
# --------------------------------------------------------------------------
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                      "Nov", "Dec"], 1)}
CLF_TS = re.compile(r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?: ([+-])(\d{2}):?(\d{2}))?$")
ISO_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?\s*(Z|[+-]\d{2}:?\d{2})?$")


def to_epoch(y, mo, d, H, M, S, off=None):
    """Calendar fields -> epoch seconds. off = UTC offset in seconds, None = host local time.
    Returns None for impossible values instead of guessing."""
    if not (1970 <= y <= 2100 and 1 <= mo <= 12 and 1 <= d <= 31 and 0 <= H <= 23 and 0 <= M <= 59 and 0 <= S <= 60):
        return None
    try:
        if off is None:
            return time.mktime((y, mo, d, H, M, S, 0, 0, -1))
        return float(calendar.timegm((y, mo, d, H, M, S)) - off)
    except (OverflowError, ValueError, OSError):
        return None


@functools.lru_cache(maxsize=8192)
def parse_access_ts(s):
    """Parse a log timestamp in one of the known layouts. Month names are matched against a fixed English table
    (nginx/Apache always log English month names), so the host locale cannot break parsing. Day-first and
    year-first layouts are told apart by their shape; ambiguous layouts such as 10/22/2026 are not guessed."""
    s = s.strip()
    m = CLF_TS.match(s)
    if m:
        d, mon, y, H, M, S, sg, oh, om = m.groups()
        mo = MONTHS.get(mon.title())
        if not mo:
            return None
        off = None
        if sg:
            off = (int(oh) * 3600 + int(om) * 60) * (1 if sg == "+" else -1)
        return to_epoch(int(y), mo, int(d), int(H), int(M), int(S), off)
    m = ISO_TS.match(s)
    if m:
        y, mo, d, H, M, S, tz = m.groups()
        off = None
        if tz:
            off = 0 if tz == "Z" else (int(tz[1:3]) * 3600 + int(tz[-2:]) * 60) * (1 if tz[0] == "+" else -1)
        return to_epoch(int(y), int(mo), int(d), int(H), int(M), int(S), off)
    if re.match(r"^\d{9,11}(\.\d+)?$", s):
        return float(s)
    return None


def _first(*vals):
    for v in vals:
        if v not in (None, "", []):
            return v
    return None


def parse_json_access(line):
    """Parse one JSON access-log line (Caddy, nginx json_log, Traefik-style). Returns
    (ip, epoch, request_line, status, user_agent, referer) or None if the line is not recognised."""
    try:
        o = json.loads(line)
    except ValueError:
        return None
    if not isinstance(o, dict):
        return None
    rq = o.get("request") if isinstance(o.get("request"), dict) else {}
    hd = rq.get("headers") if isinstance(rq.get("headers"), dict) else {}
    raw = _first(o.get("ts"), o.get("time"), o.get("@timestamp"), o.get("timestamp"), o.get("time_iso8601"),
                 o.get("time_local"))
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        ts = float(raw) / 1000.0 if raw > 1e11 else float(raw)
    elif isinstance(raw, str):
        ts = parse_access_ts(raw)
    else:
        ts = None
    if ts is None:
        return None
    try:
        status = int(_first(o.get("status"), o.get("resp_status"), o.get("status_code")))
    except (TypeError, ValueError):
        return None
    ip = str(_first(rq.get("remote_ip"), rq.get("client_ip"), o.get("remote_addr"), o.get("remote_ip"),
                    o.get("client_ip"), "-"))
    if isinstance(o.get("request"), str):
        reqline = o["request"]
    else:
        reqline = "%s %s HTTP" % (_first(rq.get("method"), o.get("method"), o.get("request_method"), "-"),
                                  _first(rq.get("uri"), o.get("uri"), o.get("request_uri"), o.get("path"), "-"))
    ua = _first(hd.get("User-Agent"), o.get("http_user_agent"), o.get("user_agent")) or ""
    ref = _first(hd.get("Referer"), o.get("http_referer")) or ""
    if isinstance(ua, list):
        ua = ua[0] if ua else ""
    if isinstance(ref, list):
        ref = ref[0] if ref else ""
    return ip, ts, str(reqline), status, str(ua), str(ref)


def parse_since(text):
    """--since accepts YYYY-MM-DD, 'YYYY-MM-DD HH:MM' and DD.MM.YYYY. Layouts with slashes (10/22/2026) are
    rejected on purpose: day/month order would be a guess."""
    t = text.strip()
    for fmt_, rx in (("%Y-%m-%d", r"\d{4}-\d{2}-\d{2}"), ("%Y-%m-%d %H:%M", r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}"),
                     ("%Y-%m-%dT%H:%M", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}"), ("%d.%m.%Y", r"\d{1,2}\.\d{1,2}\.\d{4}")):
        if re.match("^" + rx + "$", t):
            d = dt.datetime.strptime(t, fmt_)
            if not 2000 <= d.year <= 2100:
                raise ValueError("year out of range")
            return d
    raise ValueError("unrecognised date layout")


CFG_LOG_RES = (
    ("access", re.compile(r"(?:^|[;{}])\s*access_log\s+(/[^\s;]+)")),
    ("error", re.compile(r"(?:^|[;{}])\s*error_log\s+(/[^\s;]+)")),
    ("access", re.compile(r'^\s*CustomLog\s+"?((?:/|\$\{APACHE_LOG_DIR\})[^\s"]+)"?\s')),
    ("error", re.compile(r'^\s*ErrorLog\s+"?((?:/|\$\{APACHE_LOG_DIR\})[^\s"]+)"?')),
)
ACCESS_OFF_RE = re.compile(r"(?:^|[;{}])\s*access_log\s+off\s*;")


@functools.lru_cache(maxsize=1)
def config_logs():
    """Log paths declared in nginx/Apache configs: (access_paths, error_paths, configs_with_access_log_off).
    Variables ($host, ${APACHE_LOG_DIR}) are turned into globs so per-site log files are found too."""
    access, error, off = set(), set(), set()
    files = []
    for pat in ("/etc/nginx/**/*", "/etc/apache2/**/*", "/etc/httpd/**/*", "/usr/local/nginx/conf/**/*",
                "/usr/local/apache2/conf/**/*"):
        files.extend(glob.glob(pat, recursive=True))
    for f in files:
        try:
            if not os.path.isfile(f) or os.path.getsize(f) > 1000000:
                continue
        except Exception:
            continue
        for line in read_text(f).splitlines():
            if line.lstrip().startswith("#"):
                continue
            if ACCESS_OFF_RE.search(line):
                off.add(f)
            for kind, rx in CFG_LOG_RES:
                m = rx.search(line)
                if not m:
                    continue
                path = m.group(1).replace("${APACHE_LOG_DIR}", "/var/log/apache2")
                path = re.sub(r"\$\{?\w+\}?", "*", path)
                if path.startswith("/dev/") or "|" in path:
                    continue
                (access if kind == "access" else error).add(path)
    return sorted(access), sorted(error), sorted(off)


def expand_paths(paths):
    """A configured log path also covers its rotated siblings (.1, .2.gz, -20261020)."""
    out = []
    for p in paths:
        out.extend([p, p + ".*", p + "-*"])
    return out


def php_error_logs():
    found = set()
    for label, files, pool_files in ini_families():
        for f in files + pool_files:
            for line in read_text(f).splitlines():
                m = re.match(r'^\s*(?:php_(?:admin_)?value\[error_log\]|error_log)\s*=\s*"?(/[^\s";]+)', line)
                if m and not m.group(1).startswith("/dev/"):
                    found.add(m.group(1))
    return sorted(found)


def app_log_globs(args):
    roots = list(APP_ROOTS) or discover_webroots(args.webroot)
    out = []
    for r in roots:
        for rel in ("storage/logs/*.log*", "var/log/*.log*", "wp-content/debug.log*"):
            out.append(os.path.join(r, rel))
    return out


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
    say("Collecting access logs (nginx, Apache, lighttpd, Caddy, LiteSpeed, Plesk paths + your --access-log "
        "globs). Rotated .gz files are read too; files last written before the cutoff are skipped ...")
    cfg_access, cfg_error, access_off = config_logs()
    say("Also found %d access-log path(s) declared in the nginx/Apache configs (access_log, CustomLog), "
        "including rotated siblings" % len(cfg_access))
    if access_off:
        say("WARNING: 'access_log off' is set in %d nginx config file(s): no request log exists for those sites" %
            len(access_off))
        rep.add("LOW", sec, "access_log is switched off in %d nginx config file(s): no request log exists for "
                "those sites, so log analysis is blind there" % len(access_off), access_off)
    files = log_files(ACCESS_GLOBS + args.access_log + expand_paths(cfg_access), since_ts)
    say("%d access log file(s) selected%s" % (len(files), ": " + ", ".join(files[:6]) + (" ..." if len(files) > 6 else "")
                                              if files else ""))
    if not files:
        rep.add("LOW", sec, "No access logs found in the usual locations; pass --access-log '/path/*.log*'")
        return
    say("Parsing every line (combined log format, with or without a leading vhost field) and applying these "
        "checks to lines newer than the cutoff:")
    say("known PoC markers ('php2shell', 'JACKALPOC') anywhere in the line", 2)
    say("'upload_progress' in the URL or referer (the exploit field itself normally sits in the body, "
        "which access logs do not show)", 2)
    say("POST requests answered with HTTP 5xx (a crashing worker is a typical exploit side effect)", 2)
    say("POST requests with an empty or very short User-Agent", 2)
    say("PHPSESSID in the URL of non-POST requests", 2)
    say("successful requests to .php files inside upload/cache/tmp/media-like folders (webshell use)", 2)
    say("bursts of POST requests per IP per minute (brute-forcing / ASLR guessing / scanning)", 2)
    counts = Counter()
    ipc = defaultdict(Counter)
    samples = defaultdict(list)
    burst = Counter()
    post_targets = Counter()
    first_ts = last_ts = None
    lines_total = parsed = recognized = 0
    bad_format = []

    def rec(cat, line, ip):
        counts[cat] += 1
        ipc[cat][ip] += 1
        if len(samples[cat]) < 40:
            samples[cat].append(trunc(line.strip(), 260))

    for path in files:
        say("Reading %s ..." % path, 2)
        l0, p0, r0 = lines_total, parsed, recognized
        try:
            fh = open_log(path)
        except Exception as e:  # noqa
            say("cannot open (%s), skipping" % e, 3)
            continue
        with fh:
            try:
                for line in fh:
                    lines_total += 1
                    rec_ = None
                    if line.lstrip().startswith("{"):
                        rec_ = parse_json_access(line)
                    else:
                        m = ACC_RE.match(line) or ACC_RE_VHOST.match(line)
                        if m:
                            ts_ = parse_access_ts(m.group("ts"))
                            if ts_ is not None:
                                rec_ = (m.group("ip"), ts_, m.group("req"), int(m.group("status")),
                                        m.group("ua") or "", m.group("ref") or "")
                    if rec_ is None:
                        continue
                    recognized += 1
                    ip, ts, req, status, ua, ref = rec_
                    if ts < since_ts:
                        continue
                    parsed += 1
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)
                    parts = req.split(" ", 2)
                    method = parts[0] if parts else ""
                    target = parts[1] if len(parts) > 1 else ""
                    if POC_RE.search(line):
                        rec("poc", line, ip)
                    if UP_RE.search(req) or UP_RE.search(ref):
                        rec("upload_progress", line, ip)
                    if method == "POST":
                        burst[(ip, int(ts // 60))] += 1
                        pt = target.split("?")[0][:120]
                        if pt in post_targets or len(post_targets) < 50000:
                            post_targets[pt] += 1
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
        n_lines, n_rec = lines_total - l0, recognized - r0
        say("%d lines read, %d in a recognised log format, %d inside the time range" %
            (n_lines, n_rec, parsed - p0), 3)
        if n_lines >= 50 and n_rec < 0.5 * n_lines:
            say("WARNING: most lines of this file could not be parsed (unknown log format?). Findings for it are "
                "unreliable.", 3)
            bad_format.append("%s: %d of %d lines recognised" % (path, n_rec, n_lines))

    cov = "no matching lines"
    if first_ts:
        cov = "%s .. %s" % (fts(first_ts),
                            fts(last_ts))
    say("Coverage of the parsed lines: %s. If this starts later than your cutoff, older logs were rotated away "
        "and that period cannot be checked." % cov)
    rep.add("INFO", sec, "Read %d log files, %d lines (%d in a recognised format, %d inside the time range). "
            "Coverage: %s" % (len(files), lines_total, recognized, parsed, cov), files[:12])
    if bad_format:
        rep.add("MEDIUM", sec, "Access-log format not recognised in %d file(s): fewer than half of the lines could "
                "be parsed (supported: combined/common log format with optional vhost, ISO-8601 in brackets, JSON "
                "lines from Caddy/nginx). A silent miss here means attacks may not be seen; use a standard format "
                "or inspect these logs manually." % len(bad_format), bad_format)
    if post_targets:
        say("Top POST targets in the period: " + ", ".join("%s(%d)" % (p, c) for p, c in post_targets.most_common(5)))
        rep.add("INFO", sec, "Top POST targets in the period (look for endpoints that never take forms or uploads)",
                ["%6d  %s" % (c, p) for p, c in post_targets.most_common(15)])

    def top_ips(cat):
        return "top IPs: " + ", ".join("%s(%d)" % kv for kv in ipc[cat].most_common(5))

    say("Hit counts: PoC markers=%d, upload_progress=%d, PHP-in-uploads=%d, POST-5xx=%d, empty-UA POST=%d, "
        "PHPSESSID-in-URL=%d" % (counts["poc"], counts["upload_progress"], counts["php_in_uploads"],
                                 counts["post500"], counts["emptyua"], counts["phpsessid_url"]))
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
    say("Counting POSTs per IP per minute (threshold %d): %d burst(s) found" % (args.burst, len(big)))
    if big:
        big.sort(key=lambda kv: -kv[1])
        lines = ["%s: %d POSTs in one minute (%s)" % (k[0], v, fts(k[1] * 60))
                 for k, v in big[:15]]
        rep.add("MEDIUM", sec, "POST bursts >= %d per minute from one IP (brute-force/ASLR guessing or "
                "scanning)" % args.burst, lines)
    if not any(counts[c] for c in counts) and not big:
        rep.add("INFO", sec, "No suspicious patterns found in the parsed access-log range "
                "(does not prove the absence of attacks)")


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


ERR_APACHE = re.compile(r"^\[\w{3} (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]")
ERR_PHP = re.compile(r"^\[(\d{2})-(\w{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})")
ERR_BRACKET_ISO = re.compile(r"^\[(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})")
ERR_NGINX = re.compile(r"^(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})")
ERR_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
ERR_SYSLOG = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ")


def err_ts(line):
    """Timestamp of an error-log / syslog line (epoch) or None. Month names come from a fixed English table, so
    the host locale is irrelevant. Classic syslog lines carry no year: the most recent past date is assumed."""
    c = line[:1]
    if c == "[":
        m = ERR_APACHE.match(line)
        if m:
            mon, d, H, M, S, y = m.groups()
            return to_epoch(int(y), MONTHS.get(mon.title(), 0), int(d), int(H), int(M), int(S))
        m = ERR_PHP.match(line)
        if m:
            d, mon, y, H, M, S = m.groups()
            return to_epoch(int(y), MONTHS.get(mon.title(), 0), int(d), int(H), int(M), int(S))
        m = ERR_BRACKET_ISO.match(line)
        if m:
            return to_epoch(*[int(x) for x in m.groups()])
        return None
    if c.isdigit():
        m = ERR_NGINX.match(line)
        if m:
            return to_epoch(*[int(x) for x in m.groups()])
        m = ERR_ISO.match(line)
        if m:
            return parse_access_ts(m.group(1))
        return None
    if c.isalpha():
        m = ERR_SYSLOG.match(line)
        if m:
            mon, d, H, M, S = m.groups()
            mo = MONTHS.get(mon.title())
            if not mo:
                return None
            y = dt.datetime.fromtimestamp(NOW).year
            ts = to_epoch(y, mo, int(d), int(H), int(M), int(S))
            if ts is not None and ts > NOW + 86400:
                ts = to_epoch(y - 1, mo, int(d), int(H), int(M), int(S))
            return ts
    return None


def check_error_logs(rep, args, since_ts):
    sec = "7. Logs: error / syslog"
    say("Collecting PHP, FPM, Apache and nginx error logs plus syslog/messages/kern.log (+ your --error-log "
        "globs) that were written since the cutoff ...")
    cfg_access, cfg_error, access_off = config_logs()
    php_logs = php_error_logs()
    app_logs = app_log_globs(args)
    say("Additional sources: %d error-log path(s) from nginx/Apache configs, %d from php.ini/FPM pools, plus "
        "application logs (Laravel storage/logs, Symfony var/log, WordPress debug.log) under the project roots" %
        (len(cfg_error), len(php_logs)))
    files = log_files(ERROR_GLOBS + args.error_log + expand_paths(cfg_error + php_logs) + app_logs, since_ts)
    say("%d error/syslog file(s) selected%s" % (len(files), ": " + ", ".join(files[:6]) + (" ..." if len(files) > 6 else "")
                                                if files else ""))
    if not files:
        rep.add("LOW", sec, "No PHP/web error logs found in the usual locations; pass --error-log '/path/*.log*'")
        return
    say("Searching every line for: memory exhaustion 'in Unknown on line 0' and PHP fatals outside any script "
        "(the reported PHP2Shell signature), worker crashes (Apache AH00052, 'exited on signal 11', SIGSEGV), "
        "kernel segfaults in PHP/web processes, and plain memory/timeout errors (informational) ...")
    counts = Counter()
    samples = defaultdict(list)
    undated = 0
    oom_days = Counter()
    for path in files:
        say("Reading %s ..." % path, 2)
        try:
            fh = open_log(path)
        except Exception as e:  # noqa
            say("cannot open (%s), skipping" % e, 3)
            continue
        with fh:
            try:
                last_known = None
                for line in fh:
                    ts_line = err_ts(line)
                    if ts_line is not None:
                        last_known = ts_line
                    for name, sev, rx in ERR_PATTERNS:
                        if rx.search(line):
                            ts = ts_line if ts_line is not None else last_known
                            if ts is not None and ts < since_ts:
                                break
                            if ts is None:
                                undated += 1
                            counts[name] += 1
                            if name == "oom":
                                oom_days[fts(ts)[:10] if ts is not None else "unknown date"] += 1
                            if len(samples[name]) < 25:
                                samples[name].append("%s: %s" % (os.path.basename(path), trunc(line.strip(), 240)))
                            break
            except Exception:
                continue
    say("Hit counts: " + ", ".join("%s=%d" % (n, counts[n]) for n, _, _ in ERR_PATTERNS))
    rep.add("INFO", sec, "Read %d error/syslog files" % len(files), files[:12])
    if undated:
        say("%d matching line(s) had no parsable date (no earlier dated line in the file either) and were counted "
            "anyway" % undated)
        rep.add("LOW", sec, "%d matching error-log line(s) had no parsable date and were counted regardless of "
                "the cutoff; check them manually" % undated)
    shown = False
    for name, sev, _ in ERR_PATTERNS:
        if counts[name]:
            shown = True
            s = sev
            if name == "child_signal" and counts[name] < 3:
                s = "LOW"
            det, title = list(samples[name]), "%s: %d" % (ERR_TITLES[name], counts[name])
            if name == "oom":
                det.insert(0, "per day: " + ", ".join("%s=%d" % kv for kv in sorted(oom_days.items())))
                if counts[name] >= 4:
                    s = "MEDIUM"
                    title += (" - a cluster of 4 or more; fatal memory errors are listed as a sign of exploitation "
                              "attempts in the URSIV order (point V), especially on multipart requests")
            rep.add(s, sec, title, det)
    if not shown:
        rep.add("INFO", sec, "No matching error-log patterns in range")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
STEP_TEXT = {
    1: ("PHP versions and patch status",
        "Finds every PHP executable and Apache mod_php module, reads its version, asks dpkg/rpm which package "
        "owns it and searches that package's changelog for the two CVE ids (distros often backport the fix "
        "without changing the version number).",
        "Only a patched PHP is a complete fix: 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or a vendor backport). "
        "Everything else below only matters in relation to this result.",
        "version is below the fixed release and no backport is found (HIGH); branch is end-of-life (HIGH); "
        "changelog mentions only one CVE (MEDIUM)."),
    2: ("PHP configuration (interim mitigations)",
        "Reads php.ini, conf.d and every PHP-FPM pool to see session.upload_progress.enabled, memory_limit, "
        "post_max_size, fatal_error_backtraces and pm.max_requests, and whether values are enforced "
        "(php_admin_value) or overridable (php_value). Also reads session.serialize_handler (php.ini, pools, "
        "Apache) for CVE-2026-115560.",
        "The PHP advisory lists these settings as stop-gaps that reduce exposure to specific attack paths "
        "while you cannot update. upload_progress should stay off even after patching; it is also the only "
        "mitigation for CVE-2026-115560, which has no fixed release yet.",
        "upload_progress is on; memory_limit=-1 is not enforced per pool; pm.max_requests is not 1 "
        "(MEDIUM when PHP is vulnerable, otherwise low/info); serialize_handler php_binary/php_serialize with "
        "upload progress on (LOW, the code is checked in step 4)."),
    3: ("Running processes and network connections",
        "Reads /proc: finds PHP workers still running a replaced binary, shells/recon tools started below a "
        "web or PHP process, and established TCP connections: those owned by a child of a web process, by the "
        "web process itself, and by other processes to public IPs on unusual ports.",
        "Patching without restarting leaves the vulnerable code in memory, and a successful exploit usually "
        "shows up as a web worker spawning a shell that opens a connection to the internet (any port, "
        "including 443).",
        "stale worker (HIGH); shell with recon commands or whoami/id/nc under a web process (HIGH); a "
        "connection owned by a child of a web process (HIGH); plain shell (MEDIUM); outbound connections from "
        "web processes or on unusual ports (LOW, review the peer)."),
    4: ("Web root files, webshells and temp directories",
        "Finds web roots (and the framework project root above them), scans files changed since the cutoff "
        "and everything in upload/cache-like folders for webshell code, hidden PHP in images and malicious "
        ".htaccess/.user.ini; flags PHP in directories where Laravel/Symfony/Drupal/WordPress never keep PHP "
        "at ANY date; compares git checkouts with the committed code; searches EVERY PHP file for a runtime "
        "switch of session.serialize_handler (CVE-2026-115560) and combines it with the configuration from "
        "step 2; then inspects /tmp, /var/tmp and /dev/shm for dropped tools.",
        "Updating PHP does not remove a webshell that was planted earlier. File evidence is stronger proof of "
        "compromise than any log line, and a git diff is the cleanest truth for deployed code.",
        "eval(base64_decode()), system($_POST[]) and similar (HIGH); PHP inside images (HIGH); "
        "auto_prepend_file (HIGH); PHP in upload or no-PHP framework folders, files with a future "
        "modification time, git differences in PHP/public files, new executables (MEDIUM); ELF files owned "
        "by the web user in /tmp (HIGH). Long lists of changed files after a deployment are summarised. "
        "CVE-2026-115560: all three preconditions (HIGH), runtime switch to 'php' with upload progress on but "
        "no risky config found (MEDIUM), other runtime changes (LOW), mitigated (INFO)."),
    5: ("Persistence and system changes",
        "Checks crontabs, SSH keys and login shells of web accounts, /etc/ld.so.preload, extra UID 0 accounts, "
        "shell history files (bash/zsh) of all accounts, successful SSH logins since the cutoff (grouped by "
        "user, source and method), and whether passwd, shadow, sudoers, cron (incl. spools), systemd units, "
        "every user's authorized_keys and similar files changed since the cutoff.",
        "After code execution attackers typically add a way back in or log in with stolen credentials. Web "
        "accounts normally have none of these.",
        "ld.so.preload content, a second UID 0 account, suspicious commands in a web account's history or an "
        "SSH login as a web account (HIGH); web user with crontab/authorized_keys/history file, root password "
        "login, risky commands or tampering in other histories, or a changed system file (MEDIUM - package "
        "updates also change files, so verify). All SSH sources are listed as INFO for you to recognise."),
    6: ("Access logs",
        "Parses nginx/Apache/Caddy access logs (combined, ISO-8601 and JSON formats, including rotated .gz) "
        "from the cutoff onward - found through standard paths AND the access_log/CustomLog directives in the "
        "web server configs - and counts PoC markers, upload_progress in URLs, POST 5xx, empty User-Agent "
        "POSTs, PHPSESSID in URLs, requests to PHP files in upload folders, POST bursts per IP and the top POST "
        "targets. Warns where 'access_log off' leaves no logs at all.",
        "Shows who is probing or attacking and from where. The earliest reported attempt was 17 October, so "
        "that is the default cutoff.",
        "PoC markers (HIGH); upload_progress, PHP-in-uploads, POST 5xx from one IP >= 10, POST bursts "
        "(MEDIUM); other patterns, disabled logging (LOW). A hit is an attempt, not a compromise."),
    7: ("Error logs and syslog",
        "Searches PHP/FPM/Apache/nginx error logs, syslog and application logs (Laravel storage/logs, Symfony "
        "var/log, WordPress debug.log; log paths also come from the web server and php.ini/FPM configs) for "
        "memory exhaustion, 'in Unknown on line 0' fatals, worker crashes and kernel segfaults in PHP or web "
        "processes.",
        "The exploits work by driving PHP into memory errors and crashes, which are logged even when the "
        "request body is not. The URSIV order names fatal memory errors (especially on multipart requests) "
        "and worker crashes as signs to look for.",
        "'in Unknown on line 0' errors, repeated crashes/segfaults and clusters of 4 or more memory "
        "exhaustion errors (MEDIUM); isolated memory or timeout errors (LOW)."),
}


def parse_args():
    ap = argparse.ArgumentParser(description="Local read-only checker for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) "
                                             "and CVE-2026-115560")
    ap.add_argument("--since", default=DEFAULT_SINCE,
                    help="start of the period: YYYY-MM-DD, 'YYYY-MM-DD HH:MM' or DD.MM.YYYY, in the host's local time "
                         "(default %s, the earliest reported attempt)" % DEFAULT_SINCE)
    ap.add_argument("--webroot", action="append", default=[], help="extra web root to scan (repeatable)")
    ap.add_argument("--access-log", action="append", default=[], help="extra access log glob (repeatable)")
    ap.add_argument("--error-log", action="append", default=[], help="extra error log glob (repeatable)")
    ap.add_argument("--skip-files", action="store_true", help="skip step 4 (file/webshell scan)")
    ap.add_argument("--skip-logs", action="store_true", help="skip steps 6 and 7 (logs)")
    ap.add_argument("--skip-procs", action="store_true", help="skip steps 3 and 5 (processes, persistence)")
    ap.add_argument("--max-files", type=int, default=400000, help="max files to walk in web roots")
    ap.add_argument("--burst", type=int, default=60, help="POSTs per minute per IP to flag as a burst")
    ap.add_argument("--sample", type=int, default=12, help="detail lines per finding on screen")
    ap.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    ap.add_argument("--quiet", action="store_true", help="no step narration, only the final report")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version="php2shell_check %s (%s)" % (__version__, VERSION_DATE))
    return ap.parse_args()


def main():
    global QUIET
    args = parse_args()
    QUIET = args.quiet
    try:
        since = parse_since(args.since)
        since_ts = time.mktime(since.timetuple())
    except (ValueError, OverflowError):
        print("--since: use YYYY-MM-DD, 'YYYY-MM-DD HH:MM' or DD.MM.YYYY. Layouts like 10/22/2026 are refused on "
              "purpose because the day/month order would be a guess.", file=sys.stderr)
        return 3
    if since_ts > time.time():
        print("--since is in the future (%s)" % args.since, file=sys.stderr)
        return 3
    rep = Report(sys.stdout.isatty() and not args.no_color)
    total = len(STEP_TEXT)

    print("php2shell_check v%s (%s) - CVE-2026-109618 / CVE-2026-109619 / CVE-2026-115560  (read-only, nothing is "
          "changed or sent)" %
          (__version__, VERSION_DATE))
    print("host=%s  user=%s  time=%s  checking from=%s" % (socket.gethostname(), uname(os.geteuid()),
                                                          time.strftime("%Y-%m-%d %H:%M"),
                                                          fts(since_ts) + " (host local time)"))
    if not sys.platform.startswith("linux"):
        print("This checker supports Linux only.", file=sys.stderr)
        return 3
    if os.geteuid() != 0:
        rep.add("MEDIUM", "0. Notes", "Not running as root: logs, /proc of other users and many files will be "
                "unreadable, so results are incomplete. Re-run with sudo.")
        print("WARNING: not running as root - logs, /proc of other users and many files will be unreadable, "
              "so results will be incomplete. Re-run with sudo.")

    if not QUIET:
        print("\nSCOPE - which systems this script is suitable for:")
        for k, v in SCOPE_TEXT:
            print(labelled(k, v))
        print("\nDETECTED ON THIS HOST:")
    safe(rep, "0. Environment and scope", check_environment, rep)

    skip = {3: args.skip_procs, 5: args.skip_procs, 4: args.skip_files, 6: args.skip_logs, 7: args.skip_logs}
    if not QUIET:
        print("\nPLAN - this run will perform the following steps:")
        for n in range(1, total + 1):
            print("  %d. %s%s" % (n, STEP_TEXT[n][0], "   [SKIPPED by option]" if skip.get(n) else ""))

    results = {}

    def step(n, fn, *a):
        title, what, why, flagged = STEP_TEXT[n]
        if skip.get(n):
            banner(n, total, title, what, why, flagged)
            say("SKIPPED because of a --skip-* option")
            results[n] = None
            return None
        banner(n, total, title, what, why, flagged)
        start = len(rep.items)
        out = safe(rep, "%d. %s" % (n, title), fn, *a)
        c = Counter(i["severity"] for i in rep.items[start:])
        results[n] = c
        if not QUIET:
            print("-" * 78)
            worst = max([SEV_RANK[k] for k in c] or [0])
            verdict = {3: "ATTENTION - HIGH finding(s)", 2: "REVIEW - MEDIUM finding(s)", 1: "minor items only",
                       0: "nothing to report"}[worst]
            print("  STEP %d RESULT: HIGH=%d MEDIUM=%d LOW=%d INFO=%d  ->  %s" %
                  (n, c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"], verdict))
        return out

    state = step(1, check_php, rep) or {"vulnerable": False, "found": False, "fpm_bins": []}
    pool_users = step(2, check_config, rep, state["vulnerable"], state) or set()
    web_users = step(3, check_processes, rep) or set()
    step(4, check_files, rep, args, since_ts, web_users | pool_users)
    step(5, check_persistence, rep, since_ts, web_users, pool_users)
    step(6, check_access_logs, rep, args, since_ts)
    step(7, check_error_logs, rep, args, since_ts)

    print("\n" + "=" * 78)
    print("FINAL REPORT (all findings, grouped by step)")
    print("=" * 78)
    rep.print(args.sample)
    c = rep.counts()

    print("\n== Checklist ==")
    for n in range(1, total + 1):
        r = results.get(n)
        if r is None:
            print("  step %d  %-48s SKIPPED" % (n, STEP_TEXT[n][0]))
        else:
            print("  step %d  %-48s HIGH=%d MEDIUM=%d LOW=%d" % (n, STEP_TEXT[n][0], r["HIGH"], r["MEDIUM"], r["LOW"]))

    print("\n== Summary ==")
    print("HIGH=%d  MEDIUM=%d  LOW=%d  INFO=%d" % (c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
    print("Updating PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) and restarting all workers is the only complete fix.")
    print("No findings does NOT prove the host was not attacked: access logs have no request bodies, and memory\n"
          "disclosure or file reads leave no files. If the host was exposed, rotate secrets PHP could read.")
    print("Rotate what the web user could read: framework keys (Laravel APP_KEY, WordPress salts, Symfony "
          "APP_SECRET), database/API/SMTP\ncredentials, session secrets, TLS private keys and deploy/SSH keys.")
    if args.json:
        try:
            with open(args.json, "w") as f:
                json.dump({"script_version": __version__, "script_date": VERSION_DATE, "host": socket.gethostname(), "since": args.since, "summary": c, "items": rep.items},
                          f, indent=2)
            print("JSON report written to %s" % args.json)
        except Exception as e:  # noqa
            print("Could not write JSON: %s" % e, file=sys.stderr)
    return 2 if rep.worst() >= 3 else (1 if rep.worst() == 2 else 0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. output piped into head/less and closed early
        try:
            sys.stdout = open(os.devnull, "w")
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
