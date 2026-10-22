# php2shell_check

All-in-one, **read-only** local checker for the PHP vulnerabilities known as *PHP2Shell*
(CVE-2026-109618 / CVE-2026-109619, unauthenticated remote code execution, fixed in PHP
8.5.12, 8.4.27, 8.3.36 and 8.2.35, released 21 October 2026).

One Python file, standard library only, Python 3.6+, Linux. It changes nothing and sends nothing
over the network. While it runs it explains in English what each step does and what it looks for,
so the output doubles as a record of what was verified.

> **Not an official tool.** There are no official IOCs for these CVEs. The log and file heuristics
> come from public write-ups and can produce false positives and miss real attacks. A log hit is an
> attempt, not proof of compromise. *No findings does not prove the host was not attacked.*

## Quick start

```bash
sudo python3 php2shell_check.py                                  # everything, from 2026-10-17
sudo python3 php2shell_check.py --since 17.10.2026 --json report.json
sudo python3 php2shell_check.py --webroot /srv/app --access-log '/data/logs/*.log*'
sudo python3 php2shell_check.py --quiet                          # final report only
python3 php2shell_check.py --version
```

Run it as root, otherwise logs, other users' processes and many files are unreadable (the script warns).
Exit code: `2` at least one HIGH finding, `1` at least one MEDIUM, `0` otherwise.

## Which systems

| | |
|---|---|
| **Supported** | Linux (Debian/Ubuntu, RHEL/Alma/Rocky/CentOS/Fedora/Amazon Linux, SUSE) on bare metal, VM or LXC, and *inside* a Docker/Podman container. nginx, Apache (mod_php), LiteSpeed, Caddy, lighttpd, FrankenPHP with PHP-FPM / CGI / mod_php. Plesk, cPanel, Hestia, DirectAdmin work, paths only partly covered. |
| **Limited** | Alpine (version check only, no distro-backport check). A Docker/Kubernetes *host* cannot see inside images: run the script in each container or check image tags. Non-standard web root or log paths: use `--webroot`, `--access-log`, `--error-log`. |
| **Not for** | Windows (IIS, XAMPP, WAMP), macOS, *BSD, shared hosting without shell access, managed PaaS (use the provider's advisory). |

The script prints this scope and what it detected on the host at the start of every run.

## What it checks

| Step | What |
|---|---|
| 0 | Environment: OS, package manager, container, hosting panels |
| 1 | PHP versions of every binary and `mod_php` module against the fixed releases; the distro package changelog is searched for the two CVE ids (distros backport without changing the version number) |
| 2 | Interim mitigations: `session.upload_progress.enabled`, `memory_limit=-1` enforced with `php_admin_value`, `pm.max_requests`, `post_max_size`, `fatal_error_backtraces` |
| 3 | Processes and connections: workers still running a replaced binary, shells/recon tools below a web process, connections owned by a child of a web process, outbound connections |
| 4 | Files: webshell patterns, PHP hidden in images, malicious `.htaccess`/`.user.ini`, PHP where Laravel/Symfony/Drupal/WordPress never keep PHP, `git status` against the committed code, dropped tools in `/tmp`, `/var/tmp`, `/dev/shm` |
| 5 | Persistence: web-account cron/keys/shell, `ld.so.preload`, extra UID 0, shell history of all accounts, SSH logins since the cutoff, changed system files |
| 6 | Access logs (combined, ISO-8601, JSON; `.gz`): PoC markers, `upload_progress`, POST 5xx, empty User-Agent, POST bursts, top POST targets; log paths are also read from the nginx/Apache configs |
| 7 | Error logs, syslog and application logs: memory exhaustion (`in Unknown on line 0`, clusters), worker crashes, segfaults |

## Options

`--since DATE` (`YYYY-MM-DD`, `YYYY-MM-DD HH:MM`, `DD.MM.YYYY`; host local time; default `2026-10-17`),
`--webroot PATH`, `--access-log GLOB`, `--error-log GLOB`, `--skip-files`, `--skip-logs`, `--skip-procs`
(also skips step 5), `--max-files N`, `--burst N`, `--sample N`, `--json FILE`, `--quiet`, `--no-color`, `--version`.

## Limits worth knowing

- Access logs contain no request bodies; memory disclosure and file reads leave no files on disk.
  If a host was exposed, rotate what the web user could read (framework keys, database/API/SMTP
  credentials, session secrets, TLS and deploy keys).
- Updating PHP and restarting all workers is the only complete fix. The interim mitigations only reduce exposure.
- Error-log lines without a time zone are read in the host's local time.

## Testing status

Developed and tested on synthetic fixtures: planted webshells, forged timestamps, nginx/Apache/Caddy/JSON
logs, syslog without a year, a Laravel project with a git checkout, SSH log lines, fake PHP-FPM processes and a
mocked `ss`. **Not yet exercised on production hosts**: PHP configuration on real `/etc/php` layouts with several
pools, `mod_php` and `rpm` paths, log discovery on real multi-vhost configs, `git status` on repositories owned by
another user, `journalctl`. Review the first results by hand.

## Versions

Releases are git tags (`v1.0.0` ... ), the script prints its own version (`--version`), and every change is
in [CHANGELOG.md](CHANGELOG.md). Mapping to the Slovenian URSIV order: [docs/URSIV-odredba.md](docs/URSIV-odredba.md).

## License

No license file yet. Add one before making the repository public.
