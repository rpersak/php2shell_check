# Changelog

All notable changes to `php2shell_check.py`. The format follows [Keep a Changelog](https://keepachangelog.com/); versions follow semantic versioning, where the command-line options and the report format are the public interface.

## [2.2.0] - 2026-10-22

### Added
- ISO-8601 (bracketed) and JSON-lines access logs (Caddy, nginx json), in addition to combined/common log format.
- Classic syslog lines without a year are parsed (most recent past date assumed); continuation lines inherit the previous timestamp.
- MEDIUM warning when fewer than half of the lines of an access log can be parsed.
- `--since` accepts `YYYY-MM-DD`, `YYYY-MM-DD HH:MM` and `DD.MM.YYYY`; layouts with slashes are refused because day/month order would be a guess; dates in the future are refused.
- Files with a modification time in the future are flagged (possible timestamp manipulation); the change time (ctime) is used for the cutoff.

### Changed
- All timestamp output goes through one helper that never raises; month names are read from a fixed English table, independent of the host locale.

### Fixed
- A forged or corrupt file timestamp (huge, negative, NaN) could abort a whole scan step.
- Access-log lines with an ISO timestamp were silently dropped instead of parsed.
- Syslog lines without a year were counted regardless of the cutoff, producing false positives from old entries.
- The shell-history check used only `mtime`; it now uses `max(mtime, ctime)`.

## [2.1.0] - 2026-10-22

### Added
- Shell history check (step 5) for `.bash_history`, `.zsh_history` and similar: reverse shells, download-and-run, decode-and-run, execution from temp directories, history tampering, PoC markers, `php -r` one-liners. A history file on a web account is flagged on its own. Secrets are masked in the output.

### Fixed
- The temp-directory execution pattern missed `chmod +x /tmp/a; /tmp/a`.

## [2.0.0] - 2026-10-22

### Added
- Live English narration of every step: plan at the start, a banner per step (what it does, why, when it flags), sub-action echo lines, a result line per step and a checklist at the end.
- `--quiet` for the final report only.
- Environment and scope detection (OS, package manager, container, hosting panels) with a printed list of supported / limited / unsupported systems.
- Alpine (`apk`) and cPanel EA-PHP support.
- `--version`; script version in the header and in the JSON report.
- Clean handling of `BrokenPipeError` and Ctrl+C.

### Changed
- Rebuilt from scratch around seven numbered steps.

## [1.0.0] - 2026-10-22

### Added
- First all-in-one checker: PHP versions with distro changelog (backport) check, configuration mitigations, processes and connections, webshell and `.htaccess` scan, persistence, access logs, error logs; exit codes 0/1/2 and `--json`.

