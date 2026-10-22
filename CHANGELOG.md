# Changelog

All notable changes to `php2shell_check.py`. The format follows [Keep a Changelog](https://keepachangelog.com/); versions follow semantic versioning, where the command-line options and the report format are the public interface.

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

