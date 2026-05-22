# Changelog

All notable changes to FORTRESS PRIME are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.2] – 2026-05-22

### Changed
- Step 09 verifier now reports missing mount options (e.g., `/dev/shm` missing `noexec`)
- Step 26 verifier now reports when no compilers are installed on the system
- Step 27 verifier now checks IPv6 sysctl hardening, returning `pass` when appropriate
- Step 48 verifier provides detailed display manager and default target status
- License changed to **Apache License 2.0**

### Fixed
- Step 48 verifier no longer reports `fail` when GDM is not installed but default target is `graphical` – now correctly returns `pass` if no display manager is active

---

## [1.1.1] – 2026-05-22

### Fixed
- Step 47 (USBGuard) verifier now checks the actual systemd service state instead of the `--enable-usbguard` CLI flag
- Step 54 (Disable IPv6) verifier now checks the kernel parameter `net.ipv6.conf.all.disable_ipv6` instead of the `--disable-ipv6` CLI flag
- Step 48 (Disable GDM) verifier now returns `fail` when the default systemd target is `graphical.target` on a server profile
- Step 43 (haveged) and Step 46 (ClamAV) verifiers now check actual system state, not CLI flags

### Changed
- License updated to Apache 2.0

---

## [1.1.0] – 2026-05-22

### Added
- **25 new hardening steps (31–55)**
  - 31 – systemd‑resolved DNS‑over‑TLS + DNSSEC
  - 32 – PSAD (Port Scan Attack Detector)
  - 33 – `/proc` hidepid=invisible
  - 34 – Firmware update tooling (fwupd)
  - 35 – systemd‑journald hardening (persistent + sealed)
  - 36 – systemd‑logind hardening (idle lock, kill user processes, remove IPC)
  - 37 – Mask systemd debug‑shell service
  - 38 – PAM password history (`pam_pwhistory`)
  - 39 – `libpam‑tmpdir` (per‑user `/tmp`)
  - 40 – vlock (console session lock)
  - 41 – APT hardening (no unauthenticated, strict TLS, no recommends/suggests)
  - 42 – DPkg invoke hook for noexec `/tmp`
  - 43 – haveged entropy daemon (opt‑in)
  - 44 – Disable motd‑news and apt‑news
  - 45 – rkhunter daily scan
  - 46 – ClamAV (opt‑in, for mail/upload servers)
  - 47 – USBGuard (opt‑in, USB device whitelisting)
  - 48 – Disable GDM (server profile)
  - 49 – sysstat / sar performance monitoring
  - 50 – Remove `.rhosts` and `hosts.equiv`
  - 51 – No duplicate user accounts (verify‑only)
  - 52 – Only root has UID 0 (verify‑only)
  - 53 – Sticky bit on world‑writable directories
  - 54 – Disable IPv6 (opt‑in, NOT recommended)
  - 55 – Production readiness checklist
- New CLI flags: `--disable-ipv6`, `--enable-usbguard`, `--enable-clamav`, `--enable-haveged`

### Changed
- Extended step ID range to 01–55 with matching verifiers
- Verifier report summary now correctly shows `verify_pass` / `verify_fail` / `verify_na` counts
- Banner updated to v1.1.0

---

## [1.0.2] – 2026-05-22

### Fixed
- Dpkg lock contention: `_wait_for_apt_lock()` helper waits for unattended‑upgrades, apt‑daily, etc.
- Apt‑get retry with exponential backoff (up to 3 attempts)
- Fail2ban verifier now retries for up to 12 seconds while the jail populates

---

## [1.0.1] – 2026-05-19

### Fixed
- Step 20 no longer crashes with `KeyError` when the admin user does not yet exist (dry‑run guard added)

---

## [1.0.0] – 2026-05-19

### Added
- Initial release: 30 core hardening steps
- Self‑verification for every step
- JSON audit report generation
- Rollback ledger and automatic `rollback.sh` generation
- Dry‑run (`--dry-run`) and selective step execution (`--only`, `--skip`)
- Lockout‑safe SSH and firewall changes with self‑test
- Syslog + file + console logging
- Ubuntu 24.04 LTS pre‑flight check
