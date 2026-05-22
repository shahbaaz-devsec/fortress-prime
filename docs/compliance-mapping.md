# Compliance Mapping — FORTRESS PRIME v1.1.2

This document maps each hardening step to the relevant **CIS Ubuntu 24.04 L1 Server**
and **NIST SP 800‑53r5** controls. The references are extracted directly from the
tool’s step registry and are also included in every JSON audit report.

> **Disclaimer:** This mapping is a best‑effort alignment, not a formal compliance
> certification. Every step addresses a *subset* of the listed controls; full
> implementation of any NIST control requires organisational processes beyond what
> a single script can automate. See [KNOWN LIMITATIONS](../KNOWN_LIMITATIONS.md).

---

| ID | Step Name | CIS Reference | NIST SP 800‑53r5 |
|----|-----------|---------------|-------------------|
| 01 | Admin user + sudo + SSH key dir | 5.3 | AC‑2, AC‑6 |
| 02 | SSH server hardening (key‑only, modern crypto) | 5.2 | AC‑17, IA‑2, SC‑8, SC‑13 |
| 03 | Host firewall (ufw default‑deny + allowlist) | 3.5 | AC‑4, SC‑7 |
| 04 | Fail2ban for SSH brute‑force protection | 3.5, 5.2 | AC‑7, SI‑4 |
| 05 | Unattended security upgrades | 1.9 | SI‑2 |
| 06 | Kernel sysctls (network + memory + fs hardening) | 3.1, 3.2, 3.3 | SC‑5, SC‑7, SI‑4 |
| 07 | Kernel module blacklist (unused FS + protocols) | 1.1.1, 3.4 | CM‑7 |
| 08 | PAM password quality, aging, and lockout | 5.4 | IA‑5 |
| 09 | /etc/fstab hardening guidance (manual review) | 1.1 | CM‑7 |
| 10 | AppArmor mandatory access control | 1.6 | AC‑3 |
| 11 | Auditd with MITRE‑aligned rules | 4.1 | AU‑2, AU‑3, AU‑12 |
| 12 | AIDE file integrity monitoring | 1.4 | SI‑7 |
| 13 | Login banners | 1.7 | AC‑8 |
| 14 | Time synchronisation (chrony) | 2.2.1 | AU‑8 |
| 15 | Disable coredumps | 1.5 | SC‑7 |
| 16 | Restrict cron and at to root | 5.1 | AC‑6 |
| 17 | Disable unnecessary services | 2.1, 2.2 | CM‑7 |
| 18 | SUID/SGID inventory (advisory) | 6.1 | CM‑7 |
| 19 | Empty‑password account audit | 6.2.5 | IA‑5 |
| 20 | Lock root account (sudo‑only access) | 5.3 | AC‑6 |
| 21 | Process accounting (acct) | 4.1 | AU‑2 |
| 22 | rsyslog hardening | 4.2 | AU‑9 |
| 23 | Disable USB storage at runtime | 1.1.10 | MP‑7 |
| 24 | Hostname | 2.1 | CM‑6 |
| 25 | Default umask 027 system‑wide | 5.5 | AC‑6 |
| 26 | Compiler permissions (root group only) | 6.1 | CM‑7 |
| 27 | IPv6 audit (informational) | 3.3 | CM‑7 |
| 28 | Lynis baseline audit run | — | CA‑2 |
| 29 | SSH self‑test (lockout prevention) | — | — |
| 30 | System baseline snapshot | — | CM‑2 |
| 31 | systemd‑resolved DNS over TLS + DNSSEC | 3.5 | SC‑8, SC‑13 |
| 32 | PSAD — port scan attack detector | 3.5 | SI‑4 |
| 33 | /proc with hidepid=invisible | 1.1 | AC‑3, AC‑6 |
| 34 | Firmware update tooling (fwupd) | 1.9 | SI‑2 |
| 35 | systemd‑journald hardening (persistent + sealed) | 4.2 | AU‑9, AU‑11 |
| 36 | systemd‑logind hardening (idle lock, kill, remove IPC) | 1.5 | AC‑11, AC‑12 |
| 37 | Mask systemd debug‑shell service | 1.5 | CM‑7 |
| 38 | PAM password history (pam_pwhistory) | 5.4.3 | IA‑5 |
| 39 | libpam‑tmpdir (per‑user /tmp) | — | AC‑3 |
| 40 | vlock (console session lock) | — | AC‑11 |
| 41 | APT hardening (no unauth, strict TLS, no recommends) | 1.9 | CM‑5, SR‑3 |
| 42 | DPkg invoke hook for noexec /tmp | 1.1 | CM‑7 |
| 43 | haveged entropy daemon (opt‑in) | — | SC‑13 |
| 44 | Disable motd‑news and apt‑news | 1.7 | AC‑8 |
| 45 | rkhunter daily scan | — | SI‑3, SI‑4 |
| 46 | ClamAV (opt‑in, for mail/upload servers) | — | SI‑3 |
| 47 | USBGuard — USB device whitelisting (opt‑in) | 1.1.10 | MP‑7 |
| 48 | Disable GDM (server profile) | 1.8 | CM‑7 |
| 49 | sysstat / sar performance monitoring | — | AU‑2, AU‑12 |
| 50 | Remove .rhosts and hosts.equiv legacy r‑services | 6.2 | AC‑6 |
| 51 | No duplicate user accounts (verify) | 6.2.6, 6.2.7 | IA‑4 |
| 52 | Only root has UID 0 (verify) | 6.2.5 | AC‑6 |
| 53 | Sticky bit on world‑writable directories | 6.1 | AC‑6 |
| 54 | Disable IPv6 (opt‑in only; NOT recommended) | 3.3.1 | — |
| 55 | Production readiness checklist | — | PL‑2 |

---

## Framework Alignment Summary

| Framework | Coverage | Evidence |
|-----------|----------|----------|
| **CIS Ubuntu 24.04 L1 Server** | ~80‑85% of automatable controls | All applied controls cite CIS section numbers; verifier output confirms presence |
| **DISA STIG V1R1** | STIG‑style configuration | SSH ciphers, audit rules, PAM lockout, login banners, kernel parameters |
| **NIST SP 800‑53r5** | AC, AU, CM, IA, MP, PL, SC, SI families | Each step maps to specific controls; mapping is partial — no single step fully satisfies any NIST control |

*For an honest assessment of what is **not** covered, see `KNOWN_LIMITATIONS.md`.*
