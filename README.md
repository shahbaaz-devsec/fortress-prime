# FORTRESS PRIME — Ubuntu 24.04 LTS Hardening & Audit Tool

**55‑step, single‑file Python hardening script for Ubuntu Server.**  
Aligns with **CIS Level 1 Server**, **DISA STIG‑style** settings, and **NIST SP 800‑53r5** controls.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.2-green)](https://github.com/shahbaaz-devsec/fortress-prime/releases)

```
███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
█████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```

> **One command. 55 controls. Fully verified.**  

---

## Quick Start

```bash
# 1. Download the script
wget https://raw.githubusercontent.com/shahbaaz-devsec/fortress-prime/main/fortress_prime.py

# 2. Make it executable
chmod +x fortress_prime.py

# 3. Preview changes (safe – shows what would be applied)
sudo ./fortress_prime.py --dry-run

# 4. Apply full hardening
sudo ./fortress_prime.py \
    --admin-user <your-admin> \
    --ssh-port 2222 \
    --allow-from 192.168.1.0/24 \
    --hostname <your-hostname> \
    --non-interactive

# 5. Verify posture (read‑only, no changes)
sudo ./fortress_prime.py --verify \
    --admin-user <your-admin> \
    --ssh-port 2222 \
    --non-interactive
```

---

## What It Does

FORTRESS PRIME applies and **verifies** 55 security controls covering:

| Category | Controls |
|----------|----------|
| **Access** | SSH key‑only, root locked, PAM password policies, faillock, `pam_pwhistory`, `su` restriction, `vlock` |
| **Network** | UFW default‑deny firewall, fail2ban SSH jail, PSAD port scan detector, DNS‑over‑TLS + DNSSEC |
| **Kernel** | 40 sysctl hardening parameters, 16 blacklisted modules, `hidepid=invisible`, `kexec`/`kdump` disable |
| **Filesystem** | AppArmor enforcing, `/proc hidepid=invisible`, sticky bits, AIDE file integrity, mount‑option guidance |
| **Audit & Logging** | Auditd with MITRE‑aligned rules, journald persistent+sealed, sysstat, rsyslog |
| **System** | Unattended‑upgrades, chrony time sync, coredumps disabled, cron/at restricted, umask 027, APT hardening, hostname set |
| **Opt‑in** | USBGuard, ClamAV, haveged, IPv6 disable |

All steps are **idempotent** (safe to re‑run), **backed up** before modification, and **verified** after application.  
A **JSON audit report** and a **rollback script** are generated on every run.

---

## Compliance Mapping

The tool aligns with the following frameworks:

| Framework | Coverage | Evidence |
|-----------|----------|----------|
| **CIS Ubuntu 24.04 L1 Server** | ~80% of automatable controls | All applied controls cite CIS section numbers |
| **DISA STIG V1R1** | STIG‑style configuration (network, audit, PAM, kernel) | Audit rules, SSH ciphers, login banners |
| **NIST SP 800‑53r5** | AC‑2, AC‑3, AC‑6, AC‑7, AC‑17, AU‑2, AU‑8, AU‑9, CM‑7, IA‑5, SC‑5, SC‑7, SC‑13, SI‑2, SI‑3, SI‑4, SI‑7 | Each step’s registry entry maps to specific controls |

---

## Requirements

- **Ubuntu 24.04 LTS Server** (x86‑64)
- Python 3.10 or later (standard library only)
- Internet access (for package installation)
- Root privileges (sudo)

> ⚠️ **Always test in a virtual machine first.** This tool makes deep system changes.

---

## Documentation

| File | Purpose |
|------|---------|
| [`SECURITY.md`](SECURITY.md) | How to report vulnerabilities |
| [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) | Honest list of what the tool doesn’t cover |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history and version notes |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute |

---

## Author

**Mohammad Shahbaaz Ahmed**  
- GitHub: [@shahbaaz-devsec](https://github.com/shahbaaz-devsec)  
- LinkedIn: [Mohammad Shahbaaz Ahmed](https://www.linkedin.com/in/mohammad-shahbaaz-ahmed-138a423bb)

---

## License

This project is licensed under the **Apache License 2.0** – see the [LICENSE](LICENSE) file for details.

---

## Acknowledgements

FORTRESS PRIME builds on decades of public hardening knowledge from the **Center for Internet Security**, the **Defense Information Systems Agency**, **NIST**, and the countless open‑source maintainers who ship the tools this script configures.
