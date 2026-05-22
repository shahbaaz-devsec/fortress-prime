# Known Limitations — FORTRESS PRIME v1.1.2

This document is **not** a list of bugs we intend to ignore; it is an **honest
inventory** of what the tool currently does not cover, what it cannot safely
automate, and where its verifiers are intentionally lenient.

If you are evaluating FORTRESS PRIME for production use, read this first.

---

## 1. CIS / STIG Coverage

| Aspect | Honest status |
|--------|---------------|
| **CIS Level 1 Server** | ~80‑85% of *automatable* controls are implemented. Many remaining controls require manual inspection (partition layout, physical security, interactive PAM profiles, LDAP/Kerberos integration). |
| **CIS Level 2 Server** | Partial coverage. Several L2 controls (e.g., GRUB password, FIPS mode, immutable audit rules) are implemented, but many others are intentionally skipped because they break common operational patterns. |
| **DISA STIG** | We implement **STIG‑style** configurations (SSH ciphers, audit rules, PAM lockout, login banners). We do **not** ship a formal STIG compliance checklist or XCCDF results file. |
| **NIST SP 800‑53r5** | Every step maps to relevant control families (AC, AU, CM, IA, SC, SI), but the mapping is partial — no single step fully satisfies any NIST control on its own. |

---

## 2. What the Script Cannot Automate

### 2.1 Filesystem Mount Options (Step 09)
The script writes a **guidance file** (`/var/lib/fortress-prime/fstab-hardening.guide.txt`) but does not edit `/etc/fstab`. Editing fstab is too environment‑specific to automate safely. The operator must review the guide and apply options manually.

### 2.2 SUID/SGID Cleanup (Step 18)
The script creates an **inventory** of SUID/SGID binaries but does not remove setuid bits. Auto‑stripping SUID bits risks breaking essential system utilities (`sudo`, `passwd`, `newgrp`, etc.).

### 2.3 Root Account Lock (Step 20)
Root is locked **only** if the admin user exists and has a non‑empty `authorized_keys` file. If you skip creating an SSH key for the admin user, root remains unlocked — by design, to prevent lockout.

### 2.4 Compiler Permissions (Step 26)
The verifier reports `n/a` because compiler restriction is an **advisory** step. If compilers are not installed, the verifier notes this rather than passing/failing.

### 2.5 IPv6 Audit (Step 27)
The verifier now checks whether IPv6 hardening sysctls are applied, but it does not enforce a specific policy (disable vs. harden). IPv6 disable is available as an **opt‑in** feature (Step 54).

---

## 3. Verifier Behaviour

### 3.1 Opt‑in Steps
Steps 43 (haveged), 46 (ClamAV), 47 (USBGuard), and 54 (IPv6 disable) are **opt‑in**. If not enabled via CLI flags, they return `n/a` — not `fail`. Starting with v1.1.1, verifiers for USBGuard and IPv6 check **actual system state**, not just the CLI flag.

### 3.2 Fail2ban Timing (Step 04)
The fail2ban verifier retries for ~12 seconds because the jail may take a few seconds to populate after restart. On extremely busy systems, this retry may still be insufficient, causing a rare false `fail`. A manual check (`fail2ban-client status sshd`) confirms the actual state.

### 3.3 GDM Detection (Step 48)
The verifier checks the default systemd target and the presence of `gdm.service`. It may not detect other display managers (LightDM, SDDM, etc.) unless the target is `graphical.target`. Starting with v1.1.2, the verifier reports the actual default target and whether any known display manager is active.

---

## 4. Rollback Limitations

The `--rollback` script restores **file contents only**. It does **not**:

- Remove packages installed during the run
- Revert systemd unit state (enabled/disabled/masked)
- Remove UFW rules that were added
- Unload kernel modules that were blacklisted
- Revert sysctl runtime changes
- Remove the AIDE database
- Unlock the root account

**Rollback is a best‑effort safety net, not a full system restore.** Always take a VM snapshot before running in production.

---

## 5. Environment Constraints

| Environment | Status |
|-------------|--------|
| Ubuntu 24.04 LTS Server (x86‑64) | ✅ Tested |
| Ubuntu 24.04 LTS Desktop | ⚠️ Not tested; may disable services you need (step 17, step 48) |
| Ubuntu 22.04 / 26.04 | ❌ Not tested; OS‑version check will refuse to run |
| Debian 12/13 | ❌ Not tested |
| ARM64 (aarch64) | ❌ Not tested |
| LXC containers | ⚠️ UFW/auditd behave differently inside unprivileged containers |
| Cloud‑init concurrent runs | ⚠️ May conflict if cloud‑init is still running first‑boot setup |
| Air‑gapped systems | ❌ Package installation steps will fail without internet |

---

## 6. Interactions with Other Tools

- **Existing UFW rules** are **erased** by Step 03 (`ufw --force reset`). Capture custom rules before running.
- **Existing audit rules** are **replaced** by Step 11 (`-D` directive). Merge custom rules manually.
- **Other PAM configuration tools** (LDAP, SSSD, `pam-auth-update`) may conflict with Steps 08, 14, 38, 39, 48. Review `/etc/pam.d/` after hardening.
- **Other cron/at managers** (e.g., `cronie`, `fcron`) may not respect `/etc/cron.allow` permissions set by Step 16.

---

## 7. Security Claims We Do NOT Make

- ❌ We do not claim **100% CIS compliance** — a formal CIS‑CAT scan would score below 100%.
- ❌ We do not claim **FIPS 140‑3 validation** — we configure FIPS‑grade ciphers but do not enable FIPS mode kernel‑wide.
- ❌ We do not claim **Common Criteria certification**.
- ❌ We do not claim the script is **bug‑free** — see the [CHANGELOG](CHANGELOG.md) for past fixes.
- ❌ We do not claim the script handles **every Ubuntu 24.04 variant** — it has been tested on a minimal server install in a VM.

---

## 8. Future Work (v1.2.0+)

- Formal OpenSCAP scan integration (step with XCCDF results)
- AIDE baseline auto‑refresh after authorised package changes
- Full idempotency test suite (run each step twice, diff system state)
- Multi‑distro support (Debian, RHEL derivatives)
- Windows hardening counterpart
- Docker/Kubernetes CIS benchmark automation

---

*If you find a limitation not listed here, please open an issue — we keep this document current.*
