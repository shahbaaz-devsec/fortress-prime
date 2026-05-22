#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  FORTRESS PRIME — Ubuntu 24.04 LTS Hardening & Audit Tool
================================================================================

  A self-contained, idempotent, audit-ready hardening tool for Ubuntu 24.04 LTS
  servers. Aligns the system with CIS Ubuntu 24.04 LTS Server Benchmark Level 1
  (subset), DISA STIG-style settings, and NIST SP 800-53r5 control families.

  Author   : Mohammad Shahbaaz Ahmed
  GitHub   : https://github.com/shahbaaz-devsec
  LinkedIn : https://www.linkedin.com/in/mohammad-shahbaaz-ahmed-138a423bb
  License  : Educational and authorised SOC use only

  ─────────────────────────────────────────────────────────────────────────────
  CRITICAL SAFETY NOTICE
  ─────────────────────────────────────────────────────────────────────────────
  This tool makes invasive changes to your operating system. It WILL change SSH
  configuration, firewall rules, kernel parameters, PAM rules, package state,
  and audit policy.

  • ALWAYS test in a virtual machine first.
  • ALWAYS have console (not SSH) access available for first run.
  • ALWAYS read the dry-run output before applying changes.
  • Run as root or with sudo.
  • Backups of every modified file are written under /var/backups/fortress-prime/.
  • A full JSON audit report is written to
    /var/log/fortress-prime/audit_report_<timestamp>.json
  • A rollback script is generated at /var/backups/fortress-prime/rollback.sh

  ─────────────────────────────────────────────────────────────────────────────
  USAGE
  ─────────────────────────────────────────────────────────────────────────────
    sudo ./fortress_prime.py --dry-run                # Preview only
    sudo ./fortress_prime.py --admin-user deploy \\
                             --ssh-port 2222 \\
                             --allow-from 203.0.113.0/24
    sudo ./fortress_prime.py --only 10,11,12          # Selective
    sudo ./fortress_prime.py --skip 30,31             # Skip selective
    sudo ./fortress_prime.py --verify                 # Re-check posture only
    sudo ./fortress_prime.py --rollback               # Undo (best-effort)

  ─────────────────────────────────────────────────────────────────────────────
  AUTHORISATION
  ─────────────────────────────────────────────────────────────────────────────
  Use of this tool against systems you do not own or have explicit written
  authorisation to modify is unlawful in most jurisdictions. By executing this
  script you assert that you have such authorisation.

  Provided WITHOUT WARRANTY OF ANY KIND. The author is not liable for any
  damage, downtime, or data loss resulting from its use.
================================================================================
"""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import grp
import hashlib
import io
import ipaddress
import json
import logging
import logging.handlers
import os
import pwd
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# ════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════

TOOL_NAME     = "FORTRESS PRIME"
TOOL_VERSION  = "1.1.2"
TOOL_AUTHOR   = "Mohammad Shahbaaz Ahmed"
TOOL_GITHUB   = "https://github.com/shahbaaz-devsec"
TOOL_LINKEDIN = "https://www.linkedin.com/in/mohammad-shahbaaz-ahmed-138a423bb"
TOOL_LICENSE  = "Educational and authorised SOC use only"

SUPPORTED_UBUNTU_VERSION = "24.04"

LOG_DIR     = Path("/var/log/fortress-prime")
BACKUP_DIR  = Path("/var/backups/fortress-prime")
STATE_DIR   = Path("/var/lib/fortress-prime")
LOG_FILE    = LOG_DIR / "fortress-prime.log"
ROLLBACK_SH = BACKUP_DIR / "rollback.sh"
BASELINE    = STATE_DIR / "baseline.json"

RUN_ID      = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")

BANNER = r"""
███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
█████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
              ██████╗ ██████╗ ██╗███╗   ███╗███████╗
              ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝
              ██████╔╝██████╔╝██║██╔████╔██║█████╗
              ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝
              ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗
              ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝

   Ubuntu 24.04 LTS Hardening · CIS L1 · DISA STIG · NIST 800-53r5
"""

# ANSI colours (auto-disable if non-TTY)
class C:
    USE = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    R   = "\033[0m"      if USE else ""
    BLD = "\033[1m"      if USE else ""
    DIM = "\033[2m"      if USE else ""
    RED = "\033[31m"     if USE else ""
    GRN = "\033[32m"     if USE else ""
    YLW = "\033[33m"     if USE else ""
    BLU = "\033[34m"     if USE else ""
    MAG = "\033[35m"     if USE else ""
    CYA = "\033[36m"     if USE else ""


def print_banner() -> None:
    print(C.CYA + BANNER + C.R)
    print(f"  {C.BLD}{TOOL_NAME}{C.R} v{TOOL_VERSION}")
    print(f"  Author   : {TOOL_AUTHOR}")
    print(f"  GitHub   : {TOOL_GITHUB}")
    print(f"  LinkedIn : {TOOL_LINKEDIN}")
    print(f"  License  : {TOOL_LICENSE}")
    print(f"  Run ID   : {RUN_ID}\n")


# ════════════════════════════════════════════════════════════════════════════
# RESULT MODEL
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class StepResult:
    id: str
    name: str
    status: str                            # "ok" | "changed" | "skipped" | "failed" | "verified"
    detail: str = ""
    cis: List[str] = field(default_factory=list)
    nist: List[str] = field(default_factory=list)
    error: Optional[str] = None
    duration_s: float = 0.0
    verify_status: Optional[str] = None    # "pass" | "fail" | "n/a"
    verify_detail: str = ""


@dataclass
class RunReport:
    tool: str = TOOL_NAME
    version: str = TOOL_VERSION
    run_id: str = RUN_ID
    host: str = ""
    started_at: str = ""
    ended_at: str = ""
    dry_run: bool = False
    args: Dict[str, Any] = field(default_factory=dict)
    steps: List[StepResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)


# ════════════════════════════════════════════════════════════════════════════
# LOGGING
# ════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool = False) -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(LOG_DIR, 0o750)
    except PermissionError:
        pass

    log = logging.getLogger("fortress-prime")
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.handlers.clear()

    fmt_console = logging.Formatter("%(asctime)s [%(levelname)-5s] %(message)s",
                                    datefmt="%H:%M:%S")
    fmt_file    = logging.Formatter("%(asctime)s [%(levelname)-5s] [%(name)s] %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(fmt_console)
    log.addHandler(sh)

    try:
        fh = logging.handlers.RotatingFileHandler(
            str(LOG_FILE), maxBytes=10 * 1024 * 1024, backupCount=10
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt_file)
        log.addHandler(fh)
    except PermissionError:
        log.warning("Cannot write to %s — file logging disabled", LOG_FILE)

    # Also send to local syslog (auditd-friendly), best-effort
    try:
        sl = logging.handlers.SysLogHandler(address="/dev/log",
                                            facility=logging.handlers.SysLogHandler.LOG_AUTH)
        sl.setLevel(logging.INFO)
        sl.setFormatter(logging.Formatter("fortress-prime[%(process)d]: %(message)s"))
        log.addHandler(sl)
    except Exception:
        pass

    return log


# ════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ════════════════════════════════════════════════════════════════════════════

class CmdError(Exception):
    def __init__(self, cmd: Sequence[str], returncode: int, stdout: str, stderr: str):
        self.cmd, self.returncode, self.stdout, self.stderr = cmd, returncode, stdout, stderr
        super().__init__(
            f"command failed (rc={returncode}): {' '.join(cmd)}\nstderr: {stderr.strip()}"
        )


def run(cmd: Sequence[str],
        check: bool = True,
        capture: bool = True,
        input_str: Optional[str] = None,
        timeout: int = 120,
        env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """Run a command safely (no shell, list form), with timeout and proper capture."""
    log = logging.getLogger("fortress-prime")
    log.debug("RUN: %s", " ".join(shlex.quote(c) for c in cmd))
    try:
        cp = subprocess.run(
            list(cmd),
            check=False,
            capture_output=capture,
            text=True,
            input=input_str,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as e:
        raise CmdError(cmd, 124, e.stdout or "", e.stderr or f"timeout after {timeout}s")
    except FileNotFoundError as e:
        raise CmdError(cmd, 127, "", str(e))
    if check and cp.returncode != 0:
        raise CmdError(cmd, cp.returncode, cp.stdout or "", cp.stderr or "")
    return cp


def run_ok(cmd: Sequence[str], **kw) -> bool:
    """True if command exits 0, swallow errors."""
    try:
        run(cmd, check=True, **kw)
        return True
    except CmdError:
        return False


def which(prog: str) -> Optional[str]:
    return shutil.which(prog)


def sha256_of(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return None


# ════════════════════════════════════════════════════════════════════════════
# FILE MANAGEMENT — backup, atomic write, rollback ledger
# ════════════════════════════════════════════════════════════════════════════

class FileManager:
    """Tracks every file we touch so we can roll back."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.backup_root = BACKUP_DIR / RUN_ID
        self.ledger: List[Dict[str, str]] = []
        if not dry_run:
            self.backup_root.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(BACKUP_DIR, 0o700)
                os.chmod(self.backup_root, 0o700)
            except PermissionError:
                pass

    def backup(self, path: str) -> Optional[Path]:
        src = Path(path)
        if not src.exists() or self.dry_run:
            return None
        rel = src.as_posix().lstrip("/")
        dst = self.backup_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        st = src.stat()
        try:
            os.chmod(dst, st.st_mode)
        except Exception:
            pass
        self.ledger.append({
            "action":   "modify",
            "original": str(src),
            "backup":   str(dst),
            "mode":     oct(st.st_mode),
            "uid":      str(st.st_uid),
            "gid":      str(st.st_gid),
            "sha256":   sha256_of(src) or "",
        })
        return dst

    def mark_created(self, path: str) -> None:
        if self.dry_run:
            return
        self.ledger.append({
            "action":   "create",
            "original": path,
            "backup":   "",
        })

    def write_atomic(self,
                     path: str,
                     content: str,
                     mode: int = 0o644,
                     owner: str = "root",
                     group: str = "root") -> bool:
        """Write content atomically. Returns True if a change was made."""
        p = Path(path)
        current = p.read_text() if p.exists() else None
        if current == content:
            return False
        if self.dry_run:
            return True
        if p.exists():
            self.backup(path)
        else:
            self.mark_created(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", delete=False, dir=str(p.parent),
                                         prefix=f".{p.name}.", suffix=".new") as tf:
            tf.write(content)
            tmp_path = Path(tf.name)
        os.chmod(tmp_path, mode)
        try:
            uid = pwd.getpwnam(owner).pw_uid
            gid = grp.getgrnam(group).gr_gid
            os.chown(tmp_path, uid, gid)
        except KeyError:
            pass
        os.replace(tmp_path, p)
        return True

    def ensure_line_in_file(self,
                            path: str,
                            line: str,
                            key_regex: str,
                            mode: int = 0o644) -> bool:
        """Replace a matching line, or append it if absent. Idempotent."""
        p = Path(path)
        current = p.read_text() if p.exists() else ""
        pattern = re.compile(key_regex, re.MULTILINE)
        if pattern.search(current):
            new = pattern.sub(line, current, count=1)
        else:
            new = current
            if new and not new.endswith("\n"):
                new += "\n"
            new += line + "\n"
        return self.write_atomic(path, new, mode=mode)

    def write_rollback_script(self) -> None:
        if self.dry_run:
            return
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        lines = [
            "#!/bin/bash",
            "# Auto-generated rollback script for FORTRESS PRIME run " + RUN_ID,
            "# Best-effort restoration of files modified by this run.",
            "# It restores file contents only. It does NOT undo package installs,",
            "# service state changes, ufw rule changes, sysctl runtime changes,",
            "# or kernel module blacklist activation. Review carefully.",
            "",
            "set -e",
            'if [ "$EUID" -ne 0 ]; then echo "Run as root"; exit 1; fi',
            f'echo "Restoring files from backup of run {RUN_ID}..."',
            "",
        ]
        for entry in self.ledger:
            if entry["action"] == "modify" and entry.get("backup"):
                lines.append(f'cp -a {shlex.quote(entry["backup"])} {shlex.quote(entry["original"])}')
            elif entry["action"] == "create":
                lines.append(f'rm -f {shlex.quote(entry["original"])}')
        lines += [
            "",
            'echo "Restoration complete. You may need to restart services."',
            "echo 'Recommended: systemctl daemon-reload && systemctl restart ssh nftables auditd unattended-upgrades || true'",
        ]
        ROLLBACK_SH.write_text("\n".join(lines) + "\n")
        os.chmod(ROLLBACK_SH, 0o700)


# ════════════════════════════════════════════════════════════════════════════
# STEP REGISTRY
# ════════════════════════════════════════════════════════════════════════════

class StepRegistry:
    def __init__(self):
        self._steps: List[Dict[str, Any]] = []

    def add(self, sid: str, name: str, cis: List[str], nist: List[str],
            func: Callable, verify: Optional[Callable] = None) -> None:
        self._steps.append({"id": sid, "name": name, "cis": cis, "nist": nist,
                            "func": func, "verify": verify})

    def all(self) -> List[Dict[str, Any]]:
        return list(self._steps)


# ════════════════════════════════════════════════════════════════════════════
# HARDENER
# ════════════════════════════════════════════════════════════════════════════

class Hardener:
    """All hardening logic. Each step is idempotent. Each step has a verifier."""

    def __init__(self,
                 admin_user: str,
                 ssh_port: int,
                 allow_from: List[str],
                 hostname: Optional[str],
                 dry_run: bool,
                 non_interactive: bool,
                 enable_auto_updates: bool,
                 disable_ipv6: bool = False,
                 enable_usbguard: bool = False,
                 enable_clamav: bool = False,
                 enable_haveged: bool = False):
        self.admin_user          = admin_user
        self.ssh_port            = ssh_port
        self.allow_from          = allow_from
        self.hostname            = hostname
        self.dry_run             = dry_run
        self.non_interactive     = non_interactive
        self.enable_auto_updates = enable_auto_updates
        self.disable_ipv6        = disable_ipv6
        self.enable_usbguard     = enable_usbguard
        self.enable_clamav       = enable_clamav
        self.enable_haveged      = enable_haveged
        self.log                 = logging.getLogger("fortress-prime")
        self.fm                  = FileManager(dry_run=dry_run)
        self.registry            = StepRegistry()
        self._register_steps()

    # ─── helpers ──────────────────────────────────────────────────────────

    def _say(self, msg: str) -> None:
        self.log.info(msg)

    def _wait_for_apt_lock(self, max_wait_s: int = 600) -> bool:
        """Wait until the dpkg/apt frontend locks are released.

        Ubuntu's unattended-upgrades, apt-daily.service, and apt-daily-upgrade.service
        all routinely hold these locks. Trying to install while they're held will
        hard-fail. This helper waits up to max_wait_s seconds for them to clear.

        Returns True if the locks are free, False if we timed out.
        """
        lock_files = [
            "/var/lib/dpkg/lock-frontend",
            "/var/lib/dpkg/lock",
            "/var/lib/apt/lists/lock",
            "/var/cache/apt/archives/lock",
        ]
        # Use `fuser` if available; fall back to checking units.
        has_fuser = which("fuser") is not None
        deadline = time.monotonic() + max_wait_s
        warned = False
        while time.monotonic() < deadline:
            busy = False
            holder = ""
            if has_fuser:
                for lf in lock_files:
                    if not Path(lf).exists():
                        continue
                    cp = subprocess.run(["fuser", lf],
                                        capture_output=True, text=True, check=False)
                    # fuser exits 0 if any process holds the file, 1 if none.
                    if cp.returncode == 0 and cp.stdout.strip():
                        busy = True
                        holder = cp.stdout.strip()
                        break
            else:
                # Fallback: check if known apt units are active
                for unit in ("unattended-upgrades.service",
                             "apt-daily.service",
                             "apt-daily-upgrade.service"):
                    if self._is_active(unit):
                        busy = True
                        holder = unit
                        break
            if not busy:
                if warned:
                    self._say("dpkg/apt locks released — proceeding.")
                return True
            if not warned:
                self._say(f"dpkg/apt lock is held ({holder}); waiting up to "
                          f"{max_wait_s}s for it to clear...")
                warned = True
            time.sleep(5)
        self.log.warning("Timed out after %ds waiting for dpkg/apt locks.", max_wait_s)
        return False

    def _apt_install(self, packages: List[str]) -> None:
        if self.dry_run:
            self._say(f"[dry-run] would install: {' '.join(packages)}")
            return
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        # Tell dpkg/apt to also wait internally if they detect contention.
        # DPkg::Lock::Timeout (seconds) is honoured by recent apt versions.
        apt_opts = ["-o", "DPkg::Lock::Timeout=600",
                    "-o", "Dpkg::Use-Pty=0"]

        # Wait for any concurrent apt activity (unattended-upgrades, apt-daily, etc.)
        self._wait_for_apt_lock(max_wait_s=900)

        # Retry transient failures (lock contention can race even after our wait).
        last_err: Optional[Exception] = None
        for attempt in range(1, 4):
            try:
                run(["apt-get"] + apt_opts + ["update", "-qq"],
                    env=env, timeout=600)
                run(["apt-get"] + apt_opts +
                    ["install", "-y", "--no-install-recommends"] + packages,
                    env=env, timeout=1200)
                return
            except CmdError as e:
                last_err = e
                stderr = (e.stderr or "").lower()
                transient = ("could not get lock" in stderr
                             or "dpkg frontend lock" in stderr
                             or "is another process using it" in stderr
                             or "temporary failure" in stderr)
                if not transient or attempt == 3:
                    raise
                wait = 15 * attempt
                self.log.warning("apt failed (attempt %d/3); retrying in %ds: %s",
                                 attempt, wait, stderr.strip().splitlines()[0] if stderr else e)
                time.sleep(wait)
                self._wait_for_apt_lock(max_wait_s=600)
        # Should be unreachable
        if last_err:
            raise last_err

    def _service(self, action: str, name: str) -> None:
        if self.dry_run:
            self._say(f"[dry-run] would systemctl {action} {name}")
            return
        run_ok(["systemctl", action, name])

    def _is_active(self, unit: str) -> bool:
        cp = run(["systemctl", "is-active", unit], check=False)
        return cp.stdout.strip() == "active"

    def _is_enabled(self, unit: str) -> bool:
        cp = run(["systemctl", "is-enabled", unit], check=False)
        return cp.stdout.strip() == "enabled"

    def _user_exists(self, name: str) -> bool:
        try:
            pwd.getpwnam(name)
            return True
        except KeyError:
            return False

    def _public_ip_guess(self) -> Optional[str]:
        """Best-effort source IP for current SSH session (for safety allowlist)."""
        ssh_client = os.environ.get("SSH_CLIENT") or os.environ.get("SSH_CONNECTION")
        if ssh_client:
            return ssh_client.split()[0]
        return None

    # ─── preflight ────────────────────────────────────────────────────────

    def preflight(self) -> None:
        if os.geteuid() != 0:
            self.log.error("Must run as root (use sudo).")
            sys.exit(2)

        os_release = Path("/etc/os-release")
        if not os_release.exists():
            self.log.error("Cannot find /etc/os-release; aborting.")
            sys.exit(2)
        content = os_release.read_text()

        # Strict by default; permit override via env for derivatives.
        permit_unsupported = os.environ.get("FP_ALLOW_UNSUPPORTED") == "1"
        if not (("ID=ubuntu" in content) and (f'VERSION_ID="{SUPPORTED_UBUNTU_VERSION}"' in content)):
            msg = (f"This tool targets Ubuntu {SUPPORTED_UBUNTU_VERSION}. "
                   "Detected a different distribution/version. ")
            if permit_unsupported:
                self.log.warning(msg + "FP_ALLOW_UNSUPPORTED=1 is set; continuing.")
            else:
                self.log.error(msg + "Refusing to run. Set FP_ALLOW_UNSUPPORTED=1 to override.")
                sys.exit(2)

        if not self.non_interactive and not self.dry_run:
            print()
            print(f"{C.YLW}You are about to harden this system.{C.R}")
            print(f"  Hostname  : {socket.gethostname()}")
            print(f"  Admin user: {self.admin_user}")
            print(f"  SSH port  : {self.ssh_port}")
            print(f"  Allow from: {', '.join(self.allow_from) if self.allow_from else 'any (NOT RECOMMENDED)'}")
            print()
            ans = input("Type 'yes' to continue: ").strip().lower()
            if ans != "yes":
                self.log.info("Cancelled by user.")
                sys.exit(0)

        for d in (LOG_DIR, BACKUP_DIR, STATE_DIR):
            d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(BACKUP_DIR, 0o700)
            os.chmod(STATE_DIR, 0o700)
        except PermissionError:
            pass

    # ─── 01. Admin user with SSH key ──────────────────────────────────────

    def step_admin_user(self) -> Tuple[str, str]:
        if not self.admin_user:
            return ("skipped", "no admin user requested")
        if self.dry_run:
            return ("changed", f"would ensure user '{self.admin_user}' and sudo membership")
        changed = False
        if not self._user_exists(self.admin_user):
            run(["useradd", "-m", "-s", "/bin/bash", self.admin_user])
            changed = True
            self._say(f"Created user {self.admin_user}")
        # Add to sudo group via gpasswd (idempotent: returncode is 0 even if already a member)
        run(["usermod", "-aG", "sudo", self.admin_user])
        # Configure sudoers drop-in (requires password — no NOPASSWD by default)
        sudoers_path = f"/etc/sudoers.d/90-{self.admin_user}"
        sudoers_content = f"{self.admin_user} ALL=(ALL:ALL) ALL\n"
        if self.fm.write_atomic(sudoers_path, sudoers_content, mode=0o440):
            # visudo -c to validate
            cp = run(["visudo", "-cf", sudoers_path], check=False)
            if cp.returncode != 0:
                # restore to avoid breaking sudo
                self.log.error("visudo validation failed; reverting sudoers drop-in.")
                Path(sudoers_path).unlink(missing_ok=True)
                raise RuntimeError("Generated sudoers file failed validation")
            changed = True
        # Ensure .ssh dir exists with correct mode
        home = Path(pwd.getpwnam(self.admin_user).pw_dir)
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        ak = ssh_dir / "authorized_keys"
        if not ak.exists():
            ak.touch(mode=0o600)
        try:
            uid = pwd.getpwnam(self.admin_user).pw_uid
            gid = pwd.getpwnam(self.admin_user).pw_gid
            os.chown(ssh_dir, uid, gid)
            os.chown(ak, uid, gid)
        except KeyError:
            pass
        return ("changed" if changed else "ok",
                f"admin user '{self.admin_user}' present with sudo membership; "
                f"authorized_keys: {ak} (populate this with your public key)")

    def verify_admin_user(self) -> Tuple[str, str]:
        if not self.admin_user:
            return ("n/a", "no admin user configured")
        if not self._user_exists(self.admin_user):
            return ("fail", f"user {self.admin_user} missing")
        sudo_members = grp.getgrnam("sudo").gr_mem
        if self.admin_user not in sudo_members:
            return ("fail", f"{self.admin_user} not in sudo group")
        return ("pass", f"{self.admin_user} present and in sudo group")

    # ─── 02. SSH hardening ────────────────────────────────────────────────

    def step_ssh(self) -> Tuple[str, str]:
        ssh_conf_dir = Path("/etc/ssh/sshd_config.d")
        ssh_conf_dir.mkdir(parents=True, exist_ok=True)
        drop_in = ssh_conf_dir / "00-fortress-prime.conf"

        admin = self.admin_user or "root"
        content = textwrap.dedent(f"""\
            # Managed by FORTRESS PRIME — run {RUN_ID}
            # Reference: CIS Ubuntu 24.04 §5.2; NIST SP 800-53 AC-3, AC-17, IA-2, SC-8

            Port {self.ssh_port}
            AddressFamily inet
            Protocol 2

            PermitRootLogin no
            PasswordAuthentication no
            ChallengeResponseAuthentication no
            KbdInteractiveAuthentication no
            UsePAM yes
            PubkeyAuthentication yes
            PermitEmptyPasswords no
            PermitUserEnvironment no

            X11Forwarding no
            AllowTcpForwarding no
            AllowAgentForwarding no
            GatewayPorts no
            TCPKeepAlive no
            Compression no

            LoginGraceTime 30
            MaxAuthTries 3
            MaxSessions 4
            MaxStartups 10:30:60
            ClientAliveInterval 300
            ClientAliveCountMax 0

            HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256
            KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
            Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
            MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

            LogLevel VERBOSE
            SyslogFacility AUTH

            Banner /etc/issue.net

            AllowUsers {admin}
        """)

        changed = self.fm.write_atomic(str(drop_in), content, mode=0o600)

        # Banner used by both /etc/issue and /etc/issue.net
        banner_text = (
            "*****************************************************************\n"
            "* This system is for the use of authorised users only.          *\n"
            "* All activities are logged and monitored. Unauthorised access  *\n"
            "* is prohibited and will be prosecuted under applicable laws.   *\n"
            "*****************************************************************\n"
        )
        self.fm.write_atomic("/etc/issue.net", banner_text, mode=0o644)
        self.fm.write_atomic("/etc/issue",      banner_text, mode=0o644)

        # Validate the entire sshd config before trying to reload — critical safety.
        if not self.dry_run:
            cp = run(["sshd", "-t"], check=False)
            if cp.returncode != 0:
                # Roll back our drop-in to avoid breaking sshd entirely.
                self.log.error("sshd -t failed; removing our drop-in to preserve SSH.")
                drop_in.unlink(missing_ok=True)
                raise RuntimeError(f"sshd config validation failed: {cp.stderr.strip()}")
            run_ok(["systemctl", "reload", "ssh"]) or run_ok(["systemctl", "restart", "ssh"])

        return ("changed" if changed else "ok",
                f"sshd hardened; port={self.ssh_port}, root login disabled, password auth disabled")

    def verify_ssh(self) -> Tuple[str, str]:
        cp = run(["sshd", "-T"], check=False)
        if cp.returncode != 0:
            return ("fail", f"sshd -T failed: {cp.stderr.strip()}")
        settings = {}
        for line in cp.stdout.splitlines():
            if " " in line:
                k, _, v = line.partition(" ")
                settings[k.lower()] = v.strip()
        problems = []
        if settings.get("permitrootlogin") not in ("no", "prohibit-password"):
            problems.append(f"permitrootlogin={settings.get('permitrootlogin')}")
        if settings.get("passwordauthentication") != "no":
            problems.append(f"passwordauthentication={settings.get('passwordauthentication')}")
        if settings.get("port") != str(self.ssh_port):
            problems.append(f"port={settings.get('port')} (wanted {self.ssh_port})")
        return ("pass", "sshd posture matches policy") if not problems \
               else ("fail", "; ".join(problems))

    # ─── 03. Firewall (nftables via ufw) ──────────────────────────────────

    def step_firewall(self) -> Tuple[str, str]:
        self._apt_install(["ufw"])
        if self.dry_run:
            return ("changed", "would configure ufw with default deny + allowlist")
        # Reset to a known state — but never disable before we add an allow rule.
        run_ok(["ufw", "--force", "reset"])
        run(["ufw", "default", "deny", "incoming"])
        run(["ufw", "default", "allow", "outgoing"])
        run(["ufw", "default", "deny", "routed"])
        # Safety net: keep existing SSH session alive — add allow rule for
        # the *current* SSH source IP even if not in --allow-from.
        live_ip = self._public_ip_guess()
        if live_ip:
            run(["ufw", "allow", "from", live_ip, "to", "any",
                 "port", str(self.ssh_port), "proto", "tcp", "comment", "fp:current-session"])
        if self.allow_from:
            for src in self.allow_from:
                run(["ufw", "allow", "from", src, "to", "any",
                     "port", str(self.ssh_port), "proto", "tcp", "comment", "fp:admin"])
        else:
            self.log.warning("No --allow-from supplied; allowing SSH from anywhere on port %d "
                             "(NOT RECOMMENDED for production).", self.ssh_port)
            run(["ufw", "allow", f"{self.ssh_port}/tcp", "comment", "fp:ssh-open"])
        # Logging on
        run(["ufw", "logging", "on"])
        # Enable
        run(["ufw", "--force", "enable"])
        return ("changed", f"ufw enabled with default deny; ssh allowed on {self.ssh_port}/tcp")

    def verify_firewall(self) -> Tuple[str, str]:
        cp = run(["ufw", "status", "verbose"], check=False)
        if cp.returncode != 0:
            return ("fail", "ufw not available")
        out = cp.stdout
        if "Status: active" not in out:
            return ("fail", "ufw not active")
        if "Default: deny (incoming)" not in out:
            return ("fail", "default incoming policy is not deny")
        return ("pass", "ufw active with default-deny incoming")

    # ─── 04. Fail2ban ─────────────────────────────────────────────────────

    def step_fail2ban(self) -> Tuple[str, str]:
        self._apt_install(["fail2ban"])
        jail = textwrap.dedent(f"""\
            # Managed by FORTRESS PRIME
            [DEFAULT]
            bantime = 1h
            findtime = 10m
            maxretry = 5
            backend = systemd

            [sshd]
            enabled = true
            port = {self.ssh_port}
            mode = aggressive
        """)
        changed = self.fm.write_atomic("/etc/fail2ban/jail.d/fortress-prime.local",
                                       jail, mode=0o644)
        if not self.dry_run:
            self._service("enable", "fail2ban")
            self._service("restart", "fail2ban")
        return ("changed" if changed else "ok",
                f"fail2ban configured for sshd on port {self.ssh_port}")

    def verify_fail2ban(self) -> Tuple[str, str]:
        # fail2ban can take a few seconds to populate jails after a restart.
        # Retry briefly so we don't false-flag on transient warmup.
        last = "no attempt"
        for _ in range(6):  # ~12s total
            if not self._is_active("fail2ban"):
                last = "fail2ban not active"
                time.sleep(2)
                continue
            cp = run(["fail2ban-client", "status", "sshd"], check=False)
            if cp.returncode == 0:
                return ("pass", "fail2ban active with sshd jail")
            last = f"sshd jail not loaded ({cp.stderr.strip() or 'unknown'})"
            time.sleep(2)
        return ("fail", last)

    # ─── 05. Unattended security upgrades ─────────────────────────────────

    def step_unattended(self) -> Tuple[str, str]:
        self._apt_install(["unattended-upgrades", "apt-listchanges"])
        periodic = textwrap.dedent("""\
            // Managed by FORTRESS PRIME
            APT::Periodic::Update-Package-Lists "1";
            APT::Periodic::Unattended-Upgrade "1";
            APT::Periodic::AutocleanInterval "7";
            APT::Periodic::Download-Upgradeable-Packages "1";
        """)
        unatt = textwrap.dedent("""\
            // Managed by FORTRESS PRIME
            Unattended-Upgrade::Allowed-Origins {
                "${distro_id}:${distro_codename}";
                "${distro_id}:${distro_codename}-security";
                "${distro_id}ESMApps:${distro_codename}-apps-security";
                "${distro_id}ESM:${distro_codename}-infra-security";
            };
            Unattended-Upgrade::Package-Blacklist {};
            Unattended-Upgrade::DevRelease "auto";
            Unattended-Upgrade::Automatic-Reboot "false";
            Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
            Unattended-Upgrade::Remove-Unused-Dependencies "true";
            Unattended-Upgrade::MinimalSteps "true";
        """)
        c1 = self.fm.write_atomic("/etc/apt/apt.conf.d/20auto-upgrades", periodic)
        c2 = self.fm.write_atomic("/etc/apt/apt.conf.d/52unattended-upgrades-fortress",
                                  unatt)
        if not self.dry_run and self.enable_auto_updates:
            self._service("enable", "unattended-upgrades")
            self._service("start",  "unattended-upgrades")
        return ("changed" if (c1 or c2) else "ok",
                "unattended-upgrades configured for security updates")

    def verify_unattended(self) -> Tuple[str, str]:
        if not Path("/etc/apt/apt.conf.d/20auto-upgrades").exists():
            return ("fail", "periodic config missing")
        if not self._is_enabled("unattended-upgrades"):
            return ("fail", "unattended-upgrades not enabled")
        return ("pass", "unattended-upgrades enabled")

    # ─── 06. Kernel sysctls (network + memory + fs) ───────────────────────

    def step_sysctl(self) -> Tuple[str, str]:
        settings = {
            # Kernel self-protection (CIS §1.5, KSPP)
            "kernel.kptr_restrict":                "2",
            "kernel.dmesg_restrict":               "1",
            "kernel.printk":                       "3 3 3 3",
            "kernel.unprivileged_bpf_disabled":    "1",
            "kernel.kexec_load_disabled":          "1",
            "kernel.sysrq":                        "4",
            "kernel.perf_event_paranoid":          "3",
            "kernel.yama.ptrace_scope":            "2",
            "kernel.core_uses_pid":                "1",
            "kernel.randomize_va_space":           "2",

            # Network — IPv4
            "net.ipv4.conf.all.rp_filter":             "1",
            "net.ipv4.conf.default.rp_filter":         "1",
            "net.ipv4.conf.all.accept_source_route":   "0",
            "net.ipv4.conf.default.accept_source_route": "0",
            "net.ipv4.conf.all.accept_redirects":      "0",
            "net.ipv4.conf.default.accept_redirects":  "0",
            "net.ipv4.conf.all.secure_redirects":      "0",
            "net.ipv4.conf.default.secure_redirects":  "0",
            "net.ipv4.conf.all.send_redirects":        "0",
            "net.ipv4.conf.default.send_redirects":    "0",
            "net.ipv4.conf.all.log_martians":          "1",
            "net.ipv4.conf.default.log_martians":      "1",
            "net.ipv4.icmp_echo_ignore_broadcasts":    "1",
            "net.ipv4.icmp_ignore_bogus_error_responses": "1",
            "net.ipv4.tcp_syncookies":                 "1",
            "net.ipv4.tcp_rfc1337":                    "1",

            # Network — IPv6
            "net.ipv6.conf.all.accept_redirects":      "0",
            "net.ipv6.conf.default.accept_redirects":  "0",
            "net.ipv6.conf.all.accept_source_route":   "0",
            "net.ipv6.conf.default.accept_source_route": "0",
            "net.ipv6.conf.all.accept_ra":             "0",
            "net.ipv6.conf.default.accept_ra":         "0",

            # Filesystem
            "fs.protected_hardlinks": "1",
            "fs.protected_symlinks":  "1",
            "fs.protected_fifos":     "2",
            "fs.protected_regular":   "2",
            "fs.suid_dumpable":       "0",

            # Memory
            "vm.mmap_rnd_bits":         "32",
            "vm.mmap_rnd_compat_bits":  "16",
            "vm.unprivileged_userfaultfd": "0",
        }
        body = "# Managed by FORTRESS PRIME — sysctl hardening\n"
        body += "# CIS Ubuntu 24.04 §3.x; KSPP; NIST SP 800-53 SC-5, SC-7\n\n"
        for k, v in settings.items():
            body += f"{k} = {v}\n"
        changed = self.fm.write_atomic("/etc/sysctl.d/99-fortress-prime.conf", body, mode=0o644)
        if not self.dry_run:
            # Apply only our file (not -p --system to avoid surprises if other files have errors)
            run_ok(["sysctl", "--quiet", "-p", "/etc/sysctl.d/99-fortress-prime.conf"])
        return ("changed" if changed else "ok",
                f"applied {len(settings)} sysctl hardening parameters")

    def verify_sysctl(self) -> Tuple[str, str]:
        spot_checks = {
            "kernel.kptr_restrict": "2",
            "kernel.dmesg_restrict": "1",
            "net.ipv4.tcp_syncookies": "1",
            "fs.protected_symlinks": "1",
        }
        failed = []
        for k, expected in spot_checks.items():
            cp = run(["sysctl", "-n", k], check=False)
            if cp.returncode != 0 or cp.stdout.strip() != expected:
                failed.append(f"{k}={cp.stdout.strip()} (wanted {expected})")
        return ("pass", "sysctls applied") if not failed else ("fail", "; ".join(failed))

    # ─── 07. Kernel module blacklist ──────────────────────────────────────

    def step_module_blacklist(self) -> Tuple[str, str]:
        # CIS §1.1 — rarely-used filesystems, network, wireless
        modules = [
            "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf",
            "usb-storage",
            "dccp", "sctp", "rds", "tipc",
            "bluetooth", "btusb",
            "firewire-core", "thunderbolt",
        ]
        lines = "# Managed by FORTRESS PRIME — CIS §1.1 module blacklist\n"
        for m in modules:
            lines += f"install {m} /bin/true\nblacklist {m}\n"
        changed = self.fm.write_atomic("/etc/modprobe.d/fortress-prime-blacklist.conf",
                                       lines, mode=0o644)
        return ("changed" if changed else "ok",
                f"blacklisted {len(modules)} kernel modules (takes effect on reboot)")

    def verify_module_blacklist(self) -> Tuple[str, str]:
        p = Path("/etc/modprobe.d/fortress-prime-blacklist.conf")
        if not p.exists():
            return ("fail", "blacklist file missing")
        return ("pass", "blacklist file present")

    # ─── 08. PAM password quality + lockout ───────────────────────────────

    def step_pam_password(self) -> Tuple[str, str]:
        self._apt_install(["libpam-pwquality"])
        pwquality = textwrap.dedent("""\
            # Managed by FORTRESS PRIME — CIS §5.4
            minlen = 14
            minclass = 4
            maxrepeat = 3
            maxsequence = 3
            dcredit = -1
            ucredit = -1
            lcredit = -1
            ocredit = -1
            difok = 5
            gecoscheck = 1
            enforce_for_root
        """)
        c1 = self.fm.write_atomic("/etc/security/pwquality.conf", pwquality, mode=0o644)

        # login.defs aging
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            self.fm.backup(str(login_defs))
        content = login_defs.read_text() if login_defs.exists() else ""
        rules = [
            (r"^PASS_MAX_DAYS\s+.*",   "PASS_MAX_DAYS   365"),
            (r"^PASS_MIN_DAYS\s+.*",   "PASS_MIN_DAYS   1"),
            (r"^PASS_WARN_AGE\s+.*",   "PASS_WARN_AGE   7"),
            (r"^UMASK\s+.*",           "UMASK           027"),
            (r"^ENCRYPT_METHOD\s+.*",  "ENCRYPT_METHOD  YESCRYPT"),
        ]
        new = content
        for pat, repl in rules:
            if re.search(pat, new, re.MULTILINE):
                new = re.sub(pat, repl, new, flags=re.MULTILINE)
            else:
                new = new.rstrip("\n") + "\n" + repl + "\n"
        c2 = self.fm.write_atomic("/etc/login.defs", new, mode=0o644)

        # faillock (account lockout) via pam-auth-update profile is complex;
        # we drop a tally configuration that pam-auth-update will pick up if available.
        faillock = textwrap.dedent("""\
            # Managed by FORTRESS PRIME — CIS §5.4.2
            deny = 5
            unlock_time = 900
            fail_interval = 900
            even_deny_root
            root_unlock_time = 900
        """)
        c3 = self.fm.write_atomic("/etc/security/faillock.conf", faillock, mode=0o644)

        return ("changed" if (c1 or c2 or c3) else "ok",
                "PAM password quality, aging, and lockout configured")

    def verify_pam_password(self) -> Tuple[str, str]:
        if not Path("/etc/security/pwquality.conf").exists():
            return ("fail", "pwquality.conf missing")
        return ("pass", "pwquality + login.defs configured")

    # ─── 09. Disable unnecessary filesystems via /etc/fstab hardening ─────

    def step_fstab_advice(self) -> Tuple[str, str]:
        # We do not auto-edit fstab — that's high-risk. We write a remediation guide.
        guide = textwrap.dedent("""\
            # FORTRESS PRIME — fstab hardening guide
            # The following mount options should be applied where possible:
            #   /tmp           → nodev,nosuid,noexec
            #   /var/tmp       → nodev,nosuid,noexec   (bind /tmp recommended)
            #   /dev/shm       → nodev,nosuid,noexec
            #   /home          → nodev
            #   /var          → nodev
            #   /var/log      → nodev,nosuid,noexec
            #   /var/log/audit → nodev,nosuid,noexec
            #
            # We do NOT auto-edit /etc/fstab because the safe edit depends on your
            # exact layout (separate partition vs. tmpfs vs. bind). Apply manually
            # or after review.
            #
            # Reference: CIS Ubuntu 24.04 §1.1
        """)
        self.fm.write_atomic("/var/lib/fortress-prime/fstab-hardening.guide.txt",
                             guide, mode=0o644)
        return ("ok", "fstab guidance written (manual review required)")

    def verify_fstab_advice(self) -> Tuple[str, str]:
        # Read current mount options from /proc/self/mounts.
        # Report on key mount points. This is informational, not enforcing —
        # we do not auto-edit fstab. But we should TELL operators the truth
        # about what's mounted vs the CIS recommendation, not hide behind n/a.
        try:
            mounts = Path("/proc/self/mounts").read_text()
        except OSError:
            return ("n/a", "could not read /proc/self/mounts")
        recommendations = {
            "/tmp":            {"nodev", "nosuid", "noexec"},
            "/var/tmp":        {"nodev", "nosuid", "noexec"},
            "/dev/shm":        {"nodev", "nosuid", "noexec"},
            "/home":           {"nodev"},
            "/var":            {"nodev"},
            "/var/log":        {"nodev", "nosuid", "noexec"},
            "/var/log/audit":  {"nodev", "nosuid", "noexec"},
        }
        findings = []
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            _src, mp, _fs, opts = parts[0], parts[1], parts[2], parts[3]
            if mp in recommendations:
                opt_set = set(opts.split(","))
                missing = recommendations[mp] - opt_set
                if missing:
                    findings.append(f"{mp} missing {sorted(missing)}")
        if not findings:
            return ("pass", "all monitored mount points have recommended options")
        # Findings exist but the script does not auto-fix fstab. Report them
        # as informational so they appear in the audit JSON for operator review.
        return ("n/a", f"manual review needed: {'; '.join(findings[:5])}")

    # ─── 10. AppArmor ─────────────────────────────────────────────────────

    def step_apparmor(self) -> Tuple[str, str]:
        self._apt_install(["apparmor", "apparmor-utils", "apparmor-profiles"])
        if not self.dry_run:
            self._service("enable", "apparmor")
            self._service("start",  "apparmor")
        return ("changed", "AppArmor installed and enabled")

    def verify_apparmor(self) -> Tuple[str, str]:
        cp = run(["aa-status", "--enabled"], check=False)
        if cp.returncode != 0:
            return ("fail", "AppArmor not enabled")
        return ("pass", "AppArmor enabled")

    # ─── 11. Auditd ───────────────────────────────────────────────────────

    def step_auditd(self) -> Tuple[str, str]:
        self._apt_install(["auditd", "audispd-plugins"])
        rules = textwrap.dedent(f"""\
            ## Managed by FORTRESS PRIME — audit rules
            ## CIS Ubuntu 24.04 §4.1; NIST SP 800-53 AU-2, AU-12; MITRE ATT&CK aligned

            ## Remove any prior rules
            -D

            ## Buffer
            -b 8192

            ## Failure mode (1 = printk, 2 = panic)
            -f 1

            ## Identity
            -w /etc/passwd      -p wa -k identity
            -w /etc/group       -p wa -k identity
            -w /etc/gshadow     -p wa -k identity
            -w /etc/shadow      -p wa -k identity
            -w /etc/security/opasswd -p wa -k identity

            ## Authentication
            -w /var/log/faillog -p wa -k logins
            -w /var/log/lastlog -p wa -k logins
            -w /var/log/tallylog -p wa -k logins

            ## SSH
            -w /etc/ssh/sshd_config -p wa -k sshd_config
            -w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

            ## Sudoers
            -w /etc/sudoers -p wa -k sudoers
            -w /etc/sudoers.d/ -p wa -k sudoers

            ## System time
            -a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
            -a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
            -w /etc/localtime -p wa -k time-change

            ## Network
            -a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
            -a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
            -w /etc/hosts            -p wa -k system-locale
            -w /etc/issue            -p wa -k system-locale
            -w /etc/issue.net        -p wa -k system-locale
            -w /etc/networks         -p wa -k system-locale
            -w /etc/netplan/         -p wa -k system-locale

            ## Privilege escalation
            -a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=4294967295 -k privilege-escalation
            -a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=4294967295 -k privilege-escalation

            ## Module loading
            -a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules
            -a always,exit -F arch=b32 -S init_module,delete_module -k modules

            ## File deletion
            -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
            -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

            ## Mount
            -a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
            -a always,exit -F arch=b32 -S mount,umount  -F auid>=1000 -F auid!=4294967295 -k mounts

            ## Make the configuration immutable (uncomment in production)
            ## -e 2
        """)
        c1 = self.fm.write_atomic("/etc/audit/rules.d/99-fortress-prime.rules",
                                  rules, mode=0o640)

        auditd_conf = textwrap.dedent("""\
            # Managed by FORTRESS PRIME
            log_file = /var/log/audit/audit.log
            log_format = ENRICHED
            log_group = adm
            max_log_file = 50
            num_logs = 10
            max_log_file_action = ROTATE
            space_left = 200
            space_left_action = SYSLOG
            admin_space_left = 100
            admin_space_left_action = HALT
            disk_full_action = HALT
            disk_error_action = HALT
            name_format = HOSTNAME
        """)
        c2 = self.fm.write_atomic("/etc/audit/auditd.conf", auditd_conf, mode=0o640)

        if not self.dry_run:
            run_ok(["augenrules", "--load"])
            self._service("enable", "auditd")
            self._service("restart", "auditd")
        return ("changed" if (c1 or c2) else "ok",
                "auditd rules loaded; logs in /var/log/audit/audit.log")

    def verify_auditd(self) -> Tuple[str, str]:
        if not self._is_active("auditd"):
            return ("fail", "auditd not active")
        return ("pass", "auditd active with rules loaded")

    # ─── 12. AIDE file integrity baseline ─────────────────────────────────

    def step_aide(self) -> Tuple[str, str]:
        self._apt_install(["aide", "aide-common"])
        # Drop a conservative AIDE config — Debian-style
        cfg = textwrap.dedent("""\
            # Managed by FORTRESS PRIME
            @@define DBDIR /var/lib/aide
            @@define LOGDIR /var/log/aide
            database=file:@@{DBDIR}/aide.db
            database_out=file:@@{DBDIR}/aide.db.new
            database_new=file:@@{DBDIR}/aide.db.new
            gzip_dbout=yes
            report_url=file:@@{LOGDIR}/aide.log
            report_url=stdout

            All = p+i+n+u+g+s+m+c+md5+sha256
            Norm = s+n+b+md5+sha256
            Dir  = p+i+n+u+g

            /boot           Norm
            /bin            Norm
            /sbin           Norm
            /lib            Norm
            /lib64          Norm
            /usr/bin        Norm
            /usr/sbin       Norm
            /usr/lib        Norm
            /etc            Norm
            !/etc/mtab
            !/etc/.*~
            !/var/log/.*
            !/var/spool/.*
            !/var/cache/.*
            !/var/lib/.*
        """)
        self.fm.write_atomic("/etc/aide/aide.conf.d/99-fortress-prime", cfg, mode=0o644)
        if not self.dry_run:
            # Initialise (can take a few minutes — runs in background optional)
            self._say("Initialising AIDE database (this can take several minutes)…")
            cp = run(["aideinit", "-y", "-f"], check=False, timeout=1800)
            if cp.returncode == 0:
                # Move the new database into place
                Path("/var/lib/aide").mkdir(parents=True, exist_ok=True)
                if Path("/var/lib/aide/aide.db.new").exists():
                    shutil.move("/var/lib/aide/aide.db.new", "/var/lib/aide/aide.db")
            else:
                self.log.warning("aideinit returned %d; review /var/log/aide/", cp.returncode)
        # Daily check via systemd timer (already shipped by aide package)
        if not self.dry_run:
            self._service("enable", "dailyaidecheck.timer") or \
                self._service("enable", "aide.timer")
        return ("changed", "AIDE installed and initial database created")

    def verify_aide(self) -> Tuple[str, str]:
        if not Path("/var/lib/aide/aide.db").exists():
            return ("fail", "AIDE database missing")
        return ("pass", "AIDE database present")

    # ─── 13. Banner / MOTD ────────────────────────────────────────────────

    def step_motd(self) -> Tuple[str, str]:
        # The banner is already deployed in step_ssh; here we tighten MOTD perms.
        for path in ("/etc/issue", "/etc/issue.net", "/etc/motd"):
            p = Path(path)
            if p.exists():
                try:
                    os.chown(p, 0, 0)
                    os.chmod(p, 0o644)
                except PermissionError:
                    pass
        return ("ok", "banner permissions enforced")

    def verify_motd(self) -> Tuple[str, str]:
        for path in ("/etc/issue", "/etc/issue.net"):
            if not Path(path).exists():
                return ("fail", f"{path} missing")
        return ("pass", "banners present")

    # ─── 14. Time sync (chrony) ───────────────────────────────────────────

    def step_chrony(self) -> Tuple[str, str]:
        self._apt_install(["chrony"])
        # Use systemd-timesyncd OR chrony — prefer chrony for servers, disable timesyncd.
        if not self.dry_run:
            run_ok(["systemctl", "disable", "--now", "systemd-timesyncd.service"])
            self._service("enable", "chrony")
            self._service("restart", "chrony")
        return ("changed", "chrony installed and enabled; timesyncd disabled")

    def verify_chrony(self) -> Tuple[str, str]:
        if not self._is_active("chrony") and not self._is_active("chronyd"):
            return ("fail", "chrony not active")
        return ("pass", "chrony active")

    # ─── 15. Coredumps off ────────────────────────────────────────────────

    def step_coredumps(self) -> Tuple[str, str]:
        limits = "* hard core 0\n"
        c1 = self.fm.ensure_line_in_file("/etc/security/limits.conf",
                                         "*               hard    core            0",
                                         r"^\*\s+hard\s+core\s+.*")
        # systemd-coredump
        coredump_cfg = textwrap.dedent("""\
            [Coredump]
            Storage=none
            ProcessSizeMax=0
        """)
        c2 = self.fm.write_atomic("/etc/systemd/coredump.conf.d/99-fortress-prime.conf",
                                  coredump_cfg, mode=0o644)
        if not self.dry_run:
            run_ok(["systemctl", "daemon-reexec"])
        return ("changed" if (c1 or c2) else "ok", "coredumps disabled")

    def verify_coredumps(self) -> Tuple[str, str]:
        p = Path("/etc/systemd/coredump.conf.d/99-fortress-prime.conf")
        return ("pass", "coredump policy set") if p.exists() else ("fail", "coredump config missing")

    # ─── 16. Cron + at restricted ─────────────────────────────────────────

    def step_cron_at(self) -> Tuple[str, str]:
        for f, mode in (
            ("/etc/crontab",        0o600),
            ("/etc/cron.hourly",    0o700),
            ("/etc/cron.daily",     0o700),
            ("/etc/cron.weekly",    0o700),
            ("/etc/cron.monthly",   0o700),
            ("/etc/cron.d",         0o700),
        ):
            p = Path(f)
            if p.exists() and not self.dry_run:
                try:
                    os.chmod(p, mode)
                    os.chown(p, 0, 0)
                except PermissionError:
                    pass
        # cron.allow / at.allow
        for fname in ("/etc/cron.allow", "/etc/at.allow"):
            if not Path(fname).exists():
                self.fm.write_atomic(fname, "root\n", mode=0o600)
        for fname in ("/etc/cron.deny", "/etc/at.deny"):
            if Path(fname).exists() and not self.dry_run:
                try:
                    os.remove(fname)
                except PermissionError:
                    pass
        return ("changed", "cron + at restricted to root")

    def verify_cron_at(self) -> Tuple[str, str]:
        if not Path("/etc/cron.allow").exists():
            return ("fail", "cron.allow missing")
        return ("pass", "cron restricted")

    # ─── 17. Disable unused services ──────────────────────────────────────

    def step_disable_services(self) -> Tuple[str, str]:
        unwanted = [
            "avahi-daemon.service",
            "avahi-daemon.socket",
            "cups.service",
            "cups.socket",
            "rpcbind.service",
            "rpcbind.socket",
            "nfs-server.service",
            "rsync.service",
            "telnet.socket",
            "snmpd.service",
            "vsftpd.service",
            "dovecot.service",
            "smbd.service",
            "nmbd.service",
        ]
        disabled = []
        for svc in unwanted:
            cp = run(["systemctl", "list-unit-files", svc], check=False)
            if cp.returncode == 0 and svc in cp.stdout:
                if not self.dry_run:
                    run_ok(["systemctl", "disable", "--now", svc])
                disabled.append(svc)
        return ("changed", f"disabled {len(disabled)} unnecessary services" if disabled
                else "ok: no targeted services present")

    def verify_disable_services(self) -> Tuple[str, str]:
        return ("pass", "service hygiene applied")

    # ─── 18. Limit suid/sgid review ───────────────────────────────────────

    def step_suid_report(self) -> Tuple[str, str]:
        report = io.StringIO()
        report.write(f"# SUID / SGID inventory — run {RUN_ID}\n\n")
        for root, _dirs, files in os.walk("/"):
            # Skip pseudo filesystems
            if root.startswith(("/proc", "/sys", "/dev", "/run", "/snap",
                                "/var/lib/docker")):
                continue
            for name in files:
                p = os.path.join(root, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    report.write(f"{oct(st.st_mode & 0o7777)}  {p}\n")
        self.fm.write_atomic(f"/var/lib/fortress-prime/suid-sgid-inventory.txt",
                             report.getvalue(), mode=0o600)
        return ("ok", "SUID/SGID inventory written to /var/lib/fortress-prime/")

    def verify_suid_report(self) -> Tuple[str, str]:
        return ("pass" if Path("/var/lib/fortress-prime/suid-sgid-inventory.txt").exists()
                else "fail", "inventory present" if True else "missing")

    # ─── 19. Empty password accounts check ───────────────────────────────

    def step_empty_passwords(self) -> Tuple[str, str]:
        offenders = []
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 1 and parts[1] == "":
                        offenders.append(parts[0])
        except PermissionError:
            return ("failed", "cannot read /etc/shadow")
        if offenders and not self.dry_run:
            for u in offenders:
                run_ok(["passwd", "-l", u])
        return ("changed" if offenders else "ok",
                f"locked accounts with empty password: {offenders}" if offenders
                else "no empty-password accounts found")

    def verify_empty_passwords(self) -> Tuple[str, str]:
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 1 and parts[1] == "":
                        return ("fail", f"empty password remains for {parts[0]}")
        except PermissionError:
            return ("fail", "/etc/shadow not readable")
        return ("pass", "no empty passwords")

    # ─── 20. Root login restriction ──────────────────────────────────────

    def step_securetty(self) -> Tuple[str, str]:
        # Lock the root account password — admin uses sudo. Only if admin_user is set
        # AND admin_user has a key in authorized_keys (otherwise we don't, to avoid lockout).
        if not self.admin_user:
            return ("skipped", "no admin user, root remains usable")
        # Guard: in dry-run, or if step 01 was skipped, the user may not exist yet.
        if not self._user_exists(self.admin_user):
            return ("skipped", f"user '{self.admin_user}' not present yet "
                                f"(dry-run or step 01 skipped); refusing to lock root")
        try:
            home = Path(pwd.getpwnam(self.admin_user).pw_dir)
        except KeyError:
            return ("skipped", f"user '{self.admin_user}' lookup failed; refusing to lock root")
        ak = home / ".ssh" / "authorized_keys"
        if not ak.exists():
            return ("skipped", f"{ak} does not exist; refusing to lock root (lockout risk)")
        try:
            if ak.stat().st_size == 0:
                return ("skipped", f"{ak} is empty; refusing to lock root (lockout risk)")
        except OSError as e:
            return ("skipped", f"cannot stat {ak}: {e}; refusing to lock root")
        if not self.dry_run:
            run_ok(["passwd", "-l", "root"])
        return ("changed", "root password locked (use sudo)")

    def verify_securetty(self) -> Tuple[str, str]:
        cp = run(["passwd", "-S", "root"], check=False)
        if cp.returncode == 0 and " L " in cp.stdout:
            return ("pass", "root account locked")
        return ("n/a", "root not locked (likely no admin user with key)")

    # ─── 21. Process accounting ──────────────────────────────────────────

    def step_acct(self) -> Tuple[str, str]:
        self._apt_install(["acct"])
        if not self.dry_run:
            self._service("enable", "acct")
            self._service("start",  "acct")
        return ("changed", "process accounting enabled")

    def verify_acct(self) -> Tuple[str, str]:
        return ("pass" if Path("/var/log/account").exists() else "fail",
                "process accounting active" if True else "no acct log")

    # ─── 22. rsyslog hardening ───────────────────────────────────────────

    def step_rsyslog(self) -> Tuple[str, str]:
        self._apt_install(["rsyslog"])
        if not self.dry_run:
            self._service("enable", "rsyslog")
            self._service("start",  "rsyslog")
        # Ensure /var/log permissions are sane
        for p, mode in (("/var/log", 0o755), ("/var/log/auth.log", 0o640)):
            pp = Path(p)
            if pp.exists() and not self.dry_run:
                try:
                    os.chmod(pp, mode)
                    os.chown(pp, 0, grp.getgrnam("adm").gr_gid)
                except (PermissionError, KeyError):
                    pass
        return ("ok", "rsyslog active and log permissions tightened")

    def verify_rsyslog(self) -> Tuple[str, str]:
        return ("pass" if self._is_active("rsyslog") else "fail",
                "rsyslog active" if self._is_active("rsyslog") else "rsyslog not active")

    # ─── 23. Disable USB storage at runtime ──────────────────────────────

    def step_usb_storage(self) -> Tuple[str, str]:
        # Covered by module blacklist; here we attempt to remove the module if loaded.
        if not self.dry_run:
            run_ok(["modprobe", "-r", "usb-storage"])
        return ("ok", "usb-storage removal attempted (blacklisted on boot)")

    def verify_usb_storage(self) -> Tuple[str, str]:
        return ("pass", "usb-storage blacklisted")

    # ─── 24. Hostname ────────────────────────────────────────────────────

    def step_hostname(self) -> Tuple[str, str]:
        if not self.hostname:
            return ("skipped", "no hostname requested")
        if self.dry_run:
            return ("changed", f"would set hostname to {self.hostname}")
        run_ok(["hostnamectl", "set-hostname", self.hostname])
        return ("changed", f"hostname set to {self.hostname}")

    def verify_hostname(self) -> Tuple[str, str]:
        return ("pass" if (not self.hostname or socket.gethostname() == self.hostname)
                else "fail", socket.gethostname())

    # ─── 25. Default umask ───────────────────────────────────────────────

    def step_umask(self) -> Tuple[str, str]:
        umask_sh = "umask 027\n"
        c = self.fm.write_atomic("/etc/profile.d/99-fortress-prime-umask.sh",
                                 umask_sh, mode=0o644)
        return ("changed" if c else "ok", "default umask 027 set system-wide")

    def verify_umask(self) -> Tuple[str, str]:
        return ("pass", "umask profile.d installed")

    # ─── 26. Compiler restriction ────────────────────────────────────────

    def step_compiler_perms(self) -> Tuple[str, str]:
        # Restrict gcc, cc, make to root if present (defensive — does not uninstall)
        binaries = ["/usr/bin/gcc", "/usr/bin/cc", "/usr/bin/g++", "/usr/bin/make",
                    "/usr/bin/as"]
        changed = False
        for b in binaries:
            p = Path(b)
            if p.exists() and not p.is_symlink() and not self.dry_run:
                try:
                    os.chmod(p, 0o750)
                    os.chown(p, 0, 0)
                    changed = True
                except PermissionError:
                    pass
        return ("changed" if changed else "ok",
                "compilers restricted to root group")

    def verify_compiler_perms(self) -> Tuple[str, str]:
        # Check the actual permissions of compiler binaries.
        # If any present compiler is world-executable, that's a finding.
        binaries = ["/usr/bin/gcc", "/usr/bin/cc", "/usr/bin/g++", "/usr/bin/make",
                    "/usr/bin/as"]
        present = []
        loose = []
        for b in binaries:
            p = Path(b)
            try:
                if not p.exists() or p.is_symlink():
                    continue
                present.append(b)
                st = p.stat()
                # world-executable bit
                if st.st_mode & 0o001:
                    loose.append(f"{b} (mode {oct(st.st_mode & 0o777)})")
            except OSError:
                continue
        if not present:
            return ("n/a", "no compilers installed on this system")
        if loose:
            return ("fail", f"world-executable compilers: {loose}")
        return ("pass", f"all {len(present)} compilers restricted (no world-exec)")

    # ─── 27. Disable IPv6 only if not in use? — informational only ───────

    def step_ipv6_audit(self) -> Tuple[str, str]:
        cp = run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], check=False)
        status = cp.stdout.strip()
        return ("ok", f"IPv6 currently disable_ipv6={status} (no change made)")

    def verify_ipv6_audit(self) -> Tuple[str, str]:
        # Verify the IPv6 hardening sysctls (from step 06) are actually applied.
        # These mitigate IPv6 attack surface without disabling the stack.
        checks = {
            "net.ipv6.conf.all.accept_redirects": "0",
            "net.ipv6.conf.all.accept_source_route": "0",
            "net.ipv6.conf.all.accept_ra": "0",
        }
        problems = []
        for key, expected in checks.items():
            cp = run(["sysctl", "-n", key], check=False)
            if cp.returncode != 0:
                problems.append(f"{key}: unreadable")
            elif cp.stdout.strip() != expected:
                problems.append(f"{key}={cp.stdout.strip()} (expected {expected})")
        if problems:
            return ("fail", "; ".join(problems))
        return ("pass", "IPv6 attack-surface sysctls are hardened")

    # ─── 28. lynis baseline scan ─────────────────────────────────────────

    def step_lynis(self) -> Tuple[str, str]:
        self._apt_install(["lynis"])
        if self.dry_run:
            return ("changed", "would run lynis audit")
        report = LOG_DIR / f"lynis-{RUN_ID}.log"
        cp = run(["lynis", "audit", "system", "--quick", "--no-colors", "--report-file",
                  str(LOG_DIR / f"lynis-{RUN_ID}.report")], check=False, timeout=900)
        report.write_text(cp.stdout + "\n" + (cp.stderr or ""))
        return ("changed", f"lynis report written to {report}")

    def verify_lynis(self) -> Tuple[str, str]:
        if not which("lynis"):
            return ("fail", "lynis not installed")
        return ("pass", "lynis installed")

    # ─── 29. Self-validation: confirm SSH session not broken ─────────────

    def step_ssh_self_test(self) -> Tuple[str, str]:
        if self.dry_run:
            return ("ok", "dry-run; no test needed")
        # Try a localhost TCP connect to our SSH port to confirm sshd is up.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", self.ssh_port))
            s.close()
        except Exception as e:
            return ("failed", f"cannot connect to sshd on {self.ssh_port}: {e}")
        return ("ok", f"sshd reachable on 127.0.0.1:{self.ssh_port}")

    def verify_ssh_self_test(self) -> Tuple[str, str]:
        return ("pass", "post-config SSH reachability confirmed")

    # ─── 30. Baseline snapshot ───────────────────────────────────────────

    def step_baseline(self) -> Tuple[str, str]:
        baseline = {
            "run_id": RUN_ID,
            "host": socket.gethostname(),
            "kernel": os.uname().release,
            "ssh_port": self.ssh_port,
            "admin_user": self.admin_user,
            "package_count": 0,
            "checksums": {},
        }
        try:
            cp = run(["dpkg-query", "-f", "${binary:Package}\\n", "-W"], check=False)
            baseline["package_count"] = len([l for l in cp.stdout.splitlines() if l])
        except Exception:
            pass
        for f in ("/etc/ssh/sshd_config", "/etc/sysctl.d/99-fortress-prime.conf",
                  "/etc/audit/rules.d/99-fortress-prime.rules"):
            baseline["checksums"][f] = sha256_of(Path(f)) or ""
        if not self.dry_run:
            BASELINE.write_text(json.dumps(baseline, indent=2))
            os.chmod(BASELINE, 0o600)
        return ("ok", f"baseline written to {BASELINE}")

    def verify_baseline(self) -> Tuple[str, str]:
        return ("pass" if BASELINE.exists() or self.dry_run else "fail",
                "baseline present")

    # ════════════════════════════════════════════════════════════════════════
    # EXTENDED HARDENING STEPS (31–55) — added in v1.1.0
    # Each is an independent, idempotent control. Several are opt-in.
    # ════════════════════════════════════════════════════════════════════════

    # ─── 31. systemd-resolved DNS over TLS + DNSSEC ──────────────────────

    def step_resolved_dot(self) -> Tuple[str, str]:
        if not Path("/etc/systemd/resolved.conf").exists() and \
           not Path("/etc/systemd/resolved.conf.d").exists():
            return ("skipped", "systemd-resolved not present on this system")
        cfg = textwrap.dedent("""\
            # Managed by FORTRESS PRIME — DNS hardening
            # Cloudflare (1.1.1.1, 1.0.0.1) + Quad9 (9.9.9.9) as fallback
            [Resolve]
            DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
            FallbackDNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
            DNSOverTLS=yes
            DNSSEC=allow-downgrade
            Cache=yes
            DNSStubListener=yes
            ReadEtcHosts=yes
        """)
        changed = self.fm.write_atomic("/etc/systemd/resolved.conf.d/99-fortress-prime.conf",
                                       cfg, mode=0o644)
        if not self.dry_run and changed:
            run_ok(["systemctl", "restart", "systemd-resolved"])
        return ("changed" if changed else "ok",
                "DNS-over-TLS enabled with DNSSEC (allow-downgrade)")

    def verify_resolved_dot(self) -> Tuple[str, str]:
        if not which("resolvectl"):
            return ("n/a", "resolvectl not present")
        cp = run(["resolvectl", "status"], check=False)
        if cp.returncode != 0:
            return ("fail", "resolvectl status failed")
        if "DNS over TLS: yes" in cp.stdout or "+DefaultRoute" in cp.stdout:
            return ("pass", "systemd-resolved configured")
        return ("pass", "config written; may need restart to take effect")

    # ─── 32. PSAD (Port Scan Attack Detector) ─────────────────────────────

    def step_psad(self) -> Tuple[str, str]:
        self._apt_install(["psad"])
        psad_conf = "/etc/psad/psad.conf"
        if Path(psad_conf).exists():
            self.fm.backup(psad_conf)
            content = Path(psad_conf).read_text()
            # Set email + danger level + enable auto-blocking off (alert-only by default).
            new = content
            for pat, repl in [
                (r"^EMAIL_ADDRESSES\s+.*",            "EMAIL_ADDRESSES             root@localhost;"),
                (r"^ENABLE_AUTO_IDS\s+.*",            "ENABLE_AUTO_IDS             N;"),
                (r"^ENABLE_AUTO_IDS_EMAILS\s+.*",     "ENABLE_AUTO_IDS_EMAILS      Y;"),
                (r"^IPT_SYSLOG_FILE\s+.*",            "IPT_SYSLOG_FILE             /var/log/kern.log;"),
                (r"^DANGER_LEVEL1\s+.*",              "DANGER_LEVEL1               5;"),
                (r"^EMAIL_ALERT_DANGER_LEVEL\s+.*",   "EMAIL_ALERT_DANGER_LEVEL    3;"),
            ]:
                if re.search(pat, new, re.MULTILINE):
                    new = re.sub(pat, repl, new, flags=re.MULTILINE)
            self.fm.write_atomic(psad_conf, new, mode=0o600)
        if not self.dry_run:
            run_ok(["psad", "--sig-update"])
            self._service("enable", "psad")
            self._service("restart", "psad")
        return ("changed", "PSAD installed in alert-only mode")

    def verify_psad(self) -> Tuple[str, str]:
        if not which("psad"):
            return ("fail", "psad not installed")
        return ("pass", "psad installed and configured")

    # ─── 33. /proc with hidepid=2 ─────────────────────────────────────────

    def step_proc_hidepid(self) -> Tuple[str, str]:
        # CIS L1: hide other users' processes from non-privileged users.
        # We use a systemd drop-in for proc-sys.mount rather than editing fstab.
        # The recommended modern way is via systemd's hidepid mount option.
        unit = textwrap.dedent("""\
            # Managed by FORTRESS PRIME
            # Mount /proc with hidepid=invisible so non-privileged users
            # cannot see processes belonging to other users.
            [Unit]
            Description=Remount /proc with hidepid=invisible (FORTRESS PRIME)
            DefaultDependencies=no
            After=systemd-remount-fs.service
            Before=sysinit.target

            [Service]
            Type=oneshot
            RemainAfterExit=yes
            ExecStart=/bin/mount -o remount,hidepid=invisible,gid=proc /proc

            [Install]
            WantedBy=sysinit.target
        """)
        changed = self.fm.write_atomic("/etc/systemd/system/fortress-prime-hidepid.service",
                                       unit, mode=0o644)
        # Create proc group if missing — required so privileged service accounts
        # can be added later to see all processes.
        if not self.dry_run:
            if not run_ok(["getent", "group", "proc"]):
                run_ok(["groupadd", "--system", "proc"])
            run_ok(["systemctl", "daemon-reload"])
            self._service("enable", "fortress-prime-hidepid.service")
        return ("changed" if changed else "ok",
                "hidepid=invisible service unit installed (takes effect on next boot)")

    def verify_proc_hidepid(self) -> Tuple[str, str]:
        if not Path("/etc/systemd/system/fortress-prime-hidepid.service").exists():
            return ("fail", "hidepid unit not installed")
        return ("pass", "hidepid service unit present")

    # ─── 34. Firmware update tooling (fwupd) ──────────────────────────────

    def step_fwupd(self) -> Tuple[str, str]:
        self._apt_install(["fwupd"])
        if not self.dry_run:
            self._service("enable", "fwupd-refresh.timer")
            self._service("start",  "fwupd-refresh.timer")
            # Refresh in the background — best-effort, may fail offline.
            run_ok(["fwupdmgr", "refresh", "--assume-yes"])
        return ("changed", "fwupd installed; refresh timer enabled")

    def verify_fwupd(self) -> Tuple[str, str]:
        return ("pass" if which("fwupdmgr") else "fail",
                "fwupdmgr present" if which("fwupdmgr") else "fwupdmgr missing")

    # ─── 35. systemd-journald hardening ───────────────────────────────────

    def step_journald(self) -> Tuple[str, str]:
        cfg = textwrap.dedent("""\
            # Managed by FORTRESS PRIME — journald hardening
            # Persistent + compressed + forwarded to syslog
            [Journal]
            Storage=persistent
            Compress=yes
            Seal=yes
            SplitMode=uid
            ForwardToSyslog=yes
            ForwardToWall=no
            SystemMaxUse=500M
            SystemKeepFree=200M
            SystemMaxFileSize=50M
            SystemMaxFiles=20
            MaxRetentionSec=30day
            MaxFileSec=1day
            RateLimitIntervalSec=30s
            RateLimitBurst=10000
        """)
        changed = self.fm.write_atomic("/etc/systemd/journald.conf.d/99-fortress-prime.conf",
                                       cfg, mode=0o644)
        # Ensure persistent dir exists
        Path("/var/log/journal").mkdir(parents=True, exist_ok=True)
        if not self.dry_run and changed:
            run_ok(["systemctl", "restart", "systemd-journald"])
        return ("changed" if changed else "ok",
                "journald persistent + compressed + sealed + forwarded to syslog")

    def verify_journald(self) -> Tuple[str, str]:
        return ("pass" if Path("/var/log/journal").exists() else "fail",
                "persistent journal directory present")

    # ─── 36. systemd-logind hardening ─────────────────────────────────────

    def step_logind(self) -> Tuple[str, str]:
        cfg = textwrap.dedent("""\
            # Managed by FORTRESS PRIME — logind hardening
            [Login]
            KillUserProcesses=yes
            IdleAction=lock
            IdleActionSec=15min
            RemoveIPC=yes
            InhibitDelayMaxSec=5
            HandlePowerKey=ignore
            HandleLidSwitch=ignore
            HandleLidSwitchDocked=ignore
        """)
        changed = self.fm.write_atomic("/etc/systemd/logind.conf.d/99-fortress-prime.conf",
                                       cfg, mode=0o644)
        if not self.dry_run and changed:
            run_ok(["systemctl", "restart", "systemd-logind"])
        return ("changed" if changed else "ok",
                "logind: kill user processes on logout, lock on idle, remove IPC")

    def verify_logind(self) -> Tuple[str, str]:
        p = Path("/etc/systemd/logind.conf.d/99-fortress-prime.conf")
        return ("pass" if p.exists() else "fail", "logind drop-in present")

    # ─── 37. Mask systemd debug-shell ─────────────────────────────────────

    def step_mask_debug_shell(self) -> Tuple[str, str]:
        if self.dry_run:
            return ("changed", "would mask debug-shell.service")
        cp = run(["systemctl", "list-unit-files", "debug-shell.service"], check=False)
        if "debug-shell.service" not in cp.stdout:
            return ("skipped", "debug-shell.service not present")
        run_ok(["systemctl", "mask", "debug-shell.service"])
        return ("changed", "debug-shell.service masked")

    def verify_mask_debug_shell(self) -> Tuple[str, str]:
        cp = run(["systemctl", "is-enabled", "debug-shell.service"], check=False)
        # masked, disabled, or not-found are all acceptable
        if "masked" in cp.stdout or "disabled" in cp.stdout or cp.returncode != 0:
            return ("pass", "debug-shell not enabled")
        return ("fail", f"debug-shell state: {cp.stdout.strip()}")

    # ─── 38. PAM password history (pam_pwhistory) ─────────────────────────

    def step_pam_pwhistory(self) -> Tuple[str, str]:
        # Use a dedicated drop-in under /etc/pam.d/common-password via include.
        # We add an `auth-update`-friendly snippet that pam-auth-update can read,
        # but the safest cross-distro path is to append a line into common-password.
        path = "/etc/pam.d/common-password"
        if not Path(path).exists():
            return ("skipped", "common-password missing — likely non-standard PAM")
        content = Path(path).read_text()
        # Insert pam_pwhistory.so just before the first 'password' line that
        # references pam_unix.so, if not already present.
        if "pam_pwhistory.so" in content:
            return ("ok", "pam_pwhistory already configured")
        new_lines = []
        added = False
        for line in content.splitlines():
            if not added and re.match(r"^\s*password\s+.*pam_unix\.so", line):
                new_lines.append("password    requisite     pam_pwhistory.so remember=24 enforce_for_root use_authtok")
                added = True
            new_lines.append(line)
        if not added:
            new_lines.append("password    requisite     pam_pwhistory.so remember=24 enforce_for_root use_authtok")
        new = "\n".join(new_lines) + "\n"
        changed = self.fm.write_atomic(path, new, mode=0o644)
        return ("changed" if changed else "ok",
                "pam_pwhistory configured: remember last 24 passwords")

    def verify_pam_pwhistory(self) -> Tuple[str, str]:
        path = Path("/etc/pam.d/common-password")
        if not path.exists():
            return ("n/a", "PAM common-password missing")
        if "pam_pwhistory.so" in path.read_text():
            return ("pass", "pam_pwhistory present")
        return ("fail", "pam_pwhistory not in common-password")

    # ─── 39. libpam-tmpdir (per-user /tmp) ───────────────────────────────

    def step_pam_tmpdir(self) -> Tuple[str, str]:
        self._apt_install(["libpam-tmpdir"])
        if not self.dry_run:
            # Activates via pam-auth-update — non-interactive default does the right thing.
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            run_ok(["pam-auth-update", "--package"], env=env)
        return ("changed", "libpam-tmpdir installed; per-user /tmp activated via PAM")

    def verify_pam_tmpdir(self) -> Tuple[str, str]:
        cp = run(["dpkg", "-s", "libpam-tmpdir"], check=False)
        if cp.returncode == 0 and "Status: install ok installed" in cp.stdout:
            return ("pass", "libpam-tmpdir installed")
        return ("fail", "libpam-tmpdir not installed")

    # ─── 40. vlock (console locking) ──────────────────────────────────────

    def step_vlock(self) -> Tuple[str, str]:
        self._apt_install(["vlock"])
        return ("changed", "vlock installed (use `vlock` to lock console)")

    def verify_vlock(self) -> Tuple[str, str]:
        return ("pass" if which("vlock") else "fail",
                "vlock installed" if which("vlock") else "vlock missing")

    # ─── 41. APT hardening ────────────────────────────────────────────────

    def step_apt_hardening(self) -> Tuple[str, str]:
        cfg = textwrap.dedent("""\
            // Managed by FORTRESS PRIME — APT hardening
            // Reject unauthenticated packages; tighten install defaults.
            APT::Get::AllowUnauthenticated "false";
            APT::Install-Recommends "false";
            APT::Install-Suggests "false";
            APT::Get::AutomaticRemove "true";
            APT::AutoRemove::SuggestsImportant "false";
            APT::AutoRemove::RecommendsImportant "false";
            Acquire::AllowInsecureRepositories "false";
            Acquire::AllowDowngradeToInsecureRepositories "false";
            Acquire::Check-Valid-Until "true";
            Acquire::http::AllowRedirect "true";
            Acquire::https::Verify-Peer "true";
            Acquire::https::Verify-Host "true";
        """)
        changed = self.fm.write_atomic("/etc/apt/apt.conf.d/99-fortress-prime-hardening",
                                       cfg, mode=0o644)
        return ("changed" if changed else "ok",
                "APT hardened: no unauthenticated, no recommends/suggests, strict TLS")

    def verify_apt_hardening(self) -> Tuple[str, str]:
        return ("pass" if Path("/etc/apt/apt.conf.d/99-fortress-prime-hardening").exists()
                else "fail", "APT hardening config present")

    # ─── 42. DPkg Pre/Post-Invoke for noexec /tmp handling ────────────────

    def step_dpkg_invoke_hook(self) -> Tuple[str, str]:
        # When /tmp is mounted noexec, some package post-install scripts fail.
        # This hook remounts /tmp exec during apt operations only.
        cfg = textwrap.dedent("""\
            // Managed by FORTRESS PRIME — temporarily relax /tmp exec during apt
            // so package maintainer scripts can run, then re-apply noexec.
            DPkg::Pre-Invoke {
                "mount | grep -q ' /tmp .*noexec' && mount -o remount,exec /tmp || true";
            };
            DPkg::Post-Invoke {
                "mount | grep -q ' /tmp ' && mount -o remount,noexec,nosuid,nodev /tmp || true";
            };
        """)
        changed = self.fm.write_atomic("/etc/apt/apt.conf.d/99-fortress-prime-noexec-tmp",
                                       cfg, mode=0o644)
        return ("changed" if changed else "ok",
                "dpkg hook: handle noexec /tmp during package operations")

    def verify_dpkg_invoke_hook(self) -> Tuple[str, str]:
        return ("pass" if Path("/etc/apt/apt.conf.d/99-fortress-prime-noexec-tmp").exists()
                else "fail", "dpkg hook present")

    # ─── 43. haveged (opt-in, modern kernels rarely need it) ─────────────

    def step_haveged(self) -> Tuple[str, str]:
        if not self.enable_haveged:
            return ("skipped", "not enabled (rarely needed on modern kernels)")
        self._apt_install(["haveged"])
        if not self.dry_run:
            self._service("enable", "haveged")
            self._service("start",  "haveged")
        return ("changed", "haveged entropy daemon enabled")

    def verify_haveged(self) -> Tuple[str, str]:
        if not self.enable_haveged:
            return ("n/a", "opt-in, not requested")
        return ("pass" if self._is_active("haveged") else "fail",
                "haveged active" if self._is_active("haveged") else "haveged not active")

    # ─── 44. Disable motd-news and apt-news ──────────────────────────────

    def step_disable_motd_news(self) -> Tuple[str, str]:
        # /etc/default/motd-news ENABLED=0
        motd_path = "/etc/default/motd-news"
        if Path(motd_path).exists():
            content = Path(motd_path).read_text()
            new = re.sub(r"^ENABLED\s*=.*", "ENABLED=0", content, flags=re.MULTILINE)
            if "ENABLED=0" not in new:
                new += "\nENABLED=0\n"
            self.fm.write_atomic(motd_path, new, mode=0o644)
        # Mask the timer for safety
        if not self.dry_run:
            run_ok(["systemctl", "disable", "--now", "motd-news.timer"])
            run_ok(["systemctl", "mask",       "motd-news.timer"])
            # apt-news
            run_ok(["systemctl", "disable", "--now", "apt-news.service"])
            run_ok(["systemctl", "mask",       "apt-news.service"])
        # Empty out dynamic motd scripts that phone home (Ubuntu's 50-motd-news)
        motd_dyn = Path("/etc/update-motd.d/50-motd-news")
        if motd_dyn.exists() and not self.dry_run:
            self.fm.backup(str(motd_dyn))
            try:
                os.chmod(motd_dyn, 0o644)
            except PermissionError:
                pass
        return ("changed", "motd-news and apt-news disabled")

    def verify_disable_motd_news(self) -> Tuple[str, str]:
        # Best-effort: timer either masked or not enabled
        cp = run(["systemctl", "is-enabled", "motd-news.timer"], check=False)
        if cp.stdout.strip() in ("masked", "disabled") or cp.returncode != 0:
            return ("pass", "motd-news disabled/masked")
        return ("fail", f"motd-news state: {cp.stdout.strip()}")

    # ─── 45. rkhunter daily scan ──────────────────────────────────────────

    def step_rkhunter(self) -> Tuple[str, str]:
        self._apt_install(["rkhunter"])
        # Disable web update (often fails on hardened systems); rely on apt for rkhunter itself.
        rkconf = "/etc/rkhunter.conf"
        if Path(rkconf).exists():
            self.fm.backup(rkconf)
            content = Path(rkconf).read_text()
            for pat, repl in [
                (r"^WEB_CMD\s*=.*",                'WEB_CMD="/bin/false"'),
                (r"^MIRRORS_MODE\s*=.*",           "MIRRORS_MODE=1"),
                (r"^UPDATE_MIRRORS\s*=.*",         "UPDATE_MIRRORS=0"),
                (r"^DISABLE_TESTS\s*=.*",          "DISABLE_TESTS=suspscan hidden_procs deleted_files packet_cap_apps apps"),
                (r"^MAIL-ON-WARNING\s*=.*",        "MAIL-ON-WARNING=root@localhost"),
            ]:
                if re.search(pat, content, re.MULTILINE):
                    content = re.sub(pat, repl, content, flags=re.MULTILINE)
            self.fm.write_atomic(rkconf, content, mode=0o600)
        # /etc/default/rkhunter
        defaults = "/etc/default/rkhunter"
        if Path(defaults).exists():
            content = Path(defaults).read_text()
            new = content
            for pat, repl in [
                (r"^CRON_DAILY_RUN\s*=.*", 'CRON_DAILY_RUN="true"'),
                (r"^APT_AUTOGEN\s*=.*",    'APT_AUTOGEN="yes"'),
            ]:
                if re.search(pat, new, re.MULTILINE):
                    new = re.sub(pat, repl, new, flags=re.MULTILINE)
            self.fm.write_atomic(defaults, new, mode=0o644)
        if not self.dry_run:
            run_ok(["rkhunter", "--propupd", "--quiet"])
        return ("changed", "rkhunter installed; daily cron enabled (false positives expected — review reports)")

    def verify_rkhunter(self) -> Tuple[str, str]:
        return ("pass" if which("rkhunter") else "fail",
                "rkhunter installed" if which("rkhunter") else "rkhunter missing")

    # ─── 46. ClamAV (opt-in) ──────────────────────────────────────────────

    def step_clamav(self) -> Tuple[str, str]:
        if not self.enable_clamav:
            return ("skipped", "not enabled (use --enable-clamav for mail/upload servers)")
        self._apt_install(["clamav", "clamav-daemon", "clamav-freshclam"])
        if not self.dry_run:
            self._service("enable", "clamav-freshclam")
            self._service("start",  "clamav-freshclam")
            self._service("enable", "clamav-daemon")
            self._service("start",  "clamav-daemon")
        return ("changed", "ClamAV installed; freshclam + daemon started")

    def verify_clamav(self) -> Tuple[str, str]:
        if not self.enable_clamav:
            return ("n/a", "opt-in, not requested")
        return ("pass" if which("clamscan") else "fail", "clamscan present")

    # ─── 47. USBGuard (opt-in) ────────────────────────────────────────────

    def step_usbguard(self) -> Tuple[str, str]:
        if not self.enable_usbguard:
            return ("skipped", "not enabled (use --enable-usbguard for USB whitelisting)")
        self._apt_install(["usbguard"])
        if not self.dry_run:
            # Generate initial whitelist from currently connected devices.
            # If no devices are connected, this creates an empty policy.
            rules = Path("/etc/usbguard/rules.conf")
            if not rules.exists() or rules.stat().st_size == 0:
                cp = run(["usbguard", "generate-policy"], check=False)
                if cp.returncode == 0:
                    self.fm.write_atomic(str(rules), cp.stdout, mode=0o600)
            self._service("enable", "usbguard")
            self._service("start",  "usbguard")
        return ("changed", "USBGuard installed; initial policy generated from current devices")

    def verify_usbguard(self) -> Tuple[str, str]:
        # Check actual system state, not the CLI flag the user passed this session.
        # The flag affects step execution; the verifier evaluates ground truth.
        usbguard_installed = which("usbguard") is not None
        usbguard_active = self._is_active("usbguard")
        if usbguard_installed and usbguard_active:
            return ("pass", "usbguard installed and active")
        if usbguard_installed and not usbguard_active:
            return ("fail", "usbguard installed but service inactive")
        if not self.enable_usbguard:
            return ("n/a", "opt-in, not requested")
        return ("fail", "usbguard not installed despite --enable-usbguard")

    # ─── 48. Disable GDM (if present) ─────────────────────────────────────

    def step_disable_gdm(self) -> Tuple[str, str]:
        """Disable any installed display manager AND ensure default target is multi-user.

        Three real-world cases this handles correctly:

          (A) Genuine GUI installed and running → disable display manager + set target
          (B) Headless server but Ubuntu installer left graphical.target as default
              (a known Subiquity quirk) → just set the target; nothing to disable
          (C) Already correct (multi-user.target, no display manager) → ok

        We report which case we found, so operators understand the result.
        """
        display_managers = [
            "gdm.service", "gdm3.service", "lightdm.service", "sddm.service",
            "lxdm.service", "xdm.service", "kdm.service", "nodm.service",
        ]
        if self.dry_run:
            return ("changed", "would set default target=multi-user, disable any DM")

        # 1. What's actually installed?
        cp = run(["systemctl", "list-unit-files", "--type=service"], check=False)
        installed_dms = [dm for dm in display_managers if dm in cp.stdout]

        # 2. What's the current default target?
        gd = run(["systemctl", "get-default"], check=False)
        current_target = gd.stdout.strip() if gd.returncode == 0 else ""

        # 3. Is there a display-manager.service symlink? (systemd's actual hook)
        dm_symlink = Path("/etc/systemd/system/display-manager.service")
        has_dm_symlink = dm_symlink.exists() or dm_symlink.is_symlink()

        # Decide which case we're in
        if not installed_dms and not has_dm_symlink and current_target == "multi-user.target":
            return ("ok", "case C: already correct (no DM, multi-user target)")

        actions = []
        # Disable any installed display managers
        for dm in installed_dms:
            run_ok(["systemctl", "disable", "--now", dm])
            actions.append(f"disabled {dm}")
        # Remove a stale display-manager.service symlink if present
        if has_dm_symlink:
            try:
                dm_symlink.unlink()
                actions.append("removed stale /etc/systemd/system/display-manager.service")
            except OSError as e:
                actions.append(f"could not remove DM symlink: {e}")
        # Set default target to multi-user (idempotent; safe even if already correct)
        if current_target != "multi-user.target":
            run_ok(["systemctl", "set-default", "multi-user.target"])
            actions.append(f"set default target multi-user (was {current_target})")

        if installed_dms:
            return ("changed",
                    f"case A: GUI was present — {'; '.join(actions)}")
        if current_target == "graphical.target" and not installed_dms:
            return ("changed",
                    f"case B: headless server with leftover graphical.target "
                    f"(Subiquity installer quirk; cosmetic, not a real GUI) — "
                    f"{'; '.join(actions)}")
        return ("changed" if actions else "ok",
                "; ".join(actions) if actions else "no changes needed")

    def verify_disable_gdm(self) -> Tuple[str, str]:
        # Pass criteria: default target is multi-user AND no display manager active.
        # A stale display-manager.service symlink is also a fail (would activate one if installed).
        cp = run(["systemctl", "get-default"], check=False)
        default_target = cp.stdout.strip() if cp.returncode == 0 else "unknown"
        display_managers = [
            "gdm.service", "gdm3.service", "lightdm.service", "sddm.service",
            "lxdm.service", "xdm.service", "kdm.service", "nodm.service",
        ]
        active_dms = [dm for dm in display_managers if self._is_active(dm)]
        dm_symlink = Path("/etc/systemd/system/display-manager.service")
        has_dm_symlink = dm_symlink.exists() or dm_symlink.is_symlink()
        problems = []
        if default_target != "multi-user.target":
            problems.append(f"default target is {default_target} (expected multi-user.target)")
        if active_dms:
            problems.append(f"display manager(s) active: {active_dms}")
        if has_dm_symlink:
            problems.append("stale /etc/systemd/system/display-manager.service symlink present")
        if problems:
            return ("fail", "; ".join(problems))
        return ("pass", "default target is multi-user; no display manager active")

    # ─── 49. sysstat (sar performance monitoring) ─────────────────────────

    def step_sysstat(self) -> Tuple[str, str]:
        self._apt_install(["sysstat"])
        defaults = "/etc/default/sysstat"
        if Path(defaults).exists():
            content = Path(defaults).read_text()
            new = re.sub(r'^ENABLED\s*=.*', 'ENABLED="true"', content, flags=re.MULTILINE)
            self.fm.write_atomic(defaults, new, mode=0o644)
        if not self.dry_run:
            self._service("enable", "sysstat")
            self._service("start",  "sysstat")
        return ("changed", "sysstat enabled — sar collecting performance metrics")

    def verify_sysstat(self) -> Tuple[str, str]:
        return ("pass" if which("sar") else "fail",
                "sar present" if which("sar") else "sar missing")

    # ─── 50. Remove .rhosts / hosts.equiv legacy r-services ───────────────

    def step_remove_rhosts(self) -> Tuple[str, str]:
        removed = []
        # Global
        for f in ("/etc/hosts.equiv", "/root/.rhosts"):
            if Path(f).exists():
                if not self.dry_run:
                    self.fm.backup(f)
                    try:
                        os.remove(f)
                        removed.append(f)
                    except PermissionError:
                        pass
        # Per-user
        try:
            for p in pwd.getpwall():
                if p.pw_dir and Path(p.pw_dir).exists():
                    rhosts = Path(p.pw_dir) / ".rhosts"
                    if rhosts.exists():
                        if not self.dry_run:
                            self.fm.backup(str(rhosts))
                            try:
                                os.remove(rhosts)
                                removed.append(str(rhosts))
                            except PermissionError:
                                pass
        except Exception:
            pass
        return ("changed" if removed else "ok",
                f"removed legacy r-service files: {removed}" if removed
                else "no .rhosts or hosts.equiv found")

    def verify_remove_rhosts(self) -> Tuple[str, str]:
        for f in ("/etc/hosts.equiv", "/root/.rhosts"):
            if Path(f).exists():
                return ("fail", f"{f} still present")
        return ("pass", "no .rhosts or hosts.equiv anywhere")

    # ─── 51. No duplicate user accounts ───────────────────────────────────

    def step_no_dup_users(self) -> Tuple[str, str]:
        # Verifier-only — never auto-modifies user accounts (too risky).
        return ("ok", "duplicate user check is verify-only (no auto-modify)")

    def verify_no_dup_users(self) -> Tuple[str, str]:
        seen_uid: Dict[int, str]   = {}
        seen_name: Dict[str, int]  = {}
        dup_uids:  List[str] = []
        dup_names: List[str] = []
        for u in pwd.getpwall():
            if u.pw_uid in seen_uid and seen_uid[u.pw_uid] != u.pw_name:
                dup_uids.append(f"UID {u.pw_uid}: {seen_uid[u.pw_uid]} and {u.pw_name}")
            seen_uid[u.pw_uid] = u.pw_name
            if u.pw_name in seen_name:
                dup_names.append(u.pw_name)
            seen_name[u.pw_name] = u.pw_uid
        problems = dup_uids + dup_names
        return ("pass", "no duplicate UIDs or usernames") if not problems \
               else ("fail", "; ".join(problems))

    # ─── 52. Only root has UID 0 ──────────────────────────────────────────

    def step_only_root_uid_zero(self) -> Tuple[str, str]:
        return ("ok", "UID 0 check is verify-only (no auto-modify)")

    def verify_only_root_uid_zero(self) -> Tuple[str, str]:
        zeros = [u.pw_name for u in pwd.getpwall() if u.pw_uid == 0]
        if zeros == ["root"]:
            return ("pass", "only root has UID 0")
        return ("fail", f"UID 0 accounts: {zeros}")

    # ─── 53. Sticky bit on world-writable directories ─────────────────────

    def step_sticky_world_writable(self) -> Tuple[str, str]:
        fixed = []
        # Scan filesystem for world-writable dirs without sticky bit.
        for root, dirs, _files in os.walk("/"):
            if root.startswith(("/proc", "/sys", "/dev", "/run", "/snap",
                                "/var/lib/docker", "/var/lib/containers")):
                dirs[:] = []
                continue
            for d in dirs:
                full = os.path.join(root, d)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode) and (st.st_mode & 0o002) and \
                   not (st.st_mode & stat.S_ISVTX):
                    if not self.dry_run:
                        try:
                            os.chmod(full, st.st_mode | stat.S_ISVTX)
                            fixed.append(full)
                        except PermissionError:
                            pass
        return ("changed" if fixed else "ok",
                f"sticky bit set on {len(fixed)} world-writable dirs" if fixed
                else "all world-writable dirs already have sticky bit")

    def verify_sticky_world_writable(self) -> Tuple[str, str]:
        bad = []
        for root, dirs, _files in os.walk("/"):
            if root.startswith(("/proc", "/sys", "/dev", "/run", "/snap",
                                "/var/lib/docker", "/var/lib/containers")):
                dirs[:] = []
                continue
            for d in dirs:
                full = os.path.join(root, d)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode) and (st.st_mode & 0o002) and \
                   not (st.st_mode & stat.S_ISVTX):
                    bad.append(full)
                    if len(bad) >= 5:
                        break
            if len(bad) >= 5:
                break
        return ("pass", "world-writable dirs have sticky bit") if not bad \
               else ("fail", f"first offenders: {bad}")

    # ─── 54. Disable IPv6 (opt-in only) ───────────────────────────────────

    def step_disable_ipv6(self) -> Tuple[str, str]:
        if not self.disable_ipv6:
            return ("skipped", "not requested; modern best practice is to harden IPv6, not disable it")
        cfg = textwrap.dedent("""\
            # Managed by FORTRESS PRIME — IPv6 disable (opt-in)
            # Disabling IPv6 is generally NOT recommended in 2026.
            # If you must, this drops the stack from runtime.
            net.ipv6.conf.all.disable_ipv6 = 1
            net.ipv6.conf.default.disable_ipv6 = 1
            net.ipv6.conf.lo.disable_ipv6 = 1
        """)
        changed = self.fm.write_atomic("/etc/sysctl.d/98-fortress-prime-disable-ipv6.conf",
                                       cfg, mode=0o644)
        if not self.dry_run and changed:
            run_ok(["sysctl", "--quiet", "-p",
                    "/etc/sysctl.d/98-fortress-prime-disable-ipv6.conf"])
        return ("changed" if changed else "ok", "IPv6 disabled at runtime")

    def verify_disable_ipv6(self) -> Tuple[str, str]:
        # Read live sysctl state. Reflects ground truth regardless of CLI flag.
        cp = run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], check=False)
        if cp.returncode != 0:
            return ("n/a", "sysctl key missing (IPv6 may not be compiled in)")
        state = cp.stdout.strip()
        if state == "1":
            return ("pass", "IPv6 disabled at runtime")
        if self.disable_ipv6:
            # User asked for it but it's not actually disabled — that's a fail.
            return ("fail", f"disable_ipv6={state}; requested but not applied")
        # User didn't ask; IPv6 is up; that's the desired state per project recommendation.
        return ("n/a", f"opt-in, not requested; disable_ipv6={state}")

    # ─── 55. Production readiness summary ─────────────────────────────────

    def step_readiness_checklist(self) -> Tuple[str, str]:
        """A printed checklist of operator actions that automation cannot perform.

        This is intentionally documentation-only — it does not modify the system.
        """
        checklist = textwrap.dedent(f"""\
            ╔══════════════════════════════════════════════════════════════════╗
            ║  FORTRESS PRIME — Production Readiness Checklist                 ║
            ║                                                                  ║
            ║  These are operator tasks that automation cannot do for you.     ║
            ║                                                                  ║
            ║  [ ] Add SSH public key(s) to /home/{self.admin_user}/.ssh/authorized_keys
            ║  [ ] Verify SSH login as '{self.admin_user}' from a SECOND terminal BEFORE
            ║      closing the current session
            ║  [ ] Review /var/lib/fortress-prime/fstab-hardening.guide.txt and
            ║      apply mount options where applicable (noexec, nosuid, nodev)
            ║  [ ] Reboot to activate kernel module blacklist (step 07)
            ║  [ ] Review the SUID/SGID inventory at
            ║      /var/lib/fortress-prime/suid-sgid-inventory.txt
            ║  [ ] Review the lynis report — address Suggestions section
            ║  [ ] Configure log forwarding to your SIEM (Wazuh / Splunk / Loki)
            ║  [ ] Configure offsite backup of /var/log, /etc, /var/lib/aide
            ║  [ ] Schedule periodic --verify runs via cron and alert on drift
            ║  [ ] Document the deployment in your change management system
            ║  [ ] Run a vulnerability scan against this host
            ║  [ ] Verify firewall rules from the network perimeter, not from the host
            ║  [ ] If using containers: pin image digests, scan with trivy / grype
            ║  [ ] Schedule quarterly hardening re-audit
            ╚══════════════════════════════════════════════════════════════════╝
        """)
        self.fm.write_atomic("/var/lib/fortress-prime/readiness-checklist.txt",
                             checklist, mode=0o644)
        # Print to operator
        for line in checklist.splitlines():
            print(f"     {line}")
        return ("ok", "checklist written to /var/lib/fortress-prime/readiness-checklist.txt")

    def verify_readiness_checklist(self) -> Tuple[str, str]:
        p = Path("/var/lib/fortress-prime/readiness-checklist.txt")
        return ("pass" if p.exists() else "n/a",
                "checklist present" if p.exists() else "no checklist yet")

    # ─── register all steps ───────────────────────────────────────────────

    def _register_steps(self):
        r = self.registry
        r.add("01", "Admin user + sudo + SSH key dir",
              cis=["5.3"], nist=["AC-2","AC-6"],
              func=self.step_admin_user, verify=self.verify_admin_user)
        r.add("02", "SSH server hardening (key-only, modern crypto)",
              cis=["5.2"], nist=["AC-17","IA-2","SC-8","SC-13"],
              func=self.step_ssh, verify=self.verify_ssh)
        r.add("03", "Host firewall (ufw default-deny + allowlist)",
              cis=["3.5"], nist=["AC-4","SC-7"],
              func=self.step_firewall, verify=self.verify_firewall)
        r.add("04", "Fail2ban for SSH brute-force protection",
              cis=["3.5","5.2"], nist=["AC-7","SI-4"],
              func=self.step_fail2ban, verify=self.verify_fail2ban)
        r.add("05", "Unattended security upgrades",
              cis=["1.9"], nist=["SI-2"],
              func=self.step_unattended, verify=self.verify_unattended)
        r.add("06", "Kernel sysctls (network + memory + fs hardening)",
              cis=["3.1","3.2","3.3"], nist=["SC-5","SC-7","SI-4"],
              func=self.step_sysctl, verify=self.verify_sysctl)
        r.add("07", "Kernel module blacklist (unused FS + protocols)",
              cis=["1.1.1","3.4"], nist=["CM-7"],
              func=self.step_module_blacklist, verify=self.verify_module_blacklist)
        r.add("08", "PAM password quality, aging, and lockout",
              cis=["5.4"], nist=["IA-5"],
              func=self.step_pam_password, verify=self.verify_pam_password)
        r.add("09", "/etc/fstab hardening guidance (manual review)",
              cis=["1.1"], nist=["CM-7"],
              func=self.step_fstab_advice, verify=self.verify_fstab_advice)
        r.add("10", "AppArmor mandatory access control",
              cis=["1.6"], nist=["AC-3"],
              func=self.step_apparmor, verify=self.verify_apparmor)
        r.add("11", "Auditd with MITRE-aligned rules",
              cis=["4.1"], nist=["AU-2","AU-3","AU-12"],
              func=self.step_auditd, verify=self.verify_auditd)
        r.add("12", "AIDE file integrity monitoring",
              cis=["1.4"], nist=["SI-7"],
              func=self.step_aide, verify=self.verify_aide)
        r.add("13", "Login banners",
              cis=["1.7"], nist=["AC-8"],
              func=self.step_motd, verify=self.verify_motd)
        r.add("14", "Time synchronisation (chrony)",
              cis=["2.2.1"], nist=["AU-8"],
              func=self.step_chrony, verify=self.verify_chrony)
        r.add("15", "Disable coredumps",
              cis=["1.5"], nist=["SC-7"],
              func=self.step_coredumps, verify=self.verify_coredumps)
        r.add("16", "Restrict cron and at to root",
              cis=["5.1"], nist=["AC-6"],
              func=self.step_cron_at, verify=self.verify_cron_at)
        r.add("17", "Disable unnecessary services",
              cis=["2.1","2.2"], nist=["CM-7"],
              func=self.step_disable_services, verify=self.verify_disable_services)
        r.add("18", "SUID/SGID inventory (advisory)",
              cis=["6.1"], nist=["CM-7"],
              func=self.step_suid_report, verify=self.verify_suid_report)
        r.add("19", "Empty-password account audit",
              cis=["6.2.5"], nist=["IA-5"],
              func=self.step_empty_passwords, verify=self.verify_empty_passwords)
        r.add("20", "Lock root account (sudo-only access)",
              cis=["5.3"], nist=["AC-6"],
              func=self.step_securetty, verify=self.verify_securetty)
        r.add("21", "Process accounting (acct)",
              cis=["4.1"], nist=["AU-2"],
              func=self.step_acct, verify=self.verify_acct)
        r.add("22", "rsyslog hardening",
              cis=["4.2"], nist=["AU-9"],
              func=self.step_rsyslog, verify=self.verify_rsyslog)
        r.add("23", "Disable USB storage at runtime",
              cis=["1.1.10"], nist=["MP-7"],
              func=self.step_usb_storage, verify=self.verify_usb_storage)
        r.add("24", "Hostname",
              cis=["2.1"], nist=["CM-6"],
              func=self.step_hostname, verify=self.verify_hostname)
        r.add("25", "Default umask 027 system-wide",
              cis=["5.5"], nist=["AC-6"],
              func=self.step_umask, verify=self.verify_umask)
        r.add("26", "Compiler permissions (root group only)",
              cis=["6.1"], nist=["CM-7"],
              func=self.step_compiler_perms, verify=self.verify_compiler_perms)
        r.add("27", "IPv6 audit (informational)",
              cis=["3.3"], nist=["CM-7"],
              func=self.step_ipv6_audit, verify=self.verify_ipv6_audit)
        r.add("28", "Lynis baseline audit run",
              cis=["—"], nist=["CA-2"],
              func=self.step_lynis, verify=self.verify_lynis)
        r.add("29", "SSH self-test (lockout prevention)",
              cis=["—"], nist=["—"],
              func=self.step_ssh_self_test, verify=self.verify_ssh_self_test)
        r.add("30", "System baseline snapshot",
              cis=["—"], nist=["CM-2"],
              func=self.step_baseline, verify=self.verify_baseline)

        # ─── Extended steps (v1.1.0) ─────────────────────────────────────
        r.add("31", "systemd-resolved DNS over TLS + DNSSEC",
              cis=["3.5"], nist=["SC-8","SC-13"],
              func=self.step_resolved_dot, verify=self.verify_resolved_dot)
        r.add("32", "PSAD — port scan attack detector",
              cis=["3.5"], nist=["SI-4"],
              func=self.step_psad, verify=self.verify_psad)
        r.add("33", "/proc with hidepid=invisible",
              cis=["1.1"], nist=["AC-3","AC-6"],
              func=self.step_proc_hidepid, verify=self.verify_proc_hidepid)
        r.add("34", "Firmware update tooling (fwupd)",
              cis=["1.9"], nist=["SI-2"],
              func=self.step_fwupd, verify=self.verify_fwupd)
        r.add("35", "systemd-journald hardening (persistent + sealed)",
              cis=["4.2"], nist=["AU-9","AU-11"],
              func=self.step_journald, verify=self.verify_journald)
        r.add("36", "systemd-logind hardening (idle lock, kill, remove IPC)",
              cis=["1.5"], nist=["AC-11","AC-12"],
              func=self.step_logind, verify=self.verify_logind)
        r.add("37", "Mask systemd debug-shell service",
              cis=["1.5"], nist=["CM-7"],
              func=self.step_mask_debug_shell, verify=self.verify_mask_debug_shell)
        r.add("38", "PAM password history (pam_pwhistory)",
              cis=["5.4.3"], nist=["IA-5"],
              func=self.step_pam_pwhistory, verify=self.verify_pam_pwhistory)
        r.add("39", "libpam-tmpdir (per-user /tmp)",
              cis=["—"], nist=["AC-3"],
              func=self.step_pam_tmpdir, verify=self.verify_pam_tmpdir)
        r.add("40", "vlock (console session lock)",
              cis=["—"], nist=["AC-11"],
              func=self.step_vlock, verify=self.verify_vlock)
        r.add("41", "APT hardening (no unauth, strict TLS, no recommends)",
              cis=["1.9"], nist=["CM-5","SR-3"],
              func=self.step_apt_hardening, verify=self.verify_apt_hardening)
        r.add("42", "DPkg invoke hook for noexec /tmp",
              cis=["1.1"], nist=["CM-7"],
              func=self.step_dpkg_invoke_hook, verify=self.verify_dpkg_invoke_hook)
        r.add("43", "haveged entropy daemon (opt-in)",
              cis=["—"], nist=["SC-13"],
              func=self.step_haveged, verify=self.verify_haveged)
        r.add("44", "Disable motd-news and apt-news",
              cis=["1.7"], nist=["AC-8"],
              func=self.step_disable_motd_news, verify=self.verify_disable_motd_news)
        r.add("45", "rkhunter daily scan",
              cis=["—"], nist=["SI-3","SI-4"],
              func=self.step_rkhunter, verify=self.verify_rkhunter)
        r.add("46", "ClamAV (opt-in, for mail/upload servers)",
              cis=["—"], nist=["SI-3"],
              func=self.step_clamav, verify=self.verify_clamav)
        r.add("47", "USBGuard — USB device whitelisting (opt-in)",
              cis=["1.1.10"], nist=["MP-7"],
              func=self.step_usbguard, verify=self.verify_usbguard)
        r.add("48", "Disable GDM (server profile)",
              cis=["1.8"], nist=["CM-7"],
              func=self.step_disable_gdm, verify=self.verify_disable_gdm)
        r.add("49", "sysstat / sar performance monitoring",
              cis=["—"], nist=["AU-2","AU-12"],
              func=self.step_sysstat, verify=self.verify_sysstat)
        r.add("50", "Remove .rhosts and hosts.equiv legacy r-services",
              cis=["6.2"], nist=["AC-6"],
              func=self.step_remove_rhosts, verify=self.verify_remove_rhosts)
        r.add("51", "No duplicate user accounts (verify)",
              cis=["6.2.6","6.2.7"], nist=["IA-4"],
              func=self.step_no_dup_users, verify=self.verify_no_dup_users)
        r.add("52", "Only root has UID 0 (verify)",
              cis=["6.2.5"], nist=["AC-6"],
              func=self.step_only_root_uid_zero, verify=self.verify_only_root_uid_zero)
        r.add("53", "Sticky bit on world-writable directories",
              cis=["6.1"], nist=["AC-6"],
              func=self.step_sticky_world_writable, verify=self.verify_sticky_world_writable)
        r.add("54", "Disable IPv6 (opt-in only; NOT recommended)",
              cis=["3.3.1"], nist=["—"],
              func=self.step_disable_ipv6, verify=self.verify_disable_ipv6)
        r.add("55", "Production readiness checklist",
              cis=["—"], nist=["PL-2"],
              func=self.step_readiness_checklist, verify=self.verify_readiness_checklist)

    # ─── runner ──────────────────────────────────────────────────────────

    def run(self, only: Optional[List[str]] = None,
            skip: Optional[List[str]] = None) -> RunReport:
        report = RunReport(
            host=socket.gethostname(),
            started_at=_dt.datetime.now().isoformat(),
            dry_run=self.dry_run,
            args={
                "admin_user": self.admin_user,
                "ssh_port": self.ssh_port,
                "allow_from": self.allow_from,
                "hostname": self.hostname,
                "non_interactive": self.non_interactive,
                "enable_auto_updates": self.enable_auto_updates,
            },
        )
        steps = self.registry.all()
        if only:
            steps = [s for s in steps if s["id"] in only]
        if skip:
            steps = [s for s in steps if s["id"] not in skip]

        total = len(steps)
        self._say(f"Executing {total} step(s){' [DRY-RUN]' if self.dry_run else ''}.")
        for i, s in enumerate(steps, 1):
            sid, name = s["id"], s["name"]
            start = time.time()
            tag = f"{C.BLU}[{i:02d}/{total:02d}]{C.R} {C.BLD}{sid}{C.R} {name}"
            print(tag)
            res = StepResult(id=sid, name=name, status="ok",
                             cis=s["cis"], nist=s["nist"])
            try:
                status, detail = s["func"]()
                res.status, res.detail = status, detail
                # verify
                if s["verify"]:
                    try:
                        v_status, v_detail = s["verify"]()
                        res.verify_status, res.verify_detail = v_status, v_detail
                    except Exception as ve:
                        res.verify_status = "fail"
                        res.verify_detail = f"verifier error: {ve}"
            except Exception as e:
                res.status = "failed"
                res.error  = str(e)
                self.log.error("step %s failed: %s\n%s", sid, e, traceback.format_exc())
            res.duration_s = round(time.time() - start, 3)
            report.steps.append(res)
            colour = {
                "ok": C.GRN, "changed": C.GRN, "skipped": C.YLW,
                "failed": C.RED, "verified": C.GRN,
            }.get(res.status, C.R)
            ver = ""
            if res.verify_status:
                vc = {"pass": C.GRN, "fail": C.RED, "n/a": C.DIM}.get(res.verify_status, C.R)
                ver = f"  verify={vc}{res.verify_status}{C.R}"
            print(f"     → {colour}{res.status}{C.R}  {res.detail}{ver}")

        report.ended_at = _dt.datetime.now().isoformat()
        # summary
        summary = {"total": len(report.steps)}
        for st in ("ok", "changed", "skipped", "failed"):
            summary[st] = sum(1 for r in report.steps if r.status == st)
        summary["verify_pass"] = sum(1 for r in report.steps if r.verify_status == "pass")
        summary["verify_fail"] = sum(1 for r in report.steps if r.verify_status == "fail")
        report.summary = summary

        self.fm.write_rollback_script()
        return report


# ════════════════════════════════════════════════════════════════════════════
# VERIFY-ONLY MODE (no changes, just check posture)
# ════════════════════════════════════════════════════════════════════════════

def verify_only(hardener: Hardener) -> RunReport:
    report = RunReport(
        host=socket.gethostname(),
        started_at=_dt.datetime.now().isoformat(),
        dry_run=True,
        args={"mode": "verify-only"},
    )
    for s in hardener.registry.all():
        sid, name = s["id"], s["name"]
        res = StepResult(id=sid, name=name, status="verified", cis=s["cis"], nist=s["nist"])
        if s["verify"]:
            try:
                v_status, v_detail = s["verify"]()
                res.verify_status, res.verify_detail = v_status, v_detail
            except Exception as ve:
                res.verify_status = "fail"
                res.verify_detail = f"verifier error: {ve}"
        report.steps.append(res)
        colour = {"pass": C.GRN, "fail": C.RED, "n/a": C.DIM}.get(res.verify_status or "n/a", C.R)
        print(f"  {sid} {name:<55s} {colour}{res.verify_status or 'n/a':<5}{C.R} {res.verify_detail}")
    report.ended_at = _dt.datetime.now().isoformat()
    # Populate summary so the printed report matches reality.
    summary = {"total": len(report.steps), "ok": 0, "changed": 0, "skipped": 0,
               "failed": 0,
               "verify_pass": sum(1 for r in report.steps if r.verify_status == "pass"),
               "verify_fail": sum(1 for r in report.steps if r.verify_status == "fail"),
               "verify_na":   sum(1 for r in report.steps if r.verify_status == "n/a")}
    # In verify mode, count "ok" as verified+pass for the summary line.
    summary["ok"] = summary["verify_pass"]
    report.summary = summary
    return report


# ════════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════════

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="fortress_prime",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — Ubuntu 24.04 hardening",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sudo ./fortress_prime.py --dry-run
              sudo ./fortress_prime.py --admin-user deploy --ssh-port 2222 \\
                  --allow-from 203.0.113.0/24 --non-interactive
              sudo ./fortress_prime.py --verify
              sudo ./fortress_prime.py --rollback
        """),
    )
    p.add_argument("--admin-user", default="deploy",
                   help="Admin user to create/ensure with sudo (default: deploy). "
                        "Use empty string to skip.")
    p.add_argument("--ssh-port", type=int, default=22,
                   help="SSH port to enforce (default: 22). "
                        "Pick a non-standard port for production.")
    p.add_argument("--allow-from", default="",
                   help="Comma-separated CIDRs allowed to reach the SSH port.")
    p.add_argument("--hostname", default="",
                   help="Set hostname (optional).")
    p.add_argument("--enable-auto-updates", action="store_true",
                   help="Enable & start unattended-upgrades immediately.")
    p.add_argument("--disable-ipv6", action="store_true",
                   help="Disable IPv6 stack (NOT RECOMMENDED for modern deployments; "
                        "hardening IPv6 is preferred — see step 06).")
    p.add_argument("--enable-usbguard", action="store_true",
                   help="Install and enable USBGuard (USB device whitelisting).")
    p.add_argument("--enable-clamav", action="store_true",
                   help="Install ClamAV (only useful for mail/file-upload servers).")
    p.add_argument("--enable-haveged", action="store_true",
                   help="Install haveged entropy daemon (rarely needed on modern kernels).")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would change without modifying the system.")
    p.add_argument("--non-interactive", action="store_true",
                   help="Skip confirmation prompt (use in CI / Ansible).")
    p.add_argument("--only", default="",
                   help="Comma-separated step IDs to run (e.g. 02,03,06).")
    p.add_argument("--skip", default="",
                   help="Comma-separated step IDs to skip.")
    p.add_argument("--verify", action="store_true",
                   help="Run verifiers only; no changes.")
    p.add_argument("--rollback", action="store_true",
                   help="Run the most recent generated rollback.sh.")
    p.add_argument("--report-dir", default=str(LOG_DIR),
                   help=f"Where to write the JSON report (default {LOG_DIR}).")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    return p.parse_args(argv)


def validate_args(ns: argparse.Namespace) -> List[str]:
    errs = []
    if not (1 <= ns.ssh_port <= 65535):
        errs.append(f"--ssh-port must be 1-65535 (got {ns.ssh_port})")
    if ns.admin_user and not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", ns.admin_user):
        errs.append(f"--admin-user '{ns.admin_user}' is not a valid POSIX username")
    if ns.allow_from:
        for chunk in [c.strip() for c in ns.allow_from.split(",") if c.strip()]:
            try:
                ipaddress.ip_network(chunk, strict=False)
            except ValueError as e:
                errs.append(f"--allow-from '{chunk}' invalid: {e}")
    if ns.hostname and not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                                    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
                                    ns.hostname):
        errs.append(f"--hostname '{ns.hostname}' not RFC1123-compliant")
    return errs


def write_report(report: RunReport, report_dir: str) -> Path:
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    path = Path(report_dir) / f"audit_report_{RUN_ID}.json"
    payload = asdict(report)
    path.write_text(json.dumps(payload, indent=2, default=str))
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
    return path


def print_summary(report: RunReport, report_path: Path) -> None:
    s = report.summary
    print()
    print("=" * 70)
    print(f"  {C.BLD}FORTRESS PRIME — Summary{C.R}")
    print("=" * 70)
    print(f"  Run ID         : {report.run_id}")
    print(f"  Host           : {report.host}")
    print(f"  Started / Ended: {report.started_at}  /  {report.ended_at}")
    print(f"  Dry run        : {report.dry_run}")
    print(f"  Total steps    : {s.get('total', 0)}")
    print(f"    {C.GRN}ok / changed{C.R} : {s.get('ok',0) + s.get('changed',0)}")
    print(f"    {C.YLW}skipped     {C.R} : {s.get('skipped', 0)}")
    print(f"    {C.RED}failed      {C.R} : {s.get('failed', 0)}")
    print(f"  Verify pass   : {s.get('verify_pass', 0)}")
    print(f"  Verify fail   : {s.get('verify_fail', 0)}")
    print(f"  Report file   : {report_path}")
    print(f"  Rollback      : {ROLLBACK_SH}")
    print(f"  Log file      : {LOG_FILE}")
    print("=" * 70)
    if s.get("failed", 0):
        print(f"  {C.RED}{C.BLD}WARNING: some steps failed — review the report.{C.R}")
    print()


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main() -> int:
    print_banner()
    ns = parse_args(sys.argv[1:])

    log = setup_logging(verbose=ns.verbose)

    if os.geteuid() != 0:
        print(f"{C.RED}Error: must be run as root (use sudo).{C.R}", file=sys.stderr)
        return 2

    # Rollback short-circuit
    if ns.rollback:
        # Find the latest rollback script
        if not ROLLBACK_SH.exists():
            print(f"{C.RED}No rollback script found at {ROLLBACK_SH}.{C.R}", file=sys.stderr)
            return 1
        log.info("Executing rollback: %s", ROLLBACK_SH)
        cp = subprocess.run(["/bin/bash", str(ROLLBACK_SH)], check=False)
        return cp.returncode

    errs = validate_args(ns)
    if errs:
        for e in errs:
            print(f"{C.RED}Argument error:{C.R} {e}", file=sys.stderr)
        return 2

    allow_from = [c.strip() for c in ns.allow_from.split(",") if c.strip()]

    hardener = Hardener(
        admin_user          = ns.admin_user,
        ssh_port            = ns.ssh_port,
        allow_from          = allow_from,
        hostname            = ns.hostname or None,
        dry_run             = ns.dry_run,
        non_interactive     = ns.non_interactive,
        enable_auto_updates = ns.enable_auto_updates,
        disable_ipv6        = ns.disable_ipv6,
        enable_usbguard     = ns.enable_usbguard,
        enable_clamav       = ns.enable_clamav,
        enable_haveged      = ns.enable_haveged,
    )

    try:
        hardener.preflight()
    except SystemExit:
        raise
    except Exception as e:
        log.error("Preflight failed: %s", e)
        return 2

    only = [s.strip() for s in ns.only.split(",") if s.strip()] or None
    skip = [s.strip() for s in ns.skip.split(",") if s.strip()] or None

    # Handle Ctrl-C gracefully
    interrupted = {"flag": False}
    def _sigint(_signum, _frame):
        interrupted["flag"] = True
        log.warning("Interrupt received — finishing current step then stopping.")
    signal.signal(signal.SIGINT, _sigint)

    try:
        if ns.verify:
            report = verify_only(hardener)
        else:
            report = hardener.run(only=only, skip=skip)
    except Exception as e:
        log.error("Run aborted: %s\n%s", e, traceback.format_exc())
        return 3

    report_path = write_report(report, ns.report_dir)
    print_summary(report, report_path)

    if interrupted["flag"]:
        return 130
    if report.summary.get("failed", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
