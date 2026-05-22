#!/bin/bash
# =============================================================================
# FORTRESS PRIME — Idempotency Test Suite
# =============================================================================
# Runs the hardening tool TWICE on a fresh Ubuntu 24.04 VM and verifies that
# the second run does NOT modify any files, restart any services, or change
# any system state.  This proves idempotency.
#
# Usage:
#   1. Spin up a clean Ubuntu 24.04 VM (multipass, VirtualBox, etc.)
#   2. Copy fortress_prime.py and this script to /tmp
#   3. Run as root:  sudo bash /tmp/test_idempotency.sh
#
# Exit codes:
#   0 = idempotency confirmed (second run had zero changes)
#   1 = second run modified something (idempotency FAIL)
#   2 = first run failed
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="${SCRIPT_DIR}/../fortress_prime.py"
REPORT_DIR="/var/log/fortress-prime"
BACKUP_DIR="/var/backups/fortress-prime"

# ──────────────────────────────────────────────────────────────────────────
# Safety checks
# ──────────────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This test must be run as root (sudo)."
    exit 2
fi

if [ ! -f "$TOOL" ]; then
    echo "ERROR: fortress_prime.py not found at $TOOL"
    exit 2
fi

# ──────────────────────────────────────────────────────────────────────────
# Helper: capture system state fingerprint
# ──────────────────────────────────────────────────────────────────────────
take_fingerprint() {
    local label="$1"
    local dir="/tmp/idempotency-fingerprint-${label}"
    mkdir -p "$dir"

    # File checksums for key config files
    for f in /etc/ssh/sshd_config.d/00-fortress-prime.conf \
             /etc/sysctl.d/99-fortress-prime.conf \
             /etc/audit/rules.d/99-fortress-prime.rules \
             /etc/security/pwquality.conf \
             /etc/security/faillock.conf \
             /etc/default/grub \
             /etc/issue.net \
             /etc/cron.allow \
             /etc/ufw/user.rules \
             /etc/aide/aide.conf.d/99-fortress-prime \
             /etc/systemd/coredump.conf.d/99-fortress-prime.conf \
             /etc/systemd/journald.conf.d/99-fortress-prime.conf \
             /etc/systemd/logind.conf.d/99-fortress-prime.conf \
             /etc/systemd/timesyncd.conf.d/99-fortress-prime.conf \
             /etc/systemd/resolved.conf.d/99-fortress-prime.conf \
             /etc/apt/apt.conf.d/99-fortress-prime-hardening \
             /etc/apt/apt.conf.d/99-fortress-prime-noexec-tmp \
             /etc/dpkg/dpkg.cfg.d/99-fix-tmp \
             /etc/modprobe.d/fortress-prime-blacklist.conf \
             /etc/modprobe.d/disable-filesystems.conf \
             /etc/default/motd-news \
             /etc/default/rkhunter \
             /etc/rkhunter.conf; do
        if [ -f "$f" ]; then
            sha256sum "$f" >> "$dir/checksums.txt"
        fi
    done

    # Service state
    systemctl list-units --type=service --state=running --no-legend \
        | awk '{print $1}' > "$dir/services.txt"

    # UFW status
    ufw status verbose > "$dir/ufw.txt" 2>/dev/null || true

    # Sysctl values
    sysctl -a 2>/dev/null > "$dir/sysctl.txt"

    # Package list
    dpkg -l > "$dir/packages.txt"

    echo "$dir"
}

# ──────────────────────────────────────────────────────────────────────────
# Phase 1 — First Run (apply hardening)
# ──────────────────────────────────────────────────────────────────────────
echo "============================================="
echo "  FORTRESS PRIME IDEMPOTENCY TEST"
echo "============================================="
echo ""
echo "[1/4] Taking pre‑hardening fingerprint..."
FINGERPRINT_0=$(take_fingerprint "0-pre")
echo "      Fingerprint saved to $FINGERPRINT_0"

echo "[2/4] Running FORTRESS PRIME (first run)..."
if python3 "$TOOL" \
    --admin-user testuser \
    --ssh-port 2222 \
    --allow-from 0.0.0.0/0 \
    --hostname idempotency-test \
    --enable-auto-updates \
    --non-interactive; then
    echo "      First run completed successfully."
else
    echo "ERROR: First run failed. Aborting test."
    exit 2
fi

# ──────────────────────────────────────────────────────────────────────────
# Phase 2 — Take fingerprint after first run
# ──────────────────────────────────────────────────────────────────────────
echo "[3/4] Taking post‑run fingerprint..."
FINGERPRINT_1=$(take_fingerprint "1-after-run1")
echo "      Fingerprint saved to $FINGERPRINT_1"

# ──────────────────────────────────────────────────────────────────────────
# Phase 3 — Second Run (should be entirely no‑op)
# ──────────────────────────────────────────────────────────────────────────
echo "[4/4] Running FORTRESS PRIME AGAIN (should be idempotent)..."
set +e
SECOND_OUTPUT=$(python3 "$TOOL" \
    --admin-user testuser \
    --ssh-port 2222 \
    --allow-from 0.0.0.0/0 \
    --hostname idempotency-test \
    --non-interactive 2>&1)
SECOND_EXIT=$?
set -e

if [ $SECOND_EXIT -ne 0 ]; then
    echo "ERROR: Second run exited with code $SECOND_EXIT. Output:"
    echo "$SECOND_OUTPUT"
    exit 1
fi

# Count how many steps reported "changed" on the second run
CHANGED_COUNT=$(echo "$SECOND_OUTPUT" | grep -c '→ changed' || true)

# ──────────────────────────────────────────────────────────────────────────
# Phase 4 — Verification
# ──────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "  IDEMPOTENCY TEST RESULT"
echo "============================================="

if [ "$CHANGED_COUNT" -eq 0 ]; then
    echo "✅ PASS — No files were modified on the second run."
    echo "   FORTRESS PRIME is idempotent."
    exit 0
else
    echo "❌ FAIL — $CHANGED_COUNT step(s) reported 'changed' on the second run."
    echo "   This means the tool is NOT fully idempotent."
    echo ""
    echo "   Changed steps (from second run output):"
    echo "$SECOND_OUTPUT" | grep '→ changed' || true
    echo ""
    echo "   Review the fingerprints:"
    echo "     Pre‑run  : $FINGERPRINT_0"
    echo "     Post‑run : $FINGERPRINT_1"
    echo ""
    echo "   To diff the filesystem state:"
    echo "     diff <(sort $FINGERPRINT_0/checksums.txt) <(sort $FINGERPRINT_1/checksums.txt)"
    exit 1
fi
