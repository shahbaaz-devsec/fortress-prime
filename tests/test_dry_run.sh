#!/bin/bash
# =============================================================================
# FORTRESS PRIME — Dry‑Run Smoke Test (Root Required)
# =============================================================================
# This script runs the hardening tool in --dry-run mode as root.
# It validates that:
#   1. The Python syntax is correct
#   2. All 55 steps are registered and printed
#   3. The tool exits successfully
#
# Usage (requires sudo):
#   sudo bash tests/test_dry_run.sh
#
# Exit codes:
#   0 = success
#   1 = failure
# =============================================================================

set -euo pipefail

TOOL="./fortress_prime.py"

echo "============================================="
echo "  FORTRESS PRIME — Dry‑Run Smoke Test"
echo "============================================="

echo "[1/3] Checking Python syntax..."
python3 -m py_compile "$TOOL"
echo "      Syntax OK."

echo "[2/3] Checking --help..."
python3 "$TOOL" --help > /dev/null
echo "      --help OK."

echo "[3/3] Running dry‑run (55 steps expected)..."
OUTPUT=$(sudo python3 "$TOOL" --dry-run --non-interactive \
    --admin-user ci-test \
    --ssh-port 2222 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "ERROR: Dry‑run exited with code $EXIT_CODE."
    echo "$OUTPUT"
    exit 1
fi

STEP_COUNT=$(echo "$OUTPUT" | grep -cE '^\[[0-9]+/[0-9]+\]' || true)

echo ""
echo "============================================="
echo "  SMOKE TEST RESULT"
echo "============================================="

if [ "$STEP_COUNT" -eq 55 ]; then
    echo "✅ PASS — All 55 steps registered and dry‑run completed successfully."
    exit 0
else
    echo "❌ FAIL — Expected 55 steps, found $STEP_COUNT."
    echo ""
    echo "Output excerpt:"
    echo "$OUTPUT" | tail -30
    exit 1
fi
