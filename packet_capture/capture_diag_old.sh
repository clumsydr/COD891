#!/bin/bash
#
# DIAG Capture Script (legacy/older OnePlus devices, e.g., CE3)
# Tries multiple diag_mdlog binaries and flag combinations for compatibility.
#
# Usage: ./capture_diag_old.sh [duration_seconds] [output_dir] [min_size_kb]
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default parameters
DURATION=${1:-120}
OUTPUT_DIR=${2:-"old_diag_capture_$(date +%Y%m%d_%H%M%S)"}
MIN_TOTAL_KB=${3:-128}
MAX_SIZE=500
REMOTE_TMP="/sdcard/diag_temp"

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  OnePlus CE3 / Older Device DIAG Capture Script${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

err() {
    echo -e "${RED}[✗]${NC} $*"
}

ok() {
    echo -e "${GREEN}[✓]${NC} $*"
}

info() {
    echo -e "${YELLOW}[*]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

# Check connected device
info "Checking for connected device..."
if ! adb devices | grep -q "device$"; then
    err "No device found. Please connect your phone via USB."
    exit 1
fi
ok "Device connected"

# Check root access
info "Checking root access..."
if ! adb shell su -c 'id' 2>/dev/null | grep -q "uid=0"; then
    err "Root access not available. Please allow root in Magisk."
    exit 1
fi
ok "Root access confirmed"

# Choose diag_mdlog binary path
info "Detecting diag_mdlog binary path..."
DIAG_BIN=""
for candidate in /vendor/bin/diag_mdlog /system/bin/diag_mdlog /odm/bin/diag_mdlog; do
    if adb shell su -c "[ -x ${candidate} ]" >/dev/null 2>&1; then
        DIAG_BIN="${candidate}"
        break
    fi
done

if [ -z "${DIAG_BIN}" ]; then
    err "diag_mdlog binary not found in common paths."
    warn "Tried: /vendor/bin, /system/bin, /odm/bin"
    exit 1
fi
ok "Using binary: ${DIAG_BIN}"

# Try common service names (best effort)
info "Starting DIAG related services (best effort)..."
for svc in vendor.diag-router diag-router vendor.diag_mdlogd diag_mdlogd; do
    adb shell su -c "start ${svc}" >/dev/null 2>&1 || true
done
sleep 2

ROUTER_STATE=$(adb shell getprop init.svc.vendor.diag-router | tr -d '\r' || true)
if [ "${ROUTER_STATE:-}" = "running" ]; then
    ok "vendor.diag-router is running"
else
    warn "vendor.diag-router not confirmed running (continuing with fallback modes)"
fi

# Prepare remote output dir
info "Preparing remote temp directory..."
adb shell su -c "rm -rf ${REMOTE_TMP}" >/dev/null 2>&1 || true
adb shell su -c "mkdir -p ${REMOTE_TMP}"

BEFORE_KB=$(adb shell su -c "du -sk ${REMOTE_TMP} 2>/dev/null | awk '{print \$1}'" | tr -d '\r' || true)
BEFORE_KB=${BEFORE_KB:-0}

echo ""
ok "Starting DIAG capture"
echo -e "${BLUE}  Duration :${NC} ${DURATION} seconds"
echo -e "${BLUE}  Max size :${NC} ${MAX_SIZE} MB"
echo -e "${BLUE}  Output   :${NC} ${OUTPUT_DIR}/"
echo ""

# Build mode list dynamically
MODE_CMDS=()

# CE3/newer OEM mode often uses cfg + -c
if adb shell su -c "[ -f /vendor/odm/etc/modem_rf.cfg ]" >/dev/null 2>&1; then
    MODE_CMDS+=("timeout ${DURATION} ${DIAG_BIN} -o ${REMOTE_TMP} -s ${MAX_SIZE} -f /vendor/odm/etc/modem_rf.cfg -c")
fi

# Broad compatibility modes
MODE_CMDS+=("timeout ${DURATION} ${DIAG_BIN} -o ${REMOTE_TMP} -s ${MAX_SIZE} -a -e")
MODE_CMDS+=("timeout ${DURATION} ${DIAG_BIN} -o ${REMOTE_TMP} -s ${MAX_SIZE} -a")
MODE_CMDS+=("timeout ${DURATION} ${DIAG_BIN} -o ${REMOTE_TMP} -s ${MAX_SIZE}")

# If timeout doesn't exist on this device, fallback to non-timeout mode once
if ! adb shell su -c 'command -v timeout >/dev/null 2>&1' >/dev/null 2>&1; then
    warn "'timeout' command not available on device; using host-side timeout fallback"
    MODE_CMDS=("${DIAG_BIN} -o ${REMOTE_TMP} -s ${MAX_SIZE} -a")
fi

capture_succeeded=0
successful_mode=""
last_log=""

for mode_cmd in "${MODE_CMDS[@]}"; do
    info "Trying mode: ${mode_cmd}"
    CAPTURE_LOG=$(mktemp -t old_diag_capture_log.XXXXXX)
    last_log="${CAPTURE_LOG}"

    set +e
    if adb shell su -c 'command -v timeout >/dev/null 2>&1' >/dev/null 2>&1; then
        adb shell su -c "${mode_cmd}" >"${CAPTURE_LOG}" 2>&1
        CAPTURE_RC=$?
    else
        adb shell su -c "${mode_cmd}" >"${CAPTURE_LOG}" 2>&1 &
        ADB_PID=$!
        sleep "${DURATION}"
        kill "${ADB_PID}" >/dev/null 2>&1 || true
        wait "${ADB_PID}" >/dev/null 2>&1 || true
        CAPTURE_RC=0
    fi
    set -e

    grep -Ei "Logging|Error|Starting|mask|diag|failed|permission|denied|No such file|not found" "${CAPTURE_LOG}" || true

    FILECOUNT=$(adb shell "su -c 'find ${REMOTE_TMP} -type f \( -name \"*.qmdl2\" -o -name \"*.qmdl\" \) | wc -l'" | tr -d '\r' || true)
    FILECOUNT=${FILECOUNT:-0}

    AFTER_KB=$(adb shell su -c "du -sk ${REMOTE_TMP} 2>/dev/null | awk '{print \$1}'" | tr -d '\r' || true)
    AFTER_KB=${AFTER_KB:-0}
    GROWTH_KB=$((AFTER_KB - BEFORE_KB))

    if [ "${FILECOUNT}" -gt 0 ] && [ "${GROWTH_KB}" -gt 0 ] && { [ "${CAPTURE_RC}" -eq 0 ] || [ "${CAPTURE_RC}" -eq 124 ]; }; then
        capture_succeeded=1
        successful_mode="${mode_cmd}"
        ok "Capture mode succeeded"
        break
    fi

    warn "Mode failed (rc=${CAPTURE_RC}, files=${FILECOUNT}, growth=${GROWTH_KB} KB), trying next..."
done

if [ "${capture_succeeded}" -ne 1 ]; then
    err "All capture modes failed."
    if [ -n "${last_log}" ] && [ -f "${last_log}" ]; then
        warn "Last diag output:"
        tail -n 25 "${last_log}" || true
    fi
    exit 1
fi

FILECOUNT=$(adb shell "su -c 'find ${REMOTE_TMP} -type f \( -name \"*.qmdl2\" -o -name \"*.qmdl\" \) | wc -l'" | tr -d '\r')
ok "Captured ${FILECOUNT} DIAG file(s)"

info "Pulling data from device..."
mkdir -p "${OUTPUT_DIR}"
adb pull "${REMOTE_TMP}" "${OUTPUT_DIR}/" >/dev/null 2>&1
ok "Data saved to: ${OUTPUT_DIR}/"

TOTAL_KB=$(du -sk "${OUTPUT_DIR}" | awk '{print $1}')
if [ "${TOTAL_KB:-0}" -lt "${MIN_TOTAL_KB}" ]; then
    warn "Capture size is small (${TOTAL_KB} KB < ${MIN_TOTAL_KB} KB)."
    warn "Generate active traffic (call/video/web) and rerun for longer duration."
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Capture Summary${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  Files captured : ${FILECOUNT}"
echo -e "  Total size     : $(du -sh "${OUTPUT_DIR}" | cut -f1)"
echo -e "  Location       : ${OUTPUT_DIR}/"
echo -e "  Successful mode: ${successful_mode}"
echo ""

ls -lh "${OUTPUT_DIR}/"* 2>/dev/null | awk 'NR>1 {printf "  - %-40s %s\n", $9, $5}' || true

info "Cleaning up device temp files..."
adb shell su -c "rm -rf ${REMOTE_TMP}" >/dev/null 2>&1 || true
ok "Done"

echo ""
warn "To analyze captures, use QXDM / QCSuper / qcat + Wireshark."
echo ""
