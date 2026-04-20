#!/bin/bash
#
# DIAG Capture Script for OnePlus 11R
# Simple wrapper around diag_mdlog
#
# Usage: ./capture_diag.sh [duration_seconds] [output_dir]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default parameters
DURATION=${1:-60}  # Default 60 seconds
OUTPUT_DIR=${2:-"diag_capture_$(date +%Y%m%d_%H%M%S)"}
MAX_SIZE=1000  # MB

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  OnePlus 11R DIAG Capture Script${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Check if device is connected
echo -e "${YELLOW}[*]${NC} Checking for connected device..."
if ! adb devices | grep -q "device$"; then
    echo -e "${RED}[✗]${NC} No device found! Please connect your OnePlus 11R via USB."
    exit 1
fi
echo -e "${GREEN}[✓]${NC} Device connected"

# Check for root
echo -e "${YELLOW}[*]${NC} Checking root access..."
if ! adb shell su -c 'id' 2>/dev/null | grep -q "uid=0"; then
    echo -e "${RED}[✗]${NC} Root access not available!"
    echo -e "${YELLOW}[!]${NC} Please grant root access in Magisk when prompted"
    exit 1
fi
echo -e "${GREEN}[✓]${NC} Root access confirmed"

# Start DIAG router
echo -e "${YELLOW}[*]${NC} Starting DIAG router service..."
adb shell su -c 'start vendor.diag-router' >/dev/null 2>&1
sleep 1

if ! adb shell su -c "getprop init.svc.vendor.diag-router | grep -q "running""; then
    echo -e "${RED}[✗]${NC} Failed to start DIAG router service"
    exit 1
fi
echo -e "${GREEN}[✓]${NC} DIAG router running"

# Clean up old logs on device
echo -e "${YELLOW}[*]${NC} Cleaning up old logs..."
adb shell su -c 'rm -rf /sdcard/diag_temp' >/dev/null 2>&1 || true


adb shell su -c 'mkdir -p /sdcard/diag_temp'

# Start capture
echo -e "${GREEN}[✓]${NC} Starting DIAG capture..."
echo -e "${YELLOW}[!]${NC} Duration: ${DURATION} seconds"
echo -e "${YELLOW}[!]${NC} Max file size: ${MAX_SIZE} MB"
echo -e "${YELLOW}[!]${NC} Output: ${OUTPUT_DIR}/"
echo ""
echo -e "${YELLOW}[*]${NC} Capturing... (this may take a while)"

# Run diag_mdlog
# adb shell su -c "timeout ${DURATION} /vendor/bin/diag_mdlog -o /sdcard/diag_temp -s ${MAX_SIZE} -a -e" 2>&1 | \
#     grep -E "Logging|Error|Starting" || true
adb shell su -c "timeout ${DURATION} /vendor/bin/diag_mdlog -o /sdcard/diag_temp -s ${MAX_SIZE} -f /vendor/odm/etc/modem_rf.cfg -c" | \
    grep -E "Logging|Error|Starting" || true

echo ""
echo -e "${GREEN}[✓]${NC} Capture completed"

# Check if data was captured
FILECOUNT=$(adb shell "su -c 'find /sdcard/diag_temp -name \"*.qmdl\" | wc -l'" | tr -d '\r')
if [ "$FILECOUNT" -eq "0" ]; then
    echo -e "${RED}[✗]${NC} No DIAG files captured!"
    echo -e "${YELLOW}[!]${NC} Make sure your device is actively using the modem (make a call, browse web)"
    exit 1
fi
echo -e "${GREEN}[✓]${NC} Captured ${FILECOUNT} DIAG files"

# Pull data
echo -e "${YELLOW}[*]${NC} Pulling data from device..."
mkdir -p "${OUTPUT_DIR}"
adb pull /sdcard/diag_temp "${OUTPUT_DIR}/" >/dev/null 2>&1
echo -e "${GREEN}[✓]${NC} Data saved to: ${OUTPUT_DIR}/"

# Show summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Capture Summary${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  Files captured: ${FILECOUNT}"
echo -e "  Total size:     $(du -sh "${OUTPUT_DIR}" | cut -f1)"
echo -e "  Location:       ${OUTPUT_DIR}/"
echo ""
ls -lh "${OUTPUT_DIR}/"* 2>/dev/null | tail -n +2 | awk '{printf "  - %s\t(%s)\n", $9, $5}'
echo ""

# Clean up device
echo -e "${YELLOW}[*]${NC} Cleaning up device..."
adb shell su -c 'rm -rf /sdcard/diag_temp' >/dev/null 2>&1

echo -e "${GREEN}[✓]${NC} Done!"
echo ""
echo -e "${YELLOW}[!]${NC} To analyze the .qmdl2 files, use:"
echo -e "    - QXDM Professional (Qualcomm)"
echo -e "    - QCSuper (open source): https://github.com/P1sec/QCSuper"
echo -e "    - qcat + Wireshark"
echo ""
