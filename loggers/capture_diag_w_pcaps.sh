#!/bin/bash
#
# DIAG Capture Script for OnePlus 11R
# Simple wrapper around diag_mdlog and tcpdump
#
# Usage: bash capture_diag.sh [duration_seconds] [output_dir]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default parameters
DURATION=${1:-60}  # Default 60 seconds
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR=${2:-"diag_capture_${TIMESTAMP}"}
MAX_SIZE=1000  # MB

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  OnePlus 11R DIAG & PCAP Capture Script${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Check if device is connected
echo -e "${YELLOW}[*]${NC} Checking for connected device..."
if ! adb devices | grep -q -w "device"; then
    echo -e "${RED}[✗]${NC} No device found! Please connect your OnePlus 11R via USB."
    exit 1
fi
echo -e "${GREEN}[✓]${NC} Device connected"

# Check for root
echo -e "${YELLOW}[*]${NC} Checking root access..."
if ! adb shell su -c 'id' 2>/dev/null | grep -q "uid=0"; then
    echo -e "${RED}[✗]${NC} Root access not available!"
    echo -e "${YELLOW}[!]${NC} Please grant root access in Magisk when prompted."
    exit 1
fi
echo -e "${GREEN}[✓]${NC} Root access confirmed"

# Start DIAG router
echo -e "${YELLOW}[*]${NC} Starting DIAG router service..."
adb shell su -c 'start vendor.diag-router' >/dev/null 2>&1
sleep 1

# Fixed nested quotes bug here
if ! adb shell su -c 'getprop init.svc.vendor.diag-router' | grep -q "running"; then
    echo -e "${RED}[✗]${NC} Failed to start DIAG router service"
    exit 1
fi
echo -e "${GREEN}[✓]${NC} DIAG router running"

# Clean up old logs on device
echo -e "${YELLOW}[*]${NC} Preparing device directories..."
adb shell su -c 'rm -rf /sdcard/diag_temp' >/dev/null 2>&1 || true
adb shell su -c 'mkdir -p /sdcard/diag_temp'

# Setup local output directory
mkdir -p "$OUTPUT_DIR"

# Start capture
echo -e "${GREEN}[✓]${NC} Starting DIAG capture..."
echo -e "${YELLOW}[!]${NC} Duration: ${DURATION} seconds"
echo -e "${YELLOW}[!]${NC} Max file size: ${MAX_SIZE} MB"
echo -e "${YELLOW}[!]${NC} Output: ${OUTPUT_DIR}/"
echo ""
echo -e "${YELLOW}[*]${NC} Capturing... (this may take a while)"

READABLE_DATE=$(date)
PCAP_FILE="/sdcard/diag_temp/capture_$TIMESTAMP.pcap"

# Detect the active interface on the Android device (not the host)
ACTIVE_IFACE=$(adb shell su -c 'ip route get 8.8.8.8 2>/dev/null' | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n 1 | tr -d '\r')
ACTIVE_IFACE=${ACTIVE_IFACE:-any} # Fallback to 'any' if interface detection fails

echo -e "${GREEN}[✓]${NC} Starting network trace at $READABLE_DATE on device interface: $ACTIVE_IFACE"

# Start PCAP on the Android device in the background
adb shell su -c "tcpdump -i $ACTIVE_IFACE -w $PCAP_FILE" &>/dev/null &
TCPDUMP_PID=$!

sleep 2

# Run diag_mdlog
adb shell su -c "timeout ${DURATION} /vendor/bin/diag_mdlog -o /sdcard/diag_temp -s ${MAX_SIZE} -f /vendor/odm/etc/modem_rf.cfg -c" | \
    grep -E "Logging|Error|Starting" || true

echo ""
echo -e "${GREEN}[✓]${NC} Capture completed"

# Stop PCAP (Kill local adb process and ensure tcpdump stops on the device)
kill $TCPDUMP_PID 2>/dev/null || true
adb shell su -c 'pkill tcpdump' 2>/dev/null || true

# Check if data was captured (Looking for .qmdl or .qmdl2 files)
FILECOUNT=$(adb shell "su -c 'find /sdcard/diag_temp -name \"*.qmdl*\" | wc -l'" | tr -d '\r')
if [ "$FILECOUNT" -eq "0" ]; then
    echo -e "${RED}[✗]${NC} No DIAG files captured!"
    echo -e "${YELLOW}[!]${NC} Make sure your device is actively using the modem (make a call, browse web)"
    exit 1
fi
echo -e "${GREEN}[✓]${NC} Captured ${FILECOUNT} DIAG file(s)"

# Pull data
echo -e "${YELLOW}[*]${NC} Pulling data from device..."
# Using /. to copy contents into OUTPUT_DIR directly rather than creating a diag_temp subfolder
adb pull /sdcard/diag_temp/. "${OUTPUT_DIR}/" >/dev/null 2>&1
echo -e "${GREEN}[✓]${NC} Data saved to: ${OUTPUT_DIR}/"

# Show summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Capture Summary${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  Total files:    $(ls -1 "${OUTPUT_DIR}" | wc -l | tr -d ' ')"
echo -e "  Total size:     $(du -sh "${OUTPUT_DIR}" | cut -f1)"
echo -e "  Location:       ${OUTPUT_DIR}/"
echo ""
ls -lh "${OUTPUT_DIR}" | grep -v "^total" | awk '{printf "  - %s\t(%s)\n", $9, $5}'
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