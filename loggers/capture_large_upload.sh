#!/bin/bash
#
# DIAG & PCAP Capture Script (Long Upload Sequence)
# Captures PCAP and QMDL logs strictly for the duration of a long file upload.
#
# Usage: bash capture_diag_pcaps_upload.sh [output_dir]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR=${1:-"diag_capture_${TIMESTAMP}"}
MAX_SIZE=1000  # MB

# --- Upload Test Parameters ---
UPLOAD_SIZE_MB=100 # Size of the file to generate and upload
UPLOAD_URL="http://speedtest.tele2.net/upload.php" # Target server (null endpoint)
DUMMY_FILE="/data/local/tmp/dummy_upload_${TIMESTAMP}.bin"
# ------------------------------

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  OnePlus 11R DIAG & PCAP Capture (Long Upload Mode)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Check if device is connected & rooted
echo -e "${YELLOW}[*]${NC} Checking for connected device and root access..."
if ! adb devices | grep -q -w "device"; then
    echo -e "${RED}[✗]${NC} No device found! Please connect via USB."
    exit 1
fi
if ! adb shell su -c 'id' 2>/dev/null | grep -q "uid=0"; then
    echo -e "${RED}[✗]${NC} Root access not available on device!"
    exit 1
fi
echo -e "${GREEN}[✓]${NC} Device connected and rooted"

# Start DIAG router
echo -e "${YELLOW}[*]${NC} Starting DIAG router service..."
adb shell su -c 'start vendor.diag-router' >/dev/null 2>&1
sleep 1
if ! adb shell su -c 'getprop init.svc.vendor.diag-router' | grep -q "running"; then
    echo -e "${RED}[✗]${NC} Failed to start DIAG router service"
    exit 1
fi

# Clean up old logs & Set up directories
echo -e "${YELLOW}[*]${NC} Preparing directories..."
adb shell su -c 'rm -rf /sdcard/diag_temp' >/dev/null 2>&1 || true
adb shell su -c 'mkdir -p /sdcard/diag_temp'
mkdir -p "$OUTPUT_DIR"

ACTIVE_IFACE=$(adb shell su -c 'ip route get 8.8.8.8 2>/dev/null' | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n 1 | tr -d '\r')
ACTIVE_IFACE=${ACTIVE_IFACE:-any}

# Start Background PCAP
echo -e "${GREEN}[✓]${NC} Starting PCAP on interface: $ACTIVE_IFACE"
PCAP_FILE="/sdcard/diag_temp/capture_$TIMESTAMP.pcap"
adb shell su -c "tcpdump -i $ACTIVE_IFACE -w $PCAP_FILE" &>/dev/null &
TCPDUMP_PID=$!

sleep 2

# Start Background DIAG Log
echo -e "${GREEN}[✓]${NC} Starting DIAG Modem Logger..."
adb shell su -c "/vendor/bin/diag_mdlog -o /sdcard/diag_temp -s ${MAX_SIZE} -f /vendor/odm/etc/modem_rf.cfg -c" &>/dev/null &
DIAG_PID=$!

sleep 2

# Generate Dummy File on Device
echo -e "${YELLOW}[*]${NC} Generating ${UPLOAD_SIZE_MB}MB dummy file on device..."
adb shell su -c "dd if=/dev/zero of=$DUMMY_FILE bs=1048576 count=$UPLOAD_SIZE_MB 2>/dev/null"

# Execute the Upload Sequence (Blocking Call)
echo -e "${YELLOW}[*]${NC} Uploading to ${UPLOAD_URL}... (Captures will stop when finished)"
# Use -F to force a POST request, and drop the buggy -w text string
adb shell su -c "curl --progress-bar -F 'file=@$DUMMY_FILE' $UPLOAD_URL -o /dev/null" || echo -e "${RED}[!] Upload interrupted.${NC}"

# Stop Captures Immediately
echo -e "${YELLOW}[*]${NC} Sequence complete. Stopping captures..."
adb shell su -c 'pkill -INT diag_mdlog' 2>/dev/null || true
adb shell su -c 'pkill tcpdump' 2>/dev/null || true
kill $TCPDUMP_PID 2>/dev/null || true
kill $DIAG_PID 2>/dev/null || true

# Clean up the dummy file from the device
echo -e "${YELLOW}[*]${NC} Cleaning up dummy file..."
adb shell su -c "rm -f $DUMMY_FILE"

# Pull data
echo -e "${YELLOW}[*]${NC} Pulling data from device..."
adb pull /sdcard/diag_temp/. "${OUTPUT_DIR}/" >/dev/null 2>&1
adb shell su -c 'rm -rf /sdcard/diag_temp' >/dev/null 2>&1

FILECOUNT=$(ls -1 "${OUTPUT_DIR}"/*.qmdl* 2>/dev/null | wc -l | tr -d ' ')
if [ "$FILECOUNT" -eq "0" ]; then
    echo -e "${RED}[✗]${NC} Warning: No DIAG files were saved successfully."
else
    echo -e "${GREEN}[✓]${NC} Data saved to: ${OUTPUT_DIR}/"
fi
