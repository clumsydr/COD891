#!/bin/bash
#
# DIAG & PCAP Capture Script (Speedtest Triggered)
# Captures PCAP and QMDL logs strictly for the duration of a speedtest.
#
# Usage: bash capture_diag_pcaps_speedtest.sh [output_dir]
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

# Micro-container variables (on the device)
WORKDIR="/data/local/tmp"
ROOTFS="$WORKDIR/fakeroot"

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  OnePlus 11R DIAG & PCAP Capture (Speedtest Mode)${NC}"
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
echo -e "${YELLOW}[*]${NC} Preparing directories and Micro-Container..."
adb shell su -c 'rm -rf /sdcard/diag_temp' >/dev/null 2>&1 || true
adb shell su -c 'mkdir -p /sdcard/diag_temp'
mkdir -p "$OUTPUT_DIR"

# Build the micro-container for the speedtest binary via ADB using a Here-Doc
adb shell su <<EOF
umount $ROOTFS/dev 2>/dev/null
umount $ROOTFS/proc 2>/dev/null
umount $ROOTFS/sys 2>/dev/null
rm -rf $ROOTFS

mkdir -p $ROOTFS/etc/ssl/certs $ROOTFS/dev $ROOTFS/proc $ROOTFS/sys
echo 'nameserver 8.8.8.8' > $ROOTFS/etc/resolv.conf

if [ ! -f $WORKDIR/cacert.pem ]; then
    curl -s -k -o $WORKDIR/cacert.pem https://curl.se/ca/cacert.pem
fi
cp $WORKDIR/cacert.pem $ROOTFS/etc/ssl/certs/ca-certificates.crt

chmod +x $WORKDIR/speedtest
cp $WORKDIR/speedtest $ROOTFS/

mount -o bind /dev $ROOTFS/dev
mount -o bind /proc $ROOTFS/proc
mount -o bind /sys $ROOTFS/sys
EOF

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

# Execute the Speedtest (Blocking Call)
echo -e "${YELLOW}[*]${NC} Running Speedtest... (Capture will stop when finished)"
RAW_RESULTS=$(adb shell su -c "NO_COLOR=1 chroot $ROOTFS /speedtest --accept-license --accept-gdpr 2>/dev/null")

# Stop Captures Immediately
echo -e "${YELLOW}[*]${NC} Speedtest complete. Stopping captures..."
adb shell su -c 'pkill -INT diag_mdlog' 2>/dev/null || true
adb shell su -c 'pkill tcpdump' 2>/dev/null || true
kill $TCPDUMP_PID 2>/dev/null || true
kill $DIAG_PID 2>/dev/null || true

# Parse Speedtest Results
CLEAN_RESULTS=$(echo "$RAW_RESULTS" | tr -d '\033' | sed 's/\[[0-9;]*m//g')
PING=$(echo "$CLEAN_RESULTS" | grep -iE '(ping|latency)' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1 || echo "0.00")
DOWN=$(echo "$CLEAN_RESULTS" | grep -i 'download' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1 || echo "0.00")
UP=$(echo "$CLEAN_RESULTS" | grep -i 'upload' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1 || echo "0.00")

echo -e "${GREEN}  → Ping: ${PING} ms | Down: ${DOWN} Mbps | Up: ${UP} Mbps${NC}"

# Tear down the container safely
adb shell su <<EOF
umount $ROOTFS/dev 2>/dev/null
umount $ROOTFS/proc 2>/dev/null
umount $ROOTFS/sys 2>/dev/null
EOF

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
