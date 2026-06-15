#!/bin/bash
#
# DIAG & PCAP Capture Script (Speedtest & G-NetTrack Pro Triggered)
# Captures PCAP and QMDL logs strictly for the duration of a speedtest,
# while running G-NetTrack Pro in the foreground.
#
# Usage: bash capture_diag_pcaps_speedtest.sh [output_dir]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# G-NetTrack Pro tap coordinates (OnePlus 11R)
GNET_THREE_DOTS_X=1160; GNET_THREE_DOTS_Y=175
GNET_START_LOG_X=818;   GNET_START_LOG_Y=209
GNET_END_LOG_X=702;     GNET_END_LOG_Y=362

gnet_start_log() {
    adb shell input tap $GNET_THREE_DOTS_X $GNET_THREE_DOTS_Y
    sleep 1
    adb shell input tap $GNET_START_LOG_X $GNET_START_LOG_Y
}

gnet_end_log() {
    adb shell input tap $GNET_THREE_DOTS_X $GNET_THREE_DOTS_Y
    sleep 1
    adb shell input tap $GNET_END_LOG_X $GNET_END_LOG_Y
}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR=${1:-"diag_capture_${TIMESTAMP}"}
MAX_SIZE=1000  # MB

# Micro-container variables (on the device)
WORKDIR="/data/local/tmp"
ROOTFS="$WORKDIR/fakeroot"

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  OnePlus 11R DIAG & PCAP Capture (Speedtest & G-NetTrack Pro Mode)${NC}"
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

# Launch G-NetTrack Pro and start logging first
echo -e "${GREEN}[✓]${NC} Launching G-NetTrack Pro..."
adb shell su -c 'monkey -p com.gyokovsolutions.gnettrackproplus -c android.intent.category.LAUNCHER 1' >/dev/null 2>&1
sleep 3
echo -e "${GREEN}[✓]${NC} Starting G-NetTrack Pro log..."
gnet_start_log

# Start Background PCAP
echo -e "${GREEN}[✓]${NC} Starting PCAP on interface: $ACTIVE_IFACE"
PCAP_FILE="/sdcard/diag_temp/capture_$TIMESTAMP.pcap"
adb shell su -c "tcpdump -i $ACTIVE_IFACE -w $PCAP_FILE" &>/dev/null &
TCPDUMP_PID=$!

# Start Background DIAG Log
echo -e "${GREEN}[✓]${NC} Starting DIAG Modem Logger..."
adb shell su -c "/vendor/bin/diag_mdlog -o /sdcard/diag_temp -s ${MAX_SIZE} -f /vendor/odm/etc/modem_rf.cfg -c" &>/dev/null &
DIAG_PID=$!

# Execute Speedtest in Background
echo -e "${YELLOW}[*]${NC} Starting Speedtest in background..."
SPEEDTEST_RESULTS_FILE=$(mktemp)
adb shell su -c "NO_COLOR=1 chroot $ROOTFS /speedtest --accept-license --accept-gdpr 2>/dev/null" > "$SPEEDTEST_RESULTS_FILE" &
SPEEDTEST_PID=$!

# Wait for Speedtest to finish
echo -e "${YELLOW}[*]${NC} Waiting for Speedtest to finish... (all captures active)"
wait $SPEEDTEST_PID || true
RAW_RESULTS=$(cat "$SPEEDTEST_RESULTS_FILE")
rm -f "$SPEEDTEST_RESULTS_FILE"

# Stop Captures Immediately
echo -e "${YELLOW}[*]${NC} Speedtest complete. Stopping captures and apps..."
adb shell su -c 'pkill -INT diag_mdlog' 2>/dev/null || true
adb shell su -c 'pkill tcpdump' 2>/dev/null || true
kill $TCPDUMP_PID 2>/dev/null || true
kill $DIAG_PID 2>/dev/null || true

# End G-NetTrack Pro log (triggers save), then close the app
echo -e "${YELLOW}[*]${NC} Ending G-NetTrack Pro log..."
gnet_end_log
sleep 3
adb shell su -c 'am force-stop com.gyokovsolutions.gnettrackproplus' 2>/dev/null || true
echo -e "${GREEN}[✓]${NC} Closed G-NetTrack Pro."

# Parse Speedtest Results
CLEAN_RESULTS=$(echo "$RAW_RESULTS" | tr -d '\033' | sed 's/\[[0-9;]*m//g')
PING=$(echo "$CLEAN_RESULTS" | grep -iE '(ping|latency)' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1 || echo "0.00")
DOWN=$(echo "$CLEAN_RESULTS" | grep -i 'download' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1 || echo "0.00")
UP=$(echo "$CLEAN_RESULTS" | grep -i 'upload' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1 || echo "0.00")

echo -e "${GREEN}  → Ping: ${PING} ms | Down: ${DOWN} Mbps | Up: ${UP} Mbps${NC}"

# Save Speedtest Results to file
RESULTS_FILE="${OUTPUT_DIR}/speedtest_results.txt"
{
    echo "Timestamp : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Ping      : ${PING} ms"
    echo "Download  : ${DOWN} Mbps"
    echo "Upload    : ${UP} Mbps"
    echo ""
    echo "--- Raw Output ---"
    echo "$CLEAN_RESULTS"
} > "$RESULTS_FILE"
echo -e "${GREEN}[✓]${NC} Speedtest results saved to: $RESULTS_FILE"

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