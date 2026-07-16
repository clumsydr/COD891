#!/bin/bash
#
# DIAG & PCAP Capture Script (Iperf3 & G-NetTrack Pro Triggered)
# Captures PCAP and QMDL logs strictly for the duration of an iperf test,
# while running G-NetTrack Pro in the foreground.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Iperf Configuration
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR=${1:-"diag_capture_${TIMESTAMP}"}
IPERF_SERVER=${2:-"speedtest.sin1.sg.leaseweb.net"} 
IPERF_PORT=${3:-"5201"}
IPERF_DURATION=${4:-"20"}
MAX_SIZE=1000  # MB

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

echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  OnePlus 11R DIAG & PCAP Capture (Iperf3 & G-NetTrack Pro Mode)${NC}"
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

# Clean up old logs & Set up directories (MOVED TO /data/local/tmp)
echo -e "${YELLOW}[*]${NC} Preparing directories..."
adb shell su -c 'rm -rf /data/local/tmp/diag_temp' >/dev/null 2>&1 || true
adb shell su -c 'mkdir -p /data/local/tmp/diag_temp'
adb shell su -c 'chmod 777 /data/local/tmp/diag_temp'
mkdir -p "$OUTPUT_DIR"

# Launch G-NetTrack Pro and start logging first
echo -e "${GREEN}[✓]${NC} Launching G-NetTrack Pro..."
adb shell su -c 'monkey -p com.gyokovsolutions.gnettrackproplus -c android.intent.category.LAUNCHER 1' >/dev/null 2>&1
sleep 3
echo -e "${GREEN}[✓]${NC} Starting G-NetTrack Pro log..."
gnet_start_log

# RESTORED: Discover Active Interface
ACTIVE_IFACE=$(adb shell su -c 'ip route get 8.8.8.8 2>/dev/null' | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n 1 | tr -d '\r')
ACTIVE_IFACE=${ACTIVE_IFACE:-any}

# Start Background PCAP
echo -e "${GREEN}[✓]${NC} Starting PCAP on interface: $ACTIVE_IFACE"
PCAP_FILE="/data/local/tmp/diag_temp/capture_$TIMESTAMP.pcap"
adb shell su -c "tcpdump -i $ACTIVE_IFACE -w $PCAP_FILE" &>/dev/null &
TCPDUMP_PID=$!

# Start Background DIAG Log
echo -e "${GREEN}[✓]${NC} Starting DIAG Modem Logger..."
adb shell su -c "/vendor/bin/diag_mdlog -o /data/local/tmp/diag_temp -s ${MAX_SIZE} -f /vendor/odm/etc/modem_rf.cfg -c" &>/dev/null &
DIAG_PID=$!

# Give background loggers 2 seconds to initialize file handles
sleep 2

# Execute Iperf3 in Background
echo -e "${YELLOW}[*]${NC} Starting Iperf3 to ${IPERF_SERVER}:${IPERF_PORT} for ${IPERF_DURATION}s..."
IPERF_RESULTS_FILE=$(mktemp)
adb shell su -c "/data/local/tmp/iperf3 -c $IPERF_SERVER -p $IPERF_PORT -t $IPERF_DURATION" > "$IPERF_RESULTS_FILE" &
IPERF_PID=$!

# Wait for Iperf3 to finish
echo -e "${YELLOW}[*]${NC} Waiting for Iperf3 to finish... (all captures active)"
wait $IPERF_PID || true
RAW_RESULTS=$(cat "$IPERF_RESULTS_FILE")
rm -f "$IPERF_RESULTS_FILE"

# Stop Captures Immediately
echo -e "${YELLOW}[*]${NC} Iperf test complete. Stopping captures and apps..."
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

# Parse Iperf3 Results
CLEAN_RESULTS=$(echo "$RAW_RESULTS" | tr -d '\033' | sed 's/\[[0-9;]*m//g')
SENDER_BW=$(echo "$CLEAN_RESULTS" | grep -i 'sender' | awk '{print $7, $8}' | head -n 1 || echo "0.00 Mbps")
RECEIVER_BW=$(echo "$CLEAN_RESULTS" | grep -i 'receiver' | awk '{print $7, $8}' | head -n 1 || echo "0.00 Mbps")

echo -e "${GREEN}  → Sender (Upload): ${SENDER_BW} | Receiver: ${RECEIVER_BW}${NC}"

# Save Iperf3 Results to file
RESULTS_FILE="${OUTPUT_DIR}/iperf_results.txt"
{
    echo "Timestamp       : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Iperf Server    : ${IPERF_SERVER}:${IPERF_PORT}"
    echo "Duration        : ${IPERF_DURATION} seconds"
    echo "Sender Bitrate  : ${SENDER_BW}"
    echo "Receiver Bitrate: ${RECEIVER_BW}"
    echo ""
    echo "--- Raw Output ---"
    echo "$CLEAN_RESULTS"
} > "$RESULTS_FILE"
echo -e "${GREEN}[✓]${NC} Iperf3 results saved to: $RESULTS_FILE"

# Pull data
echo -e "${YELLOW}[*]${NC} Pulling data from device..."
adb pull /data/local/tmp/diag_temp/. "${OUTPUT_DIR}/" >/dev/null 2>&1
adb shell su -c 'rm -rf /data/local/tmp/diag_temp' >/dev/null 2>&1

FILECOUNT=$(ls -1 "${OUTPUT_DIR}"/*.qmdl* 2>/dev/null | wc -l | tr -d ' ')
if [ "$FILECOUNT" -eq "0" ]; then
    echo -e "${RED}[✗]${NC} Warning: No DIAG files were saved successfully."
else
    echo -e "${GREEN}[✓]${NC} Data saved to: ${OUTPUT_DIR}/"
fi
