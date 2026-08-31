#!/bin/bash
#
# Scheduled Capture Runner
# Calls capture_diag_pcap_nsg_speedtest.sh every 5 minutes.
# Each run is saved with a zero-based index and timestamp.
#

INTERVAL=60  # 5 minutes in seconds
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CAPTURE_SCRIPT="$SCRIPT_DIR/capture_diag_iperf_pcap.sh"
BASE_OUTPUT_DIR="${1:-scheduled_captures}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

INDEX=0

trap 'echo -e "\n${RED}[!]${NC} Interrupted. Stopped after run #$((INDEX-1))."; exit 0' INT TERM

mkdir -p "$BASE_OUTPUT_DIR"
echo -e "${GREEN}[✓]${NC} Output root: $(realpath "$BASE_OUTPUT_DIR")"
echo -e "${YELLOW}[*]${NC} Interval: every $((INTERVAL / 60)) minutes. Press Ctrl+C to stop."
echo ""

while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    RUN_LABEL="run_$(printf '%03d' $INDEX)_${TIMESTAMP}"
    RUN_DIR="$BASE_OUTPUT_DIR/$RUN_LABEL"

    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Run #${INDEX}  |  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"

    # Run the capture script; it saves PCAP + QMDL into RUN_DIR
    bash "$CAPTURE_SCRIPT" "$RUN_DIR"

    # Pull G-NetTrack Pro logs from device
    GNET_DIR="$RUN_DIR/gnettrack_logs"
    mkdir -p "$GNET_DIR"
    echo -e "${YELLOW}[*]${NC} Pulling G-NetTrack Pro logs..."
    adb pull "/sdcard/Documents/G-NetTrack_Pro_Logs/." "$GNET_DIR/" 2>/dev/null || true
    echo -e "${YELLOW}[*]${NC} Cleaning up G-NetTrack Pro logs from device..."
    adb shell am force-stop com.gyokovsolutions.gnettrackproplus 2>/dev/null || true
    sleep 1
    adb shell rm -rf "/sdcard/Documents/G-NetTrack_Pro_Logs/"
    echo -e "${GREEN}[✓]${NC} G-NetTrack Pro logs deleted from device."

    # Convert G-NetTrack Pro txt logs to CSV
    echo -e "${YELLOW}[*]${NC} Converting G-NetTrack Pro logs to CSV..."
    python3 "$SCRIPT_DIR/convert_gnettrack_to_csv.py" "$GNET_DIR"

    echo -e "${GREEN}[✓]${NC} Run #${INDEX} saved to: $RUN_DIR"
    echo ""

    INDEX=$((INDEX + 1))

    NEXT_RUN=$(date -d "+${INTERVAL} seconds" '+%H:%M:%S')
    echo -e "${YELLOW}[*]${NC} Waiting ${INTERVAL}s before next run (#${INDEX}) at ${NEXT_RUN}..."
    sleep "$INTERVAL"

    echo ""
done
