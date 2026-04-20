#!/system/bin/sh
# ==============================================================================
# Synthesized 5G Diagnostics & Speedtest Synchronizer
# Captures baseband logs (diag_mdlog) and PCAPs during an active throughput test.
# ==============================================================================

set -e

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Configuration ---
WORKDIR="/data/local/tmp"
ROOTFS="$WORKDIR/fakeroot"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="/sdcard/SyncLogs_$TIMESTAMP"
DIAG_TEMP="$WORKDIR/diag_temp"
PCAP_FILE="$OUTPUT_DIR/capture_$TIMESTAMP.pcap"
LOG_FILE="$OUTPUT_DIR/speed_history.csv"

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Synchronized 5G Net Logger + DIAG Capture${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"

if [ "$(id -u)" -ne 0 ]; then 
  echo -e "${RED}[✗] Error: This script requires root access (su).${NC}"
  exit 1
fi

# --- 1. Prepare Environment ---
echo -e "${YELLOW}[*] Preparing directories and micro-container...${NC}"
mkdir -p "$OUTPUT_DIR"
mkdir -p "$DIAG_TEMP"

# Clean up any broken mounts from a previous run
umount "$ROOTFS/dev" 2>/dev/null || true
umount "$ROOTFS/proc" 2>/dev/null || true
umount "$ROOTFS/sys" 2>/dev/null || true
rm -rf "$ROOTFS" 2>/dev/null

# Build the standard Linux folder tree for the binary
mkdir -p "$ROOTFS/etc/ssl/certs"
mkdir -p "$ROOTFS/dev"
mkdir -p "$ROOTFS/proc"
mkdir -p "$ROOTFS/sys"

# Inject DNS and SSL dependencies
echo "nameserver 8.8.8.8" > "$ROOTFS/etc/resolv.conf"
if [ ! -f "$WORKDIR/cacert.pem" ]; then
    curl -s -k -o "$WORKDIR/cacert.pem" "https://curl.se/ca/cacert.pem"
fi
cp "$WORKDIR/cacert.pem" "$ROOTFS/etc/ssl/certs/ca-certificates.crt"

# Copy the speedtest binary into the chroot (Requires binary to be in $WORKDIR)
cp "$WORKDIR/speedtest" "$ROOTFS/"
chmod +x "$ROOTFS/speedtest"

mount -o bind /dev "$ROOTFS/dev"
mount -t proc proc "$ROOTFS/proc"
mount -t sysfs sysfs "$ROOTFS/sys"

# --- 2. Initialize Loggers ---
ACTIVE_IFACE=$(ip route get 8.8.8.8 | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n 1)
ACTIVE_IFACE=${ACTIVE_IFACE:-wlan0}

# Stop old processes
killall diag_mdlog 2>/dev/null || true
killall tcpdump 2>/dev/null || true
sleep 1

echo -e "${YELLOW}[*] Starting PCAP on ${ACTIVE_IFACE}...${NC}"
tcpdump -i "$ACTIVE_IFACE" -s 96 -w "$PCAP_FILE" >/dev/null 2>&1 &
TCPDUMP_PID=$!

echo -e "${YELLOW}[*] Starting Baseband DIAG capture...${NC}"
diag_mdlog -o "$DIAG_TEMP" -s 1000 >/dev/null 2>&1 &
DIAG_PID=$!

# Allow loggers to lock files and initialize
sleep 2

# --- 3. Execute Speedtest ---
echo -e "${GREEN}[>] Running speedtest inside chroot container...${NC}"
RAW_RESULTS=$(NO_COLOR=1 chroot "$ROOTFS" /speedtest --accept-license --accept-gdpr 2>/dev/null)
echo -e "${GREEN}[✓] Test complete.${NC}"

# --- 4. Terminate Loggers ---
echo -e "${YELLOW}[*] Stopping active loggers...${NC}"
kill $TCPDUMP_PID 2>/dev/null || true
killall diag_mdlog 2>/dev/null || kill $DIAG_PID 2>/dev/null || true
sleep 2 # Allow buffers to flush to disk

# --- 5. Process Logs ---
# Move DIAG files out of temp workspace
mv "$DIAG_TEMP"/* "$OUTPUT_DIR/" 2>/dev/null || true
rm -rf "$DIAG_TEMP"

# Clean up chroot
umount "$ROOTFS/dev" 2>/dev/null || true
umount "$ROOTFS/proc" 2>/dev/null || true
umount "$ROOTFS/sys" 2>/dev/null || true

# --- 6. Parse and Save Results ---
CLEAN_RESULTS=$(echo "$RAW_RESULTS" | tr -d '\033' | sed 's/\[[0-9;]*m//g')

PING=$(echo "$CLEAN_RESULTS" | grep -iE '(ping|latency)' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1)
DOWN=$(echo "$CLEAN_RESULTS" | grep -i 'download' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1)
UP=$(echo "$CLEAN_RESULTS" | grep -i 'upload' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1)

PING=${PING:-0}
DOWN=${DOWN:-0}
UP=${UP:-0}

# Create CSV header if it doesn't exist
if [ ! -f "$LOG_FILE" ]; then
    echo "Timestamp,Interface,Ping_ms,Down_Mbps,Up_Mbps,Diag_Saved" > "$LOG_FILE"
fi

# Determine if Diag logged properly
DIAG_COUNT=$(find "$OUTPUT_DIR" -name "*.qmdl*" | wc -l)
DIAG_STATUS="No"
if [ "$DIAG_COUNT" -gt 0 ]; then DIAG_STATUS="Yes"; fi

echo "$TIMESTAMP,$ACTIVE_IFACE,$PING,$DOWN,$UP,$DIAG_STATUS" >> "$LOG_FILE"

echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  Results Summary"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  Ping:           ${PING} ms"
echo -e "  Download:       ${DOWN} Mbps"
echo -e "  Upload:         ${UP} Mbps"
echo -e "  Network Iface:  ${ACTIVE_IFACE}"
echo -e "  PCAP Saved:     Yes"
echo -e "  DIAG Saved:     ${DIAG_STATUS} (${DIAG_COUNT} files)"
echo -e "  Output Path:    ${OUTPUT_DIR}/"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
