#!/system/bin/sh

# ==========================================
# CONFIGURATION
# ==========================================
WORKDIR="/data/local/tmp"
ROOTFS="$WORKDIR/fakeroot"
OUTPUT_DIR="$WORKDIR/net_logs"
PCAP_DIR="$OUTPUT_DIR/pcaps"
LOG_FILE="$OUTPUT_DIR/speed_history.csv"
INTERVAL=60

mkdir -p "$PCAP_DIR"

if [ "$(id -u)" -ne 0 ]; then 
  echo "[-] Error: This script requires root access."
  exit 1
fi

# ==========================================
# MICRO-CONTAINER SETUP
# ==========================================
echo "[*] Constructing Linux Micro-Container..."

# 1. Clean up any broken mounts from a previous run
umount "$ROOTFS/dev" 2>/dev/null
umount "$ROOTFS/proc" 2>/dev/null
umount "$ROOTFS/sys" 2>/dev/null
rm -rf "$ROOTFS"

# 2. Build the standard Linux folder tree
mkdir -p "$ROOTFS/etc/ssl/certs"
mkdir -p "$ROOTFS/dev"
mkdir -p "$ROOTFS/proc"
mkdir -p "$ROOTFS/sys"

# 3. Inject our DNS instructions
echo "nameserver 8.8.8.8" > "$ROOTFS/etc/resolv.conf"

# 4. Fetch standard Linux SSL certificates so the binary can use HTTPS
if [ ! -f "$WORKDIR/cacert.pem" ]; then
    echo "[*] Downloading standard Linux SSL certificates..."
    curl -s -k -o "$WORKDIR/cacert.pem" https://curl.se/ca/cacert.pem
fi
cp "$WORKDIR/cacert.pem" "$ROOTFS/etc/ssl/certs/ca-certificates.crt"

# 5. Move the binary into the container
cp "$WORKDIR/speedtest-go" "$ROOTFS/"
chmod +x "$ROOTFS/speedtest-go"

# 6. Bind mount the system hardware so the binary can see your network interface
mount -o bind /dev "$ROOTFS/dev"
mount -o bind /proc "$ROOTFS/proc"
mount -o bind /sys "$ROOTFS/sys"

# 7. Safety trap: unmount everything cleanly if you press Ctrl+C
trap "echo -e '\n[*] Tearing down container and exiting...'; umount $ROOTFS/dev 2>/dev/null; umount $ROOTFS/proc 2>/dev/null; umount $ROOTFS/sys 2>/dev/null; exit" INT TERM

# ==========================================
# THE LOGGER LOOP
# ==========================================
if [ ! -f "$LOG_FILE" ]; then
    echo "Timestamp,Ping(ms),Download(Mbps),Upload(Mbps),Interface,PCAP_Filename" > "$LOG_FILE"
fi

echo "[*] Starting Network Logger..."
while true; do
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    READABLE_DATE=$(date)
    PCAP_FILE="$PCAP_DIR/capture_$TIMESTAMP.pcap"
    
    # Detect the active interface
    ACTIVE_IFACE=$(ip route get 8.8.8.8 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n 1)
    ACTIVE_IFACE=${ACTIVE_IFACE:-wlan0}

    echo "[*] Starting test at $READABLE_DATE on $ACTIVE_IFACE"

    # Start PCAP
    tcpdump -i "$ACTIVE_IFACE" -s 96 -w "$PCAP_FILE" &>/dev/null &
    TCPDUMP_PID=$!

    sleep 2

    # RUN THE BINARY INSIDE THE CHROOT CONTAINER
    JSON_RESULTS=$(chroot "$ROOTFS" /speedtest-go --json 2>/dev/null)

    # Stop PCAP
    kill $TCPDUMP_PID
    wait $TCPDUMP_PID 2>/dev/null

    # Parse JSON using native Android tools
    PING=$(echo "$JSON_RESULTS" | grep -o '"ping":[0-9.]*' | awk -F':' '{print $2}')
    DOWN=$(echo "$JSON_RESULTS" | grep -o '"download":[0-9.]*' | awk -F':' '{print $2}')
    UP=$(echo "$JSON_RESULTS" | grep -o '"upload":[0-9.]*' | awk -F':' '{print $2}')

    # Handle blank values if the test failed
    PING=${PING:-0}
    DOWN=${DOWN:-0}
    UP=${UP:-0}

    echo "$READABLE_DATE,$PING,$DOWN,$UP,$ACTIVE_IFACE,capture_$TIMESTAMP.pcap" >> "$LOG_FILE"
    echo "Results: Ping: ${PING}ms | Down: ${DOWN} Mbps | Up: ${UP} Mbps"

    echo "[*] Sleeping for $INTERVAL seconds..."
    sleep $INTERVAL
    echo ""
done