#!/system/bin/sh

# ==========================================
# CONFIGURATION
# ==========================================
WORKDIR="/data/local/tmp"
ROOTFS="$WORKDIR/fakeroot"
OUTPUT_DIR="$WORKDIR/net_logs"
PCAP_DIR="$OUTPUT_DIR/pcaps"
LOG_FILE="$OUTPUT_DIR/speed_history.csv"
INTERVAL=30
POISSON_INTERVAL=3

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
cp "$WORKDIR/speedtest" "$ROOTFS/"
chmod +x "$ROOTFS/speedtest"

# 6. Bind mount the system hardware so the binary can see your network interface
mount -o bind /dev "$ROOTFS/dev"
mount -o bind /proc "$ROOTFS/proc"
mount -o bind /sys "$ROOTFS/sys"

# 7. Safety trap: unmount everything cleanly if you press Ctrl+C
trap "echo -e '\n[*] Tearing down container and exiting...'; kill \$TCPDUMP_PID 2>/dev/null; umount $ROOTFS/dev 2>/dev/null; umount $ROOTFS/proc 2>/dev/null; umount $ROOTFS/sys 2>/dev/null; exit" INT TERM

# ==========================================
# THE LOGGER LOOP
# ==========================================
if [ ! -f "$LOG_FILE" ]; then
    echo "Timestamp,Ping(ms),Download(Mbps),Upload(Mbps),Interface,PCAP_Filename" > "$LOG_FILE"
fi

echo "[*] Starting Network Logger..."
while true; do
    CHANCE=$(( RANDOM % 10 ))

    if [ $CHANCE -eq 0 ]; then
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
        RAW_RESULTS=$(NO_COLOR=1 chroot "$ROOTFS" /speedtest --accept-license --accept-gdpr 2>/dev/null)

        # Stop PCAP
        kill $TCPDUMP_PID
        wait $TCPDUMP_PID 2>/dev/null

        CLEAN_RESULTS=$(echo "$RAW_RESULTS" | tr -d '\033' | sed 's/[[][0-9;]*m//g')

        # Extract the very first valid number found on each line
        PING=$(echo "$CLEAN_RESULTS" | grep -iE '(ping|latency)' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1)
        DOWN=$(echo "$CLEAN_RESULTS" | grep -i 'download' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1)
        UP=$(echo "$CLEAN_RESULTS" | grep -i 'upload' | grep -oE '[0-9]+(\.[0-9]+)?' | head -n 1)

        # Fallbacks in case the test completely failed
        PING=${PING:-0.00}
        DOWN=${DOWN:-0.00}
        UP=${UP:-0.00}

        echo "$READABLE_DATE,$PING,$DOWN,$UP,$ACTIVE_IFACE,capture_$TIMESTAMP.pcap" >> "$LOG_FILE"
        echo "Results: Ping: ${PING}ms | Down: ${DOWN} Mbps | Up: ${UP} Mbps"

        echo "[*] Sleeping for $INTERVAL seconds..."
        sleep $INTERVAL
        echo ""
    else
        echo "POISSONED... checking again in 3 seconds."
        sleep $POISSON_INTERVAL
    fi
done
