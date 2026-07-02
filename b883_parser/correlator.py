import sys
import datetime
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import PcapReader, IP, IPv6

def u16(b, o): return b[o] | (b[o+1] << 8)

def parse_qxdm_time(ts_bytes):
    """
    Converts the 8-byte QXDM hardware timestamp into a standard UNIX epoch float.
    """
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    time_seconds = (integer_ticks + fractional_ticks) * 1.25 / 1000.0
    
    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    return (cdma_epoch + datetime.timedelta(seconds=time_seconds)).timestamp()

def extract_rbs_with_time(payload_file):
    """
    Extracts tuples of (timestamp, num_rbs) for both B883 (UL) and B887 (DL).
    """
    b883_records, b887_records = [], []
    with open(payload_file, 'r') as f:
        for line in f:
            tokens = line.strip().split()
            if not tokens: 
                continue
            try:
                raw = bytes(int(t, 16) for t in tokens)
                i = 0

                while i < len(raw) - 3:
                    # Parse B883 (UL PUSCH)
                    if raw[i+2] == 0x83 and raw[i+3] == 0xB8:
                        pkt_len = raw[i] | (raw[i+1] << 8)
                        
                        if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                            pkt_data = raw[i : i + pkt_len]
                            
                            ts_bytes = pkt_data[4:12]
                            pkt_time = parse_qxdm_time(ts_bytes)
                            
                            num_records = pkt_data[19]
                            O = 20
                            
                            for rec_idx in range(num_records):
                                if O + 8 > len(pkt_data): 
                                    break 
                                
                                b5 = pkt_data[O+5]
                                chan_nibble = b5 & 0x0F
                                
                                len_map = {1: 60, 2: 44, 4: 44, 8: 32}
                                rec_len = len_map.get(chan_nibble, 44)
                                
                                # Only target PUSCH
                                if chan_nibble == 2 and O + 8 + 30 <= len(pkt_data):
                                    num_rbs = u16(pkt_data, O + 8 + 4) & 0x1FF
                                    b883_records.append((pkt_time, num_rbs))
                                    
                                O += rec_len
                            
                            i += pkt_len - 1
                    
                    # Parse B887 (DL PDSCH)
                    elif raw[i+2] == 0x87 and raw[i+3] == 0xB8:
                        pkt_len = raw[i] | (raw[i+1] << 8)
                        
                        if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                            pkt_data = raw[i : i + pkt_len]
                            
                            ts_bytes = pkt_data[4:12]
                            pkt_time = parse_qxdm_time(ts_bytes)
                            num_records = pkt_data[19]
                            
                            for j in range(num_records):
                                entry_start = 20 + j*32
                                if entry_start + 22 <= len(pkt_data):
                                    num_rbs = u16(pkt_data, entry_start + 20) & 0x1FF
                                    b887_records.append((pkt_time, num_rbs))
                            
                            i += pkt_len - 1
                    i += 1
            except Exception:
                pass
                
    return np.array(b883_records), np.array(b887_records)

def extract_pcap_split(pcap_file, device_ip):
    """
    Extracts packets and splits them by comparing the IP to the device's IP.
    """
    dl_records = []
    ul_records = []

    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            src, dst = None, None
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            else:
                continue 

            # Route to correct bucket based on IP
            if dst == device_ip:
                dl_records.append((float(pkt.time), len(pkt)))
            elif src == device_ip:
                ul_records.append((float(pkt.time), len(pkt)))

    return np.array(dl_records), np.array(ul_records)

def normalize(arr):
    """Helper to safely normalize data between 0 and 1."""
    if len(arr) == 0 or np.ptp(arr) == 0:
        return np.zeros_like(arr)
    return (arr - np.min(arr)) / np.ptp(arr)

def main():
    if len(sys.argv) < 4:
        print("Usage: python correlator.py <payloads.txt> <capture.pcap> <device_ip>")
        sys.exit(1)

    payload_file = sys.argv[1]
    pcap_file = sys.argv[2]
    device_ip = sys.argv[3]

    print(f"Targeting: Download & Upload alignment using Device IP {device_ip}")

    print("Extracting time-series sequences...")
    b883_data, b887_data = extract_rbs_with_time(payload_file)
    dl_data, ul_data = extract_pcap_split(pcap_file, device_ip)

    if len(b883_data) == 0 and len(b887_data) == 0:
        print("Error: The radio log dataset is empty.")
        return
    if len(dl_data) == 0 and len(ul_data) == 0:
        print("Error: The PCAP dataset contains no IP traffic for the provided IP.")
        return

    print(f"Extracted {len(dl_data)} DL pkts, {len(ul_data)} UL pkts.")
    print(f"Extracted {len(b887_data)} B887 DL records, {len(b883_data)} B883 UL records.")

    # Gather all timestamps to find the overlapping global time window
    all_times = []
    for d in (b883_data, b887_data, dl_data, ul_data):
        if len(d) > 0:
            all_times.extend(d[:, 0])

    if not all_times:
        print("Error: No overlapping time data found.")
        return

    min_time = min(all_times)
    max_time = max(all_times)

    BIN_SIZE_SEC = 1.0
    print(f"Grouping data into {BIN_SIZE_SEC}-second time bins...")
    bins = np.arange(min_time, max_time + BIN_SIZE_SEC, BIN_SIZE_SEC)

    # Use histogram to bucket timestamps and sum weights
    rb_ul_binned, _ = np.histogram(b883_data[:, 0], bins=bins, weights=b883_data[:, 1]) if len(b883_data) else (np.zeros(len(bins)-1), bins)
    rb_dl_binned, _ = np.histogram(b887_data[:, 0], bins=bins, weights=b887_data[:, 1]) if len(b887_data) else (np.zeros(len(bins)-1), bins)
    
    dl_binned, _ = np.histogram(dl_data[:, 0], bins=bins, weights=dl_data[:, 1]) if len(dl_data) else (np.zeros(len(bins)-1), bins)
    ul_binned, _ = np.histogram(ul_data[:, 0], bins=bins, weights=ul_data[:, 1]) if len(ul_data) else (np.zeros(len(bins)-1), bins)

    # Calculate Correlations
    corr_dl, corr_ul = 0.0, 0.0
    
    if np.std(dl_binned) != 0 and np.std(rb_dl_binned) != 0:
        corr_dl = np.corrcoef(dl_binned, rb_dl_binned)[0, 1]
    
    if np.std(ul_binned) != 0 and np.std(rb_ul_binned) != 0:
        corr_ul = np.corrcoef(ul_binned, rb_ul_binned)[0, 1]

    print(f"\n📊 B887 (DL RBs) to PCAP Download Correlation: {corr_dl:.4f}")
    print(f"📊 B883 (UL RBs) to PCAP Upload Correlation: {corr_ul:.4f}\n")

    # Normalize data for plotting
    dl_norm = normalize(dl_binned)
    ul_norm = normalize(ul_binned)
    rb_dl_norm = normalize(rb_dl_binned)
    rb_ul_norm = normalize(rb_ul_binned)

    # Plotting (2 subplots vertically stacked)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
    time_axis = bins[:-1] - min_time

    # Top Plot: Downlink
    ax1.plot(time_axis, dl_norm, label='PCAP Download (Normalized)', alpha=0.8, color='tab:blue')
    ax1.plot(time_axis, rb_dl_norm, label='Radio B887 DL RBs (Normalized)', linestyle='dashed', alpha=0.8, color='tab:red')
    ax1.set_title(f"Download Traffic Alignment - Correlation: {corr_dl:.2f}")
    ax1.set_ylabel('Normalized Magnitude')
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    # Bottom Plot: Uplink
    ax2.plot(time_axis, ul_norm, label='PCAP Upload (Normalized)', alpha=0.8, color='tab:orange')
    ax2.plot(time_axis, rb_ul_norm, label='Radio B883 UL RBs (Normalized)', linestyle='dashed', alpha=0.8, color='tab:red')
    ax2.set_title(f"Upload Traffic Alignment - Correlation: {corr_ul:.2f}")
    ax2.set_xlabel(f'Time (Seconds from capture start) [{BIN_SIZE_SEC}s bins]')
    ax2.set_ylabel('Normalized Magnitude')
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig("sequence_correlation_both.png")
    print("📈 Plot saved as 'sequence_correlation_both.png'")

if __name__ == "__main__":
    main()
