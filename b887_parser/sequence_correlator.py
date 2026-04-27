import sys
import datetime
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
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
    Extracts tuples of (timestamp, num_rbs) representing RBs.
    """
    records = []
    with open(payload_file, 'r') as f:
        for line in f:
            tokens = line.strip().split()
            try:
                raw = bytes(int(t, 16) for t in tokens)
                ts_bytes = raw[13:21]
                pkt_time = parse_qxdm_time(ts_bytes)
                
                for j in range(raw[28]):
                    entry_start = 29 + j*32
                    num_rbs = u16(raw, entry_start + 20) & 0x1FF
                    records.append((pkt_time, num_rbs))
            except:
                pass
    return np.array(records)

def guess_device_ip(pcap_file):
    """
    Scans the PCAP to find the most common IP address, assuming it belongs to the capturing device.
    """
    ips = []
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            if IP in pkt:
                ips.extend([pkt[IP].src, pkt[IP].dst])
            elif IPv6 in pkt:
                ips.extend([pkt[IPv6].src, pkt[IPv6].dst])
                
    if not ips:
        return None
    return Counter(ips).most_common(1)[0][0]

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
                continue # Skip non-IP traffic (like ARP)

            # Route to correct bucket based on IP
            if dst == device_ip:
                dl_records.append((float(pkt.time), len(pkt)))
            elif src == device_ip:
                ul_records.append((float(pkt.time), len(pkt)))
                
    return np.array(dl_records), np.array(ul_records)

def main():
    if len(sys.argv) < 4:
        print("Usage: python sequence_correlator.py <payloads.txt> <capture.pcap> <downlink|uplink>")
        sys.exit(1)
        
    payload_file = sys.argv[1]
    pcap_file = sys.argv[2]
    channel_type = sys.argv[3].lower()
    
    if channel_type not in ['downlink', 'dl', 'uplink', 'ul']:
        print("Error: The third argument must be either 'downlink' or 'uplink'.")
        sys.exit(1)
        
    is_downlink = channel_type in ['downlink', 'dl']
    target_name = "Download" if is_downlink else "Upload"
    
    print("Analyzing PCAP to determine device IP...")
    device_ip = guess_device_ip(pcap_file)
    if not device_ip:
        print("Error: Could not find any valid IPv4 or IPv6 traffic in the PCAP.")
        return
    print(f"Device IP determined as: {device_ip}")
    
    print("Extracting time-series sequences...")
    rb_data = extract_rbs_with_time(payload_file)
    dl_data, ul_data = extract_pcap_split(pcap_file, device_ip)
    
    if len(rb_data) == 0:
        print("Error: The radio log dataset is empty.")
        return
    if len(dl_data) == 0 and len(ul_data) == 0:
        print("Error: The PCAP dataset contains no IP traffic.")
        return

    print(f"Extracted {len(dl_data)} Download pkts, {len(ul_data)} Upload pkts, and {len(rb_data)} MAC records.")

    # Determine the overlapping global time window
    min_time = min(np.min(rb_data[:, 0]) if len(rb_data) else float('inf'), 
                   np.min(dl_data[:, 0]) if len(dl_data) else float('inf'),
                   np.min(ul_data[:, 0]) if len(ul_data) else float('inf'))
                   
    max_time = max(np.max(rb_data[:, 0]) if len(rb_data) else 0, 
                   np.max(dl_data[:, 0]) if len(dl_data) else 0,
                   np.max(ul_data[:, 0]) if len(ul_data) else 0)
    
    BIN_SIZE_SEC = 1.0
    print(f"Grouping data into {BIN_SIZE_SEC}-second time bins...")
    bins = np.arange(min_time, max_time + BIN_SIZE_SEC, BIN_SIZE_SEC)
    
    # Use histogram to bucket timestamps and sum weights
    rb_binned, _ = np.histogram(rb_data[:, 0], bins=bins, weights=rb_data[:, 1]) if len(rb_data) else (np.zeros(len(bins)-1), bins)
    dl_binned, _ = np.histogram(dl_data[:, 0], bins=bins, weights=dl_data[:, 1]) if len(dl_data) else (np.zeros(len(bins)-1), bins)
    ul_binned, _ = np.histogram(ul_data[:, 0], bins=bins, weights=ul_data[:, 1]) if len(ul_data) else (np.zeros(len(bins)-1), bins)

    # Select the target PCAP sequence based on user argument
    target_binned = dl_binned if is_downlink else ul_binned

    correlation = 0.0
    if np.std(target_binned) != 0 and np.std(rb_binned) != 0:
        # Calculate Pearson Correlation on the selected channel
        correlation = np.corrcoef(target_binned, rb_binned)[0, 1]
        print(f"\n📊 Radio Allocation to {target_name} PCAP Correlation: {correlation:.4f}")
        
        if correlation > 0.6:
            print(f"   -> Strong correlation! {target_name} traffic matches Radio RBs.")
        elif -0.2 <= correlation <= 0.2:
            print("   -> No correlation. The traffic and radio logs do not align in time.")
    else:
        print(f"\n⚠️ Zero Variance Detected in {target_name} or RB binned data (Flatline).")

    # Normalize data for plotting
    dl_norm = (dl_binned - np.min(dl_binned)) / (np.ptp(dl_binned) or 1)
    ul_norm = (ul_binned - np.min(ul_binned)) / (np.ptp(ul_binned) or 1)
    rb_norm = (rb_binned - np.min(rb_binned)) / (np.ptp(rb_binned) or 1)

    # Plotting
    plt.figure(figsize=(12, 5))
    time_axis = bins[:-1] - min_time
    
    # Plot both DL and UL for context, but highlight the chosen one in the legend
    plt.plot(time_axis, dl_norm, label='PCAP Download (Normalized)', alpha=0.8 if is_downlink else 0.3, color='tab:blue', linestyle='solid' if is_downlink else 'dotted')
    plt.plot(time_axis, ul_norm, label='PCAP Upload (Normalized)', alpha=0.8 if not is_downlink else 0.3, color='tab:orange', linestyle='solid' if not is_downlink else 'dotted')
    plt.plot(time_axis, rb_norm, label='Radio RBs (Normalized)', linestyle='dashed', alpha=0.8, color='tab:red')
    
    plt.title(f"{target_name} Traffic Alignment - Correlation: {correlation:.2f}")
        
    plt.xlabel(f'Time (Seconds from capture start) [{BIN_SIZE_SEC}s bins]')
    plt.ylabel('Normalized Magnitude')
    plt.legend()
    plt.tight_layout()
    plt.savefig("sequence_correlation.png")
    print("📈 Plot saved as 'sequence_correlation.png'")

if __name__ == "__main__":
    main()