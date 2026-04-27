import sys
import datetime
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import PcapReader

def u16(b, o): return b[o] | (b[o+1] << 8)

def parse_qxdm_time(ts_bytes):
    """
    Converts the 8-byte QXDM hardware timestamp into a standard UNIX epoch float.
    Upper 48 bits = ticks, Lower 16 bits = fractional. 1 tick = 1.25 ms.
    """
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    time_seconds = (integer_ticks + fractional_ticks) * 1.25 / 1000.0
    
    # FIX: Make the epoch timezone-aware (UTC) so .timestamp() yields standard UNIX epoch
    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    
    return (cdma_epoch + datetime.timedelta(seconds=time_seconds)).timestamp()

def extract_rbs_with_time(payload_file):
    """
    Extracts tuples of (timestamp, num_rbs) using the exact hardware timestamp.
    """
    records = []
    with open(payload_file, 'r') as f:
        for line in f:
            tokens = line.strip().split()
            try:
                raw = bytes(int(t, 16) for t in tokens)
                # Extract 8-byte timestamp
                ts_bytes = raw[13:21]
                pkt_time = parse_qxdm_time(ts_bytes)
                
                # Retaining your original RB extraction logic
                for j in range(raw[28]):
                    entry_start = 29 + j*32
                    num_rbs = u16(raw, entry_start + 20) & 0x1FF
                    records.append((pkt_time, num_rbs))
            except:
                pass
    return np.array(records)

def extract_pcap_with_time(pcap_file):
    """
    Extracts tuples of (timestamp, packet_length).
    """
    records = []
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            records.append((float(pkt.time), len(pkt)))
    return np.array(records)

def main():
    if len(sys.argv) < 3:
        print("Usage: python sequence_correlator.py <payloads.txt> <capture.pcap>")
        sys.exit(1)
        
    payload_file = sys.argv[1]
    pcap_file = sys.argv[2]
    
    print("Extracting time-series sequences...")
    rb_data = extract_rbs_with_time(payload_file)
    pcap_data = extract_pcap_with_time(pcap_file)
    
    if len(rb_data) == 0 or len(pcap_data) == 0:
        print("Error: One of the datasets is empty.")
        return

    print(f"Extracted {len(pcap_data)} PCAP packets and {len(rb_data)} MAC records.")

    # Determine the overlapping global time window
    min_time = min(np.min(rb_data[:, 0]), np.min(pcap_data[:, 0]))
    max_time = max(np.max(rb_data[:, 0]), np.max(pcap_data[:, 0]))
    
    # Catch massive time disparities (e.g., captures taken days apart)
    time_diff = abs(np.min(rb_data[:, 0]) - np.min(pcap_data[:, 0]))
    if time_diff > 3600:
        print(f"\n⚠️ Warning: Datasets start {time_diff / 3600:.2f} hours apart. Overlap correlation will likely fail.")

    # Group into fixed time bins (1.0 second bins)
    BIN_SIZE_SEC = 1.0
    print(f"Grouping data into {BIN_SIZE_SEC}-second time bins...")
    
    bins = np.arange(min_time, max_time + BIN_SIZE_SEC, BIN_SIZE_SEC)
    
    # Use histogram to bucket timestamps and sum their respective weights (RBs or Lengths)
    rb_binned, _ = np.histogram(rb_data[:, 0], bins=bins, weights=rb_data[:, 1])
    pcap_binned, _ = np.histogram(pcap_data[:, 0], bins=bins, weights=pcap_data[:, 1])

    # Variance Check
    if np.std(pcap_binned) == 0 or np.std(rb_binned) == 0:
        print("\n⚠️ Zero Variance Detected in binned data (Flatline).")
        correlation = 0.0
    else:
        # Calculate Pearson Correlation on the time-aligned binned sequences
        correlation = np.corrcoef(pcap_binned, rb_binned)[0, 1]
        print(f"\n📊 Time-Aligned Correlation Coefficient: {correlation:.4f}")
        
        if correlation > 0.6:
            print("   -> Strong correlation! Spikes in PCAP traffic match allocated RBs over time.")
        elif -0.2 <= correlation <= 0.2:
            print("   -> No correlation. The traffic and radio logs do not align in time.")

    # Normalize data for plotting so they fit on the same visual scale (0 to 1)
    pcap_norm = (pcap_binned - np.min(pcap_binned)) / (np.ptp(pcap_binned) or 1)
    rb_norm = (rb_binned - np.min(rb_binned)) / (np.ptp(rb_binned) or 1)

    # Plotting
    plt.figure(figsize=(12, 5))
    
    # Plot using relative time from start of the captures
    time_axis = bins[:-1] - min_time
    
    plt.plot(time_axis, pcap_norm, label='Grouped PCAP Lengths (Normalized)', alpha=0.8)
    plt.plot(time_axis, rb_norm, label='Grouped Radio RBs (Normalized)', linestyle='dashed', alpha=0.8)
    
    if np.std(pcap_binned) == 0 or np.std(rb_binned) == 0:
        plt.title("Time-Aligned Data Grouping - ZERO VARIANCE (Flatline)")
    else:
        plt.title(f"Time-Aligned Data Grouping - Correlation: {correlation:.2f}")
        
    plt.xlabel(f'Time (Seconds from capture start) [{BIN_SIZE_SEC}s bins]')
    plt.ylabel('Normalized Magnitude')
    plt.legend()
    plt.tight_layout()
    plt.savefig("sequence_correlation.png")
    print("📈 Plot saved as 'sequence_correlation.png'")

if __name__ == "__main__":
    main()
