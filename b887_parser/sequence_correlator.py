import sys
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import PcapReader

def u16(b, o): return b[o] | (b[o+1] << 8)

def extract_rbs_sequence(payload_file):
    """
    Extracts purely the sequential list of Num RBs.
    """
    rb_sequence = []
    with open(payload_file, 'r') as f:
        for line in f:
            tokens = line.strip().split()
            try:
                raw = bytes(int(t, 16) for t in tokens)
                for i in range(raw[28]):
                    entry_start = 29 + i*32
                    num_rbs = u16(raw, entry_start + 20) & 0x1FF
                    rb_sequence.append(num_rbs)
            except:
                pass
    return np.array(rb_sequence)

def extract_and_group_pcap(pcap_file, num_bins):
    """
    Extracts packets from the PCAP, calculates the total duration, 
    divides the time evenly into `num_bins`, and sums the packet lengths 
    falling into each time bucket.
    """
    pkt_times = []
    pkt_lengths = []
    
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            pkt_times.append(float(pkt.time))
            pkt_lengths.append(len(pkt))
            
    if not pkt_times:
        return np.zeros(num_bins)
        
    t_start = min(pkt_times)
    t_end = max(pkt_times)
    total_duration = t_end - t_start
    
    # Initialize our buckets with zeros
    pcap_grouped = np.zeros(num_bins)
    
    if total_duration == 0 or num_bins == 0:
        # If the capture happened in exactly 0 seconds, dump it all in the first bin
        if num_bins > 0:
            pcap_grouped[0] = sum(pkt_lengths)
        return pcap_grouped

    time_per_bin = total_duration / num_bins
    
    # Sort packets into their respective time buckets
    for t, l in zip(pkt_times, pkt_lengths):
        bin_idx = int((t - t_start) / time_per_bin)
        # Cap the index to prevent an IndexError for the very last packet
        bin_idx = min(bin_idx, num_bins - 1)
        pcap_grouped[bin_idx] += l
        
    return pcap_grouped

def main():
    if len(sys.argv) < 3:
        print("Usage: python sequence_correlator.py <payloads.txt> <capture.pcap>")
        sys.exit(1)
        
    payload_file = sys.argv[1]
    pcap_file = sys.argv[2]
    
    print("Extracting MAC sequence...")
    rb_seq = extract_rbs_sequence(payload_file)
    num_mac_records = len(rb_seq)
    
    if num_mac_records == 0:
        print("Error: The radio payload dataset is empty.")
        return
        
    print(f"Original MAC records:  {num_mac_records}")
    print(f"Grouping PCAP into {num_mac_records} time-based bins...")
    
    pcap_grouped = extract_and_group_pcap(pcap_file, num_mac_records)
    
    if len(pcap_grouped) == 0 or np.sum(pcap_grouped) == 0:
        print("Error: The PCAP dataset is empty or contains no length data.")
        return

    # Variance Check to prevent flat-line crashes
    if np.std(pcap_grouped) == 0 or np.std(rb_seq) == 0:
        print("\n⚠️ Zero Variance Detected")
        print("One or both datasets consist of a completely constant value (no spikes or drops).")
        print("Because this is a 'flat line', mathematical correlation cannot be calculated.")
        correlation = 0.0
    else:
        # Calculate Pearson Correlation safely
        correlation = np.corrcoef(pcap_grouped, rb_seq)[0, 1]
        print(f"\n📊 Time-Grouped Correlation Coefficient: {correlation:.4f}")
        
        if correlation > 0.6:
            print("   -> Strong correlation! Traffic buckets align closely with RB allocations.")
        elif -0.2 <= correlation <= 0.2:
            print("   -> No correlation. The shapes of the grouped traffic do not align.")

    # Normalize data for plotting so they fit on the same scale (0 to 1)
    pcap_norm = (pcap_grouped - np.min(pcap_grouped)) / (np.ptp(pcap_grouped) or 1)
    rb_norm = (rb_seq - np.min(rb_seq)) / (np.ptp(rb_seq) or 1)

    # Plotting
    plt.figure(figsize=(12, 5))
    plt.plot(pcap_norm, label='Grouped PCAP Lengths (Normalized)', alpha=0.8, color='tab:blue')
    plt.plot(rb_norm, label='Radio RBs (Normalized)', linestyle='dashed', alpha=0.8, color='tab:red')
    
    if np.std(pcap_grouped) == 0 or np.std(rb_seq) == 0:
        plt.title("Time-Grouped Alignment - ZERO VARIANCE (Flatline)")
    else:
        plt.title(f"Time-Grouped Alignment - Correlation: {correlation:.2f}")
        
    plt.xlabel('Time Buckets (Sequence Index)')
    plt.ylabel('Normalized Magnitude')
    plt.legend()
    plt.tight_layout()
    plt.savefig("sequence_correlation.png")
    print("📈 Plot saved as 'sequence_correlation.png'")

if __name__ == "__main__":
    main()
