import sys
import numpy as np
import matplotlib.pyplot as plt
from scipy import signal
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

def extract_pcap_sequence(pcap_file):
    """
    Extracts purely the sequential list of packet lengths.
    """
    pcap_sequence = []
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            pcap_sequence.append(len(pkt))
    return np.array(pcap_sequence)

def main():
    if len(sys.argv) < 3:
        print("Usage: python sequence_correlator.py <payloads.txt> <capture.pcap>")
        sys.exit(1)
        
    payload_file = sys.argv[1]
    pcap_file = sys.argv[2]
    
    print("Extracting sequences...")
    rb_seq = extract_rbs_sequence(payload_file)
    pcap_seq = extract_pcap_sequence(pcap_file)
    
    if len(rb_seq) == 0 or len(pcap_seq) == 0:
        print("Error: One of the datasets is empty.")
        return

    print(f"Original PCAP packets: {len(pcap_seq)}")
    print(f"Original MAC records:  {len(rb_seq)}")

    # Force the PCAP sequence to match the length of the RB sequence using signal resampling
    print("\nResampling PCAP data to match radio log length...")
    pcap_resampled = signal.resample(pcap_seq, len(rb_seq))

    # Calculate Pearson Correlation on the aligned sequences
    correlation = np.corrcoef(pcap_resampled, rb_seq)[0, 1]
    print(f"\n📊 Sequence Correlation Coefficient: {correlation:.4f}")
    
    if correlation > 0.6:
        print("   -> Strong correlation! The data bursts share a highly similar structural shape.")
    elif correlation < 0.2 and correlation > -0.2:
        print("   -> No correlation. The shapes of the traffic do not align sequentially.")

    # Normalize data for plotting so they fit on the same scale (0 to 1)
    pcap_norm = (pcap_resampled - np.min(pcap_resampled)) / (np.ptp(pcap_resampled) or 1)
    rb_norm = (rb_seq - np.min(rb_seq)) / (np.ptp(rb_seq) or 1)

    # Plotting
    plt.figure(figsize=(12, 5))
    plt.plot(pcap_norm, label='PCAP Lengths (Resampled & Normalized)', alpha=0.8)
    plt.plot(rb_norm, label='Radio RBs (Normalized)', linestyle='dashed', alpha=0.8)
    
    plt.title(f"Sequential Shape Alignment (Time Ignored) - Correlation: {correlation:.2f}")
    plt.xlabel('Sequential Event Index (Forced Alignment)')
    plt.ylabel('Normalized Magnitude')
    plt.legend()
    plt.tight_layout()
    plt.savefig("sequence_correlation.png")
    print("📈 Plot saved as 'sequence_correlation.png'")

if __name__ == "__main__":
    main()
