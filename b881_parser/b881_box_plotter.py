#!/usr/bin/env python3
import sys
import os

import glob
import datetime
import warnings
import matplotlib
# Suppress Matplotlib deprecation warning for 'labels' parameter in boxplot
warnings.filterwarnings("ignore", category=matplotlib.MatplotlibDeprecationWarning)
import numpy as np
import matplotlib.pyplot as plt



def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return int.from_bytes(b[o:o+4], byteorder='little')
def u64(b, o): return int.from_bytes(b[o:o+8], byteorder='little')

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

def extract_b881_data(payload_file):
    """
    Parses B881 packets from the payloads file and returns cumulative records.
    """
    records = []
    with open(payload_file, 'r') as f:
        for line in f:
            tokens = line.strip().split()
            if not tokens: 
                continue
            try:
                raw = bytes(int(t, 16) for t in tokens)
                i = 0
                while i < len(raw) - 3:
                    if raw[i+2] == 0x81 and raw[i+3] == 0xB8:
                        pkt_len = raw[i] | (raw[i+1] << 8)
                        if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                            pkt_data = raw[i : i + pkt_len]
                            pkt_time = parse_qxdm_time(pkt_data[4:12])
                            minor_ver = u16(pkt_data, 12)
                            major_ver = u16(pkt_data, 14)
                            
                            if major_ver == 3 and minor_ver == 1:
                                num_records = pkt_data[19]
                                O = 24
                                for rec_idx in range(num_records):
                                    if O + 80 <= len(pkt_data):
                                        new_tx = u64(pkt_data, O)
                                        retx = u64(pkt_data, O+8)
                                        num_mcs = u64(pkt_data, O+16)
                                        num_prb = u64(pkt_data, O+24)
                                        num_new_tb = u32(pkt_data, O+44)
                                        num_retx_tb = u32(pkt_data, O+48)
                                        
                                        # Skip empty/uninitialized records to prevent false delta jumps
                                        if new_tx == 0 and num_mcs == 0 and num_new_tb == 0:
                                            O += 80
                                            continue
                                            
                                        records.append({
                                            'time': pkt_time,
                                            'new_tx': new_tx,
                                            'retx': retx,
                                            'num_mcs': num_mcs,
                                            'num_prb': num_prb,
                                            'num_new_tb': num_new_tb,
                                            'num_retx_tb': num_retx_tb
                                        })
                                    O += 80
                            i += pkt_len - 1
                    i += 1
            except Exception:
                pass
    return records

def process_payload_file(payload_file, bin_size_sec=1.0):
    """
    Processes a single payload file, computes deltas, bins the data,
    and returns arrays of Average MCS, TB Retransmission Rate (BLER %),
    and Uplink Throughput (Mbps) for active bins.
    """
    raw_records = extract_b881_data(payload_file)
    if not raw_records:
        return None

    # Sort records chronologically
    raw_records.sort(key=lambda x: x['time'])

    # Compute deltas from cumulative records
    b881_deltas = []
    prev = raw_records[0]
    for r in raw_records:
        d_new_tx = r['new_tx'] - prev['new_tx']
        d_retx = r['retx'] - prev['retx']
        d_mcs = r['num_mcs'] - prev['num_mcs']
        d_prb = r['num_prb'] - prev['num_prb']
        d_new_tb = r['num_new_tb'] - prev['num_new_tb']
        d_retx_tb = r['num_retx_tb'] - prev['num_retx_tb']

        if d_new_tx < 0 or d_retx < 0 or d_mcs < 0 or d_prb < 0 or d_new_tb < 0 or d_retx_tb < 0:
            # Skip anomalies/resets
            d_new_tx = 0
            d_retx = 0
            d_mcs = 0
            d_prb = 0
            d_new_tb = 0
            d_retx_tb = 0

        b881_deltas.append({
            'time': r['time'],
            'new_tx_bytes': d_new_tx,
            'retx_bytes': d_retx,
            'num_mcs': d_mcs,
            'num_prb': d_prb,
            'num_new_tb': d_new_tb,
            'num_retx_tb': d_retx_tb,
        })
        prev = r

    if not b881_deltas:
        return None

    b881_times = np.array([d['time'] for d in b881_deltas])
    min_time = min(b881_times)
    max_time = max(b881_times)

    if max_time <= min_time:
        return None

    # Binning
    bins = np.arange(min_time, max_time + bin_size_sec, bin_size_sec)
    
    # Bin sums
    mcs_sum_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['num_mcs'] for d in b881_deltas])
    prb_sum_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['num_prb'] for d in b881_deltas])
    new_tb_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['num_new_tb'] for d in b881_deltas])
    retx_tb_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['num_retx_tb'] for d in b881_deltas])
    new_tx_bytes_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['new_tx_bytes'] for d in b881_deltas])

    total_tb_binned = new_tb_binned + retx_tb_binned
    
    # We define active bins as bins where transmission activity happened and uplink throughput is non-zero
    active_mask = (total_tb_binned > 0) & (new_tx_bytes_binned > 0)
    if not np.any(active_mask):
        return None

    # Calculate Uplink Throughput (Mbps): (bytes * 8) / (1e6 * bin_size)
    throughput_active = (new_tx_bytes_binned[active_mask] * 8.0) / (1e6 * bin_size_sec)

    # Calculate Average MCS: sum(MCS) / total_tb for active uplink throughput bins
    mcs_active = mcs_sum_binned[active_mask] / total_tb_binned[active_mask]
    
    # Calculate Average Allocated PRBs: sum(PRB) / total_tb for active uplink throughput bins
    prb_active = prb_sum_binned[active_mask] / total_tb_binned[active_mask]

    return {
        'throughput': throughput_active,
        'mcs': mcs_active,
        'prb': prb_active
    }

def clean_filename(path):
    """
    Extracts a simplified clean name for plot labeling.
    Recognizes common logging patterns (Runs, Captures, Operators, Locations, Scenarios).
    """
    norm = os.path.normpath(path)
    parts = norm.split(os.sep)
    base = os.path.basename(path)
    import re
    
    # 1. Check for run_XXX pattern (e.g. run_000 -> R0)
    run_match = re.search(r'run_(\d+)', norm, re.IGNORECASE)
    if run_match:
        return f"R{int(run_match.group(1))}"
        
    # 2. Check for capture_XXX pattern (e.g. capture_000 -> C0)
    cap_match = re.search(r'capture_(\d+)', norm, re.IGNORECASE)
    cap_str = f"C{int(cap_match.group(1))}" if cap_match else ""
    
    # 3. Check for Operator / Network / Device in path
    operators = ['Airtel', 'Jio', 'Vodafone', 'Vi', 'Wifi', 'ACN_Lab', 'Vaishali', 'Ashish', 'Tarun', 'Lajja']
    found_op = None
    for p in parts:
        for op in operators:
            if op.lower() in p.lower():
                found_op = op
                break
        if found_op:
            break
            
    # 4. Check for location / activity
    activities = ['VideoStreaming', 'WebBrowsing', 'NoActivity', 'SpeedTest', 'ExperimentalSpeedtest', 'Amul_IITDelhi', 'Amul', 'Voda']
    found_act = None
    for p in parts:
        for act in activities:
            if act.lower() in p.lower():
                found_act = act.replace('VideoStreaming', 'Video').replace('WebBrowsing', 'Web').replace('NoActivity', 'Idle').replace('Amul_IITDelhi', 'Amul')
                break
        if found_act:
            break

    # Build clean label
    if found_op:
        label = found_op
        if found_act and found_act.lower() not in found_op.lower():
            label += f"-{found_act}"
        if cap_str:
            label += f"-{cap_str}"
        return label
    elif cap_str:
        return f"{parts[-2] if len(parts) > 1 else cap_str}"

    # 5. Check for moving / lab / ground patterns
    if "moving" in base.lower():
        m = re.search(r'(\d+)', base)
        return f"M{m.group(1)}" if m else "Moving"
    if "ground" in base.lower():
        m = re.search(r'(\d+)', base)
        return f"G{m.group(1)}" if m else "Ground"
    if "lab" in base.lower():
        m = re.search(r'(\d+)', base)
        return f"L{m.group(1)}" if m else "Lab"
    if "voda" in base.lower():
        m = re.search(r'(\d+)', base)
        return f"Voda{m.group(1)}" if m else "Voda"
        
    clean = os.path.splitext(base)[0].replace("payloads_", "").replace("_payloads", "").replace("payloads", "")
    return clean if clean else base


def style_boxplot(ax, data, labels, title, ylabel, color, rotation=0):
    """
    Applies custom styling to make the boxplots look beautiful.
    """
    bp = ax.boxplot(data, labels=labels, patch_artist=True, 
                    showmeans=True, meanline=True,
                    medianprops={'color': 'black', 'linewidth': 1.5},
                    meanprops={'color': 'darkgreen', 'linestyle': '--', 'linewidth': 1.5},
                    flierprops={'marker': 'o', 'markerfacecolor': 'grey', 'markeredgecolor': 'none', 'markersize': 4, 'alpha': 0.5})
    
    for patch in bp['boxes']:
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
        patch.set_edgecolor('black')
        
    ax.set_title(title, fontsize=12, fontweight='bold', pad=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.grid(True, linestyle=':', alpha=0.6)
    ax.set_xticklabels(labels, rotation=rotation, ha='center' if rotation == 0 else 'right')


def main():
    args = sys.argv[1:]
    
    # Check if the last argument is an output plot filename (usually ends with .png)
    plot_filename = "b881_box_plots.png"
    if args and (args[-1].endswith('.png') or args[-1].endswith('.jpg') or args[-1].endswith('.pdf')):
        plot_filename = args[-1]
        args = args[:-1]
        
    # If no files are specified, let's search in the standard payload directories
    if not args:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        search_patterns = [
            os.path.join(script_dir, "payloads", "payloads_run_*.txt"),
            os.path.join(script_dir, "payloads", "payloads_lab-*.txt"),
            os.path.join(script_dir, "..", "loggers", "data", "**", "payloads_b881.txt"),
        ]
        files = []
        for p in search_patterns:
            matches = sorted(glob.glob(p, recursive=True))
            if matches:
                files.extend(matches)
        files = sorted(list(set([f for f in files if "parsed" not in f and "record" not in f and "qmdl" not in f])))
        if not files:
            print("Error: No run payloads found")
            print("Usage: python b881_box_plotter.py <payload1.txt> <payload2.txt> ... [output_plot.png]")
            sys.exit(1)
    else:
        # Resolve any globs (e.g. if the user runs in a shell that didn't expand them)
        files = []
        for a in args:
            matches = glob.glob(a, recursive=True)
            if matches:
                files.extend(matches)
            else:
                files.append(a)
        files = sorted(list(set(files)))

    print(f"Found {len(files)} payload file(s) to process:")
    for f in files:
        print(f" - {f}")

    all_tput = []
    all_mcs = []
    all_prb = []
    labels = []

    for f in files:
        base = os.path.basename(f)
        clean_name = clean_filename(f)
            
        print(f"Processing {clean_name} ({base})...")
        metrics = process_payload_file(f)
        if metrics is not None:
            all_tput.append(metrics['throughput'])
            all_mcs.append(metrics['mcs'])
            all_prb.append(metrics['prb'])
            labels.append(clean_name)
        else:
            print(f"  Warning: No active transmission data found in {f}. Skipping.")


    if not labels:
        print("Error: No data could be processed from the files.")
        sys.exit(1)

    max_label_len = max(len(l) for l in labels) if labels else 0
    rotation = 45 if len(labels) > 6 or max_label_len > 6 else 0

    # Make the figure with 3 subplots side by side in sequence: Throughput, MCS, PRB
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))

    # 1. Uplink Throughput (blue/teal-ish color)
    style_boxplot(ax1, all_tput, labels, "Uplink Throughput", "Throughput (Mbps)", "#0288d1", rotation=rotation)

    # 2. Modulation & Coding Scheme (MCS) (indigo/purple-ish color)
    style_boxplot(ax2, all_mcs, labels, "Modulation & Coding Scheme", "Average MCS Index", "#6f42c1", rotation=rotation)
    
    # 3. Physical Resource Blocks (PRB) (coral/red-ish color)
    style_boxplot(ax3, all_prb, labels, "Resource Block Allocation", "Allocated PRBs (Num PRBs)", "#d9534f", rotation=rotation)

    plt.suptitle("Uplink Performance Metrics Distribution Across Runs", fontsize=15, fontweight='bold', y=0.98)
    plt.tight_layout()
    
    # Make sure output directory exists if it's specified in a path
    output_dir = os.path.dirname(plot_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    plt.savefig(plot_filename, dpi=150)
    print(f"\n📈 Success! Box plots saved as '{plot_filename}'")

if __name__ == "__main__":
    main()
