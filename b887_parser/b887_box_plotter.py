#!/usr/bin/env python3
import sys
import os
import re
import glob
import datetime
import warnings
import matplotlib
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

def extract_b887_data(payload_file):
    """
    Parses B887 (NR5G MAC PDSCH Status) packets from the payloads file
    and returns a list of individual record dictionaries containing TB Size,
    MCS, and Num RBs along with metadata.
    Supports both Major Version 2 (28-byte records) and Version 3 (32-byte records).
    """
    records = []
    with open(payload_file, 'r') as f:
        for line in f:
            tokens = line.strip().split()
            if not tokens:
                continue
            try:
                raw = bytes(int(t, 16) for t in tokens if len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t))
                i = 0
                while i < len(raw) - 3:
                    # Look for 0xB887 log code signature
                    if raw[i+2] == 0x87 and raw[i+3] == 0xB8:
                        pkt_len = raw[i] | (raw[i+1] << 8)
                        if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                            pkt_data = raw[i : i + pkt_len]
                            pkt_time = parse_qxdm_time(pkt_data[4:12])
                            version_word = u32(pkt_data, 12)
                            major_ver = version_word >> 16
                            
                            if major_ver == 2:
                                rec_len = 28
                                rec_start = 27
                            elif major_ver == 3:
                                rec_len = 32
                                rec_start = 19
                            else:
                                rec_len = 28
                                rec_start = 27
                            
                            if rec_start < len(pkt_data):
                                num_records = pkt_data[rec_start]
                                available = (len(pkt_data) - (rec_start + 1)) // rec_len
                                num_records = min(num_records, available)
                                
                                for rec_idx in range(num_records):
                                    base = rec_start + 1 + rec_idx * rec_len
                                    rec = pkt_data[base : base + rec_len]
                                    if len(rec) >= 10:
                                        slot = rec[0]
                                        frame = u16(rec, 2) & 0x3FF
                                        entry = rec[10:]
                                        if len(entry) >= 14:
                                            pci = u16(entry, 2) & 0x3FF
                                            nr_arfcn = (u32(entry, 3) >> 2) & 0x3FFFFF
                                            tb_size = (u32(entry, 6) >> 5) & 0x1FFFF
                                            mcs = (u16(entry, 9) >> 2) & 0x1F
                                            num_rbs = u16(entry, 10) & 0x1FF
                                            harq_id = (entry[11] >> 3) & 0xF
                                            k1 = (u16(entry, 12) >> 6) & 0xF
                                            
                                            # Skip empty/uninitialized records
                                            if tb_size == 0 and num_rbs == 0 and mcs == 0:
                                                continue
                                                
                                            records.append({
                                                'time': pkt_time,
                                                'slot': slot,
                                                'frame': frame,
                                                'pci': pci,
                                                'nr_arfcn': nr_arfcn,
                                                'tb_size': tb_size,
                                                'mcs': mcs,
                                                'num_rbs': num_rbs,
                                                'harq_id': harq_id,
                                                'k1': k1,
                                            })
                            i += pkt_len - 1
                    i += 1
            except Exception:
                pass
    return records

def process_payload_file(payload_file):
    """
    Processes a single payload file and returns arrays of TB Size, MCS,
    and Num RBs for all parsed grants.
    """
    raw_records = extract_b887_data(payload_file)
    if not raw_records:
        return None

    tb_size_arr = np.array([r['tb_size'] for r in raw_records], dtype=float)
    mcs_arr = np.array([r['mcs'] for r in raw_records], dtype=float)
    num_rbs_arr = np.array([r['num_rbs'] for r in raw_records], dtype=float)

    return {
        'tb_size': tb_size_arr,
        'mcs': mcs_arr,
        'num_rbs': num_rbs_arr,
        'count': len(raw_records)
    }

def clean_filename(path):
    """
    Extracts a simplified clean name for plot labeling.
    Recognizes common logging patterns (Runs, Captures, Operators, Locations, Scenarios).
    """
    norm = os.path.normpath(path)
    parts = norm.split(os.sep)
    base = os.path.basename(path)
    
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
    Applies custom styling to make the boxplots consistent with B881 plots.
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
    
    # Check if the last argument is an output plot filename
    plot_filename = "b887_box_plots.png"
    if args and (args[-1].endswith('.png') or args[-1].endswith('.jpg') or args[-1].endswith('.pdf')):
        plot_filename = args[-1]
        args = args[:-1]
        
    # If no files are specified, find available sample files in standard project directories
    if not args:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        search_patterns = [
            os.path.join(script_dir, "..", "loggers", "data", "**", "payloads_b887.txt"),
            os.path.join(script_dir, "..", "loggers", "data", "**", "payloads*.txt"),
            os.path.join(script_dir, "TarunPhoneLogs", "*", "payloads*.txt"),
            os.path.join(script_dir, "AshishPhoneLogs", "*", "payloads*.txt"),
            os.path.join(script_dir, "..", "loggers", "lajja_logs", "run_*", "*payloads_b887.txt"),
        ]
        files = []
        for p in search_patterns:
            matches = sorted(glob.glob(p, recursive=True))
            if matches:
                files.extend(matches)
                
        # Deduplicate and filter non-raw payload files
        files = sorted(list(set([f for f in files if "parsed" not in f and "record" not in f and "qmdl" not in f])))
        if not files:
            print("Error: No B887 payload files found automatically.")
            print("Usage: python b887_box_plotter.py <payload1.txt> <payload2.txt> ... [output_plot.png]")
            sys.exit(1)
        # Select representative set if many
        if len(files) > 12:
            files = files[:12]
    else:
        # Resolve any globs
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

    all_tb_size = []
    all_mcs = []
    all_num_rbs = []
    labels = []

    print("\n" + "=" * 80)
    print(f"{'Run / File':<22} | {'Records':>8} | {'TB Size (Mean±Std)':>18} | {'MCS (Mean)':>10} | {'RBs (Mean)':>10}")
    print("=" * 80)

    for f in files:
        clean_name = clean_filename(f)
        metrics = process_payload_file(f)
        if metrics is not None and metrics['count'] > 0:
            all_tb_size.append(metrics['tb_size'])
            all_mcs.append(metrics['mcs'])
            all_num_rbs.append(metrics['num_rbs'])
            labels.append(clean_name)
            
            tb_mean = np.mean(metrics['tb_size'])
            tb_std = np.std(metrics['tb_size'])
            mcs_mean = np.mean(metrics['mcs'])
            rbs_mean = np.mean(metrics['num_rbs'])
            
            print(f"{clean_name:<22} | {metrics['count']:>8d} | {tb_mean:>8.1f} ± {tb_std:<6.1f} | {mcs_mean:>10.2f} | {rbs_mean:>10.2f}")
        else:
            print(f"  Warning: No active B887 data found in {f}. Skipping.")

    print("=" * 80 + "\n")

    if not labels:
        print("Error: No data could be processed from the files.")
        sys.exit(1)

    # Determine label rotation if many labels or long names
    max_label_len = max(len(l) for l in labels) if labels else 0
    rotation = 45 if len(labels) > 6 or max_label_len > 6 else 0

    # Make the figure with 3 subplots side by side
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))

    # Style and plot each metric
    # 1. TB Size (cool blue)
    style_boxplot(ax1, all_tb_size, labels, "Transport Block (TB) Size", "TB Size (Bytes)", "#0288d1", rotation=rotation)
    
    # 2. MCS (purple/indigo)
    style_boxplot(ax2, all_mcs, labels, "Modulation & Coding Scheme", "MCS Index", "#6f42c1", rotation=rotation)
    
    # 3. Num RBs (coral/orange)
    style_boxplot(ax3, all_num_rbs, labels, "Resource Block Allocation", "Allocated RBs (Num RBs)", "#d9534f", rotation=rotation)

    plt.suptitle("B887 NR5G MAC PDSCH Metrics Distribution Across Runs", fontsize=15, fontweight='bold', y=0.98)
    plt.tight_layout()
    
    # Make sure output directory exists if it's specified in a path
    output_dir = os.path.dirname(plot_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    plt.savefig(plot_filename, dpi=150)
    print(f"📈 Success! Box plots saved as '{plot_filename}'")

if __name__ == "__main__":
    main()
