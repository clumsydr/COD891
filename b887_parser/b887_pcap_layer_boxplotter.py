#!/usr/bin/env python3
"""
B887 Num Layers vs PCAP Speed — Box Plotter
===========================================
Extracts MIMO transmission layers (`num_layers`) from 0xB887 NR5G MAC PDSCH logs,
synchronizes with PCAP packet captures via hardware timestamps, computes
instantaneous and windowed Downlink throughput, and produces comparative box plots.

Usage:
    # Single run (payloads + pcap):
    python b887_pcap_layer_boxplotter.py payloads.txt capture.pcap

    # Directory containing both files:
    python b887_pcap_layer_boxplotter.py /path/to/capture_dir/

    # Multiple runs / custom output:
    python b887_pcap_layer_boxplotter.py run1/ run2/ -o layer_vs_pcap_boxplot.png

    # Auto-discover all runs in standard directories:
    python b887_pcap_layer_boxplotter.py
"""

import sys
import os
import re
import glob
import struct
import datetime
import argparse
import warnings
import matplotlib
warnings.filterwarnings("ignore", category=matplotlib.MatplotlibDeprecationWarning)
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

# ── Low-level Helpers ─────────────────────────────────────────────────────────
def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return int.from_bytes(b[o:o+4], byteorder='little')

def parse_qxdm_time(ts_bytes: bytes) -> float:
    """
    Converts 8-byte QXDM hardware timestamp to standard UNIX epoch float.
    Upper 48 bits = 1.25 ms ticks since CDMA epoch (Jan 6, 1980 00:00:00 UTC).
    Lower 16 bits = fractional component (1/65536th of a tick).
    """
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    time_seconds = (integer_ticks + fractional_ticks) * 1.25 / 1000.0
    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    return (cdma_epoch + datetime.timedelta(seconds=time_seconds)).timestamp()

# ── Fast Binary PCAP Parser ───────────────────────────────────────────────────
def read_pcap_fast(filepath: str):
    """
    High-speed pure-Python binary parser for PCAP captures.
    Supports DLT 113 (Linux Cooked SLL), DLT 1 (Ethernet), IPv4, IPv6,
    and microsecond / nanosecond timestamp resolutions.
    Returns: (list of (timestamp, length) for Downlink packets, device_ip)
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading PCAP file '{filepath}': {e}")
        return [], None

    if len(data) < 24:
        return [], None

    magic, v_maj, v_min, thiszone, sigfigs, snaplen, network = struct.unpack('<IHHIIII', data[:24])
    if magic == 0xa1b2c3d4:
        endian, ts_div = '<', 1e6
    elif magic == 0xd4c3b2a1:
        endian, ts_div = '>', 1e6
    elif magic == 0xa1b23c4d:
        endian, ts_div = '<', 1e9
    elif magic == 0x4d3cb2a1:
        endian, ts_div = '>', 1e9
    else:
        return read_pcap_scapy(filepath)

    hdr_fmt = endian + 'IIII'
    offset = 24
    data_len = len(data)
    parsed_pkts = []
    ips = []

    while offset + 16 <= data_len:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(hdr_fmt, data, offset)
        offset += 16
        if offset + incl_len > data_len:
            break
        t = ts_sec + (ts_usec / ts_div)
        pkt_bytes = data[offset : offset + incl_len]

        src_ip = None
        dst_ip = None
        pkt_type = None

        if network == 113 and len(pkt_bytes) >= 16:  # Linux Cooked SLL
            pkt_type, _, _, proto = struct.unpack_from('>HHHH', pkt_bytes, 0)
            if proto == 0x0800 and len(pkt_bytes) >= 36:  # IPv4
                src_ip = '.'.join(str(b) for b in pkt_bytes[28:32])
                dst_ip = '.'.join(str(b) for b in pkt_bytes[32:36])
                ips.extend([src_ip, dst_ip])
            elif proto == 0x86DD and len(pkt_bytes) >= 56:  # IPv6
                src_ip = pkt_bytes[24:40].hex()
                dst_ip = pkt_bytes[40:56].hex()
                ips.extend([src_ip, dst_ip])
        elif network == 1 and len(pkt_bytes) >= 14:  # Ethernet
            eth_type = struct.unpack_from('>H', pkt_bytes, 12)[0]
            if eth_type == 0x0800 and len(pkt_bytes) >= 34:
                src_ip = '.'.join(str(b) for b in pkt_bytes[26:30])
                dst_ip = '.'.join(str(b) for b in pkt_bytes[30:34])
                ips.extend([src_ip, dst_ip])
            elif eth_type == 0x86DD and len(pkt_bytes) >= 54:
                src_ip = pkt_bytes[22:38].hex()
                dst_ip = pkt_bytes[38:54].hex()
                ips.extend([src_ip, dst_ip])

        parsed_pkts.append((t, orig_len, src_ip, dst_ip, pkt_type))
        offset += incl_len

    device_ip = Counter(ips).most_common(1)[0][0] if ips else None

    dl_packets = []
    for t, orig_len, src_ip, dst_ip, pkt_type in parsed_pkts:
        is_dl = True
        if network == 113 and pkt_type is not None:
            if pkt_type == 4:  # Outgoing / UL
                is_dl = False
            elif pkt_type == 0:  # Incoming / DL
                is_dl = True
            elif device_ip and dst_ip:
                is_dl = (dst_ip == device_ip)
        elif device_ip and dst_ip:
            is_dl = (dst_ip == device_ip)

        if is_dl:
            dl_packets.append((t, orig_len))

    return dl_packets, device_ip

def read_pcap_scapy(filepath: str):
    """Fallback reader using Scapy."""
    try:
        from scapy.all import PcapReader, IP, IPv6
        ips = []
        raw_pkts = []
        with PcapReader(filepath) as pcap_reader:
            for pkt in pcap_reader:
                src, dst = None, None
                if IP in pkt:
                    src, dst = pkt[IP].src, pkt[IP].dst
                    ips.extend([src, dst])
                elif IPv6 in pkt:
                    src, dst = pkt[IPv6].src, pkt[IPv6].dst
                    ips.extend([src, dst])
                raw_pkts.append((float(pkt.time), len(pkt), dst))

        device_ip = Counter(ips).most_common(1)[0][0] if ips else None
        dl_packets = []
        for t, orig_len, dst in raw_pkts:
            if dst == device_ip or device_ip is None:
                dl_packets.append((t, orig_len))
        return dl_packets, device_ip
    except Exception as e:
        print(f"Scapy fallback error: {e}")
        return [], None

# ── B887 Payload Parser ───────────────────────────────────────────────────────
def extract_b887_records(payload_path: str):
    """
    Parses B887 payloads and extracts individual records with decoded `num_layers`.
    Supports Version 2 (28-byte records) and Version 3 (32-byte records).
    """
    records = []
    with open(payload_path, 'r') as f:
        for line in f:
            tokens = line.strip().split()
            if not tokens:
                continue
            try:
                raw = bytes(int(t, 16) for t in tokens if len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t))
                i = 0
                while i < len(raw) - 3:
                    if raw[i+2] == 0x87 and raw[i+3] == 0xB8:
                        pkt_len = raw[i] | (raw[i+1] << 8)
                        if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                            pkt_data = raw[i : i + pkt_len]
                            pkt_time = parse_qxdm_time(pkt_data[4:12])
                            version_word = u32(pkt_data, 12)
                            major_ver = version_word >> 16
                            rec_len = 32 if major_ver == 3 else 28
                            rec_start = 19 if major_ver == 3 else 27
                            if rec_start < len(pkt_data):
                                num_records = pkt_data[rec_start]
                                avail = (len(pkt_data) - (rec_start + 1)) // rec_len
                                num_records = min(num_records, avail)
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
                                            num_layers = ((entry[13] >> 5) & 0x7) + 1

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
                                                'num_layers': num_layers,
                                            })
                            i += pkt_len - 1
                    i += 1
            except Exception:
                pass
    return records

# ── Correlation & Processing ──────────────────────────────────────────────────
def correlate_layers_and_pcap(b887_records, dl_packets, bin_size=0.5, min_speed=0.0):
    """
    Aligns B887 records with PCAP packet stream using time-bin aggregation.
    Returns:
        dict of {layer: [pcap_speeds_mbps]},
        dict of {layer: [tb_sizes_bytes]}
    """
    if not b887_records or not dl_packets:
        return {}, {}

    t_min = min(dl_packets[0][0], b887_records[0]['time'])
    t_max = max(dl_packets[-1][0], b887_records[-1]['time'])
    if t_max <= t_min:
        return {}, {}

    num_bins = int(np.ceil((t_max - t_min) / bin_size))
    pcap_bytes = np.zeros(num_bins)
    for t, b in dl_packets:
        idx = int((t - t_min) / bin_size)
        if 0 <= idx < num_bins:
            pcap_bytes[idx] += b

    pcap_speeds = (pcap_bytes * 8.0) / (bin_size * 1e6)  # in Mbps

    layer_pcap_speeds = defaultdict(list)
    layer_tb_sizes = defaultdict(list)

    for rec in b887_records:
        idx = int((rec['time'] - t_min) / bin_size)
        if 0 <= idx < num_bins:
            spd = pcap_speeds[idx]
            if spd >= min_speed:
                layer_pcap_speeds[rec['num_layers']].append(spd)
                layer_tb_sizes[rec['num_layers']].append(rec['tb_size'])

    return layer_pcap_speeds, layer_tb_sizes

# ── Styling & Plotting ────────────────────────────────────────────────────────
def style_boxplot(ax, data, labels, title, ylabel, color):
    """Applies clean, styled formatting to boxplots."""
    bp = ax.boxplot(
        data, labels=labels, patch_artist=True,
        showmeans=True, meanline=True,
        medianprops={'color': '#111111', 'linewidth': 1.8},
        meanprops={'color': '#00701a', 'linestyle': '--', 'linewidth': 1.8},
        whiskerprops={'color': '#333333', 'linewidth': 1.2},
        capprops={'color': '#333333', 'linewidth': 1.2},
        flierprops={'marker': 'o', 'markerfacecolor': 'grey', 'markeredgecolor': 'none', 'markersize': 3.5, 'alpha': 0.4}
    )

    for patch in bp['boxes']:
        patch.set_facecolor(color)
        patch.set_alpha(0.65)
        patch.set_edgecolor('#1a237e')
        patch.set_linewidth(1.2)

    ax.set_title(title, fontsize=13, fontweight='bold', pad=12)
    ax.set_ylabel(ylabel, fontsize=11, fontweight='semibold')
    ax.grid(True, linestyle=':', alpha=0.6)
    ax.tick_params(axis='both', which='major', labelsize=10)

def find_paired_inputs(search_paths):
    """Discovers paired (payloads.txt, capture.pcap) files across directories."""
    pairs = []
    for root_search in search_paths:
        if os.path.isdir(root_search):
            for dirpath, dirnames, filenames in os.walk(root_search):
                pcaps = [os.path.join(dirpath, f) for f in filenames if f.endswith('.pcap') or f.endswith('.pcapng')]
                txts = [os.path.join(dirpath, f) for f in filenames if f.endswith('.txt') and ('b887' in f.lower() or 'payload' in f.lower()) and 'parsed' not in f.lower() and 'record' not in f.lower()]
                b887_txts = [f for f in txts if 'b887' in os.path.basename(f).lower()]
                chosen_txt = b887_txts[0] if b887_txts else (txts[0] if txts else None)
                if pcaps and chosen_txt:
                    pairs.append((chosen_txt, pcaps[0]))
        elif os.path.isfile(root_search):
            pass

    unique_pairs = []
    seen = set()
    for t, p in pairs:
        key = (os.path.abspath(t), os.path.abspath(p))
        if key not in seen:
            seen.add(key)
            unique_pairs.append((t, p))
    return unique_pairs

# ── CLI & Main ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Plot Box Plots of PCAP Downlink Speed vs 0xB887 MIMO Num Layers."
    )
    parser.add_argument("inputs", nargs="*", help="Payload files, PCAP files, or directories containing both.")
    parser.add_argument("-o", "--output", default=None, help="Output plot filename (.png/.pdf)")
    parser.add_argument("--bin-size", type=float, default=0.5, help="Throughput time window bin size in seconds (default: 0.5s)")
    parser.add_argument("--min-speed", type=float, default=0.0, help="Minimum PCAP speed threshold in Mbps (default: 0.0)")
    parser.add_argument("--title", default=None, help="Custom super title for the plot")
    args = parser.parse_args()

    # Detect if last positional argument is output image filename
    inputs = list(args.inputs)
    output_filename = args.output
    if inputs and (inputs[-1].endswith(('.png', '.jpg', '.jpeg', '.pdf', '.svg'))):
        if not output_filename:
            output_filename = inputs[-1]
            inputs = inputs[:-1]

    if not output_filename:
        output_filename = "b887_layer_pcap_boxplot.png"

    # Expand any glob patterns in inputs
    expanded_inputs = []
    for inp in inputs:
        matches = glob.glob(inp, recursive=True)
        if matches:
            expanded_inputs.extend(matches)
        else:
            expanded_inputs.append(inp)

    # Identify pairs of (payload_file, pcap_file)
    pairs = []
    if len(expanded_inputs) == 2 and os.path.isfile(expanded_inputs[0]) and os.path.isfile(expanded_inputs[1]):
        f1, f2 = expanded_inputs[0], expanded_inputs[1]
        if f1.endswith(('.pcap', '.pcapng')) and not f2.endswith(('.pcap', '.pcapng')):
            pairs.append((f2, f1))
        else:
            pairs.append((f1, f2))
    elif expanded_inputs:
        dirs_to_search = [inp for inp in expanded_inputs if os.path.isdir(inp)]
        if dirs_to_search:
            found = find_paired_inputs(dirs_to_search)
            pairs.extend(found)
    else:
        # Auto-discover in project
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(script_dir, ".."))
        discovered = find_paired_inputs([
            os.path.join(project_root, "loggers", "data"),
            os.path.join(project_root, "loggers", "Logs"),
            os.path.join(project_root, "b887_parser"),
        ])
        pairs.extend(discovered)

    if not pairs:
        print("Error: No paired B887 payload and PCAP files found.")
        print("Usage: python b887_pcap_layer_boxplotter.py payloads.txt capture.pcap")
        sys.exit(1)

    print(f"Found {len(pairs)} run pair(s) to process:")
    for t_path, p_path in pairs:
        print(f"  • Payloads: {t_path}")
        print(f"    PCAP:     {p_path}")

    combined_layer_pcap = defaultdict(list)
    combined_layer_tb = defaultdict(list)
    successful_runs = 0

    for t_path, p_path in pairs:
        dl_pkts, _ = read_pcap_fast(p_path)
        b887 = extract_b887_records(t_path)
        if not dl_pkts or not b887:
            print(f"  ⚠️ Skipping {os.path.basename(os.path.dirname(t_path))}: empty PCAP ({len(dl_pkts)} pkts) or B887 ({len(b887)} records)")
            continue

        l_pcap, l_tb = correlate_layers_and_pcap(b887, dl_pkts, bin_size=args.bin_size, min_speed=args.min_speed)
        if not l_pcap:
            continue

        successful_runs += 1
        for layer, spds in l_pcap.items():
            combined_layer_pcap[layer].extend(spds)
        for layer, tbs in l_tb.items():
            combined_layer_tb[layer].extend(tbs)

    all_layers = sorted([l for l in combined_layer_pcap.keys() if len(combined_layer_pcap[l]) > 0])
    if not all_layers:
        print("Error: No correlated data found between B887 records and PCAP packets across runs.")
        sys.exit(1)

    print(f"\nSuccessfully correlated {successful_runs} run(s).")

    # Print summary statistics table
    print("\n" + "=" * 88)
    print("  B887 MIMO Layers vs PCAP Speed Correlation Summary")
    print("=" * 88)
    print(f"{'MIMO Layer':<12} | {'Grants (N)':>10} | {'Mean Speed':>12} | {'Median Speed':>14} | {'75th %':>10} | {'Max Speed':>12}")
    print("-" * 88)

    pcap_data = []
    tb_data = []
    labels = []

    for l in all_layers:
        spds = combined_layer_pcap[l]
        tbs = combined_layer_tb[l]
        pcap_data.append(spds)
        tb_data.append(tbs)
        labels.append(f"{l} Layer{'s' if l > 1 else ''}\n(N={len(spds):,})")

        mean_spd = np.mean(spds)
        med_spd = np.median(spds)
        p75_spd = np.percentile(spds, 75)
        max_spd = np.max(spds)
        print(f"Layer {l:<6d} | {len(spds):>10,d} | {mean_spd:>10.2f} Mbps | {med_spd:>12.2f} Mbps | {p75_spd:>8.2f} Mbps | {max_spd:>10.2f} Mbps")

    print("=" * 88 + "\n")

    # Generate Box Plot Figure (2 Subplots)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # Subplot 1: PCAP Speed vs Num Layers (Deep Teal / Blue)
    style_boxplot(
        ax1, pcap_data, labels,
        f"PCAP Downlink Speed vs MIMO Layers ({args.bin_size}s Window)",
        "PCAP DL Throughput (Mbps)",
        "#00838f"
    )

    # Subplot 2: PDSCH TB Size vs Num Layers (Indigo / Purple)
    style_boxplot(
        ax2, tb_data, labels,
        "Physical PDSCH Transport Block (TB) Size vs MIMO Layers",
        "TB Size (Bytes)",
        "#5c6bc0"
    )

    # Add legend for Mean vs Median
    legend_elements = [
        plt.Line2D([0], [0], color='#111111', lw=1.8, label='Median'),
        plt.Line2D([0], [0], color='#00701a', lw=1.8, linestyle='--', label='Mean')
    ]
    ax1.legend(handles=legend_elements, loc='upper left', framealpha=0.9)
    ax2.legend(handles=legend_elements, loc='upper left', framealpha=0.9)

    super_title = args.title or "5G NR MIMO Layer Rank Correlation with Network Throughput"
    plt.suptitle(super_title, fontsize=15, fontweight='bold', y=0.98)
    plt.tight_layout()

    out_dir = os.path.dirname(output_filename)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    plt.savefig(output_filename, dpi=160)
    print(f"📈 Success! Box plot saved to '{output_filename}'\n")

if __name__ == "__main__":
    main()
