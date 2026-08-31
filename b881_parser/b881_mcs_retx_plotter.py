#!/usr/bin/env python3
import sys
import datetime
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

def main():
    if len(sys.argv) < 2:
        print("Usage: python b881_mcs_retx_plotter.py <payloads.txt> [output_plot.png]")
        sys.exit(1)

    payload_file = sys.argv[1]
    plot_filename = sys.argv[2] if len(sys.argv) > 2 else "b881_mcs_retx.png"

    print("Extracting B881 records...")
    raw_records = extract_b881_data(payload_file)
    if not raw_records:
        print("Error: No B881 records parsed.")
        return
    print(f"Parsed {len(raw_records)} B881 records.")

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

    b881_times = np.array([d['time'] for d in b881_deltas])
    min_time = min(b881_times)
    max_time = max(b881_times)

    # Binning (1.0 second bins)
    BIN_SIZE_SEC = 1.0
    print(f"Binning data into {BIN_SIZE_SEC}s bins...")
    bins = np.arange(min_time, max_time + BIN_SIZE_SEC, BIN_SIZE_SEC)
    time_axis = bins[:-1] - min_time

    # Bin raw sums for MCS and TB counts
    mcs_sum_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['num_mcs'] for d in b881_deltas])
    new_tb_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['num_new_tb'] for d in b881_deltas])
    retx_tb_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['num_retx_tb'] for d in b881_deltas])
    
    # Bin raw byte counts for byte-level retransmission rate
    new_tx_bytes_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['new_tx_bytes'] for d in b881_deltas])
    retx_bytes_binned, _ = np.histogram(b881_times, bins=bins, weights=[d['retx_bytes'] for d in b881_deltas])

    # Calculate Average MCS: sum(MCS) / (new_tb + retx_tb) for active transmission bins (where uplink throughput > 0)
    total_tb_binned = new_tb_binned + retx_tb_binned
    valid_tb_mask = (total_tb_binned > 0) & (new_tx_bytes_binned > 0)
    mcs_binned = np.full(len(mcs_sum_binned), np.nan, dtype=float)
    mcs_binned[valid_tb_mask] = mcs_sum_binned[valid_tb_mask] / total_tb_binned[valid_tb_mask]

    # Calculate TB-based Retransmission Rate (BLER)
    retx_rate_tb = np.full(len(retx_tb_binned), np.nan, dtype=float)
    retx_rate_tb[valid_tb_mask] = (retx_tb_binned[valid_tb_mask] / total_tb_binned[valid_tb_mask]) * 100.0

    # Calculate Byte-based Retransmission Rate
    total_bytes_binned = new_tx_bytes_binned + retx_bytes_binned
    retx_rate_bytes = np.full(len(retx_bytes_binned), np.nan, dtype=float)
    valid_bytes_mask = total_bytes_binned > 0
    retx_rate_bytes[valid_bytes_mask] = retx_rate_bytes[valid_bytes_mask] / total_bytes_binned[valid_bytes_mask]

    # Calculate overall average MCS throughout active transmissions (ignore zero throughput)
    active_deltas = [d for d in b881_deltas if d['new_tx_bytes'] > 0]
    total_new_tb = sum(d['num_new_tb'] for d in active_deltas)
    total_retx_tb = sum(d['num_retx_tb'] for d in active_deltas)
    total_tb = total_new_tb + total_retx_tb
    overall_avg_mcs = 0.0
    if total_tb > 0:
        total_mcs = sum(d['num_mcs'] for d in active_deltas)
        overall_avg_mcs = total_mcs / total_tb

    # Calculate correlation for active bins (non-zero uplink throughput)
    active_bins_mask = valid_tb_mask
    active_mcs = mcs_binned[active_bins_mask]
    active_retx_tb = retx_tb_binned[active_bins_mask]
    
    corr_val = 0.0
    if len(active_mcs) > 1 and np.std(active_mcs) != 0 and np.std(active_retx_tb) != 0:
        corr_val = np.corrcoef(active_mcs, active_retx_tb)[0, 1]

    # Calculate first-order differences (deltas) of the averages/volumes
    diff_time_axis = time_axis[1:]
    diff_mcs = np.full(len(diff_time_axis), np.nan, dtype=float)
    diff_retx_tb = np.full(len(diff_time_axis), np.nan, dtype=float)

    # Calculate correlation for the first-order differences
    diff_mcs_active = []
    diff_retx_active = []
    for t in range(1, len(mcs_binned)):
        if active_bins_mask[t] and active_bins_mask[t-1]:
            d_m = mcs_binned[t] - mcs_binned[t-1]
            d_r = retx_tb_binned[t] - retx_tb_binned[t-1]
            diff_mcs[t-1] = d_m
            diff_retx_tb[t-1] = d_r
            diff_mcs_active.append(d_m)
            diff_retx_active.append(d_r)
    
    diff_corr_val = 0.0
    if len(diff_mcs_active) > 1 and np.std(diff_mcs_active) != 0 and np.std(diff_retx_active) != 0:
        diff_corr_val = np.corrcoef(diff_mcs_active, diff_retx_active)[0, 1]

    # Plotting: 3-Panel Figure
    fig, (ax1, ax3, ax4) = plt.subplots(1, 3, figsize=(22, 6))

    # Panel 1: Time Series (Dual Y-Axis)
    color = 'tab:purple'
    ax1.set_xlabel(f'Time (Seconds from start) [{BIN_SIZE_SEC}s bins]')
    ax1.set_ylabel('Average MCS Index', color=color)
    mcs_label = f'Average MCS (Overall: {overall_avg_mcs:.2f})'
    line1 = ax1.plot(time_axis, mcs_binned, color=color, label=mcs_label, linewidth=2, alpha=0.8)
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.set_ylim(0, 30)
    ax1.grid(True, alpha=0.3)

    ax2 = ax1.twinx()  
    color = 'tab:red'
    ax2.set_ylabel('Retransmissions (TB count delta)', color=color)
    line2 = ax2.plot(time_axis, retx_tb_binned, color=color, linestyle='--', label='Retransmitted TBs (Delta)', linewidth=2, alpha=0.8)
    ax2.tick_params(axis='y', labelcolor=color)
    if len(retx_tb_binned) > 0 and max(retx_tb_binned) > 0:
        ax2.set_ylim(0, max(retx_tb_binned) * 1.1)

    # Put legend together
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc='upper right')
    ax1.set_title("Uplink Time-Series Alignment")

    # Panel 2: Scatter Plot & Regression
    if len(active_mcs) > 1:
        ax3.scatter(active_mcs, active_retx_tb, color='tab:blue', alpha=0.7, edgecolors='none', s=50, label='1s Binned Data')
        
        # Fit a regression line if variance exists
        if np.std(active_mcs) != 0:
            m, c = np.polyfit(active_mcs, active_retx_tb, 1)
            x_line = np.linspace(0, 30, 100)
            ax3.plot(x_line, m * x_line + c, color='tab:gray', linestyle='--', label=f'Fit (slope: {m:.2f})')
            
        ax3.set_title(f"Retx Delta vs MCS (Correlation: {corr_val:.3f})")
    else:
        ax3.set_title("Scatter Plot (Insufficient active data)")
        
    ax3.set_xlabel("Average MCS Index")
    ax3.set_ylabel("Retransmitted TB Count (Delta)")
    ax3.set_xlim(0, 30)
    if len(active_retx_tb) > 0 and max(active_retx_tb) > 0:
        ax3.set_ylim(0, max(active_retx_tb) * 1.1)
    ax3.grid(True, alpha=0.3)
    ax3.legend()

    # Panel 3: Time Series of First-Order Changes (Deltas of the Deltas)
    color = 'tab:purple'
    ax4.set_xlabel(f'Time (Seconds from start) [{BIN_SIZE_SEC}s bins]')
    ax4.set_ylabel('Change in Avg MCS (d_MCS)', color=color)
    line3 = ax4.plot(diff_time_axis, diff_mcs, color=color, label='Change in MCS (d_MCS)', linewidth=1.5, alpha=0.8)
    ax4.tick_params(axis='y', labelcolor=color)
    ax4.grid(True, alpha=0.3)
    valid_diff_mcs = diff_mcs[~np.isnan(diff_mcs)]
    if len(valid_diff_mcs) > 0:
        max_diff_mcs = max(abs(valid_diff_mcs)) or 5
        ax4.set_ylim(-max_diff_mcs - 1, max_diff_mcs + 1)

    ax5 = ax4.twinx()
    color = 'tab:red'
    ax5.set_ylabel('Change in Retransmissions (d_Retx)', color=color)
    line4 = ax5.plot(diff_time_axis, diff_retx_tb, color=color, linestyle='--', label='Change in Retx TBs (d_Retx)', linewidth=1.5, alpha=0.8)
    ax5.tick_params(axis='y', labelcolor=color)
    valid_diff_retx = diff_retx_tb[~np.isnan(diff_retx_tb)]
    if len(valid_diff_retx) > 0:
        max_diff_retx = max(abs(valid_diff_retx)) or 10
        ax5.set_ylim(-max_diff_retx * 1.1, max_diff_retx * 1.1)

    # Put legend together
    lines_diff = line3 + line4
    labels_diff = [l.get_label() for l in lines_diff]
    ax4.legend(lines_diff, labels_diff, loc='upper right')
    ax4.set_title(f"Second-to-Second Changes (Corr: {diff_corr_val:.3f})")

    plt.suptitle("Uplink Link Adaptation Analysis (MCS vs Retransmission Delta)", fontsize=14)
    plt.tight_layout()
    
    plt.savefig(plot_filename)
    print(f"📈 Plot saved as '{plot_filename}'")

if __name__ == "__main__":
    main()
