#!/usr/bin/env python3
"""
B888 Payload Byte Sequence Progression Plotter
==============================================
Reverse-engineering diagnostic tool to inspect and plot the progression of
arbitrary byte sequences/offsets across consecutive 0xB888 log payloads.

Usage:
  python byte_plotter.py <payloads_file> <start_byte> <size> [options]
  python byte_plotter.py <payloads_file> -b <start_byte> -s <size> [options]

Examples:
  python byte_plotter.py payloads_b888.txt 45 4
  python byte_plotter.py payloads_b888.txt 0x2D 4 --type uint --endian little
  python byte_plotter.py payloads_b888.txt 73 8 --x-axis time --output pass_bytes.png
  python byte_plotter.py payloads_b888.txt --offsets 45:4,49:4,53:4,73:8
"""

import os
import sys
import re
import math
import struct
import argparse
import datetime
from typing import List, Dict, Tuple, Optional, Any
import numpy as np
import matplotlib.pyplot as plt


# ── Timestamp Helper ──────────────────────────────────────────────────────────
def parse_qxdm_time(ts_bytes: bytes) -> datetime.datetime:
    """
    Converts 8-byte QXDM hardware timestamp into datetime (IST, UTC+5:30).
    Upper 48 bits = 1.25 ms ticks since CDMA epoch (Jan 6, 1980 00:00:00 UTC).
    Lower 16 bits = fractional component (1/65536 of a tick).
    """
    if len(ts_bytes) != 8:
        return datetime.datetime.now(datetime.timezone.utc)
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    total_ticks = integer_ticks + fractional_ticks
    time_seconds = total_ticks * 1.25 / 1000.0

    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    utc_dt = cdma_epoch + datetime.timedelta(seconds=time_seconds)
    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    return utc_dt.astimezone(ist)


# ── Number / Hex Parsing Helpers ──────────────────────────────────────────────
def parse_int_or_hex(val: str) -> int:
    """Parses decimal ('45') or hexadecimal ('0x2D', '2Dh') strings to int."""
    val = val.strip()
    if val.startswith("0x") or val.startswith("0X"):
        return int(val, 16)
    if val.endswith("h") or val.endswith("H"):
        return int(val[:-1], 16)
    return int(val)


def decode_bytes(raw_bytes: bytes, data_type: str = "uint", endian: str = "little") -> Any:
    """Decodes a byte slice into an integer, float, or hex representation."""
    if not raw_bytes:
        return 0
    
    byteorder = "little" if endian == "little" else "big"
    endian_char = "<" if endian == "little" else ">"

    if data_type == "uint":
        return int.from_bytes(raw_bytes, byteorder=byteorder, signed=False)
    elif data_type == "int":
        return int.from_bytes(raw_bytes, byteorder=byteorder, signed=True)
    elif data_type == "float":
        if len(raw_bytes) == 4:
            return struct.unpack(f"{endian_char}f", raw_bytes)[0]
        elif len(raw_bytes) == 8:
            return struct.unpack(f"{endian_char}d", raw_bytes)[0]
        elif len(raw_bytes) == 2:
            return struct.unpack(f"{endian_char}e", raw_bytes)[0]
        else:
            raise ValueError(f"Float decoding requires 2, 4, or 8 bytes, got {len(raw_bytes)} bytes")
    elif data_type == "hex":
        return raw_bytes.hex()
    else:
        return int.from_bytes(raw_bytes, byteorder=byteorder, signed=False)


# ── Payload Extraction ────────────────────────────────────────────────────────
def extract_byte_sequence_from_payloads(
    filepath: str,
    start_byte: int,
    size: int,
    relative_to: str = "raw",
    data_type: str = "uint",
    endian: str = "little",
    limit: Optional[int] = None,
    skip: int = 0
) -> List[Dict[str, Any]]:
    """
    Parses each payload line from the file and extracts the requested byte sequence.
    """
    with open(filepath, "r", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]

    if skip > 0:
        lines = lines[skip:]
    if limit is not None and limit > 0:
        lines = lines[:limit]

    records = []
    first_timestamp = None

    for p_idx, line in enumerate(lines):
        tokens = re.findall(r'[0-9A-Fa-f]{2}', line)
        if not tokens:
            continue
        try:
            raw_payload = bytes(int(t, 16) for t in tokens)
        except ValueError:
            continue

        # Extract timestamp if present
        hw_ts = None
        b888_idx = raw_payload.find(b"\x88\xb8")
        if b888_idx != -1 and b888_idx + 10 <= len(raw_payload):
            ts_bytes = raw_payload[b888_idx + 2 : b888_idx + 10]
            try:
                hw_ts = parse_qxdm_time(ts_bytes)
            except Exception:
                hw_ts = None

        if hw_ts is None:
            # Fallback relative timestamp based on payload index
            hw_ts = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(milliseconds=p_idx * 10)

        if first_timestamp is None:
            first_timestamp = hw_ts

        elapsed_sec = (hw_ts - first_timestamp).total_seconds()

        # Compute effective start byte
        if relative_to == "b888" or relative_to == "code":
            if b888_idx == -1:
                continue
            eff_start = b888_idx + start_byte
        elif relative_to == "body" or relative_to == "version":
            if b888_idx == -1:
                continue
            eff_start = b888_idx + 14 + start_byte
        else:
            eff_start = start_byte

        eff_end = eff_start + size
        if eff_end > len(raw_payload) or eff_start < 0:
            continue

        raw_slice = raw_payload[eff_start:eff_end]
        val = decode_bytes(raw_slice, data_type=data_type, endian=endian)

        records.append({
            "payload_idx": p_idx + skip,
            "timestamp": hw_ts,
            "elapsed_sec": elapsed_sec,
            "eff_start": eff_start,
            "raw_hex": " ".join(f"{b:02x}" for b in raw_slice),
            "raw_bytes": raw_slice,
            "value": val,
            "payload_len": len(raw_payload),
        })

    return records


# ── Statistics Analysis ───────────────────────────────────────────────────────
def analyze_sequence(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes statistical metrics and counter characteristics for a sequence."""
    if not records:
        return {}

    values = [r["value"] for r in records if isinstance(r["value"], (int, float))]
    if not values:
        return {"count": len(records), "is_numeric": False}

    vals_arr = np.array(values, dtype=float)
    deltas = np.diff(vals_arr) if len(vals_arr) > 1 else np.array([0.0])

    pos_deltas = deltas[deltas > 0]
    neg_deltas = deltas[deltas < 0]
    zero_deltas = deltas[deltas == 0]

    is_constant = (len(np.unique(vals_arr)) == 1)
    is_monotonic_inc = bool(np.all(deltas >= 0) and len(pos_deltas) > 0)
    is_monotonic_dec = bool(np.all(deltas <= 0) and len(neg_deltas) > 0)

    # Detect common step size (mode of positive deltas)
    mode_pos_delta = None
    if len(pos_deltas) > 0:
        unique_pos, counts = np.unique(pos_deltas, return_counts=True)
        mode_pos_delta = unique_pos[np.argmax(counts)]

    stats = {
        "is_numeric": True,
        "count": len(vals_arr),
        "first": vals_arr[0],
        "last": vals_arr[-1],
        "total_span": vals_arr[-1] - vals_arr[0],
        "min": float(np.min(vals_arr)),
        "max": float(np.max(vals_arr)),
        "mean": float(np.mean(vals_arr)),
        "std": float(np.std(vals_arr)),
        "num_unique": len(np.unique(vals_arr)),
        "is_constant": is_constant,
        "is_monotonic_inc": is_monotonic_inc,
        "is_monotonic_dec": is_monotonic_dec,
        "deltas": deltas,
        "min_delta": float(np.min(deltas)) if len(deltas) > 0 else 0.0,
        "max_delta": float(np.max(deltas)) if len(deltas) > 0 else 0.0,
        "mean_pos_delta": float(np.mean(pos_deltas)) if len(pos_deltas) > 0 else 0.0,
        "median_pos_delta": float(np.median(pos_deltas)) if len(pos_deltas) > 0 else 0.0,
        "mode_pos_delta": float(mode_pos_delta) if mode_pos_delta is not None else 0.0,
        "num_pos_deltas": len(pos_deltas),
        "num_neg_deltas": len(neg_deltas),
        "num_zero_deltas": len(zero_deltas),
        "pct_nonzero_deltas": (len(pos_deltas) + len(neg_deltas)) / len(deltas) * 100.0 if len(deltas) > 0 else 0.0,
    }
    return stats


# ── Terminal Summary Printing ─────────────────────────────────────────────────
def print_summary(
    filepath: str,
    start_byte: int,
    size: int,
    records: List[Dict[str, Any]],
    stats: Dict[str, Any],
    data_type: str,
    endian: str,
    relative_to: str,
    table_limit: int = 15
):
    """Prints a detailed terminal report and ASCII preview table."""
    rel_desc = f"Relative to {relative_to}" if relative_to != "raw" else "Absolute payload offset"
    print("\n" + "=" * 90)
    print("  0xB888 Payload Byte Sequence Progression Analysis")
    print("=" * 90)
    print(f"  File            : {filepath}")
    print(f"  Start Byte      : {start_byte} (Hex: 0x{start_byte:02X}) [{rel_desc}]")
    print(f"  Size            : {size} byte(s) (Byte Range: [{start_byte} .. {start_byte + size - 1}])")
    print(f"  Data Type       : {data_type} ({endian}-endian)")
    print(f"  Valid Samples   : {len(records):,}")

    if not stats or not stats.get("is_numeric", False):
        print("=" * 90)
        return

    # Counter Diagnosis
    if stats["is_constant"]:
        diagnosis = f"CONSTANT FIELD (Fixed value: {stats['first']:,.0f} / 0x{int(stats['first']):X})"
    elif stats["is_monotonic_inc"]:
        step_str = f" (Dominant step: +{stats['mode_pos_delta']:,.0f})" if stats['mode_pos_delta'] > 0 else ""
        diagnosis = f"MONOTONIC INCREASING COUNTER / ACCUMULATOR{step_str}"
    elif stats["is_monotonic_dec"]:
        diagnosis = "MONOTONIC DECREASING FIELD"
    elif stats["num_neg_deltas"] > 0 and stats["num_pos_deltas"] > 0:
        diagnosis = f"DYNAMIC / OSCILLATING FIELD (Active changes: {stats['pct_nonzero_deltas']:.1f}% of steps)"
    else:
        diagnosis = "SPORADIC COUNTER / EVENT FIELD"

    print(f"  Classification  : {diagnosis}")
    print("  " + "-" * 86)
    print(f"  Initial Value   : {stats['first']:>18,.2f}  |  Final Value     : {stats['last']:>18,.2f}")
    print(f"  Total Increase  : {stats['total_span']:>18,.2f}  |  Unique Values   : {stats['num_unique']:>18,d}")
    print(f"  Min Value       : {stats['min']:>18,.2f}  |  Max Value       : {stats['max']:>18,.2f}")
    print(f"  Mean Value      : {stats['mean']:>18,.2f}  |  Std Deviation   : {stats['std']:>18,.2f}")
    print("  " + "-" * 86)
    print(f"  Step Deltas     : Min: {stats['min_delta']:,.2f} | Max: {stats['max_delta']:,.2f} | Mean (+): {stats['mean_pos_delta']:,.2f}")
    print(f"  Delta Activity  : {stats['num_pos_deltas']:,} positive, {stats['num_neg_deltas']:,} negative, {stats['num_zero_deltas']:,} unchanged ({stats['pct_nonzero_deltas']:.1f}% active)")
    print("=" * 90)

    # ASCII Preview Table
    print(f"\n  First {min(table_limit, len(records))} Payloads Sample Preview:")
    print(f"  {'Pkt':<6} {'Elapsed':<10} {'Hex Bytes':<18} {'Decoded Value':>20} {'Delta':>16}")
    print("  " + "-" * 74)

    for i in range(min(table_limit, len(records))):
        rec = records[i]
        val_str = f"{rec['value']:,.2f}" if isinstance(rec['value'], float) else f"{rec['value']:,}"
        if i == 0:
            delta_str = "-"
        else:
            prev_val = records[i-1]["value"]
            if isinstance(rec["value"], (int, float)) and isinstance(prev_val, (int, float)):
                d = rec["value"] - prev_val
                delta_str = f"+{d:,.2f}" if d > 0 else (f"{d:,.2f}" if d < 0 else "0")
            else:
                delta_str = "-"

        ts_str = f"{rec['elapsed_sec']:.3f}s"
        print(f"  {rec['payload_idx']:<6} {ts_str:<10} {rec['raw_hex']:<18} {val_str:>20} {delta_str:>16}")

    print("=" * 90 + "\n")


# ── Plot Generation ───────────────────────────────────────────────────────────
def plot_sequence(
    records: List[Dict[str, Any]],
    stats: Dict[str, Any],
    start_byte: int,
    size: int,
    output_path: str,
    x_axis_mode: str = "index",
    data_type: str = "uint",
    endian: str = "little",
    title_suffix: str = ""
):
    """Plots the raw progression and step deltas of the extracted byte sequence."""
    if not records:
        print("No records available to plot.")
        return

    # Extract X and Y axes
    if x_axis_mode == "time":
        x_vals = np.array([r["elapsed_sec"] for r in records])
        x_label = "Elapsed Time (Seconds)"
    else:
        x_vals = np.array([r["payload_idx"] for r in records])
        x_label = "Payload Sequence Index"

    y_vals = np.array([r["value"] for r in records if isinstance(r["value"], (int, float))], dtype=float)
    if len(y_vals) == 0:
        print("Error: Selected byte field is not numeric, cannot plot.")
        return

    # Compute deltas
    deltas = np.diff(y_vals)
    x_deltas = x_vals[1:]

    # Setup 2-Panel Matplotlib Figure
    fig, (ax_top, ax_bottom) = plt.subplots(2, 1, figsize=(14, 8), sharex=True, gridspec_kw={'height_ratios': [1.2, 1]})

    # ── Top Subplot: Progression (Cumulative / Raw Value) ──────────────────────
    ax_top.plot(x_vals, y_vals, color="#1f77b4", linewidth=2.0, alpha=0.9, label=f"Offset {start_byte} (0x{start_byte:02X}), {size}B [{data_type}]")
    
    # Highlight initial and final values
    ax_top.scatter([x_vals[0]], [y_vals[0]], color="#2ca02c", s=60, zorder=5, label=f"Start: {y_vals[0]:,.0f}")
    ax_top.scatter([x_vals[-1]], [y_vals[-1]], color="#d62728", s=60, zorder=5, label=f"End: {y_vals[-1]:,.0f}")

    title_main = f"0xB888 Byte Progression — Offset {start_byte} (0x{start_byte:02X}), Size: {size} Bytes ({endian}-endian {data_type})"
    if title_suffix:
        title_main += f" | {title_suffix}"
    ax_top.set_title(title_main, fontsize=13, fontweight='bold', pad=10)
    ax_top.set_ylabel("Raw Decoded Value", fontsize=11, fontweight='semibold')
    ax_top.grid(True, linestyle="--", alpha=0.4)
    ax_top.legend(loc="upper left", framealpha=0.9)

    # Format Y axis with commas
    ax_top.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{x:,.0f}" if abs(x) < 1e9 else f"{x:.2e}"))

    # ── Bottom Subplot: Step-by-Step Delta Progression ────────────────────────
    if len(deltas) > 0:
        # Separate positive, negative, and zero deltas for clear color coding
        pos_mask = deltas > 0
        neg_mask = deltas < 0
        zero_mask = deltas == 0

        if np.any(pos_mask):
            ax_bottom.scatter(x_deltas[pos_mask], deltas[pos_mask], color="#2ca02c", s=16, alpha=0.7, label=f"Increment (+): {np.sum(pos_mask):,} pts")
        if np.any(neg_mask):
            ax_bottom.scatter(x_deltas[neg_mask], deltas[neg_mask], color="#d62728", s=20, marker="x", alpha=0.9, label=f"Decrement / Reset (-): {np.sum(neg_mask):,} pts")
        if np.any(zero_mask) and len(zero_mask) < 2000:
            ax_bottom.scatter(x_deltas[zero_mask], deltas[zero_mask], color="#7f7f7f", s=8, alpha=0.3, label="Unchanged (0)")

        # Thin baseline at 0
        ax_bottom.axhline(0, color="black", linestyle=":", linewidth=1.0, alpha=0.6)

        # Plot step line if data is not too dense
        if len(x_deltas) <= 500:
            ax_bottom.plot(x_deltas, deltas, color="#1f77b4", linewidth=0.8, alpha=0.4, linestyle="-")

        # Mean positive delta line if present
        if stats.get("mean_pos_delta", 0) > 0:
            mean_pos = stats["mean_pos_delta"]
            ax_bottom.axhline(mean_pos, color="#ff7f0e", linestyle="--", linewidth=1.2, alpha=0.8, label=f"Mean (+) Delta: {mean_pos:,.1f}")

        delta_title = f"Step-by-Step Delta Progression (Δ = $V_i - V_{{i-1}}$) | Non-zero Rate: {stats.get('pct_nonzero_deltas', 0):.1f}%"
        ax_bottom.set_title(delta_title, fontsize=11, fontweight='semibold')
        ax_bottom.set_ylabel("Delta Value (Δ)", fontsize=11, fontweight='semibold')
        ax_bottom.grid(True, linestyle="--", alpha=0.4)
        ax_bottom.legend(loc="upper right", framealpha=0.9)
        ax_bottom.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{x:,.0f}" if abs(x) < 1e9 else f"{x:.2e}"))

    ax_bottom.set_xlabel(x_label, fontsize=11, fontweight='semibold')

    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
    print(f"  [SUCCESS] Plot saved to: {output_path}")


# ── Multi-Sequence Comparison Plot ────────────────────────────────────────────
def plot_multi_sequences(
    filepath: str,
    offsets_specs: List[Tuple[int, int, str]],
    output_path: str,
    relative_to: str = "raw",
    endian: str = "little",
    x_axis_mode: str = "index",
    limit: Optional[int] = None,
    skip: int = 0
):
    """
    Plots multiple byte sequences in stacked subplots for side-by-side comparison.
    offsets_specs: list of (start_byte, size, label)
    """
    num_fields = len(offsets_specs)
    if num_fields == 0:
        return

    fig, axes = plt.subplots(num_fields, 2, figsize=(16, 3.5 * num_fields), sharex=True)
    if num_fields == 1:
        axes = np.array([axes])

    print("\n" + "=" * 90)
    print("  Multi-Field 0xB888 Byte Progression Comparison")
    print("=" * 90)

    for idx, (start_byte, size, label) in enumerate(offsets_specs):
        records = extract_byte_sequence_from_payloads(
            filepath, start_byte, size, relative_to=relative_to, data_type="uint", endian=endian, limit=limit, skip=skip
        )
        stats = analyze_sequence(records)
        print_summary(filepath, start_byte, size, records, stats, "uint", endian, relative_to, table_limit=5)

        if not records or not stats.get("is_numeric", False):
            continue

        if x_axis_mode == "time":
            x_vals = np.array([r["elapsed_sec"] for r in records])
        else:
            x_vals = np.array([r["payload_idx"] for r in records])

        y_vals = np.array([r["value"] for r in records], dtype=float)
        deltas = np.diff(y_vals) if len(y_vals) > 1 else np.array([0.0])
        x_deltas = x_vals[1:] if len(x_vals) > 1 else x_vals

        # Left Column: Raw Value
        ax_val = axes[idx, 0]
        ax_val.plot(x_vals, y_vals, color=f"C{idx}", linewidth=1.8, label=label or f"Offset {start_byte} ({size}B)")
        ax_val.set_title(f"Field: {label or f'Offset {start_byte} (0x{start_byte:02X})'} [{size}B] — Raw Value", fontsize=10, fontweight='bold')
        ax_val.set_ylabel("Value", fontsize=9)
        ax_val.grid(True, linestyle="--", alpha=0.3)
        ax_val.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{x:,.0f}" if abs(x) < 1e9 else f"{x:.2e}"))
        ax_val.legend(loc="upper left", fontsize=8)

        # Right Column: Delta Value
        ax_del = axes[idx, 1]
        if len(deltas) > 0:
            pos_m = deltas > 0
            neg_m = deltas < 0
            if np.any(pos_m):
                ax_del.scatter(x_deltas[pos_m], deltas[pos_m], color="#2ca02c", s=12, alpha=0.7, label=f"(+) Delta (Mode: {stats.get('mode_pos_delta', 0):,.0f})")
            if np.any(neg_m):
                ax_del.scatter(x_deltas[neg_m], deltas[neg_m], color="#d62728", s=14, marker="x", alpha=0.8, label="(-) Delta")
            ax_del.axhline(0, color="black", linestyle=":", linewidth=0.8, alpha=0.5)

        ax_del.set_title(f"Field: {label or f'Offset {start_byte}'} — Step Delta (Δ)", fontsize=10, fontweight='bold')
        ax_del.set_ylabel("Delta (Δ)", fontsize=9)
        ax_del.grid(True, linestyle="--", alpha=0.3)
        ax_del.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{x:,.0f}" if abs(x) < 1e9 else f"{x:.2e}"))
        ax_del.legend(loc="upper right", fontsize=8)

    x_label = "Elapsed Time (Seconds)" if x_axis_mode == "time" else "Payload Sequence Index"
    axes[-1, 0].set_xlabel(x_label, fontsize=10, fontweight='semibold')
    axes[-1, 1].set_xlabel(x_label, fontsize=10, fontweight='semibold')

    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()
    print(f"  [SUCCESS] Multi-field comparison plot saved to: {output_path}\n")


# ── CLI Interface ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Inspect and plot byte sequence progression across 0xB888 log payloads for reverse engineering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python byte_plotter.py payloads_b888.txt 45 4
  python byte_plotter.py payloads_b888.txt 0x2D 4 --type uint --endian little
  python byte_plotter.py payloads_b888.txt -b 73 -s 8 --x-axis time --output pass_bytes.png
  python byte_plotter.py payloads_b888.txt --offsets 45:4,49:4,53:4,73:8 --output comparison.png
        """
    )

    # Positional or flag arguments for input file, starting byte, size
    parser.add_argument("input_file", help="Path to raw hex payloads text file (e.g. *_payloads_b888.txt)")
    parser.add_argument("start_byte", nargs="?", type=parse_int_or_hex, default=None, help="Starting byte offset (e.g. 45 or 0x2D)")
    parser.add_argument("size", nargs="?", type=int, default=None, help="Size in bytes (1, 2, 4, 8, etc.)")

    # Optional flags
    parser.add_argument("-b", "--start-byte", dest="flag_start_byte", type=parse_int_or_hex, help="Starting byte offset (flag form)")
    parser.add_argument("-s", "--size", dest="flag_size", type=int, help="Size in bytes (flag form)")
    parser.add_argument("-o", "--output", help="Output PNG plot filepath (default: byte_plot_offset<N>_sz<M>.png)")
    parser.add_argument("-t", "--type", choices=["uint", "int", "float", "hex"], default="uint", help="Data decoding type (default: uint)")
    parser.add_argument("-e", "--endian", choices=["little", "big"], default="little", help="Byte endianness (default: little)")
    parser.add_argument("-r", "--relative-to", choices=["raw", "b888", "code", "body", "version"], default="raw", help="Offset reference point (default: raw)")
    parser.add_argument("-x", "--x-axis", choices=["index", "time"], default="index", help="X-axis unit: payload sequence index or elapsed time (default: index)")
    parser.add_argument("-n", "--limit", type=int, default=None, help="Limit number of payloads to process")
    parser.add_argument("--skip", type=int, default=0, help="Skip first N payloads")
    parser.add_argument("--preview-rows", type=int, default=15, help="Number of preview rows in terminal table (default: 15)")
    parser.add_argument("--offsets", help="Comma-separated multi-field specs: 'start:size[:label],start:size[:label]'")

    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"Error: Input file '{args.input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    # Check multi-field offsets flag
    if args.offsets:
        offset_specs = []
        for item in args.offsets.split(","):
            parts = item.strip().split(":")
            if len(parts) >= 2:
                s_byte = parse_int_or_hex(parts[0])
                s_size = int(parts[1])
                s_label = parts[2] if len(parts) > 2 else f"Offset {s_byte} ({s_size}B)"
                offset_specs.append((s_byte, s_size, s_label))

        out_name = args.output if args.output else "b888_multi_byte_comparison.png"
        plot_multi_sequences(
            args.input_file,
            offset_specs,
            output_path=out_name,
            relative_to=args.relative_to,
            endian=args.endian,
            x_axis_mode=args.x_axis,
            limit=args.limit,
            skip=args.skip
        )
        return

    # Resolve start_byte and size
    start_byte = args.flag_start_byte if args.flag_start_byte is not None else args.start_byte
    size = args.flag_size if args.flag_size is not None else args.size

    if start_byte is None or size is None:
        print("Error: Please specify both starting byte offset and size.", file=sys.stderr)
        print("Usage: python byte_plotter.py <input_file> <start_byte> <size> [options]", file=sys.stderr)
        sys.exit(1)

    if size <= 0:
        print("Error: Size must be at least 1 byte.", file=sys.stderr)
        sys.exit(1)

    # Determine default output plot name
    output_path = args.output
    if not output_path:
        base_name = os.path.splitext(os.path.basename(args.input_file))[0]
        output_path = f"{base_name}_byte_offset{start_byte}_sz{size}.png"

    # Extract data
    records = extract_byte_sequence_from_payloads(
        filepath=args.input_file,
        start_byte=start_byte,
        size=size,
        relative_to=args.relative_to,
        data_type=args.type,
        endian=args.endian,
        limit=args.limit,
        skip=args.skip
    )

    if not records:
        print(f"Error: No valid byte sequences extracted from '{args.input_file}' at offset {start_byte} (size {size}).", file=sys.stderr)
        sys.exit(1)

    # Compute statistics
    stats = analyze_sequence(records)

    # Print terminal summary
    print_summary(
        filepath=args.input_file,
        start_byte=start_byte,
        size=size,
        records=records,
        stats=stats,
        data_type=args.type,
        endian=args.endian,
        relative_to=args.relative_to,
        table_limit=args.preview_rows
    )

    # Plot sequence
    plot_sequence(
        records=records,
        stats=stats,
        start_byte=start_byte,
        size=size,
        output_path=output_path,
        x_axis_mode=args.x_axis,
        data_type=args.type,
        endian=args.endian
    )


if __name__ == "__main__":
    main()
