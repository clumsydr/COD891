#!/usr/bin/env python3
"""
B888 NR5G MAC PDSCH Stats — Multi-Carrier Telemetry Parser
===========================================================
Extracts Carrier ID, Slots Elapsed, PDSCH Decodes, CRC Pass/Fail TBs,
BLER (%), Throughput Bytes, Retransmissions, and Hardware Timestamps
from 0xB888 diagnostic log payloads.
"""

import sys, os, re, csv, struct, argparse, datetime
from dataclasses import dataclass, fields as dc_fields
from typing import List, Optional, Tuple, Dict

# ── Constants ─────────────────────────────────────────────────────────────────
LOG_CODE = 0xB888

# ── Data Model ────────────────────────────────────────────────────────────────
@dataclass
class PdschStatsRecord:
    timestamp:         datetime.datetime
    payload_idx:       int
    record_idx:        int
    version:           str
    carrier_id:        int
    slots_elapsed:     int
    pdsch_decode:      int
    crc_pass_tb:       int
    crc_fail_tb:       int
    bler_pct:          float
    retx_tb:           int
    ack_as_nack:       int
    harq_fail:         int
    crc_pass_bytes:    int
    crc_fail_bytes:    int
    tb_bytes:          int
    padding_bytes:     int
    retx_bytes:        int
    throughput_mbps:   Optional[float] = None

    def to_dict(self):
        d = {f.name: getattr(self, f.name) for f in dc_fields(self)}
        d['timestamp'] = self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        return d

# ── Binary Helpers ────────────────────────────────────────────────────────────
def u16(b: bytes, o: int) -> int:
    return b[o] | (b[o+1] << 8)

def u32(b: bytes, o: int) -> int:
    return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)

def u64(b: bytes, o: int) -> int:
    return struct.unpack("<Q", b[o:o+8])[0]

def parse_qxdm_time(ts_bytes: bytes) -> datetime.datetime:
    """
    Converts 8-byte QXDM hardware timestamp into datetime (IST, UTC+5:30).
    Upper 48 bits = 1.25 ms ticks since CDMA epoch (Jan 6, 1980 00:00:00 UTC).
    Lower 16 bits = fractional component (1/65536 of a tick).
    """
    if len(ts_bytes) != 8:
        raise ValueError(f"Expected 8 bytes for QXDM timestamp, got {len(ts_bytes)}")
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    total_ticks = integer_ticks + fractional_ticks
    time_seconds = (total_ticks * 1.25 / 1000.0)
    
    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    utc_dt = cdma_epoch + datetime.timedelta(seconds=time_seconds)
    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    return utc_dt.astimezone(ist)

# ── Packet & Record Parsing ───────────────────────────────────────────────────
def parse_record(body: bytes, payload_idx: int, rec_idx: int, version_str: str, hw_ts: datetime.datetime) -> PdschStatsRecord:
    cid            = u32(body, 0)
    slots_elapsed  = u32(body, 4)
    pdsch_decode   = u32(body, 8)
    crc_pass_tb    = u32(body, 12)
    crc_fail_tb    = u32(body, 16)
    retx_tb        = u32(body, 20)
    ack_as_nack    = u32(body, 24)
    harq_fail      = u32(body, 28)
    crc_pass_bytes = u64(body, 32)
    crc_fail_bytes = u64(body, 40)
    tb_bytes       = u64(body, 48)
    padding_bytes  = u64(body, 56)
    retx_bytes     = u64(body, 64)

    bler = (crc_fail_tb / pdsch_decode * 100.0) if pdsch_decode > 0 else 0.0

    return PdschStatsRecord(
        timestamp=hw_ts,
        payload_idx=payload_idx,
        record_idx=rec_idx,
        version=version_str,
        carrier_id=cid,
        slots_elapsed=slots_elapsed,
        pdsch_decode=pdsch_decode,
        crc_pass_tb=crc_pass_tb,
        crc_fail_tb=crc_fail_tb,
        bler_pct=bler,
        retx_tb=retx_tb,
        ack_as_nack=ack_as_nack,
        harq_fail=harq_fail,
        crc_pass_bytes=crc_pass_bytes,
        crc_fail_bytes=crc_fail_bytes,
        tb_bytes=tb_bytes,
        padding_bytes=padding_bytes,
        retx_bytes=retx_bytes
    )

def parse_payload(payload: bytes, payload_idx: int, hw_ts: datetime.datetime) -> List[PdschStatsRecord]:
    idx = payload.find(b"\x88\xb8")
    if idx == -1:
        return []

    minor = u16(payload, idx + 10)
    major = u16(payload, idx + 12)
    ver_str = f"{major}.{minor}"

    # Header is 16 bytes after version (idx + 14 .. idx + 30)
    # Body starts at idx + 30
    REC_SIZE = 72
    body_data = payload[idx + 30:]
    num_records = len(body_data) // REC_SIZE

    records = []
    for r_idx in range(num_records):
        rec_slice = body_data[r_idx * REC_SIZE : (r_idx + 1) * REC_SIZE]
        if len(rec_slice) < REC_SIZE:
            break
        records.append(parse_record(rec_slice, payload_idx, r_idx, ver_str, hw_ts))

    return records

def split_packets(raw: bytes) -> List[Tuple[bytes, datetime.datetime]]:
    packets, i = [], 0
    while i < len(raw) - 3:
        if raw[i+2] == 0x88 and raw[i+3] == 0xB8:
            pkt_len = raw[i] | (raw[i+1] << 8)
            if 32 <= pkt_len <= 8192 and i + pkt_len <= len(raw):
                pkt_data = raw[i : i + pkt_len]
                ts_bytes = pkt_data[4:12]
                try:
                    hw_ts = parse_qxdm_time(ts_bytes)
                except Exception:
                    hw_ts = datetime.datetime.now()
                packets.append((pkt_data, hw_ts))
                i += pkt_len
                continue
        i += 1
    return packets

# ── File Processing ───────────────────────────────────────────────────────────
def process_file(filepath: str) -> List[PdschStatsRecord]:
    with open(filepath, "r", errors="ignore") as f:
        content = f.read()

    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if not lines:
        return []

    all_records: List[PdschStatsRecord] = []
    last_record_per_carrier: Dict[int, PdschStatsRecord] = {}

    for p_idx, line in enumerate(lines):
        hex_tokens = line.split()
        try:
            raw_bytes = bytes.fromhex("".join(hex_tokens))
        except ValueError:
            continue

        # Check if line contains a direct single payload or embedded stream
        if b"\x88\xb8" in raw_bytes:
            # Extract timestamp from bytes 4..12 or 13..21
            idx = raw_bytes.find(b"\x88\xb8")
            ts_bytes = raw_bytes[idx+2 : idx+10]
            try:
                hw_ts = parse_qxdm_time(ts_bytes)
            except Exception:
                hw_ts = datetime.datetime.now()

            recs = parse_payload(raw_bytes, p_idx, hw_ts)
            for r in recs:
                # Compute instantaneous throughput if we have previous sample for this carrier
                cid = r.carrier_id
                if cid in last_record_per_carrier:
                    prev = last_record_per_carrier[cid]
                    dt = (r.timestamp - prev.timestamp).total_seconds()
                    dbytes = r.crc_pass_bytes - prev.crc_pass_bytes
                    if dt > 0 and dbytes >= 0:
                        r.throughput_mbps = (dbytes * 8) / (dt * 1e6)
                last_record_per_carrier[cid] = r
                all_records.append(r)

    return all_records

# ── Printing & Exporting ──────────────────────────────────────────────────────
def print_records(records: List[PdschStatsRecord], limit: Optional[int] = None):
    if not records:
        print("No B888 records found.")
        return

    print("=" * 135)
    print("  B888 NR5G MAC PDSCH Stats — Parsed Multi-Carrier Telemetry")
    print("=" * 135)
    print(f"  {'Timestamp':<26} {'Pkt':>5} {'Rec':>4} {'Ver':>4} {'CID':>4} {'Slots':>10} {'PDSCH Dec':>10} {'CRC Pass':>10} {'CRC Fail':>9} {'BLER%':>7} {'Pass MB':>10} {'Total MB':>10} {'Mbps':>8}")
    print("  " + "-" * 131)

    display_recs = records[:limit] if limit else records
    for r in display_recs:
        pass_mb = r.crc_pass_bytes / (1024 * 1024)
        total_mb = r.tb_bytes / (1024 * 1024)
        tput_str = f"{r.throughput_mbps:.2f}" if r.throughput_mbps is not None else "-"
        ts_str = r.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
        print(f"  {ts_str:<26} {r.payload_idx:>5} {r.record_idx:>4} {r.version:>4} {r.carrier_id:>4} {r.slots_elapsed:>10,d} {r.pdsch_decode:>10,d} {r.crc_pass_tb:>10,d} {r.crc_fail_tb:>9,d} {r.bler_pct:>6.2f}% {pass_mb:>9.2f}M {total_mb:>9.2f}M {tput_str:>8}")

    print("=" * 135)
    print_carrier_summary(records)

def print_carrier_summary(records: List[PdschStatsRecord]):
    if not records:
        return
    cids = sorted(list(set(r.carrier_id for r in records)))
    print(f"\n--- Multi-Carrier Performance Summary ({len(cids)} Carrier(s) Detected) ---")
    for cid in cids:
        c_recs = [r for r in records if r.carrier_id == cid]
        first, last = c_recs[0], c_recs[-1]
        dt = (last.timestamp - first.timestamp).total_seconds()
        d_slots = last.slots_elapsed - first.slots_elapsed
        d_decode = last.pdsch_decode - first.pdsch_decode
        d_pass = last.crc_pass_tb - first.crc_pass_tb
        d_fail = last.crc_fail_tb - first.crc_fail_tb
        d_bytes = last.crc_pass_bytes - first.crc_pass_bytes
        d_total_bytes = last.tb_bytes - first.tb_bytes
        bler = (d_fail / d_decode * 100.0) if d_decode > 0 else 0.0
        avg_mbps = (d_bytes * 8) / (dt * 1e6) if dt > 0 else 0.0
        
        role = "Primary Carrier (PCell)" if cid == 0 else f"Secondary Carrier (SCell {cid})"
        print(f"  Carrier ID {cid} [{role}]:")
        print(f"    Duration           : {dt:.2f} s ({len(c_recs):,} telemetry updates)")
        print(f"    Slots Elapsed      : {d_slots:,}")
        print(f"    PDSCH Decodes      : {d_decode:,} TBs")
        print(f"    CRC Pass TBs       : {d_pass:,} ({100.0 - bler:.2f}%)")
        print(f"    CRC Fail TBs       : {d_fail:,} (BLER: {bler:.2f}%)")
        print(f"    CRC Pass Payload   : {d_bytes / (1024**2):,.2f} MB")
        print(f"    Total TB Volume    : {d_total_bytes / (1024**2):,.2f} MB")
        print(f"    Average Throughput : {avg_mbps:.2f} Mbps")
        print()

def export_csv(records: List[PdschStatsRecord], csv_path: str):
    if not records:
        print("No records to export.")
        return
    keys = list(records[0].to_dict().keys())
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in records:
            writer.writerow(r.to_dict())
    print(f"Successfully exported {len(records):,} B888 records to '{csv_path}'.")

# ── Main Entrypoint ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Decode 0xB888 NR5G MAC PDSCH Stats payloads into multi-carrier performance metrics."
    )
    parser.add_argument("input_file", help="Path to text file containing raw hex payloads (*_payloads_b888.txt)")
    parser.add_argument("--csv", help="Optional path to output CSV file")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of displayed records")
    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"Error: File '{args.input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    records = process_file(args.input_file)
    if args.csv:
        export_csv(records, args.csv)
    else:
        print_records(records, limit=args.limit)

if __name__ == "__main__":
    main()
