#!/usr/bin/env python3
"""
B881 NR5G MAC UL TB Stats Parser
============================================================================
Extracts true Payload Throughput (TB New Tx Bytes), Retransmissions, and
Link Quality metrics from 0xB881 log payloads. Automatically computes the
delta throughput for immediate PCAP correlation.
"""

import sys, re, csv, argparse, datetime
from dataclasses import dataclass, fields as dc_fields
from typing import List, Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────
LOG_CODE = 0xB881

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class UlTbStatsRecord:
    timestamp:      datetime.datetime
    payload_idx:    int
    record_idx:     int
    version:        str
    
    # Core Throughput Metrics
    new_tx_bytes:   int = 0   # The raw cumulative counter
    delta_tx_bytes: int = 0   # The actual payload size of THIS packet
    retx_bytes:     int = 0
    
    # RF / Allocation Metrics
    num_mcs:        int = 0
    num_prb:        int = 0
    phr:            int = 0
    total_power:    int = 0
    
    # Block & Quality Metrics
    num_new_tx_tb:  int = 0
    num_retx_tb:    int = 0
    cqi:            int = 0
    num_ulsch_sched:int = 0

    def to_dict(self):
        return {f.name: getattr(self, f.name) for f in dc_fields(self)}

# ── Helpers ───────────────────────────────────────────────────────────────────
def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return int.from_bytes(b[o:o+4], byteorder='little')
def u64(b, o): return int.from_bytes(b[o:o+8], byteorder='little')

def parse_qxdm_time(ts_bytes: bytes) -> datetime.datetime:
    if len(ts_bytes) != 8:
        return datetime.datetime.now()
        
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    
    total_ticks = integer_ticks + fractional_ticks
    time_seconds = total_ticks * 1.25 / 1000.0
    
    cdma_epoch = datetime.datetime(1980, 1, 6, tzinfo=datetime.timezone.utc)
    return cdma_epoch + datetime.timedelta(seconds=time_seconds)

# ── Payload parser ────────────────────────────────────────────────────────────
def parse_payload(payload: bytes, payload_idx: int, hw_timestamp: datetime.datetime) -> List[UlTbStatsRecord]:
    if u16(payload, 2) != LOG_CODE:
        return []

    if len(payload) < 24:
        return []

    minor_ver = u16(payload, 12)
    major_ver = u16(payload, 14)
    num_records = payload[19]

    results = []
    
    # Process Version 3.1
    if major_ver == 3 and minor_ver == 1:
        O = 24        # Fixed offset for v3.1 TB Stats
        rec_len = 80  # Fixed 80-byte record length
        
        for rec_idx in range(num_records):
            if O + rec_len > len(payload): 
                break 
            
            # Map the 80-byte payload structure
            new_tx      = u64(payload, O)
            retx        = u64(payload, O+8)
            num_mcs     = u64(payload, O+16)
            num_prb     = u64(payload, O+24)
            phr         = u64(payload, O+32)
            
            total_pwr   = u32(payload, O+40)
            num_new_tb  = u32(payload, O+44)
            num_retx_tb = u32(payload, O+48)
            cqi         = u32(payload, O+64)
            ulsch_sched = u32(payload, O+76)
            
            results.append(UlTbStatsRecord(
                timestamp=hw_timestamp, payload_idx=payload_idx, record_idx=rec_idx,
                version="3.1", new_tx_bytes=new_tx, delta_tx_bytes=0, # Computed at the stream level
                retx_bytes=retx, num_mcs=num_mcs, num_prb=num_prb, phr=phr, total_power=total_pwr,
                num_new_tx_tb=num_new_tb, num_retx_tb=num_retx_tb, cqi=cqi, num_ulsch_sched=ulsch_sched
            ))
            
            O += rec_len
            
    return results

def split_packets(raw: bytes) -> List[Tuple[bytes, datetime.datetime]]:
    packets, i = [], 0
    # Dynamically hunt for 0x81 0xB8 to bypass custom wrappers
    while i < len(raw) - 3:
        if raw[i+2] == 0x81 and raw[i+3] == 0xB8:
            pkt_len = raw[i] | (raw[i+1] << 8)
            if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                pkt_data = raw[i : i + pkt_len]
                ts_bytes = pkt_data[4:12]
                hw_timestamp = parse_qxdm_time(ts_bytes)
                packets.append((pkt_data, hw_timestamp))
                i += pkt_len - 1
        i += 1
    return packets

def parse_stream(text: str, verbose: bool = True) -> List[UlTbStatsRecord]:
    tokens = re.findall(r'[0-9A-Fa-f]{2}', text)
    if not tokens:
        return []
    raw = bytes(int(t, 16) for t in tokens)
    
    all_results: List[UlTbStatsRecord] = []
    for idx, (pkt, hw_timestamp) in enumerate(split_packets(raw)):
        all_results.extend(parse_payload(pkt, idx, hw_timestamp))
        
    # Process sequential deltas to find actual payload size per packet
    if all_results:
        # Ensure chronological order
        all_results.sort(key=lambda x: x.timestamp)
        prev_cumulative = all_results[0].new_tx_bytes
        
        for r in all_results:
            delta = r.new_tx_bytes - prev_cumulative
            # Protect against baseband counter resets/overflows
            r.delta_tx_bytes = delta if delta >= 0 else 0 
            prev_cumulative = r.new_tx_bytes
            
    if verbose and all_results:
        print("\n=======================================================================")
        print("  B881 NR5G MAC UL TB Stats — Parsed Records")
        print("=======================================================================")
        print(f"  {'Pkt':<5} {'Ver':<6} {'Delta Tx (Bytes)':<18} {'Cumul Tx':<15} {'ReTx':<10}")
        print("  " + "-" * 67)
        for r in all_results:
            print(f"  {r.payload_idx:<5} {r.version:<6} {r.delta_tx_bytes:<18} {r.new_tx_bytes:<15} {r.retx_bytes:<10}")
        print("=======================================================================\n")
            
    return all_results

def write_csv(results: List[UlTbStatsRecord], path: str):
    if not results: return
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].to_dict().keys()))
        w.writeheader()
        w.writerows(r.to_dict() for r in results)
    print(f"CSV saved → {path}")

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Parse 0xB881 NR5G MAC UL TB Stats payloads.")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("--csv", metavar="FILE", help="Save results to CSV")
    args = ap.parse_args()

    if not args.input and sys.stdin.isatty():
        ap.print_help()
        sys.exit(1)

    text = open(args.input).read() if args.input else sys.stdin.read()
    results = parse_stream(text)

    if args.csv:
        write_csv(results, args.csv)

if __name__ == "__main__":
    main()