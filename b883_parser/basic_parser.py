#!/usr/bin/env python3
"""
B883 NR5G MAC UL Physical Channel Schedule Report Parser
============================================================================
Extracts scheduled physical channels (PUSCH, PUCCH, PRACH, SRS), MCS, RBs, 
and Absolute Timestamps from 0xB883 log payloads based on the C++ header specs.
Fully supports dynamic variable-length records for version 3.17 payloads.
"""

import sys, re, csv, argparse, datetime
from dataclasses import dataclass, fields as dc_fields
from typing import List, Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────
LOG_CODE = 0xB883
SCS_MAP  = {0: "15kHz", 1: "30kHz", 2: "60kHz", 3: "120kHz"}

RNTI_MAP = {
    0: "C_RNTI",
    2: "T_C_RNTI",
    3: "C_RNTI" # Maps to standard C_RNTI in later firmware versions
}

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class UlSchedRecord:
    timestamp:   datetime.datetime
    payload_idx: int
    record_idx:  int
    version:     str
    slot:        Optional[int] = None
    frame:       Optional[int] = None
    abs_slot:    Optional[int] = None
    scs:         Optional[str] = None
    carrier_id:  Optional[int] = None
    rnti_type:   Optional[str] = None
    c_rnti:      Optional[int] = None
    chan_type:   str = "UNKNOWN"
    length:      Optional[int] = None
    start_sym:   Optional[int] = None
    num_sym:     Optional[int] = None
    harq_id:     Optional[int] = None
    mcs:         Optional[int] = None
    num_rbs:     Optional[int] = None
    rb_start:    Optional[int] = None
    tb_size:     Optional[int] = None
    pucch_fmt:   Optional[int] = None

    def to_dict(self):
        return {f.name: getattr(self, f.name) for f in dc_fields(self)}

# ── Helpers ───────────────────────────────────────────────────────────────────
def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

def parse_qxdm_time(ts_bytes: bytes) -> datetime.datetime:
    """
    Converts the 8-byte QXDM hardware timestamp into a standard Python datetime.
    """
    if len(ts_bytes) != 8:
        return datetime.datetime.now()
        
    ts_int = int.from_bytes(ts_bytes, byteorder='little')
    integer_ticks = ts_int >> 16
    fractional_ticks = (ts_int & 0xFFFF) / 65536.0
    
    total_ticks = integer_ticks + fractional_ticks
    time_seconds = total_ticks * 1.25 / 1000.0
    
    cdma_epoch = datetime.datetime(1980, 1, 6)
    return cdma_epoch + datetime.timedelta(seconds=time_seconds)

# ── Payload parser ────────────────────────────────────────────────────────────
def parse_payload(payload: bytes, payload_idx: int, hw_timestamp: datetime.datetime) -> List[UlSchedRecord]:
    if u16(payload, 2) != LOG_CODE:
        return []

    # Requires at least the 19-byte common MAC header
    if len(payload) < 19:
        return []

    minor_ver = u16(payload, 12)
    major_ver = u16(payload, 14)
    num_records = payload[19]

    results = []
    O = 20 # Offset where the first record starts

    # ── Version 3.17 Logic (Dynamic Variable-Length Records) ──
    if major_ver == 3 and minor_ver == 17:
        for rec_idx in range(num_records):
            if O + 8 > len(payload): break 
            
            # 1. Decode 8-Byte Preamble
            slot       = payload[O]
            scs_val    = payload[O+1] & 0x0F
            frame      = u16(payload, O+2) & 0x3FF
            carrier_id = payload[O+4] & 0x03
            rnti_val   = (payload[O+4] >> 2) & 0x0F
            b5         = payload[O+5]
            
            scs        = SCS_MAP.get(scs_val, f"mu{scs_val}")
            rnti_type  = RNTI_MAP.get(rnti_val, f"Type_{rnti_val}")
            
            # 2. Extract Physical Channel & Record Length
            chan_nibble = b5 & 0x0F
            len_map = {1: 60, 2: 44, 4: 44, 8: 32}
            rec_len = len_map.get(chan_nibble, 44)
            
            chan_map = {1: "PRACH/SR", 2: "PUSCH", 4: "PUCCH", 8: "SRS"}
            chan_type = chan_map.get(chan_nibble, f"UNK_{chan_nibble}")

            # 3. Unpack Specific Payloads (Starts at Offset 8)
            p_start, p_num, p_harq, p_mcs, p_rbs, p_rbst, p_tb, p_fmt, c_rnti = [None]*9
            
            # PUSCH bit-unpacking
            if chan_type == "PUSCH" and O + 8 + 30 <= len(payload):
                p = payload[O+8 : O+rec_len]
                p_start = (p[0] >> 1) & 0x0F
                p_num   = ((p[1] & 0x01) << 3) | ((p[0] >> 5) & 0x07)
                p_harq  = (p[1] >> 1) & 0x0F
                p_mcs   = ((p[2] & 0x01) << 3) | ((p[1] >> 5) & 0x07)
                p_rbst  = (p[3] << 1) | (p[2] >> 7)
                p_rbs   = u16(p, 4) & 0x1FF
                p_tb    = ((u16(p, 6) & 0x1FFF) << 5) | ((p[5] >> 3) & 0x1F)
                c_rnti  = u16(p, 28) # RNTI is packed deeply at offset 28 of the payload
                
            # PUCCH bit-unpacking
            elif chan_type == "PUCCH" and O + 8 + 4 <= len(payload):
                p = payload[O+8 : O+rec_len]
                p_fmt   = (p[0] >> 1) & 0x0F
                p_start = p[1] & 0x0F
                p_num   = (p[1] >> 4) & 0x0F
                p_rbst  = u16(p, 2) & 0x3FF
                p_rbs   = p[4]
            
            results.append(UlSchedRecord(
                timestamp=hw_timestamp, payload_idx=payload_idx, record_idx=rec_idx,
                version="3.17", slot=slot, frame=frame, scs=scs, carrier_id=carrier_id, 
                rnti_type=rnti_type, c_rnti=c_rnti, chan_type=chan_type, length=rec_len,
                start_sym=p_start, num_sym=p_num, harq_id=p_harq, mcs=p_mcs, 
                num_rbs=p_rbs, rb_start=p_rbst, tb_size=p_tb, pucch_fmt=p_fmt
            ))
            
            O += rec_len
    return results

# ── Stream splitter ───────────────────────────────────────────────────────────
def split_packets(raw: bytes) -> List[Tuple[bytes, datetime.datetime]]:
    """
    Find all B883 packet boundaries and extract the absolute timestamp from the header.
    """
    packets, i = [], 0
    while i < len(raw) - 3:
        # Hunt for the 83 B8 log code signature which follows length bytes
        if raw[i+2] == 0x83 and raw[i+3] == 0xB8:
            pkt_len = raw[i] | (raw[i+1] << 8)
            
            if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                pkt_data = raw[i : i + pkt_len]
                ts_bytes = pkt_data[4:12]
                hw_timestamp = parse_qxdm_time(ts_bytes)
                
                packets.append((pkt_data, hw_timestamp))
                i += pkt_len
                continue
        i += 1
    return packets

# ── Public API ────────────────────────────────────────────────────────────────
def parse_stream(text: str, verbose: bool = True) -> List[UlSchedRecord]:
    tokens = re.findall(r'[0-9A-Fa-f]{2}', text)
    if not tokens:
        if verbose: print("No hex data found.")
        return []

    raw = bytes(int(t, 16) for t in tokens)
    all_results: List[UlSchedRecord] = []
    
    for idx, (pkt, hw_timestamp) in enumerate(split_packets(raw)):
        all_results.extend(parse_payload(pkt, idx, hw_timestamp))

    if verbose:
        print_results(all_results)
    return all_results

# ── Formatters ────────────────────────────────────────────────────────────────
def _fmt(v) -> str:
    return str(v) if v is not None else "—"

def print_results(results: List[UlSchedRecord]):
    if not results:
        print("No B883 records found.")
        return

    # Updated columns to handle dynamic payloads and UI friendliness 
    COL = ("Pkt", "Rec", "Ver", "Slot/Abs", "CC", "Type", "RNTI", "C-RNTI", "Len", "Syms", "Fmt/HQ", "MCS", "RB[St:Sz]", "TBSize")
    FMT = "{:>4} {:>3} {:>5} {:>8} {:>2} {:>9} {:>8} {:>6} {:>3} {:>9} {:>6} {:>3} {:>9} {:>8}"
    SEP = "=" * 110

    print(f"\n{SEP}")
    print("  B883 NR5G MAC UL Schedule — Parsed Records with Hardware Timestamps")
    print(SEP)
    print("  " + FMT.format(*COL))
    print("  " + "-" * 108)
    for r in results:
        # Safely handle attributes mapped between v2 and v3
        slot_val = str(r.abs_slot) if r.abs_slot is not None else f"{_fmt(r.slot)}/{_fmt(r.frame)}"
        syms  = f"[{r.start_sym}:{r.num_sym}]" if r.start_sym is not None else "—"
        rbs   = f"[{r.rb_start}:{r.num_rbs}]" if r.rb_start is not None else f"[{_fmt(r.num_rbs)}]"
        f_h   = r.pucch_fmt if "PUCCH" in r.chan_type else r.harq_id
        c_r   = f"{r.c_rnti:04X}" if r.c_rnti is not None else "—"

        print("  " + FMT.format(
            r.payload_idx, r.record_idx, r.version, slot_val, _fmt(r.carrier_id),
            r.chan_type, _fmt(r.rnti_type), c_r, _fmt(r.length), syms, _fmt(f_h),
            _fmt(r.mcs), rbs, _fmt(r.tb_size)))

    # Compute Statistics
    mcs_vals = [r.mcs for r in results if r.mcs is not None]
    ch_counts = {}
    for r in results:
        ch_counts[r.chan_type] = ch_counts.get(r.chan_type, 0) + 1

    print(f"\n  Total records : {len(results)}")
    print(f"  Channel Dist  : " + ", ".join(f"{k}={v}" for k,v in ch_counts.items()))
    if mcs_vals:
        print(f"  PUSCH MCS     : min={min(mcs_vals)}, max={max(mcs_vals)}, "
              f"avg={sum(mcs_vals)/len(mcs_vals):.2f}")
    print(SEP + "\n")

def write_csv(results: List[UlSchedRecord], path: str):
    if not results: return
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].to_dict().keys()))
        w.writeheader()
        w.writerows(r.to_dict() for r in results)
    print(f"CSV saved → {path}")

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Parse 0xB883 NR5G UL PUSCH/PUCCH payloads (with timestamps).")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("--csv",      metavar="FILE", help="Save results to CSV")
    ap.add_argument("--mcs-only", action="store_true",
                    help="Print compact MCS-only output for PUSCH, one record per line")
    args = ap.parse_args()

    text = open(args.input).read() if args.input else sys.stdin.read()
    results = parse_stream(text, verbose=not args.mcs_only)

    if args.mcs_only:
        for r in results:
            if r.chan_type == "PUSCH" and r.mcs is not None:
                ts_str = r.timestamp.strftime('%H:%M:%S.%f')
                print(f"time={ts_str} pkt={r.payload_idx} rec={r.record_idx} ver={r.version} "
                      f"slot={_fmt(r.abs_slot)} MCS={r.mcs} RBs={r.num_rbs}")
    if args.csv:
        write_csv(results, args.csv)

if __name__ == "__main__":
    main()
