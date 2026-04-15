#!/usr/bin/env python3
"""
B887 NR5G MAC PDSCH Status — Multi-version Parser
===================================================
Extracts MCS and other key fields from 0xB887 log payloads.
Supports two confirmed structure versions based on the Major version field:

┌──────────┬──────────────────────────────────────────────────────────────────┐
│          │  Version 2 (Major=2)          Version 3 (Major=3)               │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ Rec len  │  28 bytes                     24 bytes                          │
│ Rec hdr  │  10 bytes                     2 bytes                           │
│ Entry    │  18 bytes                     22 bytes (4 BMask-extra at end)   │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ Slot     │  rec[0]  uint8                TBD (rec hdr shorter)             │
│ Frame    │  rec[2-3] uint16 LE           TBD                               │
│ Carrier  │  rec[5]  uint8                TBD                               │
│ SCS mu   │  rec[9]  bits[2:0]            TBD                               │
│ TB Size  │  entry[6-8] (>>5)&0x1FFFF    entry[6-8] (>>5)&0x1FFFF  ✓same  │
│ MCS      │  entry[9-10] (>>2)&0x1F      entry[9-10] (>>2)&0x1F    ✓same  │
│ Num RBs  │  entry[10-11] &0x1FF         entry[10-11] &0x1FF        ✓same  │
│ HARQ ID  │  entry[11]   (>>3)&0xF       entry[11]   (>>3)&0xF      ✓same  │
│ K1       │  entry[12-13](>>6)&0xF       entry[12-13](>>6)&0xF      ✓same  │
└──────────┴──────────────────────────────────────────────────────────────────┘

NOTE: The outer framing (how the stream arrives) may include a DIAG framing
wrapper before the B887 packet. The parser automatically strips it by scanning
for the 87 B8 log code signature.

Usage:
    python b887_mcs_parser.py payloads.txt
    echo "38 00 87 B8 ..." | python b887_mcs_parser.py
    python b887_mcs_parser.py payloads.txt --csv out.csv
    python b887_mcs_parser.py payloads.txt --mcs-only
"""

import sys, re, csv, argparse
from dataclasses import dataclass, fields as dc_fields
from typing import List, Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────
LOG_CODE        = 0xB887
QXDM_HDR_LEN    = 12     # len(2) + code(2) + timestamp(8)
META_LEN        = 16     # version(4) + bmask(4) + subid(1) + pad(6) + num_records(1)
#####RECORDS_START   = QXDM_HDR_LEN + META_LEN   # = 28 (same for both versions)


# Version 2 layout
V2_REC_HDR_LEN   = 10
V2_ENTRY_LEN     = 18
V2_REC_LEN       = V2_REC_HDR_LEN + V2_ENTRY_LEN   # 28

# Version 3 layout
###### V3_REC_HDR_LEN   = 2
V3_REC_HDR_LEN   = 10
V3_ENTRY_LEN     = 22
V3_REC_LEN       = V3_REC_HDR_LEN + V3_ENTRY_LEN   # 24

SCS_MAP = {0: "15kHz", 1: "30kHz", 2: "60kHz", 3: "120kHz"}

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class PdschRecord:
    payload_idx: int
    record_idx:  int
    version:     int     # major version (2 or 3)
    slot:        Optional[int]
    frame:       Optional[int]
    scs:         Optional[str]
    carrier_id:  Optional[int]
    tb_size:     int
    mcs:         int
    num_rbs:     int
    harq_id:     int
    k1:          int

    def to_dict(self):
        return {f.name: getattr(self, f.name) for f in dc_fields(self)}

# ── Helpers ───────────────────────────────────────────────────────────────────
def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

def extract_entry_fields(entry: bytes) -> Tuple[int, int, int, int, int]:
    """
    Extract (tb_size, mcs, num_rbs, harq_id, k1) from a PDSCH entry.
    Entry layout is identical between v2 and v3 for these fields:
      entry[6-8]  : TB Size  = (uint32 LE >> 5) & 0x1FFFF
      entry[9-10] : MCS      = (uint16 LE >> 2) & 0x1F
      entry[10-11]: Num RBs  = uint16 LE & 0x1FF
      entry[11]   : HARQ ID  = (byte >> 3) & 0xF
      entry[12-13]: K1       = (uint16 LE >> 6) & 0xF
    """
    tb_size = (u32(entry, 6) >> 5) & 0x1FFFF
    mcs     = (u16(entry, 9) >> 2) & 0x1F
    num_rbs = u16(entry, 10) & 0x1FF
    harq_id = (entry[11] >> 3) & 0xF
    k1      = (u16(entry, 12) >> 6) & 0xF
    return tb_size, mcs, num_rbs, harq_id, k1

# ── Per-version record parsers ────────────────────────────────────────────────
def parse_record_v2(rec: bytes, payload_idx: int, rec_idx: int) -> PdschRecord:
    """Parse a 28-byte version-2 record."""
    slot       = rec[0]
    frame      = u16(rec, 2)
    mu         = rec[9] & 0x07
    carrier_id = rec[5]
    entry      = rec[V2_REC_HDR_LEN:]
    tb, mcs, rbs, harq, k1 = extract_entry_fields(entry)
    return PdschRecord(
        payload_idx=payload_idx, record_idx=rec_idx, version=2,
        slot=slot, frame=frame,
        scs=SCS_MAP.get(mu, f"mu{mu}"),
        carrier_id=carrier_id,
        tb_size=tb, mcs=mcs, num_rbs=rbs, harq_id=harq, k1=k1,
    )

def parse_record_v3(rec: bytes, payload_idx: int, rec_idx: int) -> PdschRecord:
    """
    Parse a 24-byte version-3 record.
    Header fields (slot, frame, SCS, carrier) have not yet been mapped
    for v3 — they are returned as None pending further samples.
    """
    entry = rec[V3_REC_HDR_LEN:]
    tb, mcs, rbs, harq, k1 = extract_entry_fields(entry)
    return PdschRecord(
        payload_idx=payload_idx, record_idx=rec_idx, version=3,
        slot=None, frame=None, scs=None, carrier_id=None,
        tb_size=tb, mcs=mcs, num_rbs=rbs, harq_id=harq, k1=k1,
    )

# ── Payload parser ────────────────────────────────────────────────────────────
def parse_payload(payload: bytes, payload_idx: int) -> List[PdschRecord]:
    """Parse one B887 payload and return all records."""
    if u16(payload, 2) != LOG_CODE:
        return []

    version_word = u32(payload, 12)
    major = version_word >> 16

    RECORDS_START = 0
    parse_rec = parse_record_v2 # beep
    if major == 2:
        rec_len     = V2_REC_LEN       # 28
        RECORDS_START = 27
        #####parse_rec   = parse_record_v2
        #####num_records = payload[27]      # explicit field in metadata
    elif major == 3:
        rec_len     = V3_REC_LEN       # 24
        #####parse_rec   = parse_record_v3
        # num_records field appears to be absent/zero in v3 metadata;
        # derive from declared packet length instead.
        #####declared_len = u16(payload, 0)
        #####num_records  = (declared_len - RECORDS_START) // rec_len
        RECORDS_START = 19
    else:
        # Unknown version — attempt v2 layout as best-effort
        rec_len     = V2_REC_LEN
        #####parse_rec   = parse_record_v2
        #####num_records = payload[27]
        RECORDS_START = 27

    num_records = payload[RECORDS_START]

    # Clamp to available data
    available = (len(payload) - RECORDS_START) // rec_len
    num_records = min(num_records, available)

    results = []
    for rec_idx in range(num_records):
        base = RECORDS_START + 1 + rec_idx * rec_len
        rec  = payload[base : base + rec_len]
        if len(rec) < rec_len:
            break
        results.append(parse_rec(rec, payload_idx, rec_idx))
    return results

# ── Stream splitter ───────────────────────────────────────────────────────────
def split_packets(raw: bytes) -> List[bytes]:
    """
    Find all B887 packet boundaries in a raw byte stream.
    Handles both bare packets and packets wrapped in a DIAG framing header
    (where the B887 packet may start at a non-zero offset in the supplied bytes).
    """
    packets, i = [], 0
    while i < len(raw) - 3:
        if raw[i+2] == 0x87 and raw[i+3] == 0xB8:
            pkt_len = raw[i] | (raw[i+1] << 8)
            if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                packets.append(raw[i : i + pkt_len])
                i += pkt_len
                continue
        i += 1
    return packets or [raw]

# ── Public API ────────────────────────────────────────────────────────────────
def parse_stream(text: str, verbose: bool = True) -> List[PdschRecord]:
    """Parse a text string containing one or more B887 hex payloads."""
    tokens = re.findall(r'[0-9A-Fa-f]{2}', text)
    if not tokens:
        if verbose: print("No hex data found.")
        return []

    raw = bytes(int(t, 16) for t in tokens)
    all_results: List[PdschRecord] = []
    for idx, pkt in enumerate(split_packets(raw)):
        all_results.extend(parse_payload(pkt, idx))

    if verbose:
        print_results(all_results)
    return all_results

# ── Formatters ────────────────────────────────────────────────────────────────
def _fmt(v) -> str:
    return str(v) if v is not None else "—"

def print_results(results: List[PdschRecord]):
    if not results:
        print("No B887 records found.")
        return

    COL = ("Pkt","Rec","Ver","Slot","Frame","SCS","CID","TB Size","MCS","Num RBs","HARQ","K1")
    FMT = "{:>4}  {:>4}  {:>4}  {:>5}  {:>6}  {:>7}  {:>4}  {:>8}  {:>4}  {:>8}  {:>5}  {:>4}"
    SEP = "=" * 83

    print(f"\n{SEP}")
    print("  B887 NR5G MAC PDSCH — Parsed Records")
    print(SEP)
    print("  " + FMT.format(*COL))
    print("  " + FMT.format(*("-"*len(c) for c in COL)))
    for r in results:
        print("  " + FMT.format(
            r.payload_idx, r.record_idx, r.version,
            _fmt(r.slot), _fmt(r.frame), _fmt(r.scs),
            _fmt(r.carrier_id), r.tb_size, r.mcs,
            r.num_rbs, r.harq_id, r.k1))

    mcs_vals = [r.mcs for r in results]
    by_ver = {}
    for r in results:
        by_ver.setdefault(r.version, []).append(r.mcs)

    print(f"\n  Total records : {len(results)}")
    for v, vals in sorted(by_ver.items()):
        print(f"  Version {v}     : {len(vals)} record(s), MCS in {sorted(set(vals))}")
    print(f"  Overall MCS   : min={min(mcs_vals)}, max={max(mcs_vals)}, "
          f"avg={sum(mcs_vals)/len(mcs_vals):.2f}")
    print(SEP + "\n")

def write_csv(results: List[PdschRecord], path: str):
    if not results: return
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].to_dict().keys()))
        w.writeheader()
        w.writerows(r.to_dict() for r in results)
    print(f"CSV saved → {path}")

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Parse 0xB887 NR5G PDSCH payloads (v2 + v3).")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("--csv",      metavar="FILE", help="Save results to CSV")
    ap.add_argument("--mcs-only", action="store_true",
                    help="Print compact MCS-only output, one record per line")
    args = ap.parse_args()

    text = open(args.input).read() if args.input else sys.stdin.read()
    results = parse_stream(text, verbose=not args.mcs_only)

    if args.mcs_only:
        for r in results:
            print(f"pkt={r.payload_idx} rec={r.record_idx} ver={r.version} "
                  f"slot={_fmt(r.slot)} frame={_fmt(r.frame)} MCS={r.mcs}")
    if args.csv:
        write_csv(results, args.csv)

if __name__ == "__main__":
    main()