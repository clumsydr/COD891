#!/usr/bin/env python3
"""
B887 NR5G MAC PDSCH Status — Parser
=====================================
Extracts MCS and other key fields from 0xB887 log payloads.

Verified field layout (28 bytes per record, starting at payload offset 28):
  [0]     Slot (uint8)
  [1]     Numerology/BW byte — lower 3 bits = SCS mu
  [2-3]   Frame (uint16 LE)
  [12-13] pci      - u16(r, 12) & 0x3FF
  [13-16] nr_arfcn - (u32(r, 13) >> 2) & 0x3FFFFF
  [16-18] TB Size — (uint32 LE >> 5) & 0x1FFFF
  [19-20] MCS    — (uint16 LE >> 2) & 0x1F       *** primary field ***
  [20-21] Num RBs— uint16 LE & 0x1FF
  [21]    HARQ ID— (byte >> 3) & 0xF
  [22-23] K1     — (uint16 LE >> 6) & 0xF

Payload structure:
  [0-11]  QXDM log header  (len 2B LE + code 2B LE + timestamp 8B)
  [12-27] Log metadata     (version 4B + bmask 4B + subid 1B + pad 6B + num_records 1B)
  [28+]   Records, each 28 bytes x num_records

Supported input formats:
  Format A — Raw B887 packet (original):
    38 00 87 B8 ...
  Format B — Framed packet with transport prefix (auto-detected):
    04 13 15 29 57 10 00 38 00 38 00 87 b8 ...
    ^^^^^^^^^^^^^^^^^^^^ framing prefix (variable length, stripped automatically)

Usage:
    python b887_mcs_parser.py payloads.txt
    echo "38 00 87 B8 ..." | python b887_mcs_parser.py
    python b887_mcs_parser.py payloads.txt --csv out.csv
    python b887_mcs_parser.py payloads.txt --mcs-only
"""

import sys, re, csv, argparse
from dataclasses import dataclass, fields as dc_fields
from typing import List, Optional

# ── Constants ─────────────────────────────────────────────────────────────────
LOG_CODE           = 0xB887
RECORDS_START      = 28       # 12 (QXDM hdr) + 16 (meta)
NUM_RECORDS_OFFSET = 27
RECORD_LEN         = 28       # verified: 6 records × 28 = 168 bytes + 28 header = 196 ✓
SCS_MAP = {0: "15kHz", 1: "30kHz", 2: "60kHz", 3: "120kHz"}

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class PdschRecord:
    payload_idx: int
    record_idx:  int
    slot:        int
    frame:       int
    scs:         str
    carrier_id:  int
    pci:         int
    nr_arfcn:    int
    tb_size:     int
    mcs:         int
    num_rbs:     int
    harq_id:     int
    k1:          int

    def to_dict(self):
        return {f.name: getattr(self, f.name) for f in dc_fields(self)}

# ── Low-level helpers ─────────────────────────────────────────────────────────
def u16(b, o): return b[o] | (b[o+1] << 8)
def u32(b, o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

# ── Framing prefix stripper ───────────────────────────────────────────────────
def strip_framing_prefix(raw: bytes) -> bytes:
    """
    Detect and strip any transport/framing prefix that appears before the
    QXDM log header.

    The QXDM log header always begins with two bytes that encode the total
    packet length (uint16 LE), immediately followed by the log code 0xB887
    (bytes 0x87 0xB8).  We scan forward up to 32 bytes to find this
    signature and return the slice starting there.

    Example framing prefix (7 bytes):
        04 13 15 29 57 10 00  |  38 00 87 B8 ...
                                 ^^^^ pkt_len  ^^^^ log code  ← QXDM header starts here
    """
    # Fast-path: already a bare QXDM packet
    if len(raw) >= 4 and raw[2] == 0x87 and raw[3] == 0xB8:
        return raw

    # Scan for the QXDM header signature within the first 32 bytes
    for offset in range(1, min(32, len(raw) - 3)):
        if raw[offset + 2] == 0x87 and raw[offset + 3] == 0xB8:
            # Sanity-check: the embedded length field should be ≤ remaining data
            pkt_len = raw[offset] | (raw[offset + 1] << 8)
            if 32 <= pkt_len <= len(raw) - offset:
                return raw[offset:]

    # No recognisable prefix found — return as-is and let the parser decide
    return raw

# ── Payload parser ────────────────────────────────────────────────────────────
def parse_payload(payload: bytes, payload_idx: int) -> List[PdschRecord]:
    results = []

    if len(payload) < RECORDS_START + RECORD_LEN:
        return results

    if u16(payload, 2) != LOG_CODE:
        return results

    num_records = payload[NUM_RECORDS_OFFSET]
    # Clamp to available data in case of truncation
    num_records = min(num_records, (len(payload) - RECORDS_START) // RECORD_LEN)

    for rec_idx in range(num_records):
        base = RECORDS_START + rec_idx * RECORD_LEN
        r = payload[base : base + RECORD_LEN]

        slot       = r[0]
        mu         = r[1]
        frame      = u16(r, 2)
        carrier_id = r[5]
        pci        = u16(r, 12) & 0x3FF
        nr_arfcn   = (u32(r, 13) >> 2) & 0x3FFFFF
        tb_size    = (u32(r, 16) >> 5) & 0x1FFFF
        mcs        = (u16(r, 19) >> 2) & 0x1F
        num_rbs    = u16(r, 20) & 0x1FF
        harq_id    = (r[21] >> 3) & 0xF
        k1         = (u16(r, 22) >> 6) & 0xF

        results.append(PdschRecord(
            payload_idx=payload_idx, record_idx=rec_idx,
            slot=slot, frame=frame,
            scs=SCS_MAP.get(mu, f"mu{mu}"),
            carrier_id=carrier_id,
            pci=pci, nr_arfcn=nr_arfcn,
            tb_size=tb_size, mcs=mcs,
            num_rbs=num_rbs, harq_id=harq_id, k1=k1,
        ))

    return results

# ── Stream splitter ───────────────────────────────────────────────────────────
def split_packets(raw: bytes) -> List[bytes]:
    """
    Scan byte stream for all 0xB887 packet boundaries.

    Handles both bare streams and streams where each packet may be
    preceded by a variable-length framing prefix (auto-stripped per packet).
    """
    packets, i = [], 0

    while i < len(raw) - 3:
        # Look for the B887 log-code bytes at position i+2 / i+3
        if raw[i+2] == 0x87 and raw[i+3] == 0xB8:
            pkt_len = raw[i] | (raw[i+1] << 8)
            if 32 <= pkt_len <= 4096 and i + pkt_len <= len(raw):
                packets.append(raw[i : i + pkt_len])
                i += pkt_len
                continue
        i += 1

    if packets:
        return packets

    # No packets found with bare scan — try stripping a framing prefix
    # from the whole buffer and re-scanning.
    stripped = strip_framing_prefix(raw)
    if stripped is not raw:
        return split_packets(stripped)

    return [raw]   # last-resort: treat entire buffer as one packet

# ── Public API ────────────────────────────────────────────────────────────────
def parse_stream(text: str, verbose: bool = True) -> List[PdschRecord]:
    """Parse a text string containing one or more B887 hex payloads."""
    tokens = re.findall(r'[0-9A-Fa-f]{2}', text)
    if not tokens:
        if verbose: print("No hex data found.")
        return []

    raw = bytes(int(t, 16) for t in tokens)

    all_results = []
    for idx, pkt in enumerate(split_packets(raw)):
        all_results.extend(parse_payload(pkt, idx))

    if verbose:
        print_results(all_results)
    return all_results

# ── Formatters ────────────────────────────────────────────────────────────────
def print_results(results: List[PdschRecord]):
    if not results:
        print("No B887 records found.")
        return

    COL = ("Pkt","Rec","Slot","Frame","SCS","Phy Cell ID","NR-ARFCN","TB Size","MCS","Num RBs","HARQ","K1")
    FMT = "{:>4}  {:>4}  {:>5}  {:>6}  {:>6} {:>7} {:>10}  {:>8}  {:>4}  {:>8}  {:>5}  {:>4}"
    SEP = "=" * 76

    print(f"\n{SEP}")
    print("  B887 NR5G MAC PDSCH — Parsed Records")
    print(SEP)
    print("  " + FMT.format(*COL))
    print("  " + FMT.format(*("-"*len(c) for c in COL)))
    for r in results:
        print("  " + FMT.format(
            r.payload_idx, r.record_idx, r.slot, r.frame,
            r.scs, r.pci, r.nr_arfcn, r.tb_size, r.mcs,
            r.num_rbs, r.harq_id, r.k1))

    mcs_vals = [r.mcs for r in results]
    print(f"\n  Total records : {len(results)}")
    print(f"  MCS range     : {min(mcs_vals)} – {max(mcs_vals)}")
    print(f"  MCS avg       : {sum(mcs_vals)/len(mcs_vals):.2f}")
    print(f"  Unique MCS    : {sorted(set(mcs_vals))}")
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
    ap = argparse.ArgumentParser(description="Parse 0xB887 NR5G PDSCH payloads.")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("--csv",      metavar="FILE", help="Save results to CSV")
    ap.add_argument("--mcs-only", action="store_true", help="Print MCS values only")
    args = ap.parse_args()

    text = open(args.input).read() if args.input else sys.stdin.read()
    results = parse_stream(text, verbose=not args.mcs_only)

    if args.mcs_only:
        for r in results:
            print(f"pkt={r.payload_idx} rec={r.record_idx} "
                  f"slot={r.slot} frame={r.frame} MCS={r.mcs}")
    if args.csv:
        write_csv(results, args.csv)

if __name__ == "__main__":
    main()