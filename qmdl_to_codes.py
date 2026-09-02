import re
import sys
import argparse

ap = argparse.ArgumentParser(description="Extract raw DIAG log payloads from scat output into a payload text file.")
ap.add_argument("input", nargs="?", default="-", help="Input scat text file (or '-' for stdin)")
ap.add_argument("output", nargs="?", default="-", help="Output payload text file (or '-' for stdout)")
ap.add_argument("--code", default="0xb887", help="DIAG log code to extract (default: 0xb887)")
args = ap.parse_args()

code_target = f"not parsing diag log item {args.code.lower()}"

in_f = sys.stdin if args.input == "-" else open(args.input, "r")
out_f = sys.stdout if args.output == "-" else open(args.output, "w")

capture = False
payload = []

try:
    for line in in_f:
        if code_target in line.lower():
            capture = True
            payload = []
            continue

        if capture and "-------- end --------" in line:
            out_f.write(" ".join(payload) + "\n")
            capture = False
            continue
        
        if capture:
            hex_part = line.split('\t')[0]
            bytes_found = re.findall(r'\b[0-9a-fA-F]{2}\b', hex_part)
            payload.extend(bytes_found)
finally:
    if in_f is not sys.stdin:
        in_f.close()
    if out_f is not sys.stdout:
        out_f.close()
