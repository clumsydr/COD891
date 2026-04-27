import re
import argparse

ap = argparse.ArgumentParser(description="Parse raw into raw_packets")
ap.add_argument("input", nargs="?", help="input text file")
ap.add_argument("output", nargs="?", help="output text file ")
ap.add_argument("-download", default=1)
args = ap.parse_args()

capture = False
payload = []
download = int(args.download)

with open(args.input, "r") as f, open(args.output, "w") as out:
    for line in f:
        if (download) and ("Not parsing DIAG log item 0xb887" in line):
            capture = True
            payload = []
            continue
        elif (not download) and "Not parsing DIAG log item 0xb883" in line:
            capture = True
            payload = []
            continue
        
        if capture and "-------- end --------" in line:
            out.write(" ".join(payload) + "\n")
            capture = False
            continue
        
        if capture:
            # extract hex bytes only (first column before ASCII)
            hex_part = line.split('\t')[0]
            bytes_found = re.findall(r'\b[0-9a-fA-F]{2}\b', hex_part)
            payload.extend(bytes_found)