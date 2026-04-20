import re

input_file = "TarunPhoneLogs/VodaLogs/qmdl-to-scat-voda-4.txt"
output_file = "TarunPhoneLogs/VodaLogs/voda4.txt"

capture = False
payload = []

with open(input_file, "r") as f, open(output_file, "w") as out:
    for line in f:
        if "Not parsing DIAG log item 0xb887" in line:
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