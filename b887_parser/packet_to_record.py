import sys, argparse

def extract_packet_records(input_filepath, output_filepath, record_count_index, record_length):
    # Constants based on your file's structure
    RECORD_COUNT_INDEX = int(record_count_index)
    RECORD_LENGTH = int(record_length)
    
    total_records_extracted = 0
    
    with open(input_filepath, 'r') as infile, open(output_filepath, 'w') as outfile:
        for line_num, line in enumerate(infile, start=1):
            # Split the line by spaces and filter for actual hex bytes.
            # This ensures any errant text (like the "" tags in your sample) is ignored.
            raw_parts = line.split()
            hex_bytes = [b for b in raw_parts if len(b) == 2 and b.isalnum()]
            
            # Skip empty lines or lines that don't even have headers
            if len(hex_bytes) <= RECORD_COUNT_INDEX:
                continue
                
            try:
                # Convert the hex byte at the 29th position to an integer
                num_records = int(hex_bytes[RECORD_COUNT_INDEX], 16)
            except ValueError:
                print(f"Line {line_num}: Invalid hex value at 29th byte ('{hex_bytes[RECORD_COUNT_INDEX]}'). Skipping.")
                continue
                
            # The records start immediately after the count byte
            current_idx = RECORD_COUNT_INDEX + 1
            
            for _ in range(num_records):
                # Ensure the line actually has enough bytes left for a full 32-byte record
                if current_idx + RECORD_LENGTH > len(hex_bytes):
                    print(f"Line {line_num}: Packet truncated. Expected {num_records} records, missing data.")
                    break
                    
                # Slice out the 32-byte record and format it back into a space-separated string
                record = hex_bytes[current_idx : current_idx + RECORD_LENGTH]
                outfile.write(" ".join(record) + "\n")
                
                total_records_extracted += 1
                current_idx += RECORD_LENGTH

    print(f"Extraction complete! {total_records_extracted} records written to {output_filepath}")

# Execution handling
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Plotter for 0xB887 NR5G PDSCH payloads (v2 + v3).")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("output", nargs="?", help="Hex text file (stdout if omitted)")
    ap.add_argument("record_count_index", default=28)
    ap.add_argument("record_length", default=32)
    args = ap.parse_args()

    try:
        extract_packet_records(args.input, args.output, args.record_count_index, args.record_length)
    except FileNotFoundError:
        print(f"Error: Could not find the input file '{args.input}'. Please ensure it is in the same directory.")
