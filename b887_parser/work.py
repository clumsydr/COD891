import argparse
import sys

def decode_full_b887_payload(hex_payload):
    # Clean the hex string and convert to raw bytes
    hex_payload = hex_payload.replace(" ", "").replace(",", "").strip()
    
    if not hex_payload:
        return # Skip empty lines
        
    try:
        payload_bytes = bytes.fromhex(hex_payload)
    except ValueError:
        print(f"Skipping invalid hex payload: {hex_payload[:30]}...")
        return
        
    if len(payload_bytes) < 28:
        print(f"Skipping truncated payload ({len(payload_bytes)} bytes).")
        return
    
    # --- 1. Parse Log Header (28 Bytes) ---
    length = int.from_bytes(payload_bytes[0:2], 'little')
    log_code = int.from_bytes(payload_bytes[2:4], 'little')
    num_records = payload_bytes[27] 
    
    print(f"========================================")
    print(f"        0xB887 MAC PDSCH DECODER        ")
    print(f"========================================")
    print(f"Total Log Length : {len(payload_bytes)} bytes")
    print(f"Log Code         : {hex(log_code)}")
    print(f"PDSCH Records    : {num_records}\n")
    
    # --- 2. Dynamically Loop Through Each 28-Byte Record ---
    for i in range(num_records):
        print(f"========================================")
        print(f" RECORD {i + 1} OF {num_records}")
        print(f"========================================")
        
        offset = 28 + (i * 28)
        
        if offset + 28 > len(payload_bytes):
            print(f"  [!] Warning: Record {i+1} exceeds payload length.")
            break
            
        record_bytes = payload_bytes[offset : offset + 28]
        
        # --- KNOWN EXTRACTED FIELDS ---
        slot = record_bytes[0]
        numerology = record_bytes[1]
        frame = int.from_bytes(record_bytes[2:4], 'little')
        
        # PCI and EARFCN chunk (Bytes 12 to 15)
        val32_pci = int.from_bytes(record_bytes[12:16], 'little')
        pci = val32_pci & 0x3FF
        earfcn = (val32_pci >> 10) & 0xFFFFF
        
        # MCS chunk (Bytes 16 to 23)
        val64_mcs = int.from_bytes(record_bytes[16:24], 'little')
        mcs = (val64_mcs >> 26) & 0x1F
        
        print("--- Reverse-Engineered Values ---")
        print(f"{'Slot':<20}: {slot}")
        print(f"{'Numerology Index':<20}: {numerology}")
        print(f"{'Frame':<20}: {frame}")
        print(f"{'Physical Cell ID':<20}: {pci}")
        print(f"{'EARFCN':<20}: {earfcn}")
        print(f"{'MCS':<20}: {mcs}")
        
        # --- RAW BIT MAP FOR REMAINING COLUMNS ---
        print("\n--- Raw 28-Byte Record Map (To find remaining CSV columns) ---")
        print("Byte | Hex | Binary")
        print("-----------------------")
        for byte_idx, b in enumerate(record_bytes):
            # Print the byte index, the hex value, and the binary representation
            # We reverse the binary string representation slightly if visualizing Little Endian
            print(f" {byte_idx:02d}  |  {b:02X} | {b:08b}")
        print("\n")

# ==========================================
# Run the decoder from a file
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decode 5G NR MAC PDSCH (0xB887) payloads line by line from a file.")
    parser.add_argument("filename", help="Path to the text file containing the hex payloads.")
    args = parser.parse_args()

    try:
        with open(args.filename, "r") as f:
            lines = f.readlines()
            
        print(f"Parsing '{args.filename}' ({len(lines)} lines detected)...\n")
        
        for idx, line in enumerate(lines):
            print(f"\n>>> DECODING LINE {idx + 1} <<<")
            decode_full_b887_payload(line)
            
    except FileNotFoundError:
        print(f"\n[ERROR] File not found: '{args.filename}'. Please check the path and try again.")
        sys.exit(1)