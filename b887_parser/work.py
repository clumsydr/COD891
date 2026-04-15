def decode_full_b887_payload(hex_payload):
    # Clean the hex string and convert to raw bytes
    hex_payload = hex_payload.replace(" ", "").replace(",", "").strip()
    payload_bytes = bytes.fromhex(hex_payload)
    
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
# Run the decoder
# ==========================================
if __name__ == "__main__":
    # Test Payload from File 1_3.xlsx
    payload = "A8 00 87 B8 79 52 E3 AC A0 6F 0F 01 05 00 02 00 00 00 00 00 00 00 00 00 00 00 00 05 03 01 D8 00 01 00 00 00 07 D8 0C 18 F6 81 B3 26 20 01 86 34 11 29 C0 42 07 00 C9 00 06 01 D8 00 01 00 00 00 07 D8 18 18 F6 81 B3 26 40 03 94 40 C4 30 00 42 03 00 C9 00 07 01 D8 00 01 00 00 00 07 D8 1C 18 F6 81 B3 26 40 02 9C 3C 11 39 C0 41 02 00 C9 00 08 01 D8 00 01 00 00 00 07 D8 20 18 F6 81 B3 26 A0 86 9B 40 10 41 C0 41 03 00 C9 00 09 01 D8 00 01 00 00 00 07 D8 24 18 F6 81 B3 26 80 05 9A 78 E0 7C 80 41 01 81 C9 00"
    payload = "38 00 87 B8 12 3C 40 05 A0 6F 0F 01 05 00 02 00 00 00 00 00 00 00 00 00 00 00 00 01 00 01 E4 03 01 00 00 00 07 E4 03 18 F6 81 B3 26 E0 0D 80 30 01 18 40 21 07 00 C9 00"
    decode_full_b887_payload(payload)
