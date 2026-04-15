import argparse
import sys

class ModularStaticBitAnalyzer:
    def __init__(self, header_size, record_size, num_records_offset, log_code="87B8"):
        """
        Initializes the Bit Analyzer with dynamic payload structures.
        """
        self.header_size = header_size
        self.record_size = record_size
        self.num_records_offset = num_records_offset
        
        # Optional: Log code search (Little Endian format for 0xB887 is b'\x87\xb8')
        try:
            self.log_code_bytes = bytes.fromhex(log_code)[::-1] 
        except ValueError:
            self.log_code_bytes = None

    def analyze_file(self, filename):
        records = []
        
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"\n[ERROR] File not found: '{filename}'.")
            sys.exit(1)
        except PermissionError:
            print(f"\n[ERROR] Permission denied: '{filename}'.")
            sys.exit(1)

        print(f"Parsing '{filename}' ({len(lines)} lines detected)...")

        # --- 1. Extract Valid Records ---
        for line in lines:
            hex_str = line.replace(" ", "").strip()
            if not hex_str:
                continue
                
            try:
                raw_bytes = bytes.fromhex(hex_str)
            except ValueError:
                continue # Skip malformed lines

            payload_start = 0
            
            # If a specific Log Code search is enabled, find where the payload actually begins.
            # Useful for files that have random QXDM/QCAT framing bytes at the start of the line.
            if self.log_code_bytes and self.log_code_bytes in raw_bytes:
                pos = raw_bytes.find(self.log_code_bytes)
                # Assume the payload starts 2 bytes before the log code (Length bytes)
                if pos >= 2:
                    payload_start = pos - 2

            # Ensure we have enough bytes to safely read the 'Num Records' byte
            if len(raw_bytes) < payload_start + self.header_size:
                continue
                
            num_records = raw_bytes[payload_start + self.num_records_offset]
            
            # Extract each dynamically-sized record block
            for i in range(num_records):
                offset = payload_start + self.header_size + (i * self.record_size)
                
                # Verify we don't read out of bounds
                if offset + self.record_size <= len(raw_bytes):
                    records.append(raw_bytes[offset : offset + self.record_size])

        print(f"Total valid {self.record_size}-byte records extracted: {len(records)}")

        if not records:
            print("[!] No valid records found matching the configured architecture.")
            return

        # --- 2. Compute the Bits That Never Change from 1 ---
        # Initialize our mask with all 1s (0xFF repeated for the length of the record)
        always_one = bytearray(b'\xff' * self.record_size)
        
        # Apply rolling Bitwise AND across every extracted record
        for record in records:
            for i in range(self.record_size):
                always_one[i] &= record[i]
                
        # --- 3. Display Results ---
        print("\n=======================================================")
        print(" BITS THAT NEVER CHANGED FROM '1' ACROSS ALL PAYLOADS")
        print("=======================================================")
        
        found_static_bits = False
        for i, byte_val in enumerate(always_one):
            if byte_val > 0:
                found_static_bits = True
                print(f"Byte {i:02d} | Hex: 0x{byte_val:02X} | Binary: {byte_val:08b}")
                
        if not found_static_bits:
            print("No bits remained static across all payloads.")

        print(f"\nFull {self.record_size}-Byte Static-One Mask (Hex):")
        print(" ".join(f"{b:02X}" for b in always_one))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze 5G NR payloads to find static bits (Always '1').")
    
    # Target File
    parser.add_argument("filename", help="Path to the text file containing hex payloads.")
    
    # Modular Payload Configurations
    parser.add_argument("--header", type=int, default=29, help="Header size in bytes (default: 20)")
    parser.add_argument("--record", type=int, default=32, help="Record size in bytes (default: 32)")
    parser.add_argument("--offset", type=int, default=28, help="Byte index for 'Num Records' in the header (default: 19)")
    parser.add_argument("--logcode", type=str, default="87B8", help="Hex Log Code to search for alignment (default: 87B8). Set to 'NONE' to disable search.")

    args = parser.parse_args()
    
    log_code_search = args.logcode if args.logcode.upper() != "NONE" else None

    # Initialize and run
    analyzer = ModularStaticBitAnalyzer(
        header_size=args.header, 
        record_size=args.record, 
        num_records_offset=args.offset,
        log_code=log_code_search
    )
    
    analyzer.analyze_file(args.filename)