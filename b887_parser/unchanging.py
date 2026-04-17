import argparse
import sys

class ModularStaticBitAnalyzer:
    def __init__(self, header_size, record_size, num_records_offset, log_code="87B8"):
        self.header_size = header_size
        self.record_size = record_size
        self.num_records_offset = num_records_offset
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

        print(f"Parsing '{filename}' ({len(lines)} lines detected)...")

        # --- 1. Extract Valid Records ---
        for line in lines:
            hex_str = line.replace(" ", "").strip()
            if not hex_str: continue
                
            try:
                raw_bytes = bytes.fromhex(hex_str)
            except ValueError:
                continue

            payload_start = 0
            if self.log_code_bytes and self.log_code_bytes in raw_bytes:
                pos = raw_bytes.find(self.log_code_bytes)
                if pos >= 2: payload_start = pos - 2

            if len(raw_bytes) < payload_start + self.header_size: continue
                
            num_records = raw_bytes[payload_start + self.num_records_offset]
            
            for i in range(num_records):
                offset = payload_start + self.header_size + (i * self.record_size)
                if offset + self.record_size <= len(raw_bytes):
                    records.append(raw_bytes[offset : offset + self.record_size])

        print(f"Total valid {self.record_size}-byte records extracted: {len(records)}\n")
        if not records: return

        # --- 2. Compute Static '1's and Static '0's ---
        
        # Initialize trackers
        always_one = bytearray(b'\xff' * self.record_size)  # Start all 1s
        always_zero_tracker = bytearray(b'\x00' * self.record_size)  # Start all 0s
        
        for record in records:
            for i in range(self.record_size):
                always_one[i] &= record[i]           # AND logic traps 0s
                always_zero_tracker[i] |= record[i]  # OR logic traps 1s
                
        # Invert the zero tracker so the static '0's light up as '1's for our final mask
        static_zeros = bytearray(self.record_size)
        for i in range(self.record_size):
            static_zeros[i] = (~always_zero_tracker[i]) & 0xFF

        # --- 3. Display Results ---
        
        # STATIC '1's
        print("=======================================================")
        print(" BITS THAT NEVER CHANGED FROM '1' (Always-One Mask)")
        print("=======================================================")
        for i, byte_val in enumerate(always_one):
            if byte_val > 0:
                print(f"Byte {i:02d} | Hex: 0x{byte_val:02X} | Binary: {byte_val:08b}")
        print(f"Full Mask (Hex): {' '.join(f'{b:02X}' for b in always_one)}\n")


        # STATIC '0's
        print("=======================================================")
        print(" BITS THAT NEVER CHANGED FROM '0' (Always-Zero Mask)")
        print("=======================================================")
        print("Note: The binary '1's printed below highlight where the bits remained '0'.\n")
        for i, byte_val in enumerate(static_zeros):
            if byte_val > 0:
                print(f"Byte {i:02d} | Hex: 0x{byte_val:02X} | Binary: {byte_val:08b}")
        print(f"Full Mask (Hex): {' '.join(f'{b:02X}' for b in static_zeros)}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze 5G NR payloads to find static bits (Always '1' or '0').")
    parser.add_argument("filename", help="Path to the text file containing hex payloads.")
    parser.add_argument("--header", type=int, default=20, help="Header size in bytes (default: 20)")
    parser.add_argument("--record", type=int, default=32, help="Record size in bytes (default: 32)")
    parser.add_argument("--offset", type=int, default=19, help="Byte index for 'Num Records' in the header (default: 19)")
    parser.add_argument("--logcode", type=str, default="87B8", help="Hex Log Code to search for alignment (default: 87B8)")

    args = parser.parse_args()
    log_code_search = args.logcode if args.logcode.upper() != "NONE" else None

    analyzer = ModularStaticBitAnalyzer(args.header, args.record, args.offset, log_code_search)
    analyzer.analyze_file(args.filename)
