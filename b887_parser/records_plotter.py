import matplotlib.pyplot as plt
import numpy as np
import math, argparse

def plot_byte_trends_batched(filepath, output_dir, record_count_index=28, record_length=32, batch_size=100):
    records = []
    
    # --- 1. Data Extraction ---
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, start=1):
                parts = line.split()
                hex_bytes = [b for b in parts if len(b) == 2 and b.isalnum()]
                
                if len(hex_bytes) <= record_count_index:
                    continue
                try:
                    num_records = int(hex_bytes[record_count_index], 16)
                except ValueError:
                    print(f"Line {line_num}: Invalid hex value at index {record_count_index}. Skipping.")
                    continue
                    
                current_idx = record_count_index + 1
                for _ in range(num_records):
                    if current_idx + record_length > len(hex_bytes):
                        print(f"Line {line_num}: Packet truncated. Missing data.")
                        break
                        
                    record_hex = hex_bytes[current_idx : current_idx + record_length]
                    record_int = [int(b, 16) for b in record_hex]
                    
                    if len(record_int) == record_length:
                        records.append(record_int)
                    current_idx += record_length
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if not records:
        print("No valid records were extracted.")
        return

    total_records = len(records)
    print(f"Total records extracted: {total_records}")

    cols = 4
    rows = math.ceil(record_length / cols)
    heatmap_height = max(8, record_length * 0.25)

    # --- 2. Process in Batches ---
    for batch_start in range(0, total_records, batch_size):
        batch_end = min(batch_start + batch_size, total_records)
        batch_records = records[batch_start:batch_end]
        data = np.array(batch_records)
        x_range = range(batch_start, batch_end)

        # Generate Subplots
        fig1, axes = plt.subplots(rows, cols, figsize=(20, 3 * rows), sharex=True)
        fig1.suptitle(f'Value of Each Byte (0-{record_length-1}) | Records {batch_start} to {batch_end-1}', fontsize=20)
        
        axes_flat = axes.flatten() if rows * cols > 1 else [axes]

        for i, ax in enumerate(axes_flat):
            if i < data.shape[1]:
                # Plot with precise X coordinates
                ax.plot(x_range, data[:, i], marker='o', markersize=3, linestyle='-', linewidth=1)
                ax.set_title(f'Byte {i}', fontsize=12)
                ax.grid(True, alpha=0.5)
                
                if i % cols == 0:
                    ax.set_ylabel('Byte Value')
                if i >= (rows - 1) * cols:
                    ax.set_xlabel('Record Index')
            else:
                ax.axis('off')

        fig1.tight_layout(rect=[0, 0.03, 1, 0.98])
        subplots_filename = f'{output_dir}/byte_trends_subplots_{batch_start}_to_{batch_end-1}.png'
        fig1.savefig(subplots_filename)
        plt.close(fig1)

# Execution Handling
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="Parse 0xB887 NR5G PDSCH payloads (v2 + v3).")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("output_dir", nargs="?", help="Output directory")
    ap.add_argument("--record_count_index", default=28, nargs="?")
    ap.add_argument("--record_length", default=32)
    args = ap.parse_args()

    plot_byte_trends_batched(args.input, args.output_dir, int(args.record_count_index), int(args.record_length))
