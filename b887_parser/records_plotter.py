import matplotlib.pyplot as plt
import numpy as np
import math, argparse

def plot_byte_trends(filepath, record_count_index=28, record_length=32):
    """
    Extracts records and plots the byte trends using subplots and a heatmap.
    
    Args:
        filepath (str): Path to the input text file.
        record_count_index (int): 0-based index of the byte indicating the number of records.
        record_length (int): The number of bytes in each record.
    """
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
        print("No valid records were extracted. Cannot generate plots.")
        return

    data = np.array(records)

    # --- 2. Generate Subplots (Line Charts) ---
    # Dynamically calculate rows needed for 4 columns based on record_length
    cols = 4
    rows = math.ceil(record_length / cols)
    
    fig1, axes = plt.subplots(rows, cols, figsize=(20, 3 * rows), sharex=True)
    fig1.suptitle(f'Value of Each Byte (0-{record_length-1}) Across Records', fontsize=20)
    
    # Flatten the axes array to iterate through it easily
    axes_flat = axes.flatten() if rows * cols > 1 else [axes]

    for i, ax in enumerate(axes_flat):
        if i < data.shape[1]:
            ax.plot(data[:, i], marker='o', markersize=3, linestyle='-', linewidth=1)
            ax.set_title(f'Byte {i}', fontsize=12)
            ax.grid(True, alpha=0.5)
            
            # Add y-labels only on the leftmost column charts
            if i % cols == 0:
                ax.set_ylabel('Byte Value')
            # Add x-labels only on the bottom row charts
            if i >= (rows - 1) * cols:
                ax.set_xlabel('Record Index')
        else:
            # Hide extra empty subplots if record_length doesn't divide evenly by 4
            ax.axis('off')

    fig1.tight_layout(rect=[0, 0.03, 1, 0.98])
    fig1.savefig('byte_trends_subplots.png')

    # --- 3. Generate Heatmap ---
    # Dynamically scale the height of the heatmap if there are many bytes
    heatmap_height = max(8, record_length * 0.25)
    fig2, ax2 = plt.subplots(figsize=(15, heatmap_height))
    
    c = ax2.imshow(data.T, aspect='auto', cmap='viridis', interpolation='none', origin='upper')
    fig2.colorbar(c, ax=ax2, label='Byte Value (0-255)')
    
    ax2.set_title('Heatmap of All Bytes Across Records')
    ax2.set_xlabel('Record Index')
    ax2.set_ylabel(f'Byte Index (0-{record_length-1})')
    
    # Only label every y-tick if we aren't plotting a massive record length
    if record_length <= 64:
        ax2.set_yticks(range(record_length))
        
    fig2.tight_layout()
    fig2.savefig('byte_trends_heatmap.png')

    print(f"Success! Extracted {len(records)} records (Length: {record_length}). Generated adaptable plots.")

# Execution Handling
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="Parse 0xB887 NR5G PDSCH payloads (v2 + v3).")
    ap.add_argument("input", nargs="?", help="Hex text file (stdin if omitted)")
    ap.add_argument("output", nargs="?", help="Hex text file (stdout if omitted)")
    ap.add_argument("record_count_index", default=28)
    ap.add_argument("record_length", default=32)
    args = ap.parse_args()

    plot_byte_trends(args.input, int(args.record_count_index), int(args.record_length))
