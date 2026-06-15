import os
import glob
import pandas as pd
import matplotlib.pyplot as plt
import xml.etree.ElementTree as ET
from datetime import datetime

def parse_gnettrack_kml(filepath):
    """Parses a G-NetTrack KML file and extracts all metrics from ExtendedData."""
    print(f"Parsing {filepath}...")
    data = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        for placemark in root.findall('.//{*}Placemark'):
            row_data = {}
            for data_node in placemark.findall('.//{*}Data'):
                name_attr = data_node.get('name')
                value_node = data_node.find('{*}value')
                if value_node is not None and value_node.text is not None:
                    row_data[name_attr] = value_node.text
            
            time_str = row_data.get('TIME')
            snr_str = row_data.get('SNR')
            dl_str = row_data.get('DL_BITRATE')
            ul_str = row_data.get('UL_BITRATE')
            
            if time_str and snr_str and dl_str and ul_str:
                try:
                    timestamp = datetime.strptime(time_str, "%Y.%m.%d_%H.%M.%S")
                    snr = float(snr_str)
                    dl_kbps = float(dl_str.lower().replace('kbps', '').strip())
                    ul_kbps = float(ul_str.lower().replace('kbps', '').strip())
                    
                    data.append({
                        'Timestamp': timestamp,
                        'SNR': snr,
                        'DL_Mbps': dl_kbps / 1000.0,
                        'UL_Mbps': ul_kbps / 1000.0
                    })
                except ValueError:
                    continue
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        
    return pd.DataFrame(data)

def extract_run_name(filepath):
    """Extracts the 'run_XXX' folder name from the path to use in the legend/CSV."""
    parts = os.path.normpath(filepath).split(os.sep)
    for part in parts:
        if part.startswith("run_"):
            return part
    return os.path.basename(os.path.dirname(filepath))

def main():
    root_dir = './scheduled_captures'
    
    if not os.path.exists(root_dir):
        root_dir = '.'
        print(f"Directory 'scheduled_captures' not found. Searching in {os.getcwd()}")

    kml_files = glob.glob(os.path.join(root_dir, '**', '*_snr.kml'), recursive=True)

    if not kml_files:
        print("No '_snr.kml' files found. Ensure you are running this in the correct directory.")
        return

    # Dictionary to hold the dataframes, keyed by the run name
    run_data = {}
    all_data_for_csv = []
    
    # 1. Parse and Normalize the Data
    for f in kml_files:
        df = parse_gnettrack_kml(f)
        if not df.empty:
            run_name = extract_run_name(f)
            
            # Sort chronologically, calculate elapsed seconds
            df = df.sort_values(by='Timestamp').reset_index(drop=True)
            df['Elapsed_Seconds'] = (df['Timestamp'] - df['Timestamp'].min()).dt.total_seconds()
            
            run_data[run_name] = df
            
            # Prepare data for the CSV export by adding the Run identifier
            df_csv = df.copy()
            # Insert the Run_Name as the very first column for easy reading
            df_csv.insert(0, 'Run_Name', run_name) 
            all_data_for_csv.append(df_csv)

    if not run_data:
        print("Failed to extract valid data from the KML files.")
        return

    # 2. Save the compiled data to CSV
    combined_csv_df = pd.concat(all_data_for_csv, ignore_index=True)
    csv_filename = 'overlapping_kml_metrics.csv'
    combined_csv_df.to_csv(csv_filename, index=False)
    print(f"\n--- Data Extraction Complete ---")
    print(f"Saved extracted data to: '{csv_filename}'")

    # 3. Plot the data
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(14, 12), sharex=True)

    for run_name, df in run_data.items():
        ax1.plot(df['Elapsed_Seconds'], df['SNR'], label=run_name, marker='.', markersize=4, linewidth=1.5, alpha=0.7)
        ax2.plot(df['Elapsed_Seconds'], df['DL_Mbps'], label=run_name, marker='.', markersize=4, linewidth=1.5, alpha=0.7)
        ax3.plot(df['Elapsed_Seconds'], df['UL_Mbps'], label=run_name, marker='.', markersize=4, linewidth=1.5, alpha=0.7)

    # Configure SNR Plot
    ax1.set_title('Signal-to-Noise Ratio (SNR) Comparison', fontsize=14)
    ax1.set_ylabel('SNR (dB)', fontsize=12)
    ax1.grid(True, linestyle='--', alpha=0.6)
    
    # Configure DL Plot
    ax2.set_title('Downlink Bitrate Comparison', fontsize=14)
    ax2.set_ylabel('Bitrate (Mbps)', fontsize=12)
    ax2.grid(True, linestyle='--', alpha=0.6)
    
    # Configure UL Plot
    ax3.set_title('Uplink Bitrate Comparison', fontsize=14)
    ax3.set_ylabel('Bitrate (Mbps)', fontsize=12)
    ax3.set_xlabel('Elapsed Time (Seconds)', fontsize=12)
    ax3.grid(True, linestyle='--', alpha=0.6)

    # Add Legend
    ax1.legend(loc='upper left', bbox_to_anchor=(1.02, 1), title="Capture Runs", fontsize=9)

    plt.tight_layout()
    
    output_filename = 'overlapping_kml_metrics_plot.png'
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"Saved chart to: '{output_filename}'\n")

if __name__ == "__main__":
    main()
