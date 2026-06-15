import pandas as pd
import matplotlib.pyplot as plt

def plot_speedtest_results(csv_filepath):
    try:
        # 1. Load the CSV data
        print(f"Loading data from {csv_filepath}...")
        df = pd.read_csv(csv_filepath)
        
        # 2. Prepare the data
        # Convert Timestamp string to actual datetime objects for proper time-scale plotting
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Sort by Timestamp just in case the directory traversal read files out of order
        df = df.sort_values(by='Timestamp')
        
        # Drop rows where data might be 'N/A' (if any parsing failed)
        df = df[pd.to_numeric(df['Download_Mbps'], errors='coerce').notnull()]
        
        # Ensure the columns are numeric
        df['Download_Mbps'] = df['Download_Mbps'].astype(float)
        df['Upload_Mbps'] = df['Upload_Mbps'].astype(float)
        df['Ping_ms'] = df['Ping_ms'].astype(float)

        # 3. Create the plots
        # Set up a figure with 3 subplots sharing the same X-axis (Time)
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 12), sharex=True)
        
        # Plot Download Speed
        ax1.plot(df['Timestamp'], df['Download_Mbps'], marker='o', color='#2ca02c', linestyle='-', linewidth=2)
        ax1.set_title('Download Speed Over Time', fontsize=14)
        ax1.set_ylabel('Speed (Mbps)', fontsize=12)
        ax1.grid(True, linestyle='--', alpha=0.7)
        
        # Plot Upload Speed
        ax2.plot(df['Timestamp'], df['Upload_Mbps'], marker='o', color='#1f77b4', linestyle='-', linewidth=2)
        ax2.set_title('Upload Speed Over Time', fontsize=14)
        ax2.set_ylabel('Speed (Mbps)', fontsize=12)
        ax2.grid(True, linestyle='--', alpha=0.7)
        
        # Plot Ping
        ax3.plot(df['Timestamp'], df['Ping_ms'], marker='o', color='#d62728', linestyle='-', linewidth=2)
        ax3.set_title('Ping / Latency Over Time', fontsize=14)
        ax3.set_ylabel('Ping (ms)', fontsize=12)
        ax3.set_xlabel('Timestamp', fontsize=12)
        ax3.grid(True, linestyle='--', alpha=0.7)
        
        # Format the X-axis for better date/time readability
        plt.xticks(rotation=45)
        
        # Adjust layout so labels don't get cut off
        plt.tight_layout()
        
        # 4. Save and show the plot
        output_filename = 'speedtest_metrics_chart.png'
        plt.savefig(output_filename, dpi=300)
        print(f"Success! Plot saved as '{output_filename}'")
        
        # Uncomment the line below if you want the window to pop up when you run it
        # plt.show() 

    except FileNotFoundError:
        print(f"Error: Could not find '{csv_filepath}'. Please run the parsing script first.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    plot_speedtest_results('aggregated_speedtest_results.csv')
