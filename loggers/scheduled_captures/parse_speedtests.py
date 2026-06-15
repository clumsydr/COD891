import os
import csv
import re

def parse_speedtest_log(filepath):
    """Parses a single speedtest_results.txt file and returns a dictionary of metrics."""
    data = {
        'Directory': os.path.basename(os.path.dirname(filepath)),
        'Timestamp': 'N/A',
        'Ping_ms': 'N/A',
        'Download_Mbps': 'N/A',
        'Upload_Mbps': 'N/A',
        'Server': 'N/A',
        'ISP': 'N/A',
        'Packet_Loss_Percent': 'N/A',
        'Result_URL': 'N/A'
    }

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

            # Using Regex to extract exact values based on the provided text format
            timestamp_match = re.search(r'Timestamp\s*:\s*(.+)', content)
            ping_match = re.search(r'Ping\s*:\s*([\d.]+)\s*ms', content)
            dl_match = re.search(r'Download\s*:\s*([\d.]+)\s*Mbps', content)
            ul_match = re.search(r'Upload\s*:\s*([\d.]+)\s*Mbps', content)
            server_match = re.search(r'Server:\s*(.+)', content)
            isp_match = re.search(r'ISP:\s*(.+)', content)
            loss_match = re.search(r'Packet Loss:\s*([\d.]+)%', content)
            url_match = re.search(r'Result URL:\s*(.+)', content)

            if timestamp_match: data['Timestamp'] = timestamp_match.group(1).strip()
            if ping_match: data['Ping_ms'] = ping_match.group(1).strip()
            if dl_match: data['Download_Mbps'] = dl_match.group(1).strip()
            if ul_match: data['Upload_Mbps'] = ul_match.group(1).strip()
            if server_match: data['Server'] = server_match.group(1).strip()
            if isp_match: data['ISP'] = isp_match.group(1).strip()
            if loss_match: data['Packet_Loss_Percent'] = loss_match.group(1).strip()
            if url_match: data['Result_URL'] = url_match.group(1).strip()

    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        
    return data

def main():
    # Define the root directory to search (defaults to the current working directory)
    root_dir = './scheduled_captures' 
    output_csv = 'aggregated_speedtest_results.csv'
    
    # Check if the directory exists, otherwise fallback to current directory
    if not os.path.exists(root_dir):
        root_dir = '.'
        print(f"Directory 'scheduled_captures' not found. Searching in current directory: {os.getcwd()}")

    results = []

    # Walk through the directory tree to find speedtest_results.txt files
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename == 'speedtest_results.txt':
                filepath = os.path.join(dirpath, filename)
                print(f"Parsing: {filepath}")
                parsed_data = parse_speedtest_log(filepath)
                results.append(parsed_data)

    if not results:
        print("No speedtest_results.txt files found.")
        return

    # Write the collected data to a CSV file
    headers = list(results[0].keys())
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nSuccess! Extracted {len(results)} records and saved to {output_csv}")

if __name__ == "__main__":
    main()