#!/usr/bin/env python3
"""
Convert G-NetTrack Pro .txt log files (tab-separated) to .csv files.
Usage: python3 convert_gnettrack_to_csv.py <gnettrack_logs_dir>
"""

import csv
import sys
import os


def convert_txt_to_csv(txt_path: str) -> None:
    csv_path = txt_path.replace(".txt", ".csv")

    with open(txt_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Skip files that have only a header and no data rows
    if len(lines) < 2:
        print(f"  [skip] {os.path.basename(txt_path)} — no data rows")
        return

    with open(txt_path, "r", encoding="utf-8", newline="") as infile, \
         open(csv_path, "w", encoding="utf-8", newline="") as outfile:

        reader = csv.reader(infile, delimiter="\t")
        writer = csv.writer(outfile, delimiter=",", quoting=csv.QUOTE_MINIMAL)

        for row in reader:
            writer.writerow(row)

    print(f"  [ok]   {os.path.basename(txt_path)} -> {os.path.basename(csv_path)}")


def process_directory(log_dir: str) -> None:
    if not os.path.isdir(log_dir):
        print(f"Error: directory not found: {log_dir}")
        sys.exit(1)

    for root, _, files in os.walk(log_dir):
        txt_files = [f for f in files if f.endswith(".txt")]
        if not txt_files:
            continue
        print(f"\n{root}")
        for fname in sorted(txt_files):
            convert_txt_to_csv(os.path.join(root, fname))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 convert_gnettrack_to_csv.py <gnettrack_logs_dir>")
        sys.exit(1)

    process_directory(sys.argv[1])
    print("\nDone.")
