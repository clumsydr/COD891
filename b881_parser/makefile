MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

INDEX=
PAYLOADDIRECTORY=../b887_parser/TarunPhoneLogs
DATA_DIR=../loggers/data/
RAWDIRECTORY=../loggers/data
INFILE=SpeedTest
INDEX=2
CAP_DIR=

.PHONY: all process_data process_all plot_box_data plot_mcs_retx plot_box

all:
	make process_data

# ==============================================================================
# Process all capture directories in DATA_DIR and generate plots
# Usage: make process_data [DATA_DIR=../loggers/data/]
# ==============================================================================
process_data:
	@echo "Scanning $(DATA_DIR) for capture directories containing QMDL files..."
	@DIRS=$$(find $(DATA_DIR) -type f -name "*.qmdl" ! -path "*/mdm2/*" -exec dirname {} + | sort -u); \
	for d in $$DIRS; do \
		echo "============================================================"; \
		echo "Processing Capture Directory: $$d"; \
		QMDL_FILES=$$(ls $$d/*.qmdl 2>/dev/null | sort); \
		SCAT_TXT="$$d/qmdl-to-scat.txt"; \
		PAYLOAD_TXT="$$d/payloads_b881.txt"; \
		PARSED_TXT="$$d/payloads_parsed_b881.txt"; \
		echo "[1/5] Running scat on all QMDLs in $$d..."; \
# 		scat -t qc -d $$QMDL_FILES > "$$SCAT_TXT"; \
		echo "[2/5] Extracting B881 payloads into single file..."; \
# 		python3 ../qmdl_to_codes.py "$$SCAT_TXT" "$$PAYLOAD_TXT"; \
		echo "[3/5] Parsing B881 records..."; \
		python3 $(MAKEFILE_DIR)parser.py "$$PAYLOAD_TXT" > "$$PARSED_TXT"; \
		pcap_file=$$(ls $$d/*.pcap 2>/dev/null | head -n 1); \
		echo "[4/5] Plotting MCS vs Retransmissions..."; \
# 		python3 $(MAKEFILE_DIR)b881_box_plotter.py "$$PAYLOAD_TXT" "$$d/b881_box_plot.png"; \
	done; \
	echo "============================================================"; \
	echo "Generating overall B881 box plots across all processed capture directories..."; \
	mkdir -p $(MAKEFILE_DIR)plots; \
	python3 $(MAKEFILE_DIR)b881_box_plotter.py "$(DATA_DIR)/**/payloads_b881.txt" $(MAKEFILE_DIR)plots/b881_data_box_plots.png; \
	echo "============================================================"; \
	echo "Finished processing and plotting all capture directories."

process_all: process_data

plot_box_data:
	@mkdir -p $(MAKEFILE_DIR)plots
	python3 $(MAKEFILE_DIR)b881_box_plotter.py "$(DATA_DIR)/**/payloads_b881.txt" $(MAKEFILE_DIR)plots/b881_data_box_plots.png

plot_mcs_retx:
	@mkdir -p $(MAKEFILE_DIR)plots/mcs_retx
	@for f in $$(ls $(MAKEFILE_DIR)payloads/payloads_run_*.txt 2>/dev/null); do \
		base=$$(basename $$f .txt); \
		run_name=$${base#payloads_}; \
		echo "Plotting MCS vs Retx for $$run_name..."; \
		python3 $(MAKEFILE_DIR)b881_mcs_retx_plotter.py $$f $(MAKEFILE_DIR)plots/mcs_retx/$$run_name.png; \
	done

plot_box:
	@mkdir -p $(MAKEFILE_DIR)plots/box-plots
	python3 $(MAKEFILE_DIR)b881_box_plotter.py $(MAKEFILE_DIR)payloads/payloads_lab-*.txt $(MAKEFILE_DIR)plots/box-plots/b881_box_plots.png
