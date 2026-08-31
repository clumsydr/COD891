MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

INDEX=
PAYLOADDIRECTORY=../b887_parser/TarunPhoneLogs
DATA_DIR=../loggers/data/
RAWDIRECTORY=../loggers/data
INFILE=SpeedTest
INDEX=2
CAP_DIR=

.PHONY: all process_data process_all parse_capture plot_data plot_box_data plot basic_plotter decode decode_all plot_runs plot_mcs_retx plot_box plot_comparison plot_ground_comparison

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
		PARSED_TXT="$$d/payloads_parsed_new.txt"; \
		echo "[1/5] Running scat on all QMDLs in $$d..."; \
# 		scat -t qc -d $$QMDL_FILES > "$$SCAT_TXT"; \
		echo "[2/5] Extracting B881 payloads into single file..."; \
# 		python3 $(MAKEFILE_DIR)qmdl_to_codes.py "$$SCAT_TXT" "$$PAYLOAD_TXT"; \
		echo "[3/5] Parsing B881 records..."; \
# 		python3 $(MAKEFILE_DIR)parser.py "$$PAYLOAD_TXT" > "$$PARSED_TXT"; \
		pcap_file=$$(ls $$d/*.pcap 2>/dev/null | head -n 1); \
		echo "[4/5] Plotting MCS vs Retransmissions..."; \
		python3 $(MAKEFILE_DIR)b881_mcs_retx_plotter.py "$$PAYLOAD_TXT" "$$d/b881_mcs_retx.png"; \
	done; \
	echo "============================================================"; \
	echo "Generating overall B881 box plots across all processed capture directories..."; \
	mkdir -p $(MAKEFILE_DIR)plots; \
	python3 $(MAKEFILE_DIR)b881_box_plotter.py "$(DATA_DIR)/**/payloads_b881.txt" $(MAKEFILE_DIR)plots/b881_data_box_plots.png; \
	echo "============================================================"; \
	echo "Finished processing and plotting all capture directories."

process_all: process_data

# ==============================================================================
# Parse & plot all QMDL files in a single capture directory
# Usage: make parse_capture CAP_DIR=../loggers/data/Airtel/Amul_IITDelhi/20260812/capture_000_20260812_114830
# ==============================================================================
parse_capture:
	@if [ -z "$(CAP_DIR)" ]; then \
		echo "Error: Please specify CAP_DIR=<path_to_capture_directory>"; \
		echo "Example: make parse_capture CAP_DIR=../loggers/data/Airtel/Amul_IITDelhi/20260812/capture_000_20260812_114830"; \
		exit 1; \
	fi
	@echo "============================================================"
	@echo "Processing capture directory: $(CAP_DIR)"
	@QMDL_FILES=$$(ls $(CAP_DIR)/*.qmdl 2>/dev/null | sort); \
	if [ -z "$$QMDL_FILES" ]; then \
		echo "Error: No .qmdl files found in $(CAP_DIR)"; \
		exit 1; \
	fi; \
	SCAT_TXT="$(CAP_DIR)/qmdl-to-scat.txt"; \
	PAYLOAD_TXT="$(CAP_DIR)/payloads_b881.txt"; \
	PARSED_TXT="$(CAP_DIR)/payloads_parsed_new.txt"; \
	echo "[1/5] Running scat decoding across all QMDLs in capture..."; \
	scat -t qc -d $$QMDL_FILES > "$$SCAT_TXT"; \
	echo "[2/5] Extracting B881 hex payloads into single file: $$PAYLOAD_TXT..."; \
	python3 $(MAKEFILE_DIR)qmdl_to_codes.py "$$SCAT_TXT" "$$PAYLOAD_TXT"; \
	echo "[3/5] Parsing B881 records with timestamps into: $$PARSED_TXT..."; \
	python3 $(MAKEFILE_DIR)parser.py "$$PAYLOAD_TXT" > "$$PARSED_TXT"; \
	pcap_file=$$(ls $(CAP_DIR)/*.pcap 2>/dev/null | head -n 1); \
	if [ -f "$$pcap_file" ]; then \
		echo "[4/5] Plotting B881 correlation graph against PCAP: $$pcap_file..."; \
		python3 $(MAKEFILE_DIR)b881_plotter.py "$$PAYLOAD_TXT" "$$pcap_file" "$(CAP_DIR)/b881_correlation_plot.png"; \
	else \
		echo "[4/5] No .pcap file found in $(CAP_DIR), skipping PCAP correlation plot."; \
	fi; \
	echo "[5/5] Plotting MCS vs Retransmissions..."; \
	python3 $(MAKEFILE_DIR)b881_mcs_retx_plotter.py "$$PAYLOAD_TXT" "$(CAP_DIR)/b881_mcs_retx.png"; \
	echo "Done! Successfully processed and plotted $(CAP_DIR)"

# ==============================================================================
# Plot all capture directories in DATA_DIR that already have payloads_b881.txt
# Usage: make plot_data [DATA_DIR=../loggers/data]
# ==============================================================================
plot_data:
	@echo "Scanning $(DATA_DIR) for capture directories containing payloads_b881.txt..."
	@DIRS=$$(find $(DATA_DIR) -type f -name "payloads_b881.txt" -exec dirname {} + | sort -u); \
	for d in $$DIRS; do \
		echo "============================================================"; \
		echo "Plotting Capture Directory: $$d"; \
		PAYLOAD_TXT="$$d/payloads_b881.txt"; \
		pcap_file=$$(ls $$d/*.pcap 2>/dev/null | head -n 1); \
		if [ -f "$$pcap_file" ]; then \
			echo "Plotting B881 correlation graph against PCAP: $$pcap_file..."; \
			python3 $(MAKEFILE_DIR)b881_plotter.py "$$PAYLOAD_TXT" "$$pcap_file" "$$d/b881_correlation_plot.png"; \
		else \
			echo "No .pcap file found in $$d, skipping PCAP correlation plot."; \
		fi; \
		echo "Plotting MCS vs Retransmissions..."; \
		python3 $(MAKEFILE_DIR)b881_mcs_retx_plotter.py "$$PAYLOAD_TXT" "$$d/b881_mcs_retx.png"; \
	done
	@echo "============================================================"
	@$(MAKE) plot_box_data

plot_box_data:
	@mkdir -p $(MAKEFILE_DIR)plots
	python3 $(MAKEFILE_DIR)b881_box_plotter.py "$(DATA_DIR)/**/payloads_b881.txt" $(MAKEFILE_DIR)plots/b881_data_box_plots.png

plot:
	python3 $(MAKEFILE_DIR)plotter.py $(MAKEFILE_DIR)payloads/payloads_$(INFILE)$(INDEX).txt $(RAWDIRECTORY)/$(INFILE)$(INDEX)/*.pcap

basic_plotter:
	python3 $(MAKEFILE_DIR)comparison_plotter.py $(MAKEFILE_DIR)payloads/payloads_$(INFILE)$(INDEX).txt 24 40

plot_runs:
	@mkdir -p $(MAKEFILE_DIR)plots/runs
	@for f in $$(ls $(MAKEFILE_DIR)payloads/payloads_run_*.txt 2>/dev/null); do \
		base=$$(basename $$f .txt); \
		run_name=$${base#payloads_}; \
		pcap_file=$$(ls $(MAKEFILE_DIR)$(RAWDIRECTORY)/$$run_name/*.pcap 2>/dev/null | head -n 1); \
		if [ -f "$$pcap_file" ]; then \
			echo "Plotting B881 for $$run_name..."; \
			python3 $(MAKEFILE_DIR)b881_plotter.py $$f $$pcap_file $(MAKEFILE_DIR)plots/runs/$$run_name.png; \
		else \
			echo "PCAP not found for $$run_name, skipping..."; \
		fi; \
	done

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

plot_comparison:
	@mkdir -p $(MAKEFILE_DIR)plots
	python3 $(MAKEFILE_DIR)compare_lab_static_moving.py

plot_ground_comparison:
	@mkdir -p $(MAKEFILE_DIR)plots
	python3 $(MAKEFILE_DIR)compare_lab_moving_ground.py
