# DIRECTORY=AshishPhoneLogs/VideoStreaming
DIRECTORY=TarunPhoneLogs/VideoStreaming
# DIRECTORY=VerificationLogs/VideoStreaming
FILE=payloads_b887

INDEX=
INFILE=ExperimentalSpeedtest
INDIRECTORY=../loggers/Logs/$(INFILE)
FINALDIRECTORY=VerificationLogs/$(INFILE)
DATA_DIR=../loggers/data
CAP_DIR=

.PHONY: ptr plot plot_box plot_box_data parse_old parse to_code scan_b567 scan_b567_nonzero unchanging work packets do run_packets correlation parse_capture process_all process_data

ptr:
	python3 packet_to_record.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)/$(FILE)_records.txt 36 28

plot:
	python3 records_plotter.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)

plot_box:
	python3 b887_box_plotter.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)/b887_box_plot.png

plot_box_data:
	python3 b887_box_plotter.py "$(DATA_DIR)/**/payloads_b887.txt" plots/b887_data_box_plots.png

parse_old:
	python3 b887_parser_ashish_phone.py $(DIRECTORY)/$(FILE).txt > $(DIRECTORY)/$(FILE)_parsed.txt

parse:
	python3 b887_parser_new_w_time.py ../loggers/lajja_logs/run_025_20260626_200446/diag_log_20260626_2004521782484492224_payloads.txt > ../loggers/lajja_logs/run_025_20260626_200446/parsed.txt

to_code:
	python3 qmdl_to_codes.py $(DIRECTORY)/qmdl-to-scat.txt $(DIRECTORY)/$(FILE).txt

scan_b567:
	python3 scan_b567.py $(DIRECTORY)/$(FILE).txt

scan_b567_nonzero:
	python3 scan_b567.py $(DIRECTORY)/$(FILE).txt --nonzero-only

unchanging:
	python3 unchanging.py $(DIRECTORY)/$(FILE).txt --header=29 --record=32 --offset=28 > unchanging.txt

work:
	python3 work.py $(DIRECTORY)/control.txt > work.txt

packets:
	scat -t qc -d $(INDIRECTORY)$(INDEX)/*.qmdl > $(FINALDIRECTORY)/$(INFILE)$(INDEX).txt
	python3 qmdl_to_codes.py $(FINALDIRECTORY)/$(INFILE)$(INDEX).txt $(FINALDIRECTORY)/$(FILE)$(INDEX).txt

D=TarunPhoneLogs/WebBrowsing
F=qmdl-to-scat.txt
do:
	scat -t qc -d $(D)/*.qmdl > $(D)/$(F)
	python3 qmdl_to_codes.py $(D)/$(F) $(D)/payloads.txt

STAGES = 1 2 3 4
run_packets:
	@for stage in $(STAGES); do \
		make packets INDEX=$$stage; \
	done

correlation:
	python3 sequence_correlator.py $(FINALDIRECTORY)/$(FILE)$(INDEX).txt $(INDIRECTORY)$(INDEX)/*.pcap dl


# ==============================================================================
# Parse all QMDL files in a single capture directory into a single payload file
# Usage: make parse_capture CAP_DIR=../loggers/data/Airtel/Amul_IITDelhi/20260812/capture_000_20260812_113954
# ==============================================================================
parse_capture:
	@if [ -z "$(CAP_DIR)" ]; then \
		echo "Error: Please specify CAP_DIR=<path_to_capture_directory>"; \
		echo "Example: make parse_capture CAP_DIR=../loggers/data/Airtel/Amul_IITDelhi/20260812/capture_000_20260812_113954"; \
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
	PAYLOAD_TXT="$(CAP_DIR)/payloads_b887.txt"; \
	PARSED_TXT="$(CAP_DIR)/payloads_parsed_new.txt"; \
	echo "[1/3] Running scat decoding across all QMDLs in capture..."; \
	scat -t qc -d $$QMDL_FILES > "$$SCAT_TXT"; \
	echo "[2/3] Extracting B887 hex payloads into single file: $$PAYLOAD_TXT..."; \
	python3 qmdl_to_codes.py "$$SCAT_TXT" "$$PAYLOAD_TXT"; \
	echo "[3/3] Parsing B887 records with timestamps into: $$PARSED_TXT..."; \
	python3 b887_parser_new_w_time.py "$$PAYLOAD_TXT" > "$$PARSED_TXT"; \
	echo "Done! Successfully generated $$PAYLOAD_TXT"


# ==============================================================================
# Process all capture directories in DATA_DIR (combining all QMDLs per capture)
# Usage: make process_data DATA_DIR=../loggers/data
# ==============================================================================
process_data:
	@echo "Scanning $(DATA_DIR) for capture directories containing QMDL files..."
	@DIRS=$$(find $(DATA_DIR) -type f -name "*.qmdl" ! -path "*/mdm2/*" -exec dirname {} + | sort -u); \
	for d in $$DIRS; do \
		echo "============================================================"; \
		echo "Processing Capture Directory: $$d"; \
		QMDL_FILES=$$(ls $$d/*.qmdl 2>/dev/null | sort); \
		SCAT_TXT="$$d/qmdl-to-scat.txt"; \
		PAYLOAD_TXT="$$d/payloads_b887.txt"; \
		PARSED_TXT="$$d/payloads_parsed_new.txt"; \
		echo "[1/3] Running scat on all QMDLs in $$d..."; \
		scat -t qc -d $$QMDL_FILES > "$$SCAT_TXT"; \
		echo "[2/3] Extracting B887 payloads into single file..."; \
		python3 qmdl_to_codes.py "$$SCAT_TXT" "$$PAYLOAD_TXT"; \
		echo "[3/3] Parsing B887 records..."; \
		python3 b887_parser_new_w_time.py "$$PAYLOAD_TXT" > "$$PARSED_TXT"; \
	done
	@echo "============================================================"
	@echo "Finished processing all capture directories."

process_all: process_data
