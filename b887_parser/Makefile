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
