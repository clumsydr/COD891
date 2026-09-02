# Configurable directories and parameters
DIR ?= ../loggers/Logs
OUTPUT ?= plots/b887_mimo_pcap_combined.png
CSV ?= plots/b887_telemetry.csv
STATS ?= plots/b887_stats.json

# DIRECTORY=AshishPhoneLogs/VideoStreaming
DIRECTORY=TarunPhoneLogs/SpeedTest
# DIRECTORY=VerificationLogs/VideoStreaming
FILE=payloads_b887

INDEX=
INFILE=ExperimentalSpeedtest
INDIRECTORY=../loggers/Logs/$(INFILE)
FINALDIRECTORY=VerificationLogs/$(INFILE)
DATA_DIR=../loggers/data
CAP_DIR=


plot_box:
	python3 b887_box_plotter.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)/b887_box_plot.png

plot_box_data:
	python3 b887_box_plotter.py "$(DATA_DIR)/**/payloads_b887.txt" plots/b887_data_box_plots.png

# ==============================================================================
# B887 MIMO Layers vs PCAP Speed & Telemetry Plotting
# Recursively searches DIR and all subdirectories for paired B887 + PCAP files.
#
# Examples:
#   make plot_pcap_layer_all DIR=../loggers/data/Airtel
#   make plot_pcap_layer_all DIR=../loggers/Logs
#   make plot_pcap_layer_all DIR=/path/to/any/folder OUTPUT=plots/custom.png
#   make plot_pcap_layer_dom DIR=../loggers/data
#   make plot_pcap_layer_per_run DIR=../loggers/data/Jio
# ==============================================================================
plot_pcap_layer_all:
	@mkdir -p plots
	python3 b887_pcap_layer_boxplotter.py $(DIR) --auto-align -o $(OUTPUT) --csv $(CSV) --stats-json $(STATS)

plot_pcap_layer_dom:
	@mkdir -p plots
	python3 b887_pcap_layer_boxplotter.py $(DIR) --auto-align --mode dominant-bin --filter-idle -o $(OUTPUT) --csv $(CSV) --stats-json $(STATS)

plot_pcap_layer_per_run:
	@mkdir -p plots
	python3 b887_pcap_layer_boxplotter.py $(DIR) --auto-align --per-run -o $(OUTPUT) --csv $(CSV) --stats-json $(STATS)

# Single run target on $(INDIRECTORY)
plot_pcap_layer:
	@mkdir -p $(FINALDIRECTORY)
	python3 b887_pcap_layer_boxplotter.py $(INDIRECTORY) --auto-align -o $(FINALDIRECTORY)/layer_pcap_boxplot.png

parse_old:
	python3 b887_parser_ashish_phone.py $(DIRECTORY)/$(FILE).txt > $(DIRECTORY)/$(FILE)_parsed.txt

parse:
	python3 b887_parser_new_w_time.py ../loggers/lajja_logs/run_025_20260626_200446/diag_log_20260626_2004521782484492224_payloads.txt > ../loggers/lajja_logs/run_025_20260626_200446/parsed.txt

packets:
	scat -t qc -d $(INDIRECTORY)$(INDEX)/*.qmdl > $(FINALDIRECTORY)/$(INFILE)$(INDEX).txt
	python3 ../qmdl_to_codes.py $(FINALDIRECTORY)/$(INFILE)$(INDEX).txt $(FINALDIRECTORY)/$(FILE)$(INDEX).txt

D=TarunPhoneLogs/WebBrowsing
F=qmdl-to-scat.txt
do:
	scat -t qc -d $(D)/*.qmdl > $(D)/$(F)
	python3 ../qmdl_to_codes.py $(D)/$(F) $(D)/payloads.txt

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
		python3 ../qmdl_to_codes.py "$$SCAT_TXT" "$$PAYLOAD_TXT"; \
		echo "[3/3] Parsing B887 records..."; \
		python3 b887_parser_new_w_time.py "$$PAYLOAD_TXT" > "$$PARSED_TXT"; \
	done
	@echo "============================================================"
	@echo "Finished processing all capture directories."

process_all: process_data

