PYTHON = python3
PARSER = b888_parser.py
PLOTTER = byte_plotter.py

# Default log file for testing
SAMPLE_FILE = ../loggers/lajja_logs/run_025_20260626_200446/diag_log_20260626_2004521782484492224_payloads_b888.txt
SAMPLE_OUT  = sample_output.csv

# Default parameters for byte plotting
FILE ?= $(SAMPLE_FILE)
BYTE ?= 45
SIZE ?= 4
TYPE ?= uint
ENDIAN ?= little
XAXIS ?= index
LIMIT ?=
OUT ?=
OFFSETS ?=

.PHONY: test parse csv batch plot plotter byte_plotter plot-test plot-multi clean help

help:
	@echo "B888 NR5G MAC PDSCH Stats Parser & Byte Plotter"
	@echo "================================================"
	@echo "Usage:"
	@echo "  make plot [FILE=<path>] [BYTE=<offset>] [SIZE=<size>] [OUT=<file.png>] [LIMIT=<n>] [XAXIS=time|index]"
	@echo "  make plotter                                    : Alias for make plot"
	@echo "  make plot-test                                  : Run plotter on sample run_025 log (byte 45, sz 4)"
	@echo "  make plot-multi [FILE=<path>] [OFFSETS=<specs>] : Plot multiple fields side-by-side"
	@echo "  make parse FILE=<path_to_payloads_b888.txt>     : Print telemetry and CA summary"
	@echo "  make csv FILE=<path> OUT=<output.csv>           : Export decoded stats to CSV"
	@echo "  make test                                       : Run parser on sample run_025 log"
	@echo "  make batch-lajja                                : Batch parse all lajja_logs to CSV"

plot:
	@cmd="$(PYTHON) $(PLOTTER) $(FILE)"; \
	if [ -n "$(OFFSETS)" ]; then \
		cmd="$$cmd --offsets \"$(OFFSETS)\""; \
	else \
		cmd="$$cmd $(BYTE) $(SIZE) --type $(TYPE) --endian $(ENDIAN)"; \
	fi; \
	if [ -n "$(OUT)" ]; then cmd="$$cmd --output $(OUT)"; fi; \
	if [ -n "$(LIMIT)" ]; then cmd="$$cmd --limit $(LIMIT)"; fi; \
	if [ -n "$(XAXIS)" ]; then cmd="$$cmd --x-axis $(XAXIS)"; fi; \
	echo "$$cmd"; \
	eval $$cmd

plotter: plot
byte_plotter: plot

plot-test:
	$(PYTHON) $(PLOTTER) $(SAMPLE_FILE) 41 4

plot-multi:
	@if [ -n "$(OFFSETS)" ]; then \
		$(PYTHON) $(PLOTTER) $(FILE) --offsets "$(OFFSETS)"; \
	elif [ "$(FILE)" = "$(SAMPLE_FILE)" ]; then \
		$(PYTHON) $(PLOTTER) $(SAMPLE_FILE) --offsets "45:4:Slots Elapsed,49:4:PDSCH Decodes,53:4:CRC Pass TBs,73:8:CRC Pass Bytes" --limit 200; \
	else \
		$(PYTHON) $(PLOTTER) $(FILE) --offsets "45:4:Slots Elapsed,49:4:PDSCH Decodes,53:4:CRC Pass TBs,73:8:CRC Pass Bytes"; \
	fi


test:
	$(PYTHON) $(PARSER) $(SAMPLE_FILE) --limit 15

parse:
	@if [ -z "$(FILE)" ]; then echo "Error: Specify FILE=<path>"; exit 1; fi
	$(PYTHON) $(PARSER) $(FILE)

csv:
	@if [ -z "$(FILE)" ] || [ -z "$(OUT)" ]; then echo "Error: Specify FILE=<path> OUT=<output.csv>"; exit 1; fi
	$(PYTHON) $(PARSER) $(FILE) --csv $(OUT)

batch-lajja:
	@echo "Processing all 0xB888 payloads in lajja_logs..."
	@find ../loggers/lajja_logs -type f -name "*_payloads_b888.txt" | while read -r f; do \
		out="$${f%_payloads_b888.txt}_b888_parsed.csv"; \
		echo "Parsing $$f -> $$out"; \
		$(PYTHON) $(PARSER) "$$f" --csv "$$out"; \
	done
	@echo "Done."

clean:
	rm -f *.csv *.png

