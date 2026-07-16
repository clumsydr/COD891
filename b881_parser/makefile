MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

INDEX=
PAYLOADDIRECTORY=../b887_parser/TarunPhoneLogs
RAWDIRECTORY=../loggers/scheduled_captures/
INFILE=SpeedTest
INDEX=2

.PHONY: plot basic_plotter decode decode_all plot_runs plot_mcs_retx

all:
	make basic_plotter

decode:
	scat -t qc -d $(RAWDIRECTORY)/$(INFILE)$(INDEX)/*.qmdl > $(RAWDIRECTORY)/$(INFILE)$(INDEX)/qmdl-to-scat.txt
	python3 $(MAKEFILE_DIR)qmdl_to_codes.py $(RAWDIRECTORY)/$(INFILE)$(INDEX)/qmdl-to-scat.txt $(MAKEFILE_DIR)payloads/payloads_$(INFILE)$(INDEX).txt

decode_all:
	@for dir in $(wildcard $(RAWDIRECTORY)run*); do \
		if [ -d "$$dir" ]; then \
			echo "Entering $$dir and running decode..."; \
			$(MAKE) -C "$$dir" -f $(MAKEFILE_DIR)makefile decode RAWDIRECTORY=.. INFILE=$$(basename "$$dir") INDEX=; \
		fi; \
	done

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
