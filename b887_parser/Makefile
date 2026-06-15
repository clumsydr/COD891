# DIRECTORY=AshishPhoneLogs/VideoStreaming
# DIRECTORY=TarunPhoneLogs/WebBrowsing
DIRECTORY=VerificationLogs/SpeedTest
FILE=payloads

INDEX=2
INFILE=SpeedTest
INDIRECTORY=../loggers/Logs/$(INFILE)
FINALDIRECTORY=VerificationLogs/$(INFILE)

ptr:
	python3 packet_to_record.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)/$(FILE)_records.txt 36 28

plot:
	python3 records_plotter.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)

parse_old:
	python3 b887_parser_ashish_phone.py $(DIRECTORY)/$(FILE).txt > $(DIRECTORY)/$(FILE)_parsed.txt

parse:
	python3 b887_parser_new_w_time.py $(DIRECTORY)/$(FILE).txt > $(DIRECTORY)/$(FILE)_parsed_new.txt

unchanging:
	python3 unchanging.py $(DIRECTORY)/$(FILE).txt --header=29 --record=32 --offset=28 > unchanging.txt

work:
	python3 work.py $(DIRECTORY)/control.txt > work.txt

packets:
	scat -t qc -d $(INDIRECTORY)$(INDEX)/*.qmdl > $(FINALDIRECTORY)/$(INFILE)$(INDEX).txt
	python3 qmdl-to-codes.py $(FINALDIRECTORY)/$(INFILE)$(INDEX).txt $(FINALDIRECTORY)/$(FILE)$(INDEX).txt -download=0

STAGES = 1 2 3 4
run_packets:
	@for stage in $(STAGES); do \
		make packets INDEX=$$stage; \
	done

correlation:
	python3 sequence_correlator.py $(FINALDIRECTORY)/$(FILE)$(INDEX).txt $(INDIRECTORY)$(INDEX)/*.pcap dl


CAPTURE_DIR = ../loggers/scheduled_captures
process_all:
	@echo "Scanning $(CAPTURE_DIR) for QMDL files..."
	@for file in $$(find $(CAPTURE_DIR) -type f \( -name "*.qmdl" \)); do \
		echo "=========================================="; \
		echo "Processing: $$file"; \
		DIR=$$(dirname "$$file"); \
		BASENAME=$$(basename "$$file" | sed -E 's/\.qmdl2?//'); \
		SCAT_TXT="$$DIR/$${BASENAME}_scat.txt"; \
		PAYLOAD_TXT="$$DIR/$${BASENAME}_payloads.txt"; \
		PARSED_TXT="$$DIR/$${BASENAME}_parsed_new.txt"; \
		echo "[1/3] Running scat extraction..."; \
		scat -t qc -d "$$file" > "$$SCAT_TXT"; \
		echo "[2/3] Running qmdl-to-codes payload extraction..."; \
		python3 qmdl-to-codes.py "$$SCAT_TXT" "$$PAYLOAD_TXT" -download=1; \
		echo "[3/3] Running B887 parser..."; \
		python3 b887_parser_new_w_time.py "$$PAYLOAD_TXT" > "$$PARSED_TXT"; \
	done
	@echo "=========================================="
	@echo "Finished processing all QMDL files."\

print