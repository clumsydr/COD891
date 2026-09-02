DATA_DIR=../loggers/Logs

all:
	make process_data

process_data:
	@echo "Scanning $(DATA_DIR) for capture directories containing QMDL files..."
	@DIRS=$$(find $(DATA_DIR) -type f -name "*.qmdl" ! -path "*/mdm2/*" -exec dirname {} + | sort -u); \
	for d in $$DIRS; do \
		echo "============================================================"; \
		echo "Processing Capture Directory: $$d"; \
		QMDL_FILES=$$(ls $$d/*.qmdl 2>/dev/null | sort); \
		SCAT_TXT="$$d/qmdl-to-scat.txt"; \
		PAYLOAD_TXT="$$d/payloads_b883.txt"; \
		PARSED_TXT="$$d/payloads_parsed_b883.txt"; \
		echo "[1/5] Running scat on all QMDLs in $$d..."; \
# 		scat -t qc -d $$QMDL_FILES > "$$SCAT_TXT"; \
		echo "[2/5] Extracting b883 payloads into single file..."; \
		python3 ../qmdl_to_codes.py "$$SCAT_TXT" "$$PAYLOAD_TXT" --code=0xb883; \
		echo "[3/5] Parsing B883 records..."; \
		python3 basic_parser.py "$$PAYLOAD_TXT" > "$$PARSED_TXT"; \
	done; \
	echo "Finished processing all capture directories."
