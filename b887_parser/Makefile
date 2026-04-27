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
