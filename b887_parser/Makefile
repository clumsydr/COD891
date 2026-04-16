DIRECTORY=AshishPhoneLogs/VideoStreaming
FILE=payloads

# DIRECTORY=TarunPhoneLogs/Output
# FILE=output_ds

ptr:
	python3 packet_to_record.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)/$(FILE)_records.txt 36 28

plot:
	python3 records_plotter.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY) 36 28

parse_old:
	python3 b887_parser_ashish_phone.py $(DIRECTORY)/$(FILE).txt > $(DIRECTORY)/$(FILE)_parsed.txt

parse:
	python3 b887_parser_new.py $(DIRECTORY)/$(FILE).txt > $(DIRECTORY)/$(FILE)_parsed_new.txt

find_scs:
	python3 unchanging.py $(DIRECTORY)/$(FILE).txt --header=37 --record=28 --offset=36 > unchanging.txt

work:
	python3 work.py $(DIRECTORY)/control.txt > work.txt
