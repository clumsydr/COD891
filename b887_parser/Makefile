# DIRECTORY=AshishPhoneLogs/NoActivity
# FILE=payloads

DIRECTORY=TarunPhoneLogs/WebBrowsing
FILE=payloads

ptr:
	python3 packet_to_record.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)/$(FILE)_records.txt 28 32

plot:
	python3 records_plotter.py $(DIRECTORY)/$(FILE).txt $(DIRECTORY)

parse_old:
	python3 b887_parser_ashish_phone.py $(DIRECTORY)/$(FILE).txt > $(DIRECTORY)/$(FILE)_parsed.txt

parse:
	python3 b887_parser_new.py $(DIRECTORY)/$(FILE).txt > $(DIRECTORY)/$(FILE)_parsed.txt

find_scs:
	python3 unchanging.py $(DIRECTORY)/$(FILE).txt > unchanging.txt