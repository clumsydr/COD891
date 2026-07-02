INDIRECTORY = ../b887_parser/VerificationLogs/VideoStreaming/
INPUT = payloads_b883_1.txt

all:
	make parse

parse:
	python basic_parser.py $(INDIRECTORY)/$(INPUT) > parser_output/parsed_$(INPUT)

correlation:
	python3 correlator.py payloads_speedtest_both.txt ../loggers/Logs/ExperimentalSpeedtest/*.pcap 192.0.0.2
