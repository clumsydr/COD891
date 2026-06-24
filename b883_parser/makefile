INDIRECTORY = ../b887_parser/VerificationLogs/VideoStreaming/
INPUT = payloads_b883_1.txt

all:
	make parse

parse:
	python basic_parser.py $(INDIRECTORY)/$(INPUT) > parser_output/parsed_$(INPUT)
