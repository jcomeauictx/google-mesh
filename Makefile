REPORT ?= /tmp/diagnostic-report
all: decode.py $(REPORT)
	./$+
