REPORT ?= /tmp/diagnostic-report
# on Bullseye, `make PYLINT=pylint`
PYLINT ?= pylint3
all: pylint run
run: decode.py $(REPORT)
	./$+
pylint: decode.lint
%.lint: %.py
	$(PYLINT) $<
