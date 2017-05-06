TDIR=$(shell uname)-$(shell uname -m)

all:
ifndef TRAVIS
	@[ -d "$(TDIR)" ] && ( cd .. && sh run_tests.sh t.archos/$(TDIR) ) || true
endif
	@echo "Debug tests doesn't work in TRAVIS yet"
