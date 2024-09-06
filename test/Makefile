-include ../config-user.mk
RUNTEST=r2r -L -o results.json

all: r2r-tests

arm.v35:
	${RUNTEST} db/extras/asm/arm.v35_64

bins:
	git clone --depth 1 https://github.com/radareorg/radare2-testbins bins

evm:
	${RUNTEST} db/extras/asm/evm

fuzz/targets:
	git clone --depth 1 https://github.com/radareorg/radare2-fuzztargets fuzz/targets

r2r-tests: bins
	$(MAKE) unit-tests
	${RUNTEST}

fuzz-tests: bins
	r2r -LF bins/fuzzed @fuzz

keystone: bins
	${RUNTEST} db/extras/asm/x86.ks_*

swf: bins
	${RUNTEST} db/extras/cmd/swf

m68k-extras: bins
	${RUNTEST} db/extras/asm/m68k

mc6809: bins
	${RUNTEST} db/extras/asm/mc6809

microblaze: bins
	${RUNTEST} db/extras/asm/microblaze.gnu

udis86: bins
	${RUNTEST} db/extras/asm/x86.udis_*

olly-extras: bins
	${RUNTEST} db/extras/asm/x86.olly

dwarf: bins
	${RUNTEST} db/extras/asm/dwarf

vc4: bins
	${RUNTEST} db/extras/asm/vc4

clean:
	$(MAKE) -C unit clean
	rm -rf tmp

rc:
	echo q | r2 -c '?V' -
	echo q12 | r2 -c '?V' - ; if [ $$? = 12 ]; then echo "Test q12" OK ; exit 0 ; else exit 1 ; fi
	echo q2 | r2 - ; if [ $$? = 2 ]; then echo "Test - q2 OK" ; exit 0 ; else exit 1 ; fi
	echo q2 | r2 -cq - ; if [ $$? = 2 ]; then echo "Test -cq q2 OK" ; exit 0 ; else exit 1 ; fi
	echo q | r2 /bin/ls # bins/fuzzed/pe12
	r2 -qcq2 - ; if [ $$? = 2 ]; then echo "Test q2 OK" ; exit 0 ; else exit 1 ; fi
	r2 -qcq -
	r2 -qqcq -
	echo q2 | r2 -qqcq - # input is ignored

symstall:

install:

uninstall:

unit unit-tests: bins
	PATH="$(BINDIR):$(PATH)" $(MAKE) rc
	PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig \
	LD_LIBRARY_PATH=$(PREFIX)/lib \
	PATH="$(BINDIR):$(PATH)" \
		$(MAKE) -C unit run

.PHONY: all clean unit install uninstall r2r-tests fuzz-tests keystone swf dwarf yara unit-tests
