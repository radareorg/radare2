all: r2r-tests unit_tests

arm.v35:
	${RUNTEST} db/extras/asm/arm.v35_64

bins:
	git clone --depth 1 https://github.com/radareorg/radare2-testbins bins

fuzz/targets:
	git clone --depth 1 https://github.com/radareorg/radare2-fuzztargets fuzz/targets

RUNTEST=r2r -L -o results.json

r2r-tests: bins
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

yara: bins
	${RUNTEST} db/extras/cmd/yara

clean:
	rm -rf tmp

symstall:

install:

uninstall:

unit unit_tests: bins
	$(MAKE) -C unit
	$(MAKE) -C unit run

.PHONY: all clean unit install uninstall r2r-tests fuzz-tests keystone swf dwarf yara
