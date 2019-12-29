DESTDIR?=/
PREFIX?=/usr/local
BINDIR=$(DESTDIR)/$(PREFIX)/bin
CWD=$(shell pwd)

TDIRS=$(shell ls -d t*| grep -v tmp) bins
LIBDIR=$(DESTDIR)/$(PREFIX)/lib

-include config.mk

all: js-tests unit_tests src/r2r

src/r2r:
	$(MAKE) -C src

bins:
	git clone --depth 1 https://github.com/radareorg/radare2-testbins bins

fuzz/targets:
	git clone --depth 1 https://github.com/radareorg/radare2-fuzztargets fuzz/targets

R2R=$(shell cd new ; npm bin)/r2r

RUNTEST=cd new && npm install ; $(R2R)

js-tests: bins
	${RUNTEST}

keystone: bins
	${RUNTEST} db/extras/asm/x86.ks_

swf: bins
	${RUNTEST} db/extras/asm/swf

m68k-extras: bins
	${RUNTEST} db/extras/asm/m68k

mc6809: bins
	${RUNTEST} db/extras/asm/x86.udis

microblaze: bins
	${RUNTEST} db/extras/asm/microblaze.gnu

udis86: bins
	${RUNTEST} db/extras/asm/mc6809

olly-extras: bins
	${RUNTEST} db/extras/asm/x86.olly

dwarf: bins
	${RUNTEST} db/extras/asm/dwarf

broken:
	grep BROKEN=1 t -r -l

clean:
	rm -rf tmp

symstall:
	mkdir -p $(BINDIR)
	ln -fs $(CWD)/r2r $(BINDIR)/r2r

install:
	mkdir -p $(BINDIR)
	sed -e 's,@R2RDIR@,$(LIBDIR)/radare2-regressions,g' < $(CWD)/r2r > $(BINDIR)/r2r
	chmod +x $(BINDIR)/r2r
	mkdir -p $(LIBDIR)/radare2-regressions
	cp -rf $(TDIRS) $(LIBDIR)/radare2-regressions
	cp -rf *.sh $(LIBDIR)/radare2-regressions

uninstall:
	rm -f $(BINDIR)/r2r
	rm -f $(BINDIR)/r2-v
	rm -rf $(LIBDIR)/radare2-regressions

unit_tests: bins
	@make -C ./unit all
	@./run_unit.sh

tested: bins
	@grep -re FILE= t*  | cut -d : -f 2- | sed -e 's/^.*bins\///g' |sort -u | grep -v FILE

untested: bins
	@${MAKE} -s tested > .a
	@${MAKE} -s allbins > .b
	@diff -ru .a .b | grep ^+ | grep -v +++ | cut -c 2-
	@rm -f .a .b

allbins: bins
	find bins -type f

.PHONY: all clean allbins
