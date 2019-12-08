VERSION=3.4.0
DESTDIR?=/
PREFIX?=/usr/local
BINDIR=$(DESTDIR)/$(PREFIX)/bin
PWD=$(shell pwd)
PKG=radare2-regressions
TAR=tar -cvf
TAREXT=tar.xz
CZ=xz -f

TDIRS=$(shell ls -d t*| grep -v tmp) bins
LIBDIR=$(DESTDIR)/$(PREFIX)/lib

-include config.mk

all: js-tests unit_tests

bins:
	git clone --depth 1 https://github.com/radareorg/radare2-testbins bins

fuzz/targets:
	git clone --depth 1 https://github.com/radareorg/radare2-fuzztargets fuzz/targets

R2R=$(shell cd new ; npm bin)/r2r

js-tests: bins
	cd new && npm install
	cd new && $(R2R)

keystone: bins
	cd new && npm install
	cd new && $(R2R) db/extras/asm/x86.ks_

swf: bins
	cd new && npm install
	cd new && $(R2R) db/extras/asm/swf

m68k-extras: bins
	cd new && npm install
	cd new && $(R2R) db/extras/asm/m68k

mc6809: bins
	cd new && npm install
	cd new && $(R2R) db/extras/asm/x86.udis

microblaze: bins
	cd new && npm install
	cd new && $(R2R) db/extras/asm/microblaze.gnu

udis86: bins
	cd new && npm install
	cd new && $(R2R) db/extras/asm/mc6809

olly-extras: bins
	cd new && npm install
	cd new && $(R2R) db/extras/asm/x86.olly

dwarf: bins
	cd new && npm install
	cd new && $(R2R) db/extras/asm/dwarf
broken:
	grep BROKEN=1 t -r -l

clean:
	rm -rf tmp

symstall:
	mkdir -p $(BINDIR)
	chmod +x r2-v r2r
	ln -fs $(PWD)/r2-v $(BINDIR)/r2-v
	ln -fs $(PWD)/r2r $(BINDIR)/r2r

install:
	mkdir -p $(BINDIR)
	sed -e 's,@R2RDIR@,$(LIBDIR)/radare2-regressions,g' < $(PWD)/r2-v > $(BINDIR)/r2-v
	sed -e 's,@R2RDIR@,$(LIBDIR)/radare2-regressions,g' < $(PWD)/r2r > $(BINDIR)/r2r
	chmod +x $(BINDIR)/r2-v
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

dist:
	git clone . $(PKG)-$(VERSION)
	rm -rf $(PKG)-$(VERSION)/.git
	$(TAR) "$(PKG)-${VERSION}.tar" "$(PKG)-$(VERSION)"
	${CZ} "$(PKG)-${VERSION}.tar"

.PHONY: all clean allbins dist
