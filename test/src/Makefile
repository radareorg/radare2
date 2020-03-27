-include ../../config-user.mk

VCOMMIT=efe21fed66574a486df3bf8b30825e6bf4ecd47b
BINDIR=$(shell r2 -H R2_PREFIX)/bin
CWD=$(shell pwd)
V=v/v

all: $(V)
	$(V) -prod r2r.v
	#$(V) -g r2r.v

mrproper: clean
	rm -rf v

$(V): v
	cd v && git pull
	cd v && git reset --hard $(VCOMMIT)
	$(MAKE) -C v
	$(MAKE) ~/.vmodules/radare/r2

~/.vmodules/radare/r2:
	$(V) install radare.r2 || \
	git clone --depth=1 https://github.com/radare/v-r2 ~/.vmodules/radare/r2

clean:
	rm -f r2r
	rm -rf ~/.vmodules/radare/r2
	rm -rf v

fmt:
	$(V) fmt -w r2r.v

v:
	git clone https://github.com/vlang/v
	cd v && git reset --hard $(VCOMMIT)

install: uninstall
	v -prod r2r.v
	rm -f $(BINDIR)/r2r
	ln -fs $(CWD)/r2r $(shell r2 -H R2_PREFIX)/bin
	mkdir -p "${DESTDIR}${MANDIR}/man1"
	cp -rf r2r.1 "${DESTDIR}${MANDIR}/man1"

uninstall:
	rm -f $(BINDIR)/r2r
	rm -f "${DESTDIR}${MANDIR}/man1/r2r.1"
