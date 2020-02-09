-include ../../config-user.mk

VCOMMIT=e3ef410a1c7961e6cd655d7dda81bf4a3b2f33dc
BINDIR=$(shell r2 -H R2_PREFIX)/bin
CWD=$(shell pwd)
V=v/v

all: $(V)
	$(V) -prod r2r.v
	#$(V) -g r2r.v

clean:
	rm -f r2r

mrproper: clean
	rm -rf v

$(V): v
	cd v && git pull
	cd v && git reset --hard $(VCOMMIT)
	$(MAKE) -C v
	$(V) install radare.r2

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
