include ../../../global.mk
include ../../../config-user.mk

P=${DESTDIR}${DATADIR}/radare2/${VERSION}/enco

CWD=$(shell pwd)

CFLAGS+=-I$(LTOP)/include -I$(LTOP)/enco/p/ -Wall $(PIC_CFLAGS)
ifeq ($(CC),cccl)
LDFLAGS+=-L$(LTOP)/util -llibr_util
LDFLAGS+=-L$(LTOP)/bin -llibr_bin
LDFLAGS+=-L$(LTOP)/io -llibr_io
else
LDFLAGS+=-L$(LTOP)/util -lr_util
LDFLAGS+=-L$(LTOP)/bin -lr_bin
LDFLAGS+=-L$(LTOP)/io -lr_io
endif
SHLR=$(LTOP)/../shlr


.PHONY: all clean do install symstall install-symlink uninstall


all: ${ALL_TARGETS}

ALL_TARGETS=
ENCODINGS=pokered.mk
ENCODINGS+=

include $(ENCODINGS)

clean:
	-rm -f *.so *.o ${STATIC_OBJ}


do:
	rm -rf "$P/p"
	mkdir -p "$P/p"
	for FILE in * ; do \
		if [ $$FILE != Makefile -a $$FILE != meson.build -a -f $$FILE ]; then \
			cp -PRpf "${CWD}/$$FILE" "$P/d/$$FILE" ; \
		fi ; \
	done

install: ${F_SDB}
	@echo "[i] Installing encoding files"
	rm -rf "$P/p"
	mkdir -p "$P/p"
	for FILE in * ; do \
		if [ $$FILE != Makefile -a $$FILE != meson.build -a -f $$FILE ]; then \
			cp -PRpf "${CWD}/$$FILE" "$P/$$FILE" ; \
		fi ; \
	done

symstall install-symlink:
	mkdir -p "$P"
	for FILE in * ; do \
		if [ $$FILE != Makefile -a $$FILE != meson.build -a -f $$FILE ]; then \
			ln -fs "${CWD}/$$FILE" "$P/$$FILE" ; \
		fi ; \
	done

uninstall:
	rm -rf "$P"
