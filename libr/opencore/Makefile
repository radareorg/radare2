# radare2 - MIT - Copyright 2026 - pancake
# standalone library, only depends on libc (and libdl on old glibc)

-include ../../config-user.mk

PREFIX?=/usr/local
LIBDIR?=$(PREFIX)/lib
INCLUDEDIR?=$(PREFIX)/include
INSTALL_DIR?=install -d
INSTALL_DATA?=install -m 644
AR?=ar
RANLIB?=ranlib
CFLAGS+=-Wall -O2 -fPIC

LIB=libr_opencore.a

all: $(LIB)

opencore.o: opencore.c r_opencore.h
	$(CC) $(CFLAGS) -c -o $@ opencore.c

$(LIB): opencore.o
	rm -f $@
	$(AR) rc $@ opencore.o
	$(RANLIB) $@

install: $(LIB)
	$(INSTALL_DIR) "$(DESTDIR)$(LIBDIR)" "$(DESTDIR)$(INCLUDEDIR)/libr"
	$(INSTALL_DATA) $(LIB) "$(DESTDIR)$(LIBDIR)/$(LIB)"
	$(INSTALL_DATA) r_opencore.h "$(DESTDIR)$(INCLUDEDIR)/libr/r_opencore.h"

uninstall:
	rm -f "$(DESTDIR)$(LIBDIR)/$(LIB)" "$(DESTDIR)$(INCLUDEDIR)/libr/r_opencore.h"

clean mrproper:
	rm -f opencore.o $(LIB)

.PHONY: all install uninstall clean mrproper
