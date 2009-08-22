NAME=r_io
DEPS=r_lib r_util
#DEPS=r_util
CFLAGS+=-Wall -DCORELIB

foo: pre libr_io.so tests plugins

STATIC_OBJS=
include ../config.mk
include ${STATIC_IO_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst io_,p/io_,$(STATIC_OBJ)))
OBJ=${STATIC_OBJS} io.o handle.o map.o section.o

pre:
	@echo STATICOBJS: ${STATIC_OBJS}
	@if [ ! -e libr_io.so ]; then rm -f ${STATIC_OBJS} ; fi

tests:
	cd t && ${MAKE} all

plugins:
	cd p && ${MAKE} all

include ../rules.mk
