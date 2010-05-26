NAME=r_io
DEPS=r_lib r_util
#DEPS=r_util
CFLAGS+=-Wall -DCORELIB


STATIC_OBJS=
include ../config.mk

foo: pre libr_io.${EXT_SO} libr_io.${EXT_AR} tests plugins

include ${STATIC_IO_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst io_,p/io_,$(STATIC_OBJ)))
OBJ=${STATIC_OBJS} io.o plugin.o map.o section.o desc.o cache.o undo.o

pre:
	@echo STATICOBJS: ${STATIC_OBJS}
	@if [ ! -e libr_io.${EXT_SO} ]; then rm -f ${STATIC_OBJS} ; fi

tests:
	cd t && ${MAKE} all

plugins:
	cd p && ${MAKE} all

include ../rules.mk
