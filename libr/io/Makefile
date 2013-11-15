include ../config.mk

NAME=r_io
DEPS=r_lib r_util r_socket r_cons
STATIC_OBJS=$(subst ..,p/..,$(subst io_,p/io_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS}
OBJS+=io.o plugin.o map.o section.o desc.o cache.o undo.o buffer.o

CFLAGS+=-Wall -DCORELIB

include ../socket/deps.mk
#include ../../shlr/zip/deps.mk
LINK+=../../shlr/zip/zlib/*.o
LINK+=../../shlr/zip/zip/*.o

.PHONY: pre
pre: libr_io.${EXT_SO} libr_io.${EXT_AR}
	@${MAKE} -C p

include ${STATIC_IO_PLUGINS}
include $(LTOP)/rules.mk
