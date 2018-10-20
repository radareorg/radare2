include ../config.mk

NAME=r_io
DEPS+=r_util
DEPS+=r_socket
STATIC_OBJS=$(subst ..,p/..,$(subst io_,p/io_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS}
OBJS+=io.o plugin.o map.o section.o desc.o cache.o p_cache.o undo.o ioutils.o fd.o

CFLAGS+=-Wall -DCORELIB

include ../socket/deps.mk
include $(SHLR)/ar/deps.mk
include $(SHLR)/zip/deps.mk
include $(SHLR)/gdb/deps.mk
include $(SHLR)/qnx/deps.mk

ifeq ($(USE_PTRACE_WRAP),1)
include $(SHLR)/ptrace-wrap/deps.mk
OBJS+=$(PTRACEWRAP_OBJS)
endif

.PHONY: pre
pre: libr_io.${EXT_SO} libr_io.${EXT_AR}
	@${MAKE} -C p

include ${STATIC_IO_PLUGINS}
include $(LTOP)/rules.mk
