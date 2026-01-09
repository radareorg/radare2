include ../config.mk

NAME=r_io
R2DEPS+=r_util r_socket r_muta r_cons
STATIC_OBJS=$(subst ..,p/..,$(subst io_,p/io_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS}
OBJS+=io.o io_plugin.o io_map.o io_desc.o io_cache.o p_cache.o io_stream.o
OBJS+=io_bank.o io_submap.o undo.o ioutils.o io_fd.o io_memory.o

CFLAGS+=-Wall -DR2_PLUGIN_INCORE

ifeq ($(USE_PTRACE_WRAP),1)
OBJS+=ptrace_wrap.o
endif

ifeq (${BUILD_OS},dragonfly)
  LDFLAGS+=-lkvm
endif

.PHONY: pre pos
pre: libr_io.$(EXT_SO) libr_io.$(EXT_AR)
	@$(MAKE) -C p
	$(MAKE) pos

pos: $(SHARED_IO_TARGETS)

include ${STATIC_IO_PLUGINS}
include $(LTOP)/rules.mk

include ../socket/deps.mk
include $(SHLR)/zip/deps.mk
include $(SHLR)/gdb/deps.mk
include $(SHLR)/qnx/deps.mk

