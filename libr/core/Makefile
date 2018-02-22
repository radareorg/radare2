include ../config.mk

NAME=r_core

DEPS=r_config r_cons r_io r_util r_flag r_asm
DEPS+=r_debug r_hash r_bin r_lang r_io r_anal r_parse r_bp r_egg
DEPS+=r_reg r_search r_syscall r_socket r_fs r_magic r_crypto
PCCFLAGS=@SSL_CFLAGS@ @CAPSTONE_CFLAGS@
PCLIBS=@SSL_LDFLAGS@ @CAPSTONE_LDFLAGS@

OBJS=core.o cmd.o file.o cconfig.o visual.o cio.o yank.o libs.o graph.o
OBJS+=fortune.o hack.o vasm.o patch.o cbin.o log.o rtr.o cmd_api.o
OBJS+=carg.o canal.o project.o gdiff.o asm.o vmenus.o disasm.o plugin.o
OBJS+=task.o panels.o pseudo.o vmarks.o anal_tp.o blaze.o

CFLAGS+=-I../../shlr/heap/include
CFLAGS+=-DCORELIB -I../../shlr
LDFLAGS+=${DL_LIBS}

ifeq ($(shell uname),OpenBSD)
LDFLAGS+=-lpthread
endif

ifeq ($(USE_LIB_MAGIC),1)
#LDFLAGS+=-lmagic
LDFLAGS+=${LIBMAGIC}
endif

first:: all

include ${STATIC_CORE_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/core/p/,$(STATIC_OBJ))
OBJS+=$(STATIC_OBJS)

#STATIC_OBJS=$(subst ..,p/..,$(subst core_,p/core_,$(STATIC_OBJ)))

include $(TOP)/shlr/gdb/deps.mk
include $(LTOP)/rules.mk

# include plugins
#include ${STATIC_CORE_PLUGINS}

cmd.o: cmd_hash.c cmd_debug.c cmd_zign.c cmd_section.c cmd_project.c \
	cmd_open.c cmd_meta.c cmd_macro.c cmd_magic.c cmd_mount.c cmd_eval.c \
	cmd_seek.c cmd_print.c cmd_help.c cmd_anal.c cmd_search.c cmd_log.c \
	cmd_cmp.c cmd_write.c cmd_egg.c cmd_info.c cmd_type.c cmd_flag.c \
	cmd_search_rop.c
