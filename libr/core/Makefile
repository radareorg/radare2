include ../config.mk

NAME=r_core

R2DEPS=r_config r_cons r_io r_util r_flag r_asm r_arch r_esil
R2DEPS+=r_debug r_bin r_lang r_io r_anal r_bp r_egg
R2DEPS+=r_reg r_search r_syscall r_socket r_fs r_magic r_muta

OBJS=core.o cmd.o cfile.o cconfig.o visual.o cio.o yank.o libs.o agraph.o xpatch.o
OBJS+=fortune.o vasm.o patch.o cbin.o corelog.o rtr.o cmd_api.o cundo.o cproject.o
OBJS+=carg.o canal.o project.o gdiff.o casm.o disasm.o cplugin.o cmd_print_list.o
OBJS+=vmenus.o vmenus_graph.o vmenus_zigns.o zdiff.o citem.o vslides.o clist.o
OBJS+=task.o panels.o pseudo.o vmarks.o anal_objc.o core_esil.o
OBJS+=vmatrix.o prompt.o

CFLAGS+=-DR2_PLUGIN_INCORE -I../../shlr
CFLAGS+=-I./p/heap
LDFLAGS+=-lm
LDFLAGS+=${DL_LIBS}
LDFLAGS+=${CLOCK_LDFLAGS}

ifeq ($(shell uname),OpenBSD)
LDFLAGS+=-lpthread
endif

ifeq ($(USE_LIB_MAGIC),1)
LDFLAGS+=${LIBMAGIC}
endif

ifeq ($(HAVE_LIBUV),1)
CFLAGS+=${LIBUV_CFLAGS}
LDFLAGS+=${LIBUV_LDFLAGS}
endif

first:: all

include ${STATIC_CORE_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/core/p/,$(STATIC_OBJ))
OBJS+=$(STATIC_OBJS)

include $(TOP)/shlr/gdb/deps.mk
# include $(LIBR)/util/spp.mk
include $(LTOP)/rules.mk
include $(STOP)/java/deps.mk

cmd.o: cmd_hash.inc.c cmd_debug.inc.c cmd_zign.inc.c cmd_project.inc.c \
	cmd_open.inc.c cmd_meta.inc.c cmd_macro.inc.c cmd_magic.inc.c cmd_mount.inc.c cmd_eval.inc.c \
	cmd_seek.inc.c cmd_print.inc.c cmd_help.inc.c cmd_anal.inc.c cmd_search.inc.c cmd_log.inc.c \
	cmd_cmp.inc.c cmd_write.inc.c cmd_egg.inc.c cmd_info.inc.c cmd_type.inc.c cmd_flag.inc.c \
	cmd_search_rop.inc.c

visual.o: visual_tabs.inc.c

disasm.o: disasm_stackptr.inc.c

rtr.o: rtr_http.inc.c rtr_shell.inc.c
