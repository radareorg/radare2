NAME=r_core

DEPS=r_config r_cons r_line r_io r_cmd r_util r_print r_flags r_asm r_lib
DEPS+=r_debug r_hash r_bin r_lang r_io r_anal r_parse r_print r_bp
DEPS+=r_reg r_search r_syscall r_sign r_diff r_socket r_fs

OBJ=core.o cmd.o file.o config.o visual.o io.o yank.o libs.o
OBJ+=anal.o project.o gdiff.o asm.o rtr.o vmenus.o disasm.o

CFLAGS+=-DLIBDIR=\"${LIBDIR}\"
CFLAGS+=-DPREFIX=\"${PREFIX}\"
LDFLAGS+=${DL_LIBS}

ifeq ($(shell uname),OpenBSD)
LDFLAGS+=-lpthread
endif

include ../rules.mk

ifeq ($(HAVE_LIB_MAGIC),1)
LDFLAGS+=-lmagic
endif
