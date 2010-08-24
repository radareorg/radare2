NAME=r_core

DEPS=r_config r_cons r_line r_io r_cmd r_util r_print r_flags r_asm r_lib
DEPS+=r_debug r_hash r_bin r_lang r_io r_anal r_parse r_print r_bp
DEPS+=r_reg r_search r_syscall r_sign r_diff r_vm r_socket

OBJ=core.o cmd.o file.o config.o visual.o io.o yank.o libs.o anal.o project.o gdiff.o asm.o rtr.o

CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"
CFLAGS+=-DPREFIX=\"${PREFIX}\"
LDFLAGS+=${DL_LIBS}

include ../rules.mk
