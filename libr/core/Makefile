NAME=r_core

DEPS=r_config r_cons r_line r_io r_cmd r_util r_print r_flags r_asm r_lib
DEPS+=r_debug r_hash r_bin r_lang r_io r_asm r_anal r_parse r_config
DEPS+=r_print r_bp r_reg r_meta r_search r_syscall r_sign

OBJ=core.o cmd.o file.o config.o visual.o io.o yank.o libs.o anal.o project.o gdiff.o

CFLAGS+=-DLIBDIR=\"${PREFIX}/lib\"
CFLAGS+=-DPREFIX=\"${PREFIX}\"
LDFLAGS+=${DL_LIBS}

include ../rules.mk
