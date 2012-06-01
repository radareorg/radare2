BIN=radiff2
BINDEPS=r_core r_diff r_config r_lib r_cons r_search r_anal
BINDEPS+=r_bin r_debug r_io r_print r_asm r_hash r_fs
BINDEPS+=r_socket r_flags r_lang r_reg r_bp r_cmd r_sign r_parse
BINDEPS+=r_line r_syscall r_db r_magic r_util r_parse r_egg

include ../binr.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif

ifeq ($(OSTYPE),qnx)
LDFLAGS+=-lsocket
endif
