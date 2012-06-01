BIN=rabin2
BINDEPS=r_lib r_magic r_core r_db r_bin r_egg r_cons
BINDEPS+=r_config r_line r_io r_cmd r_print r_flags r_asm
BINDEPS+=r_debug r_hash r_lang r_anal r_parse r_bp r_reg
BINDEPS+=r_search r_syscall r_sign r_diff r_socket r_fs r_magic r_util

include ../binr.mk
ifeq ($(OSTYPE),qnx)
LDFLAGS+=-lsocket
endif
