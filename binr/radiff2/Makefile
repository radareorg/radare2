BIN=radiff2
BINDEPS=r_core r_diff r_config r_cons r_search r_anal
BINDEPS+=r_bin r_debug r_io r_asm r_hash r_fs
BINDEPS+=r_socket r_flags r_lang r_reg r_bp r_parse
BINDEPS+=r_syscall r_db r_magic r_util r_parse r_egg

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif

include ../../libr/socket/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
