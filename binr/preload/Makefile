BIN=libr2
ISLIB=1
BINDEPS=r_core r_parse r_search r_cons r_config r_cmd
BINDEPS+=r_bin r_debug r_anal r_diff r_reg r_bp r_io
BINDEPS+=r_lang r_asm r_syscall r_db r_hash r_crypto
BINDEPS+=r_magic r_socket r_flags r_util r_egg r_fs

include ../rules.mk
CFLAGS+=-DR2_GITTAP=\"$(GIT_TAP)\"

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif
include ../../libr/socket/deps.mk
include ../../shlr/zip/deps.mk
