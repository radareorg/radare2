BIN=rahash2

BINDEPS=r_io r_hash r_socket r_asm r_cons
BINDEPS+=r_anal r_syscall r_reg r_parse
BINDEPS+=r_flag r_lang r_crypto r_util

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=-lm
endif

include ../../libr/socket/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
