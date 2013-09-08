BIN=rahash2
BINDEPS=r_io r_hash r_util r_socket r_asm r_cons
BINDEPS+=r_anal r_lib r_syscall r_reg r_diff r_db r_parse
BINDEPS+=r_flags r_core

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=-lm
endif
ifeq ($(OSTYPE),qnx)
LDFLAGS+=-lsocket
endif
