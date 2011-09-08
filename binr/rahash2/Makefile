BIN=rahash2
BINDEPS=r_hash r_util r_print r_asm r_cons r_anal r_lib r_syscall r_reg r_diff r_db

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=-lm
endif
