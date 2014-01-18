BIN=ranal2
BINDEPS=r_anal r_reg r_syscall r_diff r_db r_util

include ../rules.mk

ifeq ($(WITHNONPIC),1)
ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif
endif
