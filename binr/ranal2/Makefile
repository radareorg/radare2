BIN=ranal2
BINDEPS=r_anal r_lib r_reg r_util r_syscall r_diff

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS} -lm -lpthread
ifeq ($(HAVE_LIB_GMP),1)
LDFLAGS+=-lgmp
endif
endif
