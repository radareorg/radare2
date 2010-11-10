BIN=ranal2
BINDEPS=r_anal r_lib r_reg r_util

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS} -lm -lgmp -lpthread
endif
