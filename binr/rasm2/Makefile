BIN=rasm2
BINDEPS=r_asm r_util r_lib r_parse

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS}
endif
