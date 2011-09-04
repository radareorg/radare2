BIN=rabin2
BINDEPS=r_bin r_cons r_util r_lib r_flags r_db
# rapatch deps
BINDEPS+=r_core

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS}
endif
