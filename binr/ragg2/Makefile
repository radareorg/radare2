BIN=ragg2
BINDEPS=r_egg r_bin r_syscall r_asm r_util r_db

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS}
endif

t test:
	cd t ; ${MAKE}

.PHONY: t
