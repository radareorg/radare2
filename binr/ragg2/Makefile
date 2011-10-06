BIN=ragg2
BINDEPS=r_egg r_bin r_syscall r_asm r_util r_db r_parse

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS}
LDFLAGS+=../../libr/db/sdb/src/libsdb.a
endif

t test:
	cd t ; ${MAKE}

.PHONY: t
