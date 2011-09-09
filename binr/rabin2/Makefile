BIN=rabin2
BINDEPS=r_bin r_cons r_lib r_flags r_util r_db

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS} -lm
LDFLAGS+=../../libr/fs/p/grub/libgrubfs.a
LDFLAGS+=../../libr/db/sdb/src/libsdb.a
ifeq ($(HAVE_LIB_MAGIC),1)
LDFLAGS+=-lmagic
endif
endif

ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
endif
