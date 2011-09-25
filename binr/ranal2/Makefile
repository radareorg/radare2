BIN=ranal2
BINDEPS=r_anal r_lib r_reg r_util r_syscall r_diff r_db

include ../binr.mk

ifeq ($(WITHNONPIC),1)
ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
else
LDFLAGS+=${DL_LIBS} -lm -lpthread
endif
LDFLAGS+=../../libr/db/sdb/src/libsdb.a
ifeq ($(HAVE_LIB_GMP),1)
LDFLAGS+=-lgmp
endif
endif
