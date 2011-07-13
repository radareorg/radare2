BIN=rafind2
BINDEPS=r_search r_io r_print r_lib r_asm r_anal r_reg r_cons r_util r_syscall r_diff
BINDEPS+=r_socket

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS} -lm
LDFLAGS+=../../libr/fs/p/grub/libgrubfs.a
ifeq ($(HAVE_LIB_GMP),1)
LDFLAGS+=-lgmp
endif

endif
ifeq (${HAVE_LIB_SSL},1)
LDFLAGS+=-lssl -lcrypto
endif
