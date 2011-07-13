BIN=radiff2
BINDEPS=r_core r_diff r_config r_parse r_lib r_cons r_search r_anal r_reg
BINDEPS+=r_bin r_flags r_debug r_bp r_io r_cmd r_fs
BINDEPS+=r_sign r_print r_lang r_asm r_syscall r_hash r_line r_socket r_util

include ../binr.mk

ifeq ($(WITHNONPIC),1)
LDFLAGS+=${DL_LIBS} -lm
LDFLAGS+=../../libr/fs/p/grub/libgrubfs.a
ifeq ($(HAVE_LIB_GMP),1)
LDFLAGS+=-lgmp
endif
endif

ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
endif
