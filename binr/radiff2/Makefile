BIN=radiff2
BINDEPS=r_core r_diff r_config r_lib r_cons r_search r_anal
BINDEPS+=r_bin r_debug r_io r_print r_asm r_hash r_util r_fs
BINDEPS+=r_socket r_flags r_lang r_reg r_bp r_cmd r_sign r_parse
BINDEPS+=r_line r_syscall

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
