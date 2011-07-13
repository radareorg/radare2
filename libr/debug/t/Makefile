include ../../config.mk

OBJ=main.o
BIN=main
BINDEPS=r_lib r_debug r_bp r_io r_reg r_cons r_util r_anal r_socket r_syscall r_diff
LIBS+=${DL_LIBS}
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LIBS+=${SSL_LDFLAGS}
endif

include ../../rules.mk
