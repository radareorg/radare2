include ../../config.mk

OBJ=serverssl.o
BIN=serverssl
BINDEPS=r_socket

ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
endif

include ../../rules.mk
