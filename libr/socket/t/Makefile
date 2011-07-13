include ../../config.mk

OBJ=serverssl.o
BIN=serverssl
BINDEPS=r_socket

ifeq (${HAVE_LIB_SSL},1)
LDFLAGS+=-lssl -lcrypto
endif

include ../../rules.mk
