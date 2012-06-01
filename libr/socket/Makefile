include ../config.mk

NAME=r_socket
#DEPS=r_util
OBJ=socket.o proc.o http.o
ifeq (${HAVE_LIB_SSL},1)
CFLAGS+=${SSL_CFLAGS}
LDFLAGS+=${SSL_LDFLAGS}
endif

# OSX 10.7 (lion)
ifeq (${OSTYPE},darwin)
LDFLAGS+=-lcrypto
endif
# on solaris only
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif
ifeq (${OSTYPE},qnx)
LDFLAGS+=-lsocket
endif
# windows
ifeq (${OSTYPE},windows)
LDFLAGS=-lwsock32
endif

include ../rules.mk
