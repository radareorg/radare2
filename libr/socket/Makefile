include ../config.mk

NAME=r_socket
#DEPS=r_util
OBJ=socket.o proc.o http.o
ifeq (${HAVE_LIB_SSL},1)
LDFLAGS+=-lssl -lcrypto
endif

# on solaris only
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif
# windows
ifeq (${OSTYPE},windows)
LDFLAGS=-lwsock32
endif

include ../rules.mk
