include ../config.mk

NAME=r_socket
OBJ=socket.o proc.o

# on solaris only
ifeq (${OSTYPE},solaris)
LDFLAGS+=-lsocket
endif
# windows
ifeq (${OSTYPE},windows)
LDFLAGS=-lwsock32
endif

include ../rules.mk
