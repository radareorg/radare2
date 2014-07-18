include ../config.mk

NAME=r_socket
OBJS=socket.o proc.o http.o http_server.o rap_server.o run.o
DEPS=r_util

ifneq (,$(findstring mingw32,${OSTYPE}))
LDFLAGS+=-lws2_32
endif

include deps.mk
include ../rules.mk
