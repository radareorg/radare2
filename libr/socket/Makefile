include ../config.mk

NAME=r_socket
OBJS=socket.o proc.o http.o http_server.o
OBJS+=rap_server.o run.o r2pipe.o
DEPS=r_util

ifneq (,$(findstring mingw32,${OSTYPE}))
LDFLAGS+=-lws2_32
endif

include deps.mk
include ../rules.mk
