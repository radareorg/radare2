include ../config.mk

NAME=r_socket
OBJS=socket.o
OBJS+=socket_proc.o
OBJS+=socket_http.o # TODO: rename to socket_http_client.o
OBJS+=socket_http_server.o
OBJS+=socket_rap_server.o
OBJS+=socket_rap_client.o
OBJS+=run.o r2pipe.o socket_serial.o
R2DEPS=r_util

include deps.mk
include ../rules.mk
