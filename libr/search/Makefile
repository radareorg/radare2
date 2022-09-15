include ../config.mk

NAME=r_search
OBJS=search.o bytepat.o strings.o aes_find.o privkey_find.o sm4_find.o
OBJS+=regexp.o keyword.o uds.o rabin_karp.o
# OBJ+=rsakey.o
R2DEPS=r_util r_crypto
CFLAGS+=-g
CFLAGS+= -L../../crypto -lr_crypto

include ../rules.mk
