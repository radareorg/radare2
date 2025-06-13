-include ../../../config.mk
-include ../../../global.mk
HOST_CC?=gcc

CFLAGS+=-g
LDFLAGS+=-g
CFLAGS+=-I ../../include -I ../../../subprojects/sdb/include
LDFLAGS+=-L ../ -lr_util

all: sdbtool

sdbtool:
	$(HOST_CC) $(CFLAGS) $(LDFLAGS) -o sdbtool sdbtool.c

clean:
	rm -f sdbtool sdbtool.o
