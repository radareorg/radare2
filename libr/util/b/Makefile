CFLAGS+= -I ../../include -I ../../../subprojects/sdb/include
CFLAGS+=-g
LDFLAGS+=-g
LDFLAGS+=-L ../ -lr_util

all: sdbtool

sdbtool: sdbtool.o
	$(CC) $(LDFLAGS) -o sdbtool sdbtool.o

clean:
	rm -f sdbtool sdbtool.o
