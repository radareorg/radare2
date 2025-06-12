CFLAGS+= -I ../../include -I ../../../subprojects/sdb/include
LDFLAGS+=-L ../ -lr_util

all: sdbtool

sdbtool: sdbtool.o
	$(CC) $(LDFLAGS) -o sdbtool sdbtool.o

clean:
	rm -f sdbtool
