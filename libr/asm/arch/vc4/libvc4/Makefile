
all: decode

CC = gcc
CFLAGS = -g -Wall -Wextra -O0

libvc4.a: vc4_util.o vc4_arch.o vc4_decode.o eval.o
	@rm -f $@
	ar r $@ $^

decode: libvc4.a decode.c
	gcc -Wall -O0 -g decode.c libvc4.a -o decode

vc4_util.o vc4_arch.o vc4_decode.o eval.o: vc4.h
decode: vc4.h

%.o: %.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o libvc4.a decode
