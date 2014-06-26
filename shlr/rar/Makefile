include ../../global.mk

all:
	${CC} -I../../libr/include bin.c
	./a.out

asm:
	${CC} -ggdb -g main.c
	./a.out "mov r3,r4"

clean:
	-rm -rf a.out*
