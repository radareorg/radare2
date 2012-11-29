all:
	gcc -I../../libr/include bin.c
	./a.out

asm:
	gcc -ggdb -g main.c
	./a.out "mov r3,r4"

clean:
	-rm -rf a.out*
