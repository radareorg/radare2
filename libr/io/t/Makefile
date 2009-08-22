all: cat read4

cat:
	${CC} -I ../../include cat.c -Wl,-R.. -lr_io -g -o cat

read4:
	${CC} -I ../../include read4.c -Wl,-R.. -lr_io -g -o read4

clean:
	rm -f cat read4
