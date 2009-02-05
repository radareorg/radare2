all: test

test:
	${CC} -g -I ../../include test.c ../*.o ../../util/*.a -o test

clean:
	rm -f test test.o
