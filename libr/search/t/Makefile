all: test test-str

test:
	${CC} -g -I ../../include test.c ../*.o ../../util/*.a -o test

test-str:
	${CC} -g -I ../../include test-str.c ../*.o ../../util/*.a -o test-str

clean:
	rm -f test test.o test-str test-str.o
