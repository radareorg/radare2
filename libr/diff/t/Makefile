all: test radiff2

test:
	${CC} -g -I ../../include test.c ../*.o ../../util/*.a -o test

radiff2:
	${CC} -g -I ../../include radiff2.c ../*.o ../../util/*.a -o radiff2

clean:
	rm -f test test.o radiff2
