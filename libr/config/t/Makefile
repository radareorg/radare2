all: test

test:
	${CC} -g -I ../../include test.c ../*.o \
	../../util/*.o -o test

clean:
	rm -f test
