all: test

test:
	${CC} -g -I ../../include test.c ../*.o -lr_util -L../util -o test

clean:
	rm -f test
