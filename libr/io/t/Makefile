all: cat read4

cat:
	${CC} -I ../../include cat.c ../*.o -lr_util -g -o cat

read4:
	${CC} -I ../../include read4.c ../*.o -lr_util -g -o read4

clean:
	rm -f cat read4
