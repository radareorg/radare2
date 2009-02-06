all: test rax2 ralloc

ralloc:
	${CC} -O2 -g -I ../../include ralloc.c ../*.o -o ralloc

test:
	${CC} -g -I ../../include test.c ../*.o -o test

rax2:
	${CC} -g -I ../../include rax2.c ../*.o -o rax2

clean:
	rm -f calc rax2 ralloc test
