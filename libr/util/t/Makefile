# TODO: append EXECEXT to BINS
all: test rax2 ralloc iter file_slurp_hexpairs

ralloc:
	${CC} -O2 -g -I ../../include ralloc.c ../*.o -o ralloc

test:
	${CC} -g -I ../../include test.c ../*.o -o test

rax2:
	${CC} -g -I ../../include rax2.c ../*.o -o rax2

iter:
	${CC} iter.c `pkg-config r_util --cflags --libs` -o iter

file_slurp_hexpairs:
	${CC} -I../../include test_file_slurp_hexpairs.c -lr_util -o file_slurp_hexpairs


clean:
	rm -f calc rax2 ralloc test
