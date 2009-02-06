all: baddr entry info sections symbols imports data_resize rabin2

baddr:
	${CC} -g -I ../../include baddr.c ../*.o -o baddr
entry:
	${CC} -g -I ../../include entry.c ../*.o -o entry
info:
	${CC} -g -I ../../include info.c ../*.o -o info
sections:
	${CC} -g -I ../../include sections.c ../*.o -o sections
symbols:
	${CC} -g -I ../../include symbols.c ../*.o -o symbols
imports:
	${CC} -g -I ../../include imports.c ../*.o -o imports
data_resize:
	${CC} -g -I ../../include data_resize.c ../*.o -o data_resize
rabin2:
	${CC} -g -I ../../include rabin2.c -lr_bin -lr_util -lr_flags \
	-L.. -L../..bin -L../../flags -L../../util -o rabin2

clean:
	rm -f baddr entry info sections symbols imports data_resize rabin2
