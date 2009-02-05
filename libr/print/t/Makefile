all: hex

hex:
	${CC} ${CFLAGS} -I ../../include hex.c ../*.o ../../cons/*.o ../../util/*.a ../../line/*.a -o hex

clean:
	rm -f hex
