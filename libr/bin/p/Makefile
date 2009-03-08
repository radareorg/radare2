CFLAGS=-I../../include -Wall -fPIC -shared -Wl,-R..
# XXX
CFLAGS+=-DLIL_ENDIAN=1 -D__UNIX__ -g

OBJ_ELF=bin_elf.o elf/elf.o
OBJ_ELF64=bin_elf64.o elf/elf64.o
OBJ_PE=bin_pe.o pe/pe.o

all: bin_elf.so bin_elf64.so bin_pe.so
	@true

bin_elf.so: ${OBJ_ELF}
	${CC} ${CFLAGS} -o bin_elf.so ${OBJ_ELF}
	@#strip -s bin_elf.so

bin_elf64.so: ${OBJ_ELF64}
	${CC} ${CFLAGS} -o bin_elf64.so ${OBJ_ELF64}
	@#strip -s bin_elf64.so

bin_pe.so: ${OBJ_PE}
	${CC} ${CFLAGS} -o bin_pe.so ${OBJ_PE}
	@#strip -s bin_pe.so

clean:
	-rm -f *.so *.o ${OBJ_ELF} ${OBJ_ELF64} ${OBJ_PE}
