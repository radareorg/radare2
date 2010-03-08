CFLAGS+=-g -Wall
PREFIX?=/usr
DESTDIR?=

all: r2rc

r2rc: r2rc.o emit_x86.o emit_x64.o out.o
	gcc -I. out.o r2rc.o emit*.o -o r2rc

test:
	./rcc t/hello.r > t/hello.S
	gcc t/hello.S -o t/hello
#	cat t/hello.S
	t/hello
	#spp test.r | ./rcc
	#./rcc test.r

install:
	chmod +x r2rc
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp r2rc ${DESTDIR}${PREFIX}/bin
	chmod +x r2rc-tool
	cp r2rc-tool ${DESTDIR}${PREFIX}/bin

clean:
	cd t && ${MAKE} clean
	-rm -f r2rc r2rc.o out.o emit*.o
