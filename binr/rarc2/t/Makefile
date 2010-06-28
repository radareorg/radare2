LC=../rcc
CC=tcc
CC=gcc

BIN=ptr ret hello shell loop input inline syscall data sub if dump bytedump argv room rawsys

all: top ${BIN}


top:
	#rm -f shell
	rm -f ../rcc
	cd .. && ${MAKE} rcc

syscall:
	${LC} syscall.r > syscall.S
	${CC} syscall.S -o syscall

rawsys:
	${LC} rawsys.r > rawsys.S
	${CC} rawsys.S -o rawsys

data:
	${LC} data.r > data.S
	${CC} data.S -o data

ret:
	${LC} ret.r > ret.S
	${CC} ret.S -o ret

sub:
	${LC} sub.r > sub.S
	${CC} sub.S -o sub

inline:
	${LC} inline.r > inline.S
	${CC} inline.S -o inline

loop:
	${LC} loop.r > loop.S
	${CC} loop.S -o loop

shell:
	${LC} shell.r > shell.S
	${CC} shell.S -o shell

hello:
	${LC} hello.r > hello.S
	${CC} -g hello.S -o hello

ptr:
	${LC} ptr.r > ptr.S
	${CC} ptr.S -o ptr

input:
	${LC} input.r > input.S
	${CC} input.S -o input

if:
	${LC} if.r > if.S
	${CC} if.S -o if

dump:
	${LC} dump.r > dump.S
	${CC} dump.S -o dump

bytedump:
	${LC} bytedump.r > bytedump.S
	${CC} bytedump.S -o bytedump

argv:
	${LC} argv.r > argv.S
	${CC} argv.S -o argv

room:
	${LC} room.r > room.S
	${CC} room.S -o room

clean:
	rm -f ${BIN} *.S

run:
	for a in ${BIN}; do ./$$a ; done
