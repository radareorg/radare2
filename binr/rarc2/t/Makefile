.PHONY: all clean run top

RC=../rarc2 -s
CC=tcc
CC=gcc

BIN=hi ptr ret hello shell loop input inline syscall data sub if dump bytedump argv room rawsys

all: top ${BIN}

clean:
	rm -f ${BIN} *.S

run:
	for a in ${BIN}; do ./$$a ; done

top:
	#rm -f shell
	rm -f ../rarc2
	cd .. && ${MAKE} rarc2

syscall:
	${RC} syscall.r > syscall.S
	${CC} syscall.S -o syscall

hi:
	${RC} hi.r > hi.S
	${CC} hi.S -o hi

rawsys:
	${RC} rawsys.r > rawsys.S
	${CC} rawsys.S -o rawsys

data:
	${RC} data.r > data.S
	${CC} data.S -o data

ret:
	${RC} ret.r > ret.S
	${CC} ret.S -o ret

sub:
	${RC} sub.r > sub.S
	${CC} sub.S -o sub

inline:
	${RC} inline.r > inline.S
	${CC} inline.S -o inline

loop:
	${RC} loop.r > loop.S
	${CC} loop.S -o loop

shell:
	${RC} shell.r > shell.S
	${CC} shell.S -o shell

hello:
	${RC} hello.r > hello.S
	${CC} -g hello.S -o hello

ptr:
	${RC} ptr.r > ptr.S
	${CC} ptr.S -o ptr

input:
	${RC} input.r > input.S
	${CC} input.S -o input

if:
	${RC} if.r > if.S
	${CC} if.S -o if

dump:
	${RC} dump.r > dump.S
	${CC} dump.S -o dump

bytedump:
	${RC} bytedump.r > bytedump.S
	${CC} bytedump.S -o bytedump

argv:
	${RC} argv.r > argv.S
	${CC} argv.S -o argv

room:
	${RC} room.r > room.S
	${CC} room.S -o room
