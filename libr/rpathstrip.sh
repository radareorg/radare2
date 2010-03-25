#!/bin/sh
# UGLY HACK to remove all rpaths and make r2 work without
# installation.. rpath should be removed at some point..

BIN=bin/t/rpathdel
BINS="rasm2 radare2 rabin2 radiff2 rahash2 rax2 rafind2 rasign2" 

if [ -z "$1" ]; then
	echo "Usage: ./rpathstrip.sh /usr"
	exit 0
fi

if [ ! -x "${BIN}" ]; then
	echo "Not stripping rpaths"
	exit 0
fi
echo "Stripping rpath from installed binaries..."

for a in ${BINS}; do
	${BIN} $1/bin/$a $1/bin/$a
done

for a in ${LIBS}; do
	${BIN} $1/lib/$a $1/lib/$a
done

for a in `cd $1/lib/radare2 ; ls`; do
	${BIN} $1/lib/radare2/$a $1/lib/radare2/$a
done

for a in `cd $1/lib/radare2/test ; ls`; do
	${BIN} $1/lib/radare2/test/$a $1/lib/radare2/test/$a
done

exit 0
