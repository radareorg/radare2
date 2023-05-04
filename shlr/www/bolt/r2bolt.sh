#!/bin/sh
# arg1 = compiler+flags
# arg2 = base64(source)

if [ -z "$1" ]; then
	CC="gcc -S"
else
	CC="`rax2 -D $1`"
fi
if [ -z "$2" ]; then
	CS="main() {}"
else
	CS="`rax2 -D $2`"
fi

USE_R2=1
if [ "$USE_R2" = 1 ]; then
	echo "$CS" > .a.c
	gcc -o a.out .a.c
# r2 -qcq -e scr.color=0 -e asm.lines=0 -e asm.bytes=0 -c'pD $SS@$S;aa;agf' a.out
	r2 -qcq -e scr.color=0 -e asm.lines=0 -e asm.bytes=0 -c'af;agf' a.out
	rm -f .a.c a.out
else
	echo "$CS" > .a.c
	$CC .a.c
	cat .a.s
	rm -f .a.s .a.c
fi
