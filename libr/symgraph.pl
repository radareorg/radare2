#!/bin/sh
imports() {
	rabin2 -i $1 | cut -d = -f 8 > /dev/null
	rabin2 -s $1 | cut -d = -f 8 > /dev/null
}

LIBS="core syscall util"
for a in $LIBS ; do
	imports ${a}/libr_${a}.so
done
BINS="rabin2 radare2 rax2"
for a in $BINS ; do
	imports ../binr/${a}/${a}
done
