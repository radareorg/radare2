#!/bin/sh
t="/tmp/symgraph"
rm -rf $t
mkdir -p $t/b $t/l

dolib() {
	rabin2 -i $1/libr_$1.so | grep -v mports | cut -d = -f 8 > $t/l/$1.i
	rabin2 -s $1/libr_$1.so | grep -v xports | cut -d = -f 8 > $t/l/$1.s
}

dobin() {
	rabin2 -i ../binr/$1/$1 | grep -v mports | cut -d = -f 8 > $t/b/$1.i
#	rabin2 -s ../binr/$1/$1 | cut -d = -f 8 > $t/b/$1.s
}

LIBS="anal asm bin bp cmd config cons crypto db debug diff flags hash io lang lib line meta parse print reg search sign socket syscall sysproxy th util vm core"
for a in $LIBS ; do
	dolib ${a}
done
BINS="rabin2 rasm2 radare2 rax2 ranal2 rahash2 radiff2 rafind2"
for a in $BINS ; do
	dobin ${a}
done

cat $t/l/*.i $t/l/*.s $t/b/*.i | sort | uniq -c | sort -n | grep r_
