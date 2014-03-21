#!/bin/sh

t="/tmp/symgraph"
rm -rf $t
mkdir -p $t/b $t/l
if [ "`uname`" = Darwin ]; then
	SO=dylib
else
	SO=so
fi

dolib() {
	rabin2 -i $1/libr_$1.${SO} | grep -v mports | cut -d = -f 6 > $t/l/$1.i
	rabin2 -s $1/libr_$1.${SO} | grep -v xports | cut -d = -f 6 > $t/l/$1.s
}

dobin() {
	rabin2 -i ../binr/$1/$1 | grep -v mports | cut -d = -f 9 > $t/b/$1.i
#	rabin2 -s ../binr/$1/$1 | cut -d = -f 8 > $t/b/$1.s
}

LIBS="anal asm bin bp cmd config cons crypto db debug diff flags hash io lang parse reg search socket syscall util core"
for a in $LIBS ; do
	dolib ${a}
done
BINS="rabin2 rasm2 radare2 rax2 ranal2 rahash2 radiff2 rafind2 r2agent"
for a in $BINS ; do
	dobin ${a}
done

cat $t/l/*.i $t/l/*.s $t/b/*.i | sort | uniq -c | sort -n | grep r_
