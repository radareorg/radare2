#!/bin/sh
[ -z "$TMPDIR" ] && TMPDIR=/tmp
[ -w "$TMPDIR" ] || TMPDIR="$PWD"
T=$TMPDIR/.cc.txt
if [ -n "$1" ]; then
	echo 1 > "$T"
else
	N=`head -n1 $T 2> /dev/null`
	[ -z "$N" ] && N=0
	N=$((1+$N))
	basename `pwd`
	echo "$N" | tee "$T" 2> /dev/null
fi
exit 0
