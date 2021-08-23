#!/bin/sh
[ -z "$TMPDIR" ] && TMPDIR=/tmp
[ -w "$TMPDIR" ] || TMPDIR="$PWD"
T=$TMPDIR/.cc.txt
if [ -n "$1" ]; then
	echo 1 > "$T"
else
	N=`cat $T 2> /dev/null`
	N=$(($N+1))
	basename `pwd`
	echo "$N" | tee "$T" 2> /dev/null
fi
exit 0
