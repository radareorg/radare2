#!/bin/sh
[ -z "$TMPDIR" ] && TMPDIR=/tmp
[ -w "$TMPDIR" ] || TMPDIR="$PWD"
T=$TMPDIR/.cc.txt
if [ -n "$1" ]; then
	echo 0 > $T 2> /dev/null
	N=0
else
	N=`cat $T 2> /dev/null`
fi
N=$(($N+1))
basename `pwd`
echo $N | tee $T 2> /dev/null
exit 0
