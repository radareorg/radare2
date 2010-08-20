#!/bin/sh
TMPFILE=`mktemp`
rasm2 -B -o 0 "$@" > $TMPFILE
LEN=$?
cat $TMPFILE | ./test_anal -o 0 -l $LEN
rm -f $TMPFILE
