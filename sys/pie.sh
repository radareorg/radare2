#!/bin/sh

F="$1"

if [ -z "${F}" ]; then
	echo "Usage: sys/pie.sh [last-release-tag]"
	exit 1
fi

git log $F..@ > .ch.txt

WHO=`cat .ch.txt |grep ^Author|sort -u | cut -d '<' -f 1 | cut -d ':' -f 2 | cut -c 2- |sed -e 's, ,_,g' | sed -e 's,_$,,'`

for a in ${WHO} ; do
	USER=`echo $a | sed -e 's,_, ,g'`
	CNTR=`grep -re "${USER}" .ch.txt | wc -l |awk '{print $1}'`
	echo "$CNTR\t$USER"
done

rm -f .ch.txt

