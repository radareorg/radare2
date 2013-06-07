#!/bin/sh
[ -z "$1" ] && exit 1
for a in `echo $PATH|sed -e 's,:, ,g'` ; do
	if [ -x "$a/$1" ]; then
		echo "$a/$1"
		exit 0
	fi
done
exit 1
