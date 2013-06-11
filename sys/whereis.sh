#!/bin/sh
[ -z "$1" ] && exit 1
export IFS=:
for a in $PATH ; do
	if [ -x "$a/$1" ]; then
		echo "$a/$1"
		exit 0
	fi
done
exit 1
