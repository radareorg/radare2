#!/bin/sh
if [ -n "$1" ]; then
	HASH=`grep ^$1 commits.txt | cut -d ' ' -f 2`
	if [ -z "${HASH}" ]; then
		echo "Invalid commit number"
		exit 1
	fi
	cd radare2
	git diff ${HASH}^..${HASH}
else
	echo "Usage: diff.sh [num]"
fi
