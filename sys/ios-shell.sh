#!/bin/sh
[ -z "$SHELL" ] && SHELL=/bin/sh

if [ -d sys ]; then
	export PATH="$PWD/sys/:$PATH"
	$SHELL
else
	echo "Run from r2 root directory"
	exit 1
fi
