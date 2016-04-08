#!/bin/sh
[ -z "$SHELL" ] && SHELL=/bin/sh

if [ -d sys ]; then
	export IOSINC=`pwd`/sys/ios-include
	export PATH="$PWD/sys/:$PATH"
	export PS1="[ios-sdk \w]> "
	$SHELL
else
	echo "Run from r2 root directory"
	exit 1
fi
